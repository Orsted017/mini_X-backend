const express = require("express");
const { Pool } = require("pg");
const multer = require("multer");
const cors = require("cors");
const path = require("path");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const fs = require("fs");

const app = express();

app.use(cors());
app.use(express.json());

// Создаём папку uploads, если она не существует
if (!fs.existsSync("uploads")) {
  fs.mkdirSync("uploads");
}

// Настройка multer для загрузки файлов
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/");
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  },
});

const upload = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png|gif/;
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = filetypes.test(file.mimetype);
    if (extname && mimetype) {
      return cb(null, true);
    } else {
      cb(new Error("Only images are allowed (jpeg, jpg, png, gif)"));
    }
  },
  limits: { fileSize: 5 * 1024 * 1024 }, // Ограничение размера файла 5MB
});

// Middleware для обработки ошибок multer
const handleMulterError = (err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: "File upload error: " + err.message });
  } else if (err) {
    return res.status(400).json({ error: err.message });
  }
  next();
};

// Настройка статической папки для загрузок
app.use("/uploads", express.static("uploads"));

// Подключение к PostgreSQL
const pool = new Pool({
  host: "dpg-d0u36lu3jp1c73fb5ibg-a",
  user: "abduqodir",
  password: "uH6Ytyrf7BnyiHwZjkmwMHRyh5pNSEr0",
  database: "mini_x_ulpg",
  port: 5432,
});

pool.connect((err) => {
  if (err) {
    console.error("Error connecting to PostgreSQL:", err);
    return;
  }
  console.log("Connected to PostgreSQL");
});

const JWT_SECRET = "key";

// Middleware для аутентификации токена
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access token required" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Invalid token" });
    }
    req.user = user;
    next();
  });
};

// Регистрация пользователя
app.post("/register", upload.single("avatar"), handleMulterError, async (req, res) => {
  const { name, username, password, location, birthdate } = req.body;
  const avatarPath = req.file ? `/uploads/${req.file.filename}` : null;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      "INSERT INTO users (name, username, password, location, birthdate, avatar_url) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *",
      [name, username, hashedPassword, location, birthdate, avatarPath]
    );

    const user = result.rows[0];
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: "1h" });
    res.json({ token });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(400).json({ error: "Username already exists" });
    }
    res.status(500).json({ error: err.message });
  }
});

// Логин пользователя
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Username and password are required" });
  }

  try {
    const result = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    const user = result.rows[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: "1h" });
    res.json({ success: true, token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Получение профиля пользователя
app.get("/profile", authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  try {
    const result = await pool.query(
      "SELECT id, name, username, location, birthdate, avatar_url FROM users WHERE id = $1",
      [userId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Обновление профиля
app.post("/update-profile", authenticateToken, upload.single("avatar"), handleMulterError, async (req, res) => {
  const userId = req.user.userId;
  const { name, username, password, location, birthdate } = req.body;
  const avatarPath = req.file ? `/uploads/${req.file.filename}` : null;

  try {
    // Получаем текущие данные пользователя, чтобы сохранить старый avatar_url, если новый не загружен
    const userResult = await pool.query("SELECT avatar_url FROM users WHERE id = $1", [userId]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const currentAvatarUrl = userResult.rows[0].avatar_url;
    const finalAvatarUrl = avatarPath || currentAvatarUrl; // Если новый аватар не загружен, сохраняем старый

    // Если пароль указан, хешируем его
    let hashedPassword = null;
    if (password) {
      hashedPassword = await bcrypt.hash(password, 10);
    }

    // Обновляем данные пользователя
    if (hashedPassword) {
      await pool.query(
        "UPDATE users SET name = $1, username = $2, password = $3, location = $4, birthdate = $5, avatar_url = $6 WHERE id = $7",
        [name, username, hashedPassword, location, birthdate, finalAvatarUrl, userId]
      );
    } else {
      await pool.query(
        "UPDATE users SET name = $1, username = $2, location = $3, birthdate = $4, avatar_url = $5 WHERE id = $6",
        [name, username, location, birthdate, finalAvatarUrl, userId]
      );
    }

    res.json({ success: true });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(400).json({ error: "Username already exists" });
    }
    res.status(500).json({ error: err.message });
  }
});

// Подписка на план
app.post("/subscribe", authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  const { plan, price, period } = req.body;
  try {
    await pool.query(
      "INSERT INTO subscriptions (user_id, plan, price, period) VALUES ($1, $2, $3, $4)",
      [userId, plan, price, period]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Добавление поста
app.post("/add-post", authenticateToken, upload.single("image"), handleMulterError, async (req, res) => {
  const { text } = req.body;
  const userId = req.user.userId;

  try {
    const userResult = await pool.query("SELECT * FROM users WHERE id = $1", [userId]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = userResult.rows[0];
    const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;

    const result = await pool.query(
      "INSERT INTO posts (user_id, text, image_url, created_at) VALUES ($1, $2, $3, $4) RETURNING *",
      [userId, text, imageUrl, new Date()]
    );

    const newPost = result.rows[0];
    res.status(201).json({
      id: newPost.id,
      userId: newPost.user_id,
      author: user.name,
      username: user.username,
      avatar_url: user.avatar_url || "https://via.placeholder.com/40",
      text: newPost.text,
      image_url: newPost.image_url,
      created_at: newPost.created_at,
      likes: 0,
      comments: [],
      likedBy: [],
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Все посты (для home.html)
app.get("/posts", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT p.id, p.user_id, p.text, p.image_url, p.created_at,
              u.name AS author, u.username, u.avatar_url,
              (SELECT COUNT(*) FROM likes l WHERE l.post_id = p.id) as likes,
              (SELECT JSON_AGG(
                JSON_BUILD_OBJECT(
                  'id', c.id,
                  'username', u2.username,
                  'avatar_url', u2.avatar_url,
                  'comment', c.comment,
                  'created_at', c.created_at,
                  'likes', (SELECT COUNT(*) FROM comment_likes cl WHERE cl.comment_id = c.id)
                )
              ) FROM comments c
              JOIN users u2 ON c.user_id = u2.id
              WHERE c.post_id = p.id) as comments
       FROM posts p
       JOIN users u ON p.user_id = u.id
       ORDER BY p.created_at DESC`
    );

    const posts = result.rows.map((post) => ({
      ...post,
      comments: post.comments || [],
      likes: parseInt(post.likes) || 0,
    }));

    res.json(posts);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Персональные посты (для posts.html)
app.get("/my-posts", authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  try {
    const result = await pool.query(
      `SELECT p.id, p.user_id, p.text, p.image_url, p.created_at,
               u.name AS author, u.username, u.avatar_url,
               (SELECT COUNT(*) FROM likes l WHERE l.post_id = p.id) as likes,
               (SELECT JSON_AGG(JSON_BUILD_OBJECT('username', u2.username, 'comment', c.comment, 'created_at', c.created_at))
                FROM comments c
                JOIN users u2 ON c.user_id = u2.id
                WHERE c.post_id = p.id) as comments
        FROM posts p
        JOIN users u ON p.user_id = u.id
        WHERE p.user_id = $1
        ORDER BY p.created_at DESC`,
      [userId]
    );

    res.json(
      result.rows.map((post) => ({
        ...post,
        comments: post.comments || [],
        likes: parseInt(post.likes) || 0,
      }))
    );
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Удаление поста
app.delete("/delete-post/:postId", authenticateToken, async (req, res) => {
  const postId = parseInt(req.params.postId);
  const userId = req.user.userId;

  try {
    const postResult = await pool.query(
      "SELECT * FROM posts WHERE id = $1 AND user_id = $2",
      [postId, userId]
    );

    if (postResult.rows.length === 0) {
      return res.status(403).json({ error: "You can only delete your own posts" });
    }

    await pool.query("DELETE FROM likes WHERE post_id = $1", [postId]);
    await pool.query("DELETE FROM comments WHERE post_id = $1", [postId]);
    await pool.query("DELETE FROM posts WHERE id = $1", [postId]);

    res.json({ success: true, message: "Post deleted successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Проверка, лайкнул ли пользователь пост
app.get("/check-like/:postId", authenticateToken, async (req, res) => {
  const postId = parseInt(req.params.postId);
  const userId = req.user.userId;

  try {
    const result = await pool.query(
      "SELECT * FROM likes WHERE user_id = $1 AND post_id = $2",
      [userId, postId]
    );
    const userLiked = result.rows.length > 0;
    res.json({ liked: userLiked });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Лайк поста
app.post("/like-post", authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  const { postId } = req.body;

  try {
    const postResult = await pool.query("SELECT * FROM posts WHERE id = $1", [postId]);
    if (postResult.rows.length === 0) {
      return res.status(404).json({ error: "Post not found" });
    }

    const result = await pool.query(
      "INSERT INTO likes (user_id, post_id) VALUES ($1, $2) ON CONFLICT ON CONSTRAINT unique_like DO NOTHING RETURNING *",
      [userId, postId]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ error: "You already liked this post" });
    }

    const likesResult = await pool.query(
      "SELECT COUNT(*) as likes FROM likes WHERE post_id = $1",
      [postId]
    );
    res.json({ likes: parseInt(likesResult.rows[0].likes) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Отмена лайка
app.post("/unlike-post", authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  const { postId } = req.body;

  try {
    const postResult = await pool.query("SELECT * FROM posts WHERE id = $1", [postId]);
    if (postResult.rows.length === 0) {
      return res.status(404).json({ error: "Post not found" });
    }

    const likeResult = await pool.query(
      "DELETE FROM likes WHERE user_id = $1 AND post_id = $2 RETURNING *",
      [userId, postId]
    );

    if (likeResult.rows.length === 0) {
      return res.status(400).json({ error: "You have not liked this post" });
    }

    const likesResult = await pool.query(
      "SELECT COUNT(*) as likes FROM likes WHERE post_id = $1",
      [postId]
    );
    res.json({ likes: parseInt(likesResult.rows[0].likes) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Добавление комментария
app.post("/add-comment", authenticateToken, async (req, res) => {
  const { postId, comment } = req.body;
  const userId = req.user.userId;

  try {
    // Проверяем, существует ли пост
    const postResult = await pool.query("SELECT * FROM posts WHERE id = $1", [postId]);
    if (postResult.rows.length === 0) {
      return res.status(404).json({ error: "Post not found" });
    }

    const userResult = await pool.query("SELECT username, avatar_url FROM users WHERE id = $1", [userId]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const username = userResult.rows[0].username;
    const userAvatarUrl = userResult.rows[0].avatar_url;

    await pool.query(
      "INSERT INTO comments (post_id, user_id, comment, created_at) VALUES ($1, $2, $3, $4)",
      [postId, userId, comment, new Date()]
    );

    const result = await pool.query(
      `SELECT p.id, p.user_id, p.text, p.image_url, p.created_at,
              u.name AS author, u.username, u.avatar_url,
              (SELECT COUNT(*) FROM likes l WHERE l.post_id = p.id) as likes,
              (SELECT JSON_AGG(
                JSON_BUILD_OBJECT(
                  'id', c.id,
                  'username', u2.username,
                  'avatar_url', u2.avatar_url,
                  'comment', c.comment,
                  'created_at', c.created_at,
                  'likes', (SELECT COUNT(*) FROM comment_likes cl WHERE cl.comment_id = c.id)
                )
              ) FROM comments c
              JOIN users u2 ON c.user_id = u2.id
              WHERE c.post_id = p.id) as comments
       FROM posts p
       JOIN users u ON p.user_id = u.id
       WHERE p.id = $1`,
      [postId]
    );

    const post = result.rows[0];
    res.json({
      ...post,
      comments: post.comments || [],
      likes: parseInt(post.likes) || 0,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Поиск пользователей по username
app.get("/search-users", authenticateToken, async (req, res) => {
  const searchQuery = req.query.username ? req.query.username.toLowerCase() : "";

  try {
    const result = await pool.query(
      `SELECT id, name, username, avatar_url 
        FROM users 
        WHERE LOWER(username) LIKE $1 OR LOWER(name) LIKE $1`,
      [`%${searchQuery}%`]
    );

    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Проверка, лайкнул ли пользователь комментарий
app.get("/check-comment-like/:commentId", authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  const commentId = parseInt(req.params.commentId);

  try {
    const result = await pool.query(
      "SELECT * FROM comment_likes WHERE user_id = $1 AND comment_id = $2",
      [userId, commentId]
    );
    res.json({ liked: result.rows.length > 0 });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Лайк комментария
app.post("/like-comment", authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  const { commentId } = req.body;

  try {
    await pool.query(
      "INSERT INTO comment_likes (user_id, comment_id, created_at) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
      [userId, commentId, new Date()]
    );

    const likesResult = await pool.query(
      "SELECT COUNT(*) as likes FROM comment_likes WHERE comment_id = $1",
      [commentId]
    );

    res.json({ likes: parseInt(likesResult.rows[0].likes) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Снятие лайка с комментария
app.post("/unlike-comment", authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  const { commentId } = req.body;

  try {
    await pool.query(
      "DELETE FROM comment_likes WHERE user_id = $1 AND comment_id = $2",
      [userId, commentId]
    );

    const likesResult = await pool.query(
      "SELECT COUNT(*) as likes FROM comment_likes WHERE comment_id = $1",
      [commentId]
    );

    res.json({ likes: parseInt(likesResult.rows[0].likes) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Проверка, подписан ли пользователь на другого пользователя
app.get("/check-follow/:userId", authenticateToken, async (req, res) => {
  const followerId = req.user.userId;
  const followingId = parseInt(req.params.userId);

  try {
    const result = await pool.query(
      "SELECT * FROM followers WHERE follower_id = $1 AND following_id = $2",
      [followerId, followingId]
    );
    res.json({ isFollowing: result.rows.length > 0 });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Подписка на пользователя
app.post("/follow", authenticateToken, async (req, res) => {
  const followerId = req.user.userId;
  const { followingId } = req.body;

  try {
    await pool.query(
      "INSERT INTO followers (follower_id, following_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
      [followerId, followingId]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Отписка от пользователя
app.post("/unfollow", authenticateToken, async (req, res) => {
  const followerId = req.user.userId;
  const { followingId } = req.body;

  try {
    await pool.query(
      "DELETE FROM followers WHERE follower_id = $1 AND following_id = $2",
      [followerId, followingId]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});