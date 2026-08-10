const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const PUBLIC_DIR = path.join(__dirname, 'public');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Serve static files (the app itself)
app.use(express.static(PUBLIC_DIR));

// ===== Storage helpers =====
function readJSON(file) {
  try {
    return JSON.parse(fs.readFileSync(path.join(DATA_DIR, file), 'utf8'));
  } catch {
    return null;
  }
}
function writeJSON(file, data) {
  fs.writeFileSync(path.join(DATA_DIR, file), JSON.stringify(data, null, 2));
}

// Password hashing (SHA-256 + salt)
function hashPassword(password, salt) {
  return crypto.createHmac('sha256', salt).update(password).digest('hex');
}
function generateSalt() {
  return crypto.randomBytes(16).toString('hex');
}
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Token store (in-memory, cleared on restart)
const tokens = {}; // token -> { username, createdAt }

// Token expiry: 30 days
const TOKEN_EXPIRY = 30 * 24 * 60 * 60 * 1000;

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token || !tokens[token]) {
    return res.status(401).json({ error: '未登录或登录已过期' });
  }
  const session = tokens[token];
  if (Date.now() - session.createdAt > TOKEN_EXPIRY) {
    delete tokens[token];
    return res.status(401).json({ error: '登录已过期，请重新登录' });
  }
  req.username = session.username;
  req.token = token;
  next();
}

// ===== Routes =====

// Register
app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: '用户名和密码不能为空' });
  }
  if (username.length < 2 || username.length > 20) {
    return res.status(400).json({ error: '用户名长度 2-20 位' });
  }
  if (password.length < 4) {
    return res.status(400).json({ error: '密码至少 4 位' });
  }

  const users = readJSON('users.json') || {};
  if (users[username]) {
    return res.status(409).json({ error: '用户名已存在' });
  }

  const salt = generateSalt();
  users[username] = {
    salt,
    passwordHash: hashPassword(password, salt),
    createdAt: new Date().toISOString()
  };
  writeJSON('users.json', users);

  // Create token
  const token = generateToken();
  tokens[token] = { username, createdAt: Date.now() };

  res.json({ token, username });
});

// Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: '用户名和密码不能为空' });
  }

  const users = readJSON('users.json') || {};
  const user = users[username];
  if (!user) {
    return res.status(401).json({ error: '用户名或密码错误' });
  }

  const hash = hashPassword(password, user.salt);
  if (hash !== user.passwordHash) {
    return res.status(401).json({ error: '用户名或密码错误' });
  }

  const token = generateToken();
  tokens[token] = { username, createdAt: Date.now() };

  res.json({ token, username });
});

// Logout
app.post('/api/logout', authMiddleware, (req, res) => {
  delete tokens[req.token];
  res.json({ ok: true });
});

// Sync: GET user data
app.get('/api/sync', authMiddleware, (req, res) => {
  const userFile = `user_${req.username}.json`;
  const data = readJSON(userFile) || { tasks: [], theme: '', bg: '', settings: {} };
  res.json(data);
});

// Sync: POST user data
app.post('/api/sync', authMiddleware, (req, res) => {
  const { tasks, theme, bg, overlay, glassAlpha, glassBlur, lastModified } = req.body;
  const userFile = `user_${req.username}.json`;
  const existing = readJSON(userFile) || {};

  // Last-write-wins: only accept if newer
  if (lastModified && existing.lastModified && lastModified < existing.lastModified) {
    return res.status(409).json({
      error: '云端数据更新，请先同步',
      cloudData: existing
    });
  }

  const newData = {
    tasks: tasks !== undefined ? tasks : (existing.tasks || []),
    theme: theme !== undefined ? theme : (existing.theme || ''),
    bg: bg !== undefined ? bg : (existing.bg || ''),
    overlay: overlay !== undefined ? overlay : (existing.overlay || ''),
    glassAlpha: glassAlpha !== undefined ? glassAlpha : (existing.glassAlpha || ''),
    glassBlur: glassBlur !== undefined ? glassBlur : (existing.glassBlur || ''),
    lastModified: lastModified || new Date().toISOString(),
    syncedAt: new Date().toISOString()
  };
  writeJSON(userFile, newData);
  res.json({ ok: true, lastModified: newData.lastModified });
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

// Fallback: serve index.html for non-API routes
app.get('*', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

// Start server
app.listen(PORT, () => {
  console.log(`Admin Memo server running on port ${PORT}`);
});
