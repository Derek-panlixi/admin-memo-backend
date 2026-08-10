const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const cron = require('node-cron');

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
  const { tasks, theme, bg, overlay, glassAlpha, glassBlur, wecomWebhook, lastModified } = req.body;
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
    wecomWebhook: wecomWebhook !== undefined ? wecomWebhook : (existing.wecomWebhook || ''),
    lastModified: lastModified || new Date().toISOString(),
    syncedAt: new Date().toISOString()
  };
  writeJSON(userFile, newData);
  res.json({ ok: true, lastModified: newData.lastModified });
});

// ===== WeCom (企业微信) Webhook =====

// Save webhook URL
app.post('/api/save-webhook', authMiddleware, (req, res) => {
  const { webhook } = req.body;
  const userFile = `user_${req.username}.json`;
  const data = readJSON(userFile) || {};
  data.wecomWebhook = webhook || '';
  data.lastModified = new Date().toISOString();
  writeJSON(userFile, data);
  res.json({ ok: true });
});

// Test webhook — proxy through backend to avoid CORS (no auth needed, just forwarding)
app.post('/api/test-webhook', async (req, res) => {
  const { webhook, content } = req.body;
  if (!webhook) {
    return res.status(400).json({ error: 'Webhook 地址不能为空' });
  }
  try {
    const resp = await fetch(webhook, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ msgtype: 'markdown', markdown: { content: content || '## 测试消息\n\n行政备忘录测试推送成功！' } })
    });
    const r = await resp.json();
    res.json(r);
  } catch (e) {
    res.status(502).json({ errcode: -1, errmsg: e.message });
  }
});

// Daily push — core logic (shared by cron endpoint & built-in scheduler)
const CRON_SECRET = process.env.CRON_SECRET || 'memo2026daily';

async function executeDailyPush() {
  // Use Beijing time (UTC+8)
  const now = new Date();
  const beijingOffset = 8 * 60 * 60 * 1000;
  const beijingTime = new Date(now.getTime() + beijingOffset);
  const today = beijingTime.toISOString().slice(0, 10); // YYYY-MM-DD in Beijing time
  const users = readJSON('users.json') || {};
  const results = [];

  for (const username of Object.keys(users)) {
    const userFile = `user_${username}.json`;
    const data = readJSON(userFile);
    if (!data || !data.wecomWebhook || !data.tasks) continue;

    // Filter tasks due today or overdue
    const urgentTasks = data.tasks.filter(t => {
      const dueDate = (t.date || '').slice(0, 10);
      if (!dueDate) return false;
      if (t.done || t.completed) return false;
      return dueDate <= today;
    });

    if (urgentTasks.length === 0) continue;

    // Build markdown message
    const overdueTasks = urgentTasks.filter(t => (t.date || '').slice(0, 10) < today);
    const todayTasks = urgentTasks.filter(t => (t.date || '').slice(0, 10) === today);

    let md = `## 📋 行政备忘录 · 今日待办\n`;
    md += `> ${beijingTime.toLocaleDateString('zh-CN', { month: 'long', day: 'numeric', weekday: 'long' })}\n\n`;

    if (overdueTasks.length > 0) {
      md += `### ⚠️ 逾期未完成（${overdueTasks.length}）\n`;
      overdueTasks.slice(0, 5).forEach((t, i) => {
        md += `> ${i + 1}. <font color="warning">${t.title || t.text || '未命名任务'}</font>\n`;
      });
      if (overdueTasks.length > 5) md += `> …还有 ${overdueTasks.length - 5} 项\n`;
      md += '\n';
    }

    if (todayTasks.length > 0) {
      md += `### 📌 今天要处理（${todayTasks.length}）\n`;
      todayTasks.slice(0, 10).forEach((t, i) => {
        const node = t.node || '';
        md += `> ${i + 1}. ${t.title || t.text || '未命名任务'}${node ? ' 【' + node + '】' : ''}\n`;
      });
      if (todayTasks.length > 10) md += `> …还有 ${todayTasks.length - 10} 项\n`;
    }

    md += `\n[打开行政备忘录](https://67a18a7dff5e48c69feb58af28f2405a.gz4.agentos-app.net)`;

    // Send via WeCom webhook
    try {
      const resp = await fetch(data.wecomWebhook, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ msgtype: 'markdown', markdown: { content: md } })
      });
      const r = await resp.json();
      results.push({ username, tasks: urgentTasks.length, sent: r.errcode === 0, status: r.errmsg || 'ok' });
    } catch (e) {
      results.push({ username, tasks: urgentTasks.length, sent: false, status: e.message });
    }
  }

  return { ok: true, today, usersChecked: Object.keys(users).length, sent: results };
}

// Manual trigger endpoint (secured)
app.get('/api/cron/daily-push', async (req, res) => {
  const secret = req.query.secret || req.headers['x-cron-secret'];
  if (secret !== CRON_SECRET) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const result = await executeDailyPush();
  res.json(result);
});

// Set push time (authenticated)
app.post('/api/set-push-time', authMiddleware, (req, res) => {
  const { pushTime } = req.body;
  const userFile = `user_${req.username}.json`;
  const data = readJSON(userFile) || {};
  data.pushTime = pushTime || '08:30';
  data.lastModified = new Date().toISOString();
  writeJSON(userFile, data);
  res.json({ ok: true, pushTime: data.pushTime });
});

// Built-in scheduler — checks every minute, pushes at each user's preferred time
const pushedToday = {}; // { username: 'YYYY-MM-DD' }
cron.schedule('* * * * *', async () => {
  const now = new Date();
  const beijingOffset = 8 * 60 * 60 * 1000;
  const beijingTime = new Date(now.getTime() + beijingOffset);
  const todayStr = beijingTime.toISOString().slice(0, 10);
  const currentHHMM = String(beijingTime.getUTCHours()).padStart(2, '0') + ':' + String(beijingTime.getUTCMinutes()).padStart(2, '0');

  const users = readJSON('users.json') || {};
  let needsPush = false;

  for (const username of Object.keys(users)) {
    const userFile = `user_${username}.json`;
    const data = readJSON(userFile);
    if (!data || !data.wecomWebhook) continue;

    const pushTime = data.pushTime || '08:30';
    if (pushTime === currentHHMM && pushedToday[username] !== todayStr) {
      pushedToday[username] = todayStr;
      needsPush = true;
    }
  }

  if (needsPush) {
    console.log(`[${beijingTime.toISOString()}] Running scheduled daily push at ${currentHHMM} Beijing time`);
    const result = await executeDailyPush();
    console.log('Push result:', JSON.stringify(result.sent));
  }
});

// Self-ping every 10 minutes to reduce sleep (best-effort)
setInterval(async () => {
  try {
    await fetch(`http://localhost:${PORT}/api/health`);
  } catch (e) { /* ignore */ }
}, 10 * 60 * 1000);

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
