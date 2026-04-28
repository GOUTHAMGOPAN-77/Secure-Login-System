'use strict';
const express     = require('express');
const bcrypt      = require('bcrypt');
const session     = require('express-session');
const speakeasy   = require('speakeasy');
const QRCode      = require('qrcode');
const helmet      = require('helmet');
const rateLimit   = require('express-rate-limit');
const path        = require('path');
const fs          = require('fs');

const app  = express();
const PORT = 3000;
const DB_DIR  = path.join(__dirname, 'db');
const DB_FILE = path.join(DB_DIR, 'users.json');
if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });
if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, JSON.stringify({ users: {} }));
const BCRYPT_ROUNDS = 12;

// ── Helmet: secure HTTP headers ───────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));

// ── Body parsing ──────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

// ── Session management (server-side, httpOnly cookie) ─────────────────────────
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-this-secret-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,         // JS cannot read cookie
    secure: false,          // set true behind HTTPS in production
    sameSite: 'strict',
    maxAge: 1000 * 60 * 60  // 1 hour
  }
}));

// ── Rate limiting: max 10 login attempts per 15 min per IP ────────────────────
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many login attempts. Please try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false
});

// ── JSON "database" helpers (replaces SQL with parameterised-style reads) ─────
//    In production swap with pg / mysql2 using prepared statements.
function loadDB() {
  if (!fs.existsSync(DB_FILE)) return { users: {} };
  return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}
function saveDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

// Safe lookup — key is always lower-cased & stripped; no SQL so no injection surface
function findUser(username) {
  const db = loadDB();
  return db.users[username.toLowerCase().trim()] || null;
}
function createUser(user) {
  const db = loadDB();
  db.users[user.username] = user;
  saveDB(db);
}
function updateUser(username, fields) {
  const db = loadDB();
  if (!db.users[username]) return;
  Object.assign(db.users[username], fields);
  saveDB(db);
}

// ── Input validation helpers ──────────────────────────────────────────────────
const validators = {
  username: v => typeof v === 'string' && /^[a-zA-Z0-9_]{3,20}$/.test(v),
  email:    v => typeof v === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) && v.length < 254,
  password: v => typeof v === 'string' && v.length >= 8 && /[A-Z]/.test(v) && /\d/.test(v)
};

function validate(obj, rules) {
  for (const [field, fn] of Object.entries(rules)) {
    if (!fn(obj[field])) return `Invalid ${field}.`;
  }
  return null;
}

// ── Auth middleware ───────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (req.session?.userId) return next();
  res.status(401).json({ error: 'Not authenticated.' });
}

// ═══════════════════════════════════════════════════════════════════════════════
// Routes
// ═══════════════════════════════════════════════════════════════════════════════

// POST /api/register ───────────────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { username, email, password, confirm } = req.body;

  // Validate
  const err = validate(req.body, {
    username: validators.username,
    email:    validators.email,
    password: validators.password
  });
  if (err) return res.status(400).json({ error: err });
  if (password !== confirm) return res.status(400).json({ error: 'Passwords do not match.' });

  const key = username.toLowerCase().trim();
  if (findUser(key)) return res.status(409).json({ error: 'Username already taken.' });

  // bcrypt hash — 12 rounds
  const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

  createUser({
    username: key,
    email: email.trim().toLowerCase(),
    passwordHash,
    totpEnabled: false,
    totpSecret: null,
    createdAt: new Date().toISOString()
  });

  res.json({ message: 'Account created. Please log in.' });
});

// POST /api/login ──────────────────────────────────────────────────────────────
app.post('/api/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password)
    return res.status(400).json({ error: 'Username and password are required.' });

  const key  = username.toLowerCase().trim();
  const user = findUser(key);

  // Always run bcrypt to prevent timing attacks
  const dummyHash = '$2b$12$invalidhashfortimingprotection000000000000000000000000';
  const valid = user
    ? await bcrypt.compare(password, user.passwordHash)
    : await bcrypt.compare(password, dummyHash).then(() => false);

  if (!valid) return res.status(401).json({ error: 'Invalid username or password.' });

  if (user.totpEnabled) {
    // Store pending state — user must verify OTP before session is created
    req.session.pendingUserId = key;
    return res.json({ requires2fa: true });
  }

  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: 'Session error.' });
    req.session.userId = key;
    res.json({ message: 'Logged in.', user: publicUser(user) });
  });
});

// POST /api/login/2fa ─────────────────────────────────────────────────────────
app.post('/api/login/2fa', (req, res) => {
  const { token } = req.body;
  const key = req.session.pendingUserId;
  if (!key) return res.status(400).json({ error: 'No pending login.' });

  const user = findUser(key);
  if (!user) return res.status(400).json({ error: 'User not found.' });

  const valid = speakeasy.totp.verify({
    secret: user.totpSecret,
    encoding: 'base32',
    token: String(token).replace(/\s/g, ''),
    window: 1
  });

  if (!valid) return res.status(401).json({ error: 'Invalid or expired code.' });

  delete req.session.pendingUserId;
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: 'Session error.' });
    req.session.userId = key;
    res.json({ message: 'Logged in.', user: publicUser(user) });
  });
});

// POST /api/logout ─────────────────────────────────────────────────────────────
app.post('/api/logout', requireAuth, (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ error: 'Logout failed.' });
    res.clearCookie('connect.sid');
    res.json({ message: 'Logged out.' });
  });
});

// GET /api/me ──────────────────────────────────────────────────────────────────
app.get('/api/me', requireAuth, (req, res) => {
  const user = findUser(req.session.userId);
  if (!user) return res.status(404).json({ error: 'User not found.' });
  res.json(publicUser(user));
});

// POST /api/2fa/setup ─────────────────────────────────────────────────────────
app.post('/api/2fa/setup', requireAuth, async (req, res) => {
  const user = findUser(req.session.userId);
  const secret = speakeasy.generateSecret({ name: `SecureLogin (${user.email})`, length: 20 });
  // Temporarily store unverified secret
  updateUser(req.session.userId, { totpSecretTemp: secret.base32 });
  const qr = await QRCode.toDataURL(secret.otpauth_url);
  res.json({ secret: secret.base32, qr });
});

// POST /api/2fa/verify ────────────────────────────────────────────────────────
app.post('/api/2fa/verify', requireAuth, (req, res) => {
  const { token } = req.body;
  const user = findUser(req.session.userId);
  if (!user.totpSecretTemp) return res.status(400).json({ error: 'No 2FA setup in progress.' });

  const valid = speakeasy.totp.verify({
    secret: user.totpSecretTemp,
    encoding: 'base32',
    token: String(token).replace(/\s/g, ''),
    window: 1
  });
  if (!valid) return res.status(401).json({ error: 'Invalid code. Try again.' });

  updateUser(req.session.userId, {
    totpEnabled: true,
    totpSecret: user.totpSecretTemp,
    totpSecretTemp: null
  });
  res.json({ message: '2FA enabled.' });
});

// ── Helpers ───────────────────────────────────────────────────────────────────
function publicUser(u) {
  return { username: u.username, email: u.email, totpEnabled: u.totpEnabled, createdAt: u.createdAt };
}

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`Server running → http://localhost:${PORT}`));
