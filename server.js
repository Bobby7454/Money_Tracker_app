require('dotenv').config();
const express          = require('express');
const mongoose         = require('mongoose');
const jwt              = require('jsonwebtoken');
const bcrypt           = require('bcryptjs');
const cors             = require('cors');
const multer           = require('multer');
const { Readable }     = require('stream');
const { GridFSBucket, ObjectId } = require('mongodb');
const rateLimit        = require('express-rate-limit');
const path             = require('path');
const fs               = require('fs');
const crypto           = require('crypto');
const nodemailer       = require('nodemailer');

const app  = express();
const PORT = process.env.PORT || 5000;

/* ══════════════════════════════════════════════════════
   STARTUP GUARDS
══════════════════════════════════════════════════════ */
if (!process.env.JWT_SECRET) {
  console.error('❌  FATAL: JWT_SECRET is not set. Refusing to start.');
  process.exit(1);
}
if (!process.env.MONGO_URI) {
  console.warn('⚠️  MONGO_URI not set — falling back to localhost');
}

/* ══════════════════════════════════════════════════════
   EMAIL TRANSPORTER
══════════════════════════════════════════════════════ */
async function sendMail({ to, subject, html }) {
  if (!process.env.EMAIL || !process.env.EMAIL_PASSWORD) {
    throw new Error('Email not configured — EMAIL or EMAIL_PASSWORD missing');
  }
  const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false,
    auth: {
      user: process.env.EMAIL,
      pass: process.env.EMAIL_PASSWORD
    }
  });
  await transporter.sendMail({
    from: `"RGIL Admin" <${process.env.EMAIL}>`,
    to,
    subject,
    html
  });
}

/* ══════════════════════════════════════════════════════
   IN-MEMORY CACHE
══════════════════════════════════════════════════════ */
const memCache = new Map();

function withCache(baseKey, ttlMs = 60_000) {
  return (req, res, next) => {
    if (memCache.size > 500) memCache.clear();
    const qs  = new URLSearchParams(req.query).toString();
    const key = qs ? `${baseKey}:${qs}` : baseKey;
    const hit = memCache.get(key);
    if (hit && Date.now() < hit.exp) {
      res.set('X-Cache', 'HIT');
      res.set('Cache-Control', `public, max-age=${Math.floor(ttlMs / 1000)}, stale-while-revalidate=30`);
      return res.json(hit.data);
    }
    const originalJson = res.json.bind(res);
    res.json = (data) => {
      if (res.statusCode >= 200 && res.statusCode < 300) {
        memCache.set(key, { data, exp: Date.now() + ttlMs });
      }
      res.set('X-Cache', 'MISS');
      res.set('Cache-Control', `public, max-age=${Math.floor(ttlMs / 1000)}, stale-while-revalidate=30`);
      return originalJson(data);
    };
    next();
  };
}

function bustCache(...prefixes) {
  for (const key of memCache.keys()) {
    if (prefixes.some(p => key === p || key.startsWith(p + ':'))) {
      memCache.delete(key);
    }
  }
}

/* ══════════════════════════════════════════════════════
   FILE METADATA CACHE
══════════════════════════════════════════════════════ */
const fileMetaCache = new Map();

/* ══════════════════════════════════════════════════════
   EXPRESS SETUP
══════════════════════════════════════════════════════ */
app.set('trust proxy', 1);

app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  methods: ['GET', 'POST', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.disable('x-powered-by');

/* ══════════════════════════════════════════════════════
   RATE LIMITERS
══════════════════════════════════════════════════════ */
const EXEMPT_IPS = new Set([
  '127.0.0.1', '::1',
  '157.48.182.74', '223.185.47.116'
]);

const loginLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 10,
  standardHeaders: true, legacyHeaders: false,
  skip: (req) => EXEMPT_IPS.has(req.ip || ''),
  message: { error: 'Too many login attempts. Please try again in an hour.' }
});

const formLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 5,
  standardHeaders: true, legacyHeaders: false,
  skip: (req) => EXEMPT_IPS.has(req.ip || ''),
  message: { error: 'Too many submissions. Please try again in an hour.' }
});

const passwordResetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 5,
  standardHeaders: true, legacyHeaders: false,
  skip: (req) => EXEMPT_IPS.has(req.ip || ''),
  message: { error: 'Too many password reset requests. Try again in an hour.' }
});

/* ══════════════════════════════════════════════════════
   MONGODB + GRIDFS
══════════════════════════════════════════════════════ */
let gfsBucket;
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/rgil')
  .then(() => {
    console.log('✅  MongoDB connected');
    gfsBucket = new GridFSBucket(mongoose.connection.db, { bucketName: 'uploads' });
    console.log('✅  GridFS ready');
    cleanExpiredTokens();
  })
  .catch(e => { console.error('❌  MongoDB error:', e.message); process.exit(1); });

/* ══════════════════════════════════════════════════════
   MULTER
══════════════════════════════════════════════════════ */
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 15 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = [
      'application/pdf', 'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'application/vnd.ms-excel',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'image/jpeg', 'image/png', 'image/webp', 'image/gif'
    ];
    if (allowed.includes(file.mimetype)) cb(null, true);
    else cb(new Error('File type not allowed: ' + file.mimetype), false);
  }
});

/* ══════════════════════════════════════════════════════
   GRIDFS HELPER
══════════════════════════════════════════════════════ */
async function deleteGridFSByUrl(href) {
  if (!href || !gfsBucket) return;
  const match = href.match(/\/api\/file\/([a-f0-9]{24})$/);
  if (!match) return;
  try {
    fileMetaCache.delete(match[1]);
    await gfsBucket.delete(new ObjectId(match[1]));
    console.log('🗑  GridFS file deleted:', match[1]);
  } catch (err) {
    if (!err.message.includes('not found') && !err.message.includes('FileNotFound')) {
      console.warn('GridFS delete warning:', err.message);
    }
  }
}

/* ══════════════════════════════════════════════════════
   SCHEMAS
══════════════════════════════════════════════════════ */
const adminSchema = new mongoose.Schema({
  username:    { type: String, required: true, unique: true },
  email:       { type: String, default: '' },
  password:    { type: String, required: true },
  role:        { type: String, enum: ['super', 'admin'], default: 'admin' },
  createdAt:   { type: Date, default: Date.now },
  createdBy:   { type: String, default: '' },
  /* Track the jti of the CURRENT valid session.
     Any JWT with a different jti is rejected. */
  activeJti:   { type: String, default: '' }
});
adminSchema.pre('save', async function () {
  if (!this.isModified('password')) return;
  this.password = await bcrypt.hash(this.password, 10);
});
adminSchema.methods.checkPassword = function (plain) {
  return bcrypt.compare(plain, this.password);
};
const Admin = mongoose.model('Admin', adminSchema);

/* Password reset tokens */
const resetTokenSchema = new mongoose.Schema({
  adminId:   { type: mongoose.Schema.Types.ObjectId, ref: 'Admin', required: true },
  tokenHash: { type: String, required: true },        // SHA-256 of the raw token
  expiresAt: { type: Date, required: true },
  used:      { type: Boolean, default: false }
});
resetTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 }); // auto-delete
const ResetToken = mongoose.model('ResetToken', resetTokenSchema);

/* Invite tokens for new admin setup */
const inviteTokenSchema = new mongoose.Schema({
  tokenHash:    { type: String, required: true },
  email:        { type: String, required: true },
  suggestedUsername: { type: String, default: '' },
  role:         { type: String, enum: ['super', 'admin'], default: 'admin' },
  createdBy:    { type: String, default: '' },
  expiresAt:    { type: Date, required: true },
  used:         { type: Boolean, default: false }
});
inviteTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
const InviteToken = mongoose.model('InviteToken', inviteTokenSchema);

/* ── existing schemas (unchanged) ── */
const tickerSchema = new mongoose.Schema({
  type:  { type: String, enum: ['link', 'download', 'text'], required: true },
  text:  { type: String, required: true },
  href:  { type: String, default: '' },
  badge: { type: String, default: '' }
}, { timestamps: true });
tickerSchema.index({ createdAt: -1 });
const Ticker = mongoose.model('Ticker', tickerSchema);

const noticeSchema = new mongoose.Schema({
  panel:     { type: String, enum: ['notices', 'events'], required: true },
  date:      { type: String, required: true },
  text:      { type: String, required: true, maxlength: 300 },
  badge:     { type: String, enum: ['', 'New', 'Ongoing'], default: '' },
  type:      { type: String, enum: ['text', 'link', 'download'], default: 'text' },
  href:      { type: String, default: '' },
  createdAt: { type: Date, default: Date.now }
});
noticeSchema.index({ panel: 1, createdAt: -1 });
const Notice = mongoose.model('Notice', noticeSchema);

const applicationSchema = new mongoose.Schema({
  ref:         { type: String, required: true, unique: true },
  name:        { type: String, required: true },
  dob:         String, gender: String, category: String,
  mobile:      { type: String, required: true },
  email:       { type: String, required: true },
  address:     String, programme: { type: String, required: true },
  qual:        String, board: String, year: String,
  marks:       String, stream: String, source: String, message: String,
  ipAddress:   { type: String, default: '' },
  userAgent:   { type: String, default: '' },
  status: {
    type: String,
    enum: ['Pending', 'Under Review', 'Shortlisted', 'Admitted', 'Rejected'],
    default: 'Pending'
  },
  adminNotes:  { type: String, default: '' },
  submittedAt: { type: Date, default: Date.now }
});
applicationSchema.index({ status: 1 });
applicationSchema.index({ submittedAt: -1 });
applicationSchema.index({ email: 1 });
const Application = mongoose.model('Application', applicationSchema);

const contactSchema = new mongoose.Schema({
  name:      { type: String, required: true, maxlength: 120 },
  email:     { type: String, required: true, maxlength: 200 },
  phone:     { type: String, default: '', maxlength: 20 },
  programme: { type: String, enum: ['llb3', 'ballb5', 'general', 'other', ''], default: '' },
  subject:   { type: String, required: true, maxlength: 200 },
  message:   { type: String, required: true, maxlength: 2000 },
  status:    { type: String, enum: ['New', 'Read', 'Replied', 'Closed'], default: 'New' },
  adminNotes:  { type: String, default: '' },
  submittedAt: { type: Date, default: Date.now },
  ipAddress:   { type: String, default: '' }
});
contactSchema.index({ status: 1 });
contactSchema.index({ submittedAt: -1 });
const Contact = mongoose.model('Contact', contactSchema);

const newsSchema = new mongoose.Schema({
  title:     { type: String, required: true, maxlength: 200 },
  date:      { type: String, required: true },
  tag:       { type: String, default: '' },
  body:      { type: String, default: '', maxlength: 600 },
  imageUrl:  { type: String, default: '' },
  published: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});
newsSchema.index({ published: 1, createdAt: -1 });
const NewsItem = mongoose.model('NewsItem', newsSchema);

const gallerySchema = new mongoose.Schema({
  title: { type: String, required: true, maxlength: 200 },
  cat: {
    type: String,
    enum: [
      'consumer','juvenile','hrc','prison','corporate','market',
      'publicoffice','police','mediation','moot','nss','legal',
      'seminar','sports','competition','cultural','convocation'
    ],
    required: true
  },
  src: String, date: String, location: String,
  photographer: String, programme: String,
  description: { type: String, default: '', maxlength: 800 }
}, { timestamps: true });
gallerySchema.index({ cat: 1, createdAt: -1 });
const Gallery = mongoose.model('Gallery', gallerySchema);

const ipBlockSchema = new mongoose.Schema({
  ip:        { type: String, required: true, unique: true },
  reason:    { type: String, default: '' },
  blockedAt: { type: Date, default: Date.now }
});
const IPBlock = mongoose.model('IPBlock', ipBlockSchema);

/* ══════════════════════════════════════════════════════
   CLEANUP EXPIRED TOKENS (runs on startup + every 6h)
══════════════════════════════════════════════════════ */
async function cleanExpiredTokens() {
  try {
    const now = new Date();
    await ResetToken.deleteMany({ expiresAt: { $lt: now } });
    await InviteToken.deleteMany({ expiresAt: { $lt: now } });
  } catch {}
}
setInterval(cleanExpiredTokens, 6 * 60 * 60 * 1000);

/* ══════════════════════════════════════════════════════
   IP BLOCK MIDDLEWARE
══════════════════════════════════════════════════════ */
let blockedIPsCache = new Set();
async function refreshBlockedIPs() {
  try {
    const list = await IPBlock.find().lean();
    blockedIPsCache = new Set(list.map(b => b.ip));
  } catch {}
}
refreshBlockedIPs();
setInterval(refreshBlockedIPs, 5 * 60 * 1000);

function ipBlockMiddleware(req, res, next) {
  if (req.method !== 'POST') return next();
  const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
    || req.socket.remoteAddress || '';
  if (blockedIPsCache.has(ip))
    return res.status(403).json({ error: 'You have been blocked. Contact the administrator.' });
  next();
}
app.use('/api/contact',      ipBlockMiddleware);
app.use('/api/applications', ipBlockMiddleware);

/* ══════════════════════════════════════════════════════
   AUTH MIDDLEWARE  — enforces single active session
══════════════════════════════════════════════════════ */
async function requireAuth(req, res, next) {
  const header = req.headers['authorization'];
  if (!header || !header.startsWith('Bearer '))
    return res.status(401).json({ error: 'No token — access denied' });
  try {
    const decoded = jwt.verify(header.slice(7), process.env.JWT_SECRET);

    /* Single-session check: compare jti against DB */
    if (decoded.jti) {
      const admin = await Admin.findById(decoded.id).select('activeJti').lean();
      if (!admin || admin.activeJti !== decoded.jti) {
        return res.status(401).json({
          error: 'Session superseded. Please log in again.',
          code:  'SESSION_SUPERSEDED'
        });
      }
    }

    req.admin = decoded;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError')
      return res.status(401).json({ error: 'Token expired', expired: true });
    res.status(401).json({ error: 'Invalid token' });
  }
}

/* Super-admin guard */
async function requireSuper(req, res, next) {
  // First run requireAuth as a promise-style check
  let authPassed = false;
  await new Promise(resolve => {
    requireAuth(req, res, () => { authPassed = true; resolve(); });
  });
  if (!authPassed) return; // requireAuth already sent the 401 response

  try {
    const admin = await Admin.findById(req.admin.id).select('role').lean();
    if (!admin || admin.role !== 'super')
      return res.status(403).json({ error: 'Super-admin access required.' });
    next();
  } catch (e) { res.status(500).json({ error: e.message }); }
}

/* ══════════════════════════════════════════════════════
   TOKEN HELPERS
══════════════════════════════════════════════════════ */
function hashToken(raw) {
  return crypto.createHash('sha256').update(raw).digest('hex');
}
function generateRawToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

/* ══════════════════════════════════════════════════════
   AUTH ROUTES
══════════════════════════════════════════════════════ */

/* LOGIN — invalidates any previous session */
app.post('/api/auth/login', loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ error: 'Username and password required' });

    const admin = await Admin.findOne({ username });
    if (!admin || !(await admin.checkPassword(password)))
      return res.status(401).json({ error: 'Invalid credentials' });

    /* Generate a unique jti for this session */
    const jti       = generateRawToken(16);
    const expiresIn = process.env.JWT_EXPIRES_IN || '8h';
    const token     = jwt.sign(
      { id: admin._id, username: admin.username, role: admin.role, jti },
      process.env.JWT_SECRET,
      { expiresIn }
    );

    /* Store jti — this invalidates any previous session */
    await Admin.findByIdAndUpdate(admin._id, { activeJti: jti });

    res.json({ token, expiresIn, role: admin.role });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* VERIFY */
app.get('/api/auth/verify', requireAuth, (req, res) => {
  res.json({ valid: true, username: req.admin.username, role: req.admin.role });
});

/* LOGOUT — clear jti so the token is dead immediately */
app.post('/api/auth/logout', requireAuth, async (req, res) => {
  try {
    await Admin.findByIdAndUpdate(req.admin.id, { activeJti: '' });
    res.json({ message: 'Logged out' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* SEED — create the very first super-admin */
app.post('/api/auth/seed', loginLimiter, async (req, res) => {
  try {
    const { secret } = req.body;
    if (!process.env.ADMIN_SEED_SECRET || secret !== process.env.ADMIN_SEED_SECRET)
      return res.status(401).json({ error: 'Invalid seed secret.' });
    const exists = await Admin.findOne({ username: process.env.ADMIN_USERNAME });
    if (exists) return res.status(409).json({ error: 'Admin already exists.' });
    const admin = new Admin({
      username: process.env.ADMIN_USERNAME,
      password: process.env.ADMIN_PASSWORD,
      email:    process.env.ADMIN_EMAIL || '',
      role:     'super'
    });
    await admin.save();
    res.json({ message: `Super-admin '${admin.username}' created.` });
  } catch (e) { res.status(500).json({ error: 'Internal server error' }); }
});

/* ══════════════════════════════════════════════════════
   FORGOT PASSWORD
══════════════════════════════════════════════════════ */
app.post('/api/auth/forgot-password', passwordResetLimiter, async (req, res) => {
  try {
    const { usernameOrEmail } = req.body;
    if (!usernameOrEmail)
      return res.status(400).json({ error: 'Username or email is required.' });

    const admin = await Admin.findOne({
      $or: [
        { username: usernameOrEmail.trim() },
        { email:    usernameOrEmail.trim().toLowerCase() }
      ]
    });

    /* Always respond success — don't reveal whether account exists */
    if (!admin) return res.json({ message: 'If that account exists, a reset email has been sent.' });
    if (!admin.email) return res.json({ message: 'If that account exists, a reset email has been sent.' });

    /* Invalidate any previous reset tokens for this admin */
    await ResetToken.deleteMany({ adminId: admin._id });

    const raw  = generateRawToken();
    const hash = hashToken(raw);
    await ResetToken.create({
      adminId:   admin._id,
      tokenHash: hash,
      expiresAt: new Date(Date.now() + 15 * 60 * 1000) // 15 minutes
    });

    const BASE = process.env.HOST_URL || 'https://rgil.ac.in';
    const link = `${BASE}/admin.html?reset=${raw}`;

    await sendMail({
      to:      admin.email,
      subject: 'RGIL Admin — Password Reset',
      html: `
        <div style="font-family:sans-serif;max-width:480px;margin:auto;padding:24px;border:1px solid #e5e7eb;border-radius:8px">
          <h2 style="color:#0f2340;margin:0 0 16px">Password Reset Request</h2>
          <p style="color:#374151;line-height:1.6">
            A password reset was requested for the admin account <strong>${admin.username}</strong>.<br/>
            Click the button below to set a new password. This link expires in <strong>15 minutes</strong>.
          </p>
          <a href="${link}" style="display:inline-block;margin:20px 0;padding:12px 28px;background:#c8973a;color:#0f2340;border-radius:6px;font-weight:700;text-decoration:none;font-size:14px">
            Reset My Password
          </a>
          <p style="color:#9ca3af;font-size:12px">
            If you did not request this, ignore this email — your password will not change.<br/>
            Link: <a href="${link}" style="color:#c8973a">${link}</a>
          </p>
        </div>`
    });

    res.json({ message: 'If that account exists, a reset email has been sent.' });
  } catch (e) {
    console.error('Forgot password error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

/* ══════════════════════════════════════════════════════
   RESET PASSWORD (via token link)
══════════════════════════════════════════════════════ */
app.post('/api/auth/reset-password', passwordResetLimiter, async (req, res) => {
  try {
    const { token, newPassword, password } = req.body;
    const pw = newPassword || password;
    if (!token || !pw)
      return res.status(400).json({ error: 'Token and new password are required.' });
    if (pw.length < 8)
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });

    const hash   = hashToken(token);
    const record = await ResetToken.findOne({
      tokenHash: hash,
      used:      false,
      expiresAt: { $gt: new Date() }
    });
    if (!record)
      return res.status(400).json({ error: 'Reset link is invalid or has expired.' });

    /* Mark used first to prevent replay */
    record.used = true;
    await record.save();

    const admin = await Admin.findById(record.adminId);
    if (!admin) return res.status(404).json({ error: 'Admin not found.' });

    admin.password  = pw;   // use the resolved variable, not newPassword
    admin.activeJti = '';
    await admin.save();

    res.json({ message: 'Password updated. Please log in with your new password.' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ══════════════════════════════════════════════════════
   CHANGE PASSWORD (authenticated — for logged-in admin)
══════════════════════════════════════════════════════ */
app.post('/api/auth/change-password', requireAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword)
      return res.status(400).json({ error: 'Both current and new password are required.' });
    if (newPassword.length < 8)
      return res.status(400).json({ error: 'New password must be at least 8 characters.' });

    const admin = await Admin.findById(req.admin.id);
    if (!admin) return res.status(404).json({ error: 'Admin not found.' });
    if (!(await admin.checkPassword(currentPassword)))
      return res.status(401).json({ error: 'Current password is incorrect.' });

    /* Generate a new jti so the current session stays valid */
    const newJti = generateRawToken(16);
    const expiresIn = process.env.JWT_EXPIRES_IN || '8h';
    const newToken  = jwt.sign(
      { id: admin._id, username: admin.username, role: admin.role, jti: newJti },
      process.env.JWT_SECRET,
      { expiresIn }
    );

    admin.password  = newPassword;
    admin.activeJti = newJti;
    await admin.save();

    res.json({ message: 'Password changed.', token: newToken, expiresIn });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ══════════════════════════════════════════════════════
   ADMIN MANAGEMENT  (super-admin only)
══════════════════════════════════════════════════════ */

/* List all admins */
app.get('/api/admins', requireSuper, async (req, res) => {
  try {
    const admins = await Admin.find()
      .select('username email role createdAt createdBy activeJti')
      .lean();
    /* Indicate which ones have an active session */
    res.json(admins.map(a => ({
      ...a,
      hasActiveSession: !!a.activeJti
    })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* Invite a new admin — sends a setup link to their email */
app.post('/api/admins/invite', requireSuper, async (req, res) => {
  try {
    const { email, username: suggestedUsername, role = 'admin' } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required.' });
    if (!['super', 'admin'].includes(role))
      return res.status(400).json({ error: 'Invalid role.' });

    /* Check email not already registered */
    const existing = await Admin.findOne({ email: email.trim().toLowerCase() });
    if (existing)
      return res.status(409).json({ error: 'An admin with that email already exists.' });

    /* Invalidate previous pending invite for same email */
    await InviteToken.deleteMany({ email: email.trim().toLowerCase(), used: false });

    const raw  = generateRawToken();
    const hash = hashToken(raw);
    await InviteToken.create({
      tokenHash:         hash,
      email:             email.trim().toLowerCase(),
      suggestedUsername: suggestedUsername || '',
      role,
      createdBy:         req.admin.username,
      expiresAt:         new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours
    });

    const BASE = process.env.HOST_URL || 'https://rgil.ac.in';
    const link = `${BASE}/admin.html?invite=${raw}`;

    await sendMail({
      to:      email,
      subject: 'RGIL Admin — You have been invited',
      html: `
        <div style="font-family:sans-serif;max-width:480px;margin:auto;padding:24px;border:1px solid #e5e7eb;border-radius:8px">
          <h2 style="color:#0f2340;margin:0 0 16px">Admin Invitation</h2>
          <p style="color:#374151;line-height:1.6">
            <strong>${req.admin.username}</strong> has invited you to access the
            <strong>RGIL Admin Panel</strong> as a <strong>${role}</strong>.<br/>
            Click the button below to set up your account. This link expires in <strong>24 hours</strong>.
          </p>
          ${suggestedUsername ? `<p style="color:#374151">Suggested username: <strong>${suggestedUsername}</strong></p>` : ''}
          <a href="${link}" style="display:inline-block;margin:20px 0;padding:12px 28px;background:#c8973a;color:#0f2340;border-radius:6px;font-weight:700;text-decoration:none;font-size:14px">
            Set Up My Account
          </a>
          <p style="color:#9ca3af;font-size:12px">
            If you did not expect this, ignore this email.<br/>
            Link: <a href="${link}" style="color:#c8973a">${link}</a>
          </p>
        </div>`
    });

    res.status(201).json({ message: `Invite sent to ${email}.` });
  } catch (e) {
    console.error('Invite error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

/* Validate an invite token (GET — called when page loads with ?invite=xxx) */
app.get('/api/auth/invite-info', async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) return res.status(400).json({ error: 'Token required.' });
    const record = await InviteToken.findOne({
      tokenHash: hashToken(token),
      used:      false,
      expiresAt: { $gt: new Date() }
    });
    if (!record) return res.status(400).json({ error: 'Invite link is invalid or has expired.' });
    res.json({
      email:             record.email,
      suggestedUsername: record.suggestedUsername,
      role:              record.role
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* Accept an invite — create account */
app.post('/api/auth/accept-invite', passwordResetLimiter, async (req, res) => {
  try {
    const { token, username, password } = req.body;
    if (!token || !username || !password)
      return res.status(400).json({ error: 'Token, username and password are required.' });
    if (password.length < 8)
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });

    const hash   = hashToken(token);
    const record = await InviteToken.findOne({
      tokenHash: hash, used: false, expiresAt: { $gt: new Date() }
    });
    if (!record) return res.status(400).json({ error: 'Invite link is invalid or has expired.' });

    /* Check username not taken */
    const existing = await Admin.findOne({ username: username.trim() });
    if (existing) return res.status(409).json({ error: 'Username already taken. Choose another.' });

    record.used = true;
    await record.save();

    const admin = await Admin.create({
      username:  username.trim(),
      email:     record.email,
      password,
      role:      record.role,
      createdBy: record.createdBy
    });

    res.status(201).json({ message: `Account created. Welcome, ${admin.username}! Please log in.` });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* Update admin email (self) */
app.patch('/api/auth/update-email', requireAuth, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
      return res.status(400).json({ error: 'Valid email required.' });
    const updated = await Admin.findByIdAndUpdate(
      req.admin.id,
      { email: email.trim().toLowerCase() },
      { new: true }
    ).select('username email role');
    res.json(updated);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* Force logout another admin (super only) */
app.post('/api/admins/:id/force-logout', requireSuper, async (req, res) => {
  try {
    if (req.params.id === req.admin.id)
      return res.status(400).json({ error: 'Cannot force-logout yourself.' });
    await Admin.findByIdAndUpdate(req.params.id, { activeJti: '' });
    res.json({ message: 'Admin session terminated.' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* Delete admin (super only, cannot delete self) */
app.delete('/api/admins/:id', requireSuper, async (req, res) => {
  try {
    if (req.params.id === req.admin.id)
      return res.status(400).json({ error: 'You cannot delete your own account.' });
    const admin = await Admin.findByIdAndDelete(req.params.id);
    if (!admin) return res.status(404).json({ error: 'Admin not found.' });
    res.json({ message: 'Admin deleted.' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ══════════════════════════════════════════════════════
   IP BLOCK ROUTES
══════════════════════════════════════════════════════ */
app.get('/api/ipblocks', requireAuth, async (req, res) => {
  try {
    res.json(await IPBlock.find().sort({ blockedAt: -1 }).lean());
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/ipblocks', requireAuth, async (req, res) => {
  try {
    const { ip, reason } = req.body;
    if (!ip) return res.status(400).json({ error: 'IP address is required' });
    const block = await IPBlock.create({ ip: ip.trim(), reason: reason || '' });
    await refreshBlockedIPs();
    res.status(201).json(block);
  } catch (e) {
    if (e.code === 11000) return res.status(409).json({ error: 'IP already blocked' });
    res.status(500).json({ error: e.message });
  }
});
app.delete('/api/ipblocks/:id', requireAuth, async (req, res) => {
  try {
    const item = await IPBlock.findByIdAndDelete(req.params.id);
    if (!item) return res.status(404).json({ error: 'IP block not found' });
    await refreshBlockedIPs();
    res.json({ message: 'Unblocked' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ══════════════════════════════════════════════════════
   CONTACT ROUTES
══════════════════════════════════════════════════════ */
app.post('/api/contact', formLimiter, async (req, res) => {
  try {
    const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
      || req.socket.remoteAddress || '';
    const { name, email, phone, programme, subject, message } = req.body;
    if (!name || !email || !subject || !message)
      return res.status(400).json({ error: 'name, email, subject and message are required' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
      return res.status(400).json({ error: 'Invalid email address' });
    const enquiry = new Contact({
      name: name.trim().slice(0,120), email: email.trim().toLowerCase().slice(0,200),
      phone: (phone||'').trim().slice(0,20), programme: programme||'',
      subject: subject.trim().slice(0,200), message: message.trim().slice(0,2000),
      status: 'New', ipAddress: ip
    });
    await enquiry.save();
    res.status(201).json({ success: true, message: 'Enquiry received. We will get back to you shortly.' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/contact', requireAuth, async (req, res) => {
  try {
    const { status, programme, search } = req.query;
    const query = {};
    if (status)    query.status    = status;
    if (programme) query.programme = programme;
    if (search) {
      const re = { $regex: search, $options: 'i' };
      query.$or = [{ name: re }, { email: re }, { subject: re }, { message: re }];
    }
    res.json(await Contact.find(query).sort({ submittedAt: -1 }).lean());
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.patch('/api/contact/:id', requireAuth, async (req, res) => {
  try {
    const { status, adminNotes } = req.body;
    const allowed = ['New','Read','Replied','Closed'];
    if (status && !allowed.includes(status))
      return res.status(400).json({ error: 'Invalid status value' });
    const updated = await Contact.findByIdAndUpdate(
      req.params.id,
      { ...(status!==undefined&&{status}), ...(adminNotes!==undefined&&{adminNotes}) },
      { new: true, runValidators: true }
    );
    if (!updated) return res.status(404).json({ error: 'Enquiry not found' });
    res.json(updated);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/contact/:id', requireAuth, async (req, res) => {
  try {
    const item = await Contact.findByIdAndDelete(req.params.id);
    if (!item) return res.status(404).json({ error: 'Enquiry not found' });
    res.json({ message: 'Deleted', id: req.params.id });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ══════════════════════════════════════════════════════
   APPLICATIONS ROUTES
══════════════════════════════════════════════════════ */
app.get('/api/applications/stats', requireAuth, async (req, res) => {
  try {
    const breakdown = await Application.aggregate([{ $group: { _id: '$status', count: { $sum: 1 } } }]);
    const total = await Application.countDocuments();
    res.json({ total, breakdown });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/applications', formLimiter, async (req, res) => {
  try {
    const ip = (req.headers['x-forwarded-for']||'').split(',')[0].trim() || req.socket.remoteAddress||'';
    const userAgent = req.headers['user-agent']||'';
    const { name,dob,gender,category,mobile,email,address,programme,qual,board,year,marks,stream,source,message } = req.body;
    const ref = (req.body.ref||'').trim() || `APP-${Date.now()}-${Math.random().toString(36).slice(2,7).toUpperCase()}`;
    if (!name||!mobile||!email||!programme)
      return res.status(400).json({ error: 'Required fields missing' });
    const newApp = new Application({ ref,name,dob,gender,category,mobile,email,address,programme,qual,board,year,marks,stream,source,message,ipAddress:ip,userAgent });
    await newApp.save();
    res.status(201).json({ success: true, ref });
  } catch (e) {
    if (e.code===11000) return res.status(409).json({ error: 'Duplicate reference. Please try again.' });
    res.status(500).json({ error: e.message });
  }
});
app.get('/api/applications', requireAuth, async (req, res) => {
  try {
    const { status, programme, search } = req.query;
    const query = {};
    if (status)    query.status    = status;
    if (programme) query.programme = programme;
    if (search) {
      query.$or = [
        { name:   { $regex: search, $options: 'i' } },
        { mobile: { $regex: search, $options: 'i' } },
        { email:  { $regex: search, $options: 'i' } },
        { ref:    { $regex: search, $options: 'i' } }
      ];
    }
    res.json(await Application.find(query).sort({ submittedAt: -1 }).lean());
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.patch('/api/applications/:id', requireAuth, async (req, res) => {
  try {
    const { status, adminNotes } = req.body;
    const allowed = ['Pending','Under Review','Shortlisted','Admitted','Rejected'];
    if (status!==undefined && !allowed.includes(status))
      return res.status(400).json({ error: 'Invalid status value' });
    const updated = await Application.findByIdAndUpdate(
      req.params.id,
      { ...(status!==undefined&&{status}), ...(adminNotes!==undefined&&{adminNotes}) },
      { new: true, runValidators: true }
    );
    if (!updated) return res.status(404).json({ error: 'Application not found' });
    res.json(updated);
  } catch (e) { res.status(500).json({ error: 'Internal server error' }); }
});
app.delete('/api/applications/:id', requireAuth, async (req, res) => {
  try {
    const item = await Application.findByIdAndDelete(req.params.id);
    if (!item) return res.status(404).json({ error: 'Application not found' });
    res.json({ message: 'Deleted', id: req.params.id });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ══════════════════════════════════════════════════════
   NOTICES ROUTES
══════════════════════════════════════════════════════ */
app.get('/api/notices', withCache('notices', 2*60_000), async (req, res) => {
  try { res.json(await Notice.find().sort({ createdAt: -1 }).lean()); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/notices', requireAuth, async (req, res) => {
  try {
    const { panel,date,text,badge,type,href } = req.body;
    if (!panel||!date||!text) return res.status(400).json({ error: 'panel, date and text are required' });
    if (type!=='text'&&!href) return res.status(400).json({ error: 'href required for link/download type' });
    const notice = new Notice({ panel,date,text,badge:badge||'',type:type||'text',href:href||'' });
    await notice.save();
    bustCache('notices');
    res.status(201).json(notice);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.patch('/api/notices/:id', requireAuth, async (req, res) => {
  try {
    const { panel,date,text,badge,type,href } = req.body;
    const existing = await Notice.findById(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Notice not found' });
    if (existing.type==='download'&&existing.href) {
      if (type!=='download'||(type==='download'&&href&&href!==existing.href))
        await deleteGridFSByUrl(existing.href);
    }
    const notice = await Notice.findByIdAndUpdate(req.params.id,
      { panel,date,text,badge:badge||'',type:type||'text',href:href||'' },
      { new:true, runValidators:true });
    bustCache('notices');
    res.json(notice);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/notices/:id', requireAuth, async (req, res) => {
  try {
    const notice = await Notice.findByIdAndDelete(req.params.id);
    if (!notice) return res.status(404).json({ error: 'Notice not found' });
    if (notice.type==='download'&&notice.href) await deleteGridFSByUrl(notice.href);
    bustCache('notices');
    res.json({ message: 'Deleted', id: req.params.id });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/notices/seed', requireAuth, async (req, res) => {
  try {
    const count = await Notice.countDocuments();
    if (count>0) return res.status(409).json({ error: 'Notices already exist.' });
    const defaults=[
      {panel:'notices',date:'May 15',text:'Guest Lecture by Hon. Justice (Retd.) K. Ramakrishna on Constitutional Law',badge:'New',type:'link',href:'notices.html'},
      {panel:'notices',date:'May 10',text:'Semester III Examination Results Declared — Check Portals',badge:'',type:'download',href:'assets/sem3-results.pdf'},
      {panel:'notices',date:'May 05',text:'Moot Court National competition — Team Selection on May 8',badge:'',type:'link',href:'notices.html'},
      {panel:'notices',date:'Apr 28',text:'Legal Aid Camp at Ramanayyapeta — Volunteer Registrations Open',badge:'Ongoing',type:'text'},
      {panel:'notices',date:'Apr 20',text:'Annual Sports Day — Schedule Released',badge:'',type:'text'},
      {panel:'events',date:'Jun 01',text:'Admissions Commence — 2025–26 Batch',badge:'New',type:'link',href:'admissions.html'},
      {panel:'events',date:'May 20',text:'HRC Visit — High Court of Andhra Pradesh, Amaravati',badge:'',type:'text'},
      {panel:'events',date:'May 18',text:'NSS Camp — Village Adoption Programme, Kakinada Rural',badge:'',type:'text'},
      {panel:'events',date:'May 12',text:'Central Prison Visit — Criminal Justice Field Study',badge:'',type:'text'},
      {panel:'events',date:'May 02',text:'Inter-Collegiate Debate competition — Results Announced',badge:'',type:'text'},
    ];
    await Notice.insertMany(defaults);
    bustCache('notices');
    res.json({ message: `${defaults.length} notices seeded.` });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ══════════════════════════════════════════════════════
   TICKER ROUTES
══════════════════════════════════════════════════════ */
app.get('/api/ticker', withCache('ticker', 2*60_000), async (req, res) => {
  try { res.json(await Ticker.find().sort({ createdAt: -1 }).lean()); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/ticker', requireAuth, async (req, res) => {
  try {
    const { text,type,href,badge } = req.body;
    if (!text||!type) return res.status(400).json({ error: 'text and type are required' });
    const item = await Ticker.create({ text,type,href:href||'',badge:badge||'' });
    bustCache('ticker');
    res.status(201).json(item);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.patch('/api/ticker/:id', requireAuth, async (req, res) => {
  try {
    const { text,type,href,badge } = req.body;
    const existing = await Ticker.findById(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Ticker item not found' });
    if (existing.type==='download'&&existing.href) {
      if (type!=='download'||(type==='download'&&href&&href!==existing.href))
        await deleteGridFSByUrl(existing.href);
    }
    const item = await Ticker.findByIdAndUpdate(req.params.id,
      { ...(text!==undefined&&{text}), ...(type!==undefined&&{type}), ...(href!==undefined&&{href}), ...(badge!==undefined&&{badge}) },
      { new:true, runValidators:true });
    bustCache('ticker');
    res.json(item);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/ticker/:id', requireAuth, async (req, res) => {
  try {
    const item = await Ticker.findByIdAndDelete(req.params.id);
    if (!item) return res.status(404).json({ error: 'Ticker item not found' });
    if (item.type==='download'&&item.href) await deleteGridFSByUrl(item.href);
    bustCache('ticker');
    res.json({ message: 'Deleted', id: req.params.id });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/ticker/seed', requireAuth, async (req, res) => {
  try {
    const count = await Ticker.countDocuments();
    if (count>0) return res.status(409).json({ error: 'Ticker items already exist. Delete them first.' });
    await Ticker.insertMany([
      {type:'link',text:'Admissions Open for 2025–26 Academic Year — Apply Now',href:'admissions.html',badge:'🎓 Admissions'},
      {type:'download',text:'National Moot Court competition — Download Brochure',href:'assets/moot-court-brochure.pdf',badge:''},
      {type:'link',text:'Legal Aid Camp at Ramanayyapeta — Community Service Initiative',href:'events.html#legal-aid',badge:''},
      {type:'download',text:'Results for Semester III Declared — Download Results PDF',href:'assets/sem3-results.pdf',badge:'📄 Result'},
      {type:'link',text:'Guest Lecture by Hon. Justice (Retd.) K. Ramakrishna — 15 May 2025',href:'notices.html',badge:'📢 Notice'},
      {type:'text',text:'College closed on 14 April for Dr. Ambedkar Jayanti',badge:''},
      {type:'text',text:'College closed on 1st May for May Day',badge:''}
    ]);
    bustCache('ticker');
    res.json({ message: 'Ticker seeded' });
  } catch (e) { res.status(500).json({ error: 'Internal server error' }); }
});

/* ══════════════════════════════════════════════════════
   NEWS ROUTES
══════════════════════════════════════════════════════ */
app.get('/api/news', withCache('news'), async (req, res) => {
  try {
    if (req.query.all==='1') {
      const header = req.headers['authorization'];
      if (!header||!header.startsWith('Bearer '))
        return res.status(401).json({ error: 'Admin token required for ?all=1' });
      try { jwt.verify(header.slice(7), process.env.JWT_SECRET); }
      catch { return res.status(401).json({ error: 'Invalid or expired token' }); }
      res.set('Cache-Control','no-store');
      return res.json(await NewsItem.find().sort({ createdAt: -1 }).lean());
    }
    res.json(await NewsItem.find({ published: true }).sort({ createdAt: -1 }).lean());
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/news', requireAuth, async (req, res) => {
  try {
    const { title,date,tag,body,imageUrl,published } = req.body;
    if (!title||!date) return res.status(400).json({ error: 'title and date are required' });
    const item = new NewsItem({ title,date,tag:tag||'',body:body||'',imageUrl:imageUrl||'',published:published!==false });
    await item.save();
    bustCache('news');
    res.status(201).json(item);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.patch('/api/news/:id', requireAuth, async (req, res) => {
  try {
    const { title,date,tag,body,imageUrl,published } = req.body;
    const existing = await NewsItem.findById(req.params.id);
    if (!existing) return res.status(404).json({ error: 'News item not found' });
    if (existing.imageUrl&&imageUrl!==undefined&&imageUrl!==existing.imageUrl)
      await deleteGridFSByUrl(existing.imageUrl);
    const updated = await NewsItem.findByIdAndUpdate(req.params.id,
      { ...(title!==undefined&&{title}), ...(date!==undefined&&{date}), ...(tag!==undefined&&{tag}),
        ...(body!==undefined&&{body}), ...(imageUrl!==undefined&&{imageUrl}), ...(published!==undefined&&{published}) },
      { new:true, runValidators:true });
    bustCache('news');
    res.json(updated);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/news/:id', requireAuth, async (req, res) => {
  try {
    const item = await NewsItem.findByIdAndDelete(req.params.id);
    if (!item) return res.status(404).json({ error: 'News item not found' });
    if (item.imageUrl) await deleteGridFSByUrl(item.imageUrl);
    bustCache('news');
    res.json({ message: 'Deleted', id: req.params.id });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/news/seed', requireAuth, async (req, res) => {
  try {
    if (await NewsItem.countDocuments()>0)
      return res.status(409).json({ error: 'News items already exist.' });
    await NewsItem.insertMany([
      {title:'National Moot Court competition — Team Selected',date:'May 12, 2025',tag:'Achievement',body:"RGIL's team selected for national moot court competition June 2025.",published:true},
      {title:'Guest Lecture on Constitutional Law by Retd. Justice K. Ramakrishna',date:'May 8, 2025',tag:'Event',body:'Session on evolving interpretation of fundamental rights.',published:true},
      {title:'Legal Aid Camp — Ramanayyapeta Village',date:'Apr 28, 2025',tag:'Outreach',body:'Free legal aid camp benefiting over 150 villagers.',published:true},
      {title:'Admissions Open for 2025–26 Academic Year',date:'Apr 15, 2025',tag:'Admissions',body:'Applications invited for 3-Year LL.B and 5-Year BA LL.B. Last date July 31, 2025.',published:true},
    ]);
    bustCache('news');
    res.json({ message: 'News seeded.' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ══════════════════════════════════════════════════════
   GALLERY ROUTES
══════════════════════════════════════════════════════ */
app.get('/api/gallery', withCache('gallery', 5*60_000), async (req, res) => {
  try {
    const filter = {};
    if (req.query.cat) filter.cat = req.query.cat;
    res.json(await Gallery.find(filter).sort({ createdAt: -1 }).lean());
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/gallery', requireAuth, async (req, res) => {
  try {
    const { title,cat,src,date,location,photographer,programme,description } = req.body;
    if (!title||!cat) return res.status(400).json({ error: 'title and cat are required' });
    const item = await Gallery.create({ title,cat,src:src||'',date:date||'',location:location||'',photographer:photographer||'',programme:programme||'',description:description||'' });
    bustCache('gallery');
    res.status(201).json(item);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.patch('/api/gallery/:id', requireAuth, async (req, res) => {
  try {
    const { title,cat,src,date,location,photographer,programme,description } = req.body;
    const existing = await Gallery.findById(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Gallery item not found' });
    if (existing.src&&src!==undefined&&src!==existing.src) await deleteGridFSByUrl(existing.src);
    const item = await Gallery.findByIdAndUpdate(req.params.id,
      { ...(title!==undefined&&{title}), ...(cat!==undefined&&{cat}), ...(src!==undefined&&{src}),
        ...(date!==undefined&&{date}), ...(location!==undefined&&{location}),
        ...(photographer!==undefined&&{photographer}), ...(programme!==undefined&&{programme}),
        ...(description!==undefined&&{description}) },
      { new:true, runValidators:true });
    bustCache('gallery');
    res.json(item);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/gallery/:id', requireAuth, async (req, res) => {
  try {
    const item = await Gallery.findByIdAndDelete(req.params.id);
    if (!item) return res.status(404).json({ error: 'Gallery item not found' });
    if (item.src) await deleteGridFSByUrl(item.src);
    bustCache('gallery');
    res.json({ message: 'Deleted', id: req.params.id });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ══════════════════════════════════════════════════════
   FILE ROUTES — GridFS
══════════════════════════════════════════════════════ */
app.post('/api/upload', requireAuth, upload.single('file'), async (req, res) => {
  if (!req.file)  return res.status(400).json({ error: 'No file uploaded' });
  if (!gfsBucket) return res.status(500).json({ error: 'Database not ready yet' });
  try {
    const safeName     = Date.now()+'_'+req.file.originalname.replace(/[^a-zA-Z0-9._-]/g,'_');
    const uploadStream = gfsBucket.openUploadStream(safeName, {
      metadata: { originalName:req.file.originalname, mimetype:req.file.mimetype, uploadedBy:req.admin.username, uploadedAt:new Date() }
    });
    Readable.from(req.file.buffer).pipe(uploadStream);
    uploadStream.on('finish', () => {
      const fileId = uploadStream.id.toString();
      const host   = process.env.HOST_URL || `${req.protocol}://${req.get('host')}`;
      res.json({ url:`${host}/api/file/${fileId}`, fileId, filename:safeName, originalName:req.file.originalname, size:req.file.size, mimetype:req.file.mimetype });
    });
    uploadStream.on('error', err => res.status(500).json({ error:'Upload failed: '+err.message }));
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.get('/api/file/:id', async (req, res) => {
  if (!gfsBucket) return res.status(500).json({ error: 'Database not ready' });
  try {
    const fileId = new ObjectId(req.params.id);
    let file = fileMetaCache.get(req.params.id);
    if (!file) {
      const files = await gfsBucket.find({ _id: fileId }).toArray();
      if (!files.length) return res.status(404).json({ error: 'File not found' });
      file = files[0];
      fileMetaCache.set(req.params.id, file);
    }
    res.set('Content-Type', file.metadata?.mimetype||'application/octet-stream');
    res.set('Content-Disposition', `inline; filename="${file.metadata?.originalName||file.filename}"`);
    res.set('Cache-Control', 'public, max-age=31536000, immutable');
    gfsBucket.openDownloadStream(fileId).pipe(res);
  } catch (err) {
    if (err.message.includes('24 character hex')) return res.status(400).json({ error: 'Invalid file ID' });
    res.status(500).json({ error: err.message });
  }
});
app.delete('/api/file/:id', requireAuth, async (req, res) => {
  if (!gfsBucket) return res.status(500).json({ error: 'Database not ready' });
  try {
    fileMetaCache.delete(req.params.id);
    await gfsBucket.delete(new ObjectId(req.params.id));
    res.json({ message: 'File deleted' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.get('/api/files', requireAuth, async (req, res) => {
  if (!gfsBucket) return res.status(500).json({ error: 'Database not ready' });
  try {
    const host  = process.env.HOST_URL || `${req.protocol}://${req.get('host')}`;
    const files = await gfsBucket.find({}).sort({ uploadDate: -1 }).toArray();
    res.json(files.map(f => ({
      id:f._id.toString(), filename:f.filename, originalName:f.metadata?.originalName||f.filename,
      mimetype:f.metadata?.mimetype, size:f.length, uploadedAt:f.uploadDate, url:`${host}/api/file/${f._id}`
    })));
  } catch (err) { res.status(500).json({ error: err.message }); }
});


/* Create admin directly (super only) */
app.post('/api/auth/create-admin', requireSuper, async (req, res) => {
  try {
    const { username, email, password, role = 'admin' } = req.body;
    if (!username || !email || !password)
      return res.status(400).json({ error: 'Username, email and password are required.' });
    if (password.length < 8)
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    if (!['super', 'admin'].includes(role))
      return res.status(400).json({ error: 'Invalid role.' });

    const existingUser = await Admin.findOne({ username: username.trim() });
    if (existingUser) return res.status(409).json({ error: 'Username already taken.' });

    const existingEmail = await Admin.findOne({ email: email.trim().toLowerCase() });
    if (existingEmail) return res.status(409).json({ error: 'Email already in use.' });

    const admin = await Admin.create({
      username:  username.trim(),
      email:     email.trim().toLowerCase(),
      password,
      role,
      createdBy: req.admin.username
    });

    res.status(201).json({ message: `Admin "${admin.username}" created.`, username: admin.username, role: admin.role });
  } catch (e) {
    if (e.code === 11000) return res.status(409).json({ error: 'Username or email already exists.' });
    res.status(500).json({ error: e.message });
  }
});

/* List admins — alias for frontend compatibility */
app.get('/api/auth/admins', requireSuper, async (req, res) => {
  try {
    const admins = await Admin.find()
      .select('username email role createdAt createdBy activeJti')
      .lean();
    res.json(admins.map(a => ({ ...a, hasActiveSession: !!a.activeJti })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* Delete admin — alias for frontend compatibility */
app.delete('/api/auth/admins/:id', requireSuper, async (req, res) => {
  try {
    if (req.params.id === req.admin.id)
      return res.status(400).json({ error: 'You cannot delete your own account.' });
    const admin = await Admin.findByIdAndDelete(req.params.id);
    if (!admin) return res.status(404).json({ error: 'Admin not found.' });
    res.json({ message: 'Admin deleted.' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ══════════════════════════════════════════════════════
   STATIC SITE
══════════════════════════════════════════════════════ */
const SITE_DIR = __dirname;
app.use(express.static(SITE_DIR));
app.use((req, res, next) => {
  if (req.path.endsWith('.html')) {
    const clean = req.path.slice(0,-5)||'/';
    const qs = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
    return res.redirect(301, clean+qs);
  }
  next();
});
app.use((req, res, next) => {
  if (req.path.startsWith('/api')||path.extname(req.path)) return next();
  const htmlFile = path.join(SITE_DIR, req.path+'.html');
  if (fs.existsSync(htmlFile)) return res.sendFile(htmlFile);
  const indexFile = path.join(SITE_DIR, req.path, 'index.html');
  if (fs.existsSync(indexFile)) return res.sendFile(indexFile);
  next();
});

/* ══════════════════════════════════════════════════════
   HEALTH CHECK
══════════════════════════════════════════════════════ */
app.get('/api/health', (_, res) => res.json({ status: 'ok', time: new Date() }));

/* ══════════════════════════════════════════════════════
   ERROR HANDLERS
══════════════════════════════════════════════════════ */
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code==='LIMIT_FILE_SIZE')
      return res.status(400).json({ error: 'File too large. Maximum size is 15 MB.' });
    return res.status(400).json({ error: 'File upload error: '+err.message });
  }
  if (err&&err.message&&err.message.startsWith('File type not allowed'))
    return res.status(400).json({ error: err.message });
  next(err);
});
app.use((_, res) => res.status(404).json({ error: 'Route not found' }));

app.listen(PORT, () => console.log(`🚀  RGIL API → http://localhost:${PORT}`));
