import express from 'express';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import mysql from 'mysql2/promise';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const port = Number(process.env.PORT || 3000);
const cookieName = 'money_session';

const pool = mysql.createPool({
  uri: process.env.DATABASE_URL,
  waitForConnections: true,
  connectionLimit: 8,
  ssl: process.env.DATABASE_URL?.includes('ssl') ? { rejectUnauthorized: false } : undefined
});

const DEFAULT_STATE = {
  profile: { name: '', baseIncome: 0, targetSavings: 0, geminiKey: '' },
  transactions: [],
  budgets: {},
  bills: [],
  goals: [],
  chatHistory: [{ role: 'assistant', text: 'أهلاً بك! أنا مساعدك المالي الذكي. اسألني عن أي حاجة تخص حسابك أو التطبيق.' }]
};

app.use(express.json({ limit: '512kb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(__dirname));

function jsonState(value) {
  try { return JSON.parse(value || '{}'); } catch { return structuredClone(DEFAULT_STATE); }
}
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  return new Promise((resolve, reject) => crypto.scrypt(password, salt, 64, (error, derived) => error ? reject(error) : resolve(`${salt}:${derived.toString('hex')}`)));
}
async function verifyPassword(password, stored) {
  const [salt, expected] = String(stored).split(':');
  const actual = await hashPassword(password, salt);
  return crypto.timingSafeEqual(Buffer.from(actual.split(':')[1], 'hex'), Buffer.from(expected, 'hex'));
}
function validUsername(username) { return typeof username === 'string' && /^[\u0600-\u06FF\u0750-\u077F\s]{2,40}$/.test(username.trim()); }
function validPassword(password) { return typeof password === 'string' && /^[A-Za-z0-9]{8,72}$/.test(password); }
function publicHttps(req) {
  return req.headers['x-forwarded-proto'] === 'https' || req.headers['x-forwarded-ssl'] === 'on';
}
function sessionCookie(token, req) {
  const crossSite = publicHttps(req);
  return `${cookieName}=${token}; Path=/; HttpOnly; SameSite=${crossSite ? 'None' : 'Lax'}; Max-Age=2592000${crossSite ? '; Secure' : ''}`;
}
function clearSessionCookie(req) { const crossSite = publicHttps(req); return `${cookieName}=; Path=/; HttpOnly; SameSite=${crossSite ? 'None' : 'Lax'}; Max-Age=0${crossSite ? '; Secure' : ''}`; }
function parseCookies(header = '') { return Object.fromEntries(header.split(';').map(v => v.trim().split('=').map(decodeURIComponent)).filter(v => v.length === 2)); }

async function initDb() {
  await pool.query(`CREATE TABLE IF NOT EXISTS money_users (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(80) NOT NULL UNIQUE,
    password_hash VARCHAR(180) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
  ) ENGINE=InnoDB`);
  await pool.query(`CREATE TABLE IF NOT EXISTS money_sessions (
    token_hash CHAR(64) PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX(user_id), CONSTRAINT fk_money_sessions_user FOREIGN KEY(user_id) REFERENCES money_users(id) ON DELETE CASCADE
  ) ENGINE=InnoDB`);
  await pool.query(`CREATE TABLE IF NOT EXISTS money_user_state (
    user_id BIGINT UNSIGNED PRIMARY KEY,
    state_json LONGTEXT NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_money_state_user FOREIGN KEY(user_id) REFERENCES money_users(id) ON DELETE CASCADE
  ) ENGINE=InnoDB`);
}

async function userFromRequest(req) {
  const raw = parseCookies(req.headers.cookie || '')[cookieName];
  if (!raw) return null;
  const tokenHash = crypto.createHash('sha256').update(raw).digest('hex');
  const [rows] = await pool.query('SELECT u.id, u.username FROM money_sessions s JOIN money_users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at > NOW()', [tokenHash]);
  return rows[0] || null;
}
async function requireUser(req, res, next) {
  try { req.user = await userFromRequest(req); if (!req.user) return res.status(401).json({ ok: false, error: 'يجب تسجيل الدخول أولاً' }); next(); } catch (error) { next(error); }
}
async function createSession(userId, req, res) {
  const token = crypto.randomBytes(32).toString('base64url');
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  await pool.query('INSERT INTO money_sessions(token_hash,user_id,expires_at) VALUES(?,?,DATE_ADD(NOW(), INTERVAL 30 DAY))', [tokenHash, userId]);
  res.setHeader('Set-Cookie', sessionCookie(token, req));
}
async function getState(userId) {
  const [rows] = await pool.query('SELECT state_json FROM money_user_state WHERE user_id=?', [userId]);
  return rows[0] ? jsonState(rows[0].state_json) : structuredClone(DEFAULT_STATE);
}
async function saveState(userId, state) {
  const clean = { ...structuredClone(DEFAULT_STATE), ...state, profile: { ...DEFAULT_STATE.profile, ...(state.profile || {}) } };
  await pool.query('INSERT INTO money_user_state(user_id,state_json) VALUES(?,?) ON DUPLICATE KEY UPDATE state_json=VALUES(state_json)', [userId, JSON.stringify(clean)]);
  return clean;
}
function summary(state) {
  const transactions = Array.isArray(state.transactions) ? state.transactions : [];
  const income = Number(state.profile?.baseIncome || 0) + transactions.filter(t => t.type === 'income').reduce((n, t) => n + Number(t.amount || 0), 0);
  const expenses = transactions.filter(t => t.type === 'expense').reduce((n, t) => n + Number(t.amount || 0), 0);
  const bills = (state.bills || []).filter(b => !b.isPaid).reduce((n, b) => n + Number(b.amount || 0), 0);
  return { income, expenses, bills, cash: income - expenses, disposable: Math.max(income - expenses - bills - Number(state.profile?.targetSavings || 0), 0), transactions: transactions.length };
}

app.get('/api/health', async (_req, res) => {
  try { await pool.query('SELECT 1'); res.json({ ok: true, service: 'money-api', database: 'connected' }); } catch { res.status(503).json({ ok: false, service: 'money-api', database: 'unavailable' }); }
});
app.post('/api/auth/register', async (req, res, next) => {
  try {
    const username = String(req.body?.username || '').trim();
    const password = String(req.body?.password || '');
    if (!validUsername(username)) return res.status(400).json({ ok: false, error: 'اكتب يوزر عربي من حرفين إلى 40 حرفًا' });
    if (!validPassword(password)) return res.status(400).json({ ok: false, error: 'الباسورد يجب أن يكون 8 أحرف أو أرقام إنجليزية على الأقل' });
    const passwordHash = await hashPassword(password);
    const [result] = await pool.query('INSERT INTO money_users(username,password_hash) VALUES(?,?)', [username, passwordHash]);
    await saveState(result.insertId, { ...structuredClone(DEFAULT_STATE), profile: { ...DEFAULT_STATE.profile, name: username } });
    await createSession(result.insertId, req, res);
    res.status(201).json({ ok: true, user: { id: result.insertId, username } });
  } catch (error) { if (error.code === 'ER_DUP_ENTRY') return res.status(409).json({ ok: false, error: 'اليوزر ده مستخدم بالفعل' }); next(error); }
});
app.post('/api/auth/login', async (req, res, next) => {
  try {
    const username = String(req.body?.username || '').trim();
    const password = String(req.body?.password || '');
    const [rows] = await pool.query('SELECT id,username,password_hash FROM money_users WHERE username=?', [username]);
    if (!rows[0] || !(await verifyPassword(password, rows[0].password_hash))) return res.status(401).json({ ok: false, error: 'اليوزر أو الباسورد غير صحيح' });
    await createSession(rows[0].id, req, res);
    res.json({ ok: true, user: { id: rows[0].id, username: rows[0].username } });
  } catch (error) { next(error); }
});
app.post('/api/auth/logout', async (req, res, next) => { try { const raw = parseCookies(req.headers.cookie || '')[cookieName]; if (raw) await pool.query('DELETE FROM money_sessions WHERE token_hash=?', [crypto.createHash('sha256').update(raw).digest('hex')]); res.setHeader('Set-Cookie', clearSessionCookie(req)); res.json({ ok: true }); } catch (error) { next(error); } });
app.get('/api/auth/me', async (req, res, next) => { try { const user = await userFromRequest(req); res.json({ ok: true, user }); } catch (error) { next(error); } });
app.get('/api/state', requireUser, async (req, res, next) => { try { const state = await getState(req.user.id); res.json({ ok: true, user: req.user, data: state, summary: summary(state) }); } catch (error) { next(error); } });
app.put('/api/state', requireUser, async (req, res, next) => { try { const state = await saveState(req.user.id, req.body || {}); res.json({ ok: true, data: state, summary: summary(state) }); } catch (error) { next(error); } });

app.post('/api/assistant/chat', requireUser, async (req, res, next) => {
  try {
    const message = String(req.body?.message || '').trim();
    if (!message) return res.status(400).json({ ok: false, error: 'اكتب سؤالك أولاً' });
    const state = await getState(req.user.id);
    const compactContext = { username: req.user.username, summary: summary(state), transactions: state.transactions?.slice(-30), budgets: state.budgets, bills: state.bills, goals: state.goals };
    const upstream = await fetch(`${process.env.MANUS_API_URL}/v1/chat/completions`, { method: 'POST', headers: { Authorization: `Bearer ${process.env.MANUS_API_KEY}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ messages: [
      { role: 'system', content: `أنت مساعد Money الذكي داخل تطبيق إدارة أموال. أجب بالعربية المصرية أو العربية الواضحة حسب المستخدم. افهم كل أسئلة المستخدم المتعلقة بالتطبيق، الحسابات، المعاملات، الميزانيات، الادخار، الفواتير، ومحاكي الشراء. لا تخترع أرقامًا: استخدم سياق الحساب المرفق فقط، وقل بوضوح عندما لا تعرف. لا تنفذ أو تحفظ معاملة بنفسك؛ اطلب من المستخدم استخدام زر الإضافة. المستخدم الحالي: ${req.user.username}. سياق حسابه: ${JSON.stringify(compactContext)}` },
      ...(Array.isArray(state.chatHistory) ? state.chatHistory.slice(-12).map(m => ({ role: m.role, content: String(m.text || '') })) : []),
      { role: 'user', content: message }
    ] }) });
    const payload = await upstream.json();
    if (!upstream.ok || payload.error) return res.status(502).json({ ok: false, error: payload.error?.message || 'تعذر الاتصال بالمساعد الذكي' });
    const reply = payload.choices?.[0]?.message?.content?.trim();
    if (!reply) return res.status(502).json({ ok: false, error: 'المساعد لم يرجع ردًا' });
    state.chatHistory = [...(state.chatHistory || []), { role: 'user', text: message }, { role: 'assistant', text: reply }].slice(-40);
    await saveState(req.user.id, state);
    res.json({ ok: true, reply });
  } catch (error) { next(error); }
});

app.get('*', (_req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.use((error, _req, res, _next) => { console.error(error); res.status(500).json({ ok: false, error: 'حدث خطأ داخلي' }); });

initDb().then(() => app.listen(port, '0.0.0.0', () => console.log(`Money production API listening on 0.0.0.0:${port}`))).catch(error => { console.error('Database initialization failed', error); process.exit(1); });
