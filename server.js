// DigiShop — Express server: storefront API, admin API, reseller API.
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const multer = require('multer');
const path = require('path');
const rateLimit = require('express-rate-limit');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

app.set('trust proxy', 1);
app.use(express.json({ limit: '1mb' }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-this-secret-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 30 * 24 * 3600 * 1000 },
}));
app.use(express.static(path.join(__dirname, 'public')));

// ---------- helpers ----------
const sha256 = s => crypto.createHash('sha256').update(s).digest('hex');
const slugify = s => String(s).toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || crypto.randomBytes(3).toString('hex');
const money = n => Math.round(Number(n) * 100) / 100;
class HttpError extends Error { constructor(status, msg) { super(msg); this.status = status; } }
const wrap = fn => (req, res, next) => { try { const r = fn(req, res, next); if (r && r.catch) r.catch(next); } catch (e) { next(e); } };

const publicUser = u => u && ({ id: u.id, name: u.name, email: u.email, role: u.role, balance: u.balance, total_spent: u.total_spent, has_api_key: !!u.api_key, created_at: u.created_at });
const getUser = id => db.prepare('SELECT * FROM users WHERE id = ?').get(id);

// CSRF guard: session-authenticated writes must come from our own JS (custom header can't be sent cross-site without CORS).
app.use('/api', (req, res, next) => {
  if (req.path.startsWith('/v1/') || ['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  if (req.get('X-Requested-With') !== 'fetch') return res.status(403).json({ error: 'Bad request origin' });
  next();
});

function auth(req, res, next) {
  const u = req.session.userId && getUser(req.session.userId);
  if (!u) return res.status(401).json({ error: 'Please log in' });
  if (u.banned) return res.status(403).json({ error: 'Account suspended' });
  req.user = u; next();
}
function admin(req, res, next) {
  auth(req, res, () => req.user.role === 'admin' ? next() : res.status(403).json({ error: 'Admin only' }));
}
function apiKeyAuth(req, res, next) {
  const key = req.get('X-API-Key') || req.query.api_key;
  const u = key && db.prepare('SELECT * FROM users WHERE api_key = ?').get(sha256(key));
  if (!u) return res.status(401).json({ success: false, error: 'Invalid API key' });
  if (u.banned) return res.status(403).json({ success: false, error: 'Account suspended' });
  req.user = u; next();
}

// ---------- core purchase logic (used by website AND reseller API) ----------
const placeOrder = db.transaction((userId, variantId, qty, source) => {
  qty = parseInt(qty, 10);
  if (!Number.isInteger(qty) || qty < 1 || qty > 50) throw new HttpError(400, 'Quantity must be 1–50');
  const v = db.prepare(`SELECT v.*, p.name AS pname, p.status, p.delivery FROM variants v
                        JOIN products p ON p.id = v.product_id WHERE v.id = ?`).get(variantId);
  if (!v) throw new HttpError(404, 'Product not found');
  if (v.status !== 'active') throw new HttpError(400, 'This product is under maintenance');

  const user = getUser(userId);
  const unit = user.role === 'reseller' && v.reseller_price != null ? v.reseller_price : v.price;
  const amount = money(unit * qty);
  if (user.balance < amount) throw new HttpError(400, `Insufficient balance. Need ${amount}, you have ${user.balance}`);

  let keys = [];
  if (v.delivery === 'auto') {
    keys = db.prepare('SELECT id, value FROM stock_keys WHERE variant_id = ? AND order_id IS NULL ORDER BY id LIMIT ?').all(v.id, qty);
    if (keys.length < qty) throw new HttpError(400, `Out of stock (only ${keys.length} left)`);
  }
  const status = v.delivery === 'auto' ? 'completed' : 'pending';
  const delivered = keys.map(k => k.value).join('\n') || null;
  const orderId = db.prepare(`INSERT INTO orders (user_id, variant_id, product_name, variant_label, qty, amount, status, delivered, source)
                              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(userId, v.id, v.pname, v.label, qty, amount, status, delivered, source).lastInsertRowid;
  const mark = db.prepare('UPDATE stock_keys SET order_id = ? WHERE id = ?');
  keys.forEach(k => mark.run(orderId, k.id));
  db.prepare('UPDATE users SET balance = balance - ?, total_spent = total_spent + ? WHERE id = ?').run(amount, amount, userId);
  db.prepare('INSERT INTO transactions (user_id, amount, note) VALUES (?, ?, ?)').run(userId, -amount, `Order #${orderId}: ${v.pname} - ${v.label} x${qty}`);
  return db.prepare('SELECT * FROM orders WHERE id = ?').get(orderId);
});

const refundOrder = db.transaction(orderId => {
  const o = db.prepare('SELECT * FROM orders WHERE id = ?').get(orderId);
  if (!o) throw new HttpError(404, 'Order not found');
  if (o.status === 'cancelled') throw new HttpError(400, 'Already cancelled');
  db.prepare("UPDATE orders SET status = 'cancelled' WHERE id = ?").run(o.id);
  db.prepare('UPDATE users SET balance = balance + ?, total_spent = total_spent - ? WHERE id = ?').run(o.amount, o.amount, o.user_id);
  db.prepare('INSERT INTO transactions (user_id, amount, note) VALUES (?, ?, ?)').run(o.user_id, o.amount, `Refund for order #${o.id}`);
});

// ============================================================
//  AUTH
// ============================================================
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false });

app.post('/api/auth/register', authLimiter, wrap((req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) throw new HttpError(400, 'All fields are required');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new HttpError(400, 'Invalid email');
  if (String(password).length < 6) throw new HttpError(400, 'Password must be at least 6 characters');
  if (db.prepare('SELECT 1 FROM users WHERE email = ?').get(email.toLowerCase())) throw new HttpError(400, 'Email already registered');
  const id = db.prepare('INSERT INTO users (name, email, password) VALUES (?, ?, ?)')
    .run(String(name).slice(0, 60), email.toLowerCase(), bcrypt.hashSync(password, 10)).lastInsertRowid;
  req.session.regenerate(() => { req.session.userId = id; res.json({ user: publicUser(getUser(id)) }); });
}));

app.post('/api/auth/login', authLimiter, wrap((req, res) => {
  const { email, password } = req.body || {};
  const u = email && db.prepare('SELECT * FROM users WHERE email = ?').get(String(email).toLowerCase());
  if (!u || !bcrypt.compareSync(String(password || ''), u.password)) throw new HttpError(400, 'Wrong email or password');
  if (u.banned) throw new HttpError(403, 'Account suspended');
  req.session.regenerate(() => { req.session.userId = u.id; res.json({ user: publicUser(u) }); });
}));

app.post('/api/auth/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));

app.get('/api/me', (req, res) => {
  const u = req.session.userId && getUser(req.session.userId);
  res.json({ user: u && !u.banned ? publicUser(u) : null });
});

app.post('/api/me/password', auth, wrap((req, res) => {
  const { current, password } = req.body || {};
  if (!bcrypt.compareSync(String(current || ''), req.user.password)) throw new HttpError(400, 'Current password is wrong');
  if (String(password || '').length < 6) throw new HttpError(400, 'New password must be at least 6 characters');
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(bcrypt.hashSync(password, 10), req.user.id);
  res.json({ ok: true });
}));

// Generate / regenerate API key (shown once, stored hashed)
app.post('/api/me/apikey', auth, wrap((req, res) => {
  const key = 'sk_' + crypto.randomBytes(24).toString('hex');
  db.prepare('UPDATE users SET api_key = ? WHERE id = ?').run(sha256(key), req.user.id);
  res.json({ api_key: key });
}));

// ============================================================
//  PUBLIC STORE
// ============================================================
app.get('/api/settings', (req, res) => {
  const s = db.getSettings();
  res.json({ site_name: s.site_name, currency: s.currency, notice: s.notice, support_link: s.support_link, min_topup: Number(s.min_topup),
    methods: [['bKash', s.bkash_number], ['Nagad', s.nagad_number], ['Rocket', s.rocket_number]].filter(m => m[1]).map(([name, number]) => ({ name, number })) });
});

app.get('/api/home', (req, res) => {
  const categories = db.prepare('SELECT id, name, slug FROM categories ORDER BY sort, id').all();
  const products = db.prepare(`SELECT p.id, p.name, p.slug, p.image, p.status, p.category_id, c.slug AS category,
      (SELECT MIN(price) FROM variants v WHERE v.product_id = p.id) AS price
      FROM products p LEFT JOIN categories c ON c.id = p.category_id
      WHERE p.status != 'hidden' ORDER BY p.sort, p.id`).all();
  const sliders = db.prepare('SELECT image, link FROM sliders ORDER BY sort, id').all();
  const topBuyers = db.prepare("SELECT name, total_spent FROM users WHERE total_spent > 0 AND role != 'admin' ORDER BY total_spent DESC LIMIT 10").all();
  const recentOrders = db.prepare(`SELECT u.name, o.product_name, o.variant_label, o.amount, o.status, o.created_at FROM orders o
      JOIN users u ON u.id = o.user_id WHERE o.status = 'completed' ORDER BY o.id DESC LIMIT 10`).all();
  const reviews = db.prepare(`SELECT u.name, r.rating, r.text, r.created_at FROM reviews r JOIN users u ON u.id = r.user_id
      WHERE r.approved = 1 ORDER BY r.id DESC LIMIT 30`).all();
  res.json({ categories, products, sliders, topBuyers, recentOrders, reviews });
});

app.get('/api/products/:slug', wrap((req, res) => {
  const p = db.prepare("SELECT * FROM products WHERE slug = ? AND status != 'hidden'").get(req.params.slug);
  if (!p) throw new HttpError(404, 'Product not found');
  const variants = db.prepare(`SELECT id, label, price,
      (SELECT COUNT(*) FROM stock_keys k WHERE k.variant_id = v.id AND k.order_id IS NULL) AS stock
      FROM variants v WHERE product_id = ? ORDER BY sort, id`).all(p.id)
    .map(v => ({ ...v, stock: p.delivery === 'manual' ? null : v.stock }));
  res.json({ product: p, variants });
}));

// ============================================================
//  USER: orders, top-ups, reviews
// ============================================================
app.post('/api/orders', auth, wrap((req, res) => {
  const order = placeOrder(req.user.id, req.body.variant_id, req.body.qty || 1, 'web');
  res.json({ order, balance: getUser(req.user.id).balance });
}));

app.get('/api/orders', auth, (req, res) => {
  res.json({ orders: db.prepare(`SELECT o.*, (SELECT 1 FROM reviews r WHERE r.order_id = o.id) AS reviewed
    FROM orders o WHERE user_id = ? ORDER BY id DESC LIMIT 200`).all(req.user.id) });
});

app.get('/api/transactions', auth, (req, res) => {
  res.json({ transactions: db.prepare('SELECT * FROM transactions WHERE user_id = ? ORDER BY id DESC LIMIT 200').all(req.user.id) });
});

app.post('/api/topups', auth, wrap((req, res) => {
  const { method, amount, sender, trx_id } = req.body || {};
  const s = db.getSettings();
  const amt = money(amount);
  if (!['bKash', 'Nagad', 'Rocket'].includes(method)) throw new HttpError(400, 'Choose a payment method');
  if (!(amt >= Number(s.min_topup)) || amt > 100000) throw new HttpError(400, `Minimum top-up is ${s.min_topup}`);
  if (!/^01\d{9}$/.test(String(sender || ''))) throw new HttpError(400, 'Enter the 11-digit number you sent from');
  const trx = String(trx_id || '').trim().toUpperCase();
  if (!/^[A-Z0-9]{6,20}$/.test(trx)) throw new HttpError(400, 'Enter a valid Transaction ID');
  if (db.prepare('SELECT 1 FROM topups WHERE trx_id = ?').get(trx)) throw new HttpError(400, 'This Transaction ID was already submitted');
  const pendingCount = db.prepare("SELECT COUNT(*) c FROM topups WHERE user_id = ? AND status = 'pending'").get(req.user.id).c;
  if (pendingCount >= 5) throw new HttpError(400, 'You have too many pending requests. Please wait for approval.');
  db.prepare('INSERT INTO topups (user_id, method, amount, sender, trx_id) VALUES (?, ?, ?, ?, ?)').run(req.user.id, method, amt, sender, trx);
  res.json({ ok: true });
}));

app.get('/api/topups', auth, (req, res) => {
  res.json({ topups: db.prepare('SELECT * FROM topups WHERE user_id = ? ORDER BY id DESC LIMIT 100').all(req.user.id) });
});

app.post('/api/reviews', auth, wrap((req, res) => {
  const { order_id, rating, text } = req.body || {};
  const o = db.prepare("SELECT * FROM orders WHERE id = ? AND user_id = ? AND status = 'completed'").get(order_id, req.user.id);
  if (!o) throw new HttpError(400, 'You can only review your completed orders');
  const r = parseInt(rating, 10);
  if (!(r >= 1 && r <= 5)) throw new HttpError(400, 'Rating must be 1–5');
  if (db.prepare('SELECT 1 FROM reviews WHERE order_id = ?').get(o.id)) throw new HttpError(400, 'Already reviewed');
  db.prepare('INSERT INTO reviews (user_id, order_id, rating, text) VALUES (?, ?, ?, ?)').run(req.user.id, o.id, r, String(text || '').slice(0, 300));
  res.json({ ok: true });
}));

// ============================================================
//  ADMIN
// ============================================================
const upload = multer({
  storage: multer.diskStorage({
    destination: path.join(__dirname, 'public', 'uploads'),
    filename: (req, file, cb) => cb(null, Date.now() + '-' + crypto.randomBytes(4).toString('hex') + path.extname(file.originalname).toLowerCase()),
  }),
  limits: { fileSize: 3 * 1024 * 1024 },
  fileFilter: (req, file, cb) => cb(null, /^image\/(png|jpe?g|gif|webp)$/.test(file.mimetype) && /\.(png|jpe?g|gif|webp)$/i.test(file.originalname)),
});
app.post('/api/admin/upload', admin, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Upload a PNG, JPG, GIF or WEBP under 3 MB' });
  res.json({ url: '/uploads/' + req.file.filename });
});

app.get('/api/admin/stats', admin, (req, res) => {
  const one = (sql, ...a) => db.prepare(sql).get(...a);
  res.json({
    users: one('SELECT COUNT(*) c FROM users').c,
    orders: one('SELECT COUNT(*) c FROM orders').c,
    revenue: one("SELECT COALESCE(SUM(amount),0) s FROM orders WHERE status='completed'").s,
    today_revenue: one("SELECT COALESCE(SUM(amount),0) s FROM orders WHERE status='completed' AND date(created_at)=date('now')").s,
    pending_topups: one("SELECT COUNT(*) c FROM topups WHERE status='pending'").c,
    pending_orders: one("SELECT COUNT(*) c FROM orders WHERE status='pending'").c,
    wallet_total: one('SELECT COALESCE(SUM(balance),0) s FROM users').s,
    low_stock: db.prepare(`SELECT p.name, v.label, (SELECT COUNT(*) FROM stock_keys k WHERE k.variant_id=v.id AND k.order_id IS NULL) stock
      FROM variants v JOIN products p ON p.id=v.product_id WHERE p.delivery='auto' AND p.status!='hidden' AND stock < 3 ORDER BY stock`).all(),
    sales_7d: db.prepare(`SELECT date(created_at) d, SUM(amount) s, COUNT(*) c FROM orders WHERE status='completed'
      AND created_at >= date('now','-6 days') GROUP BY d ORDER BY d`).all(),
  });
});

// --- categories ---
app.get('/api/admin/categories', admin, (req, res) => res.json({ categories: db.prepare('SELECT * FROM categories ORDER BY sort, id').all() }));
app.post('/api/admin/categories', admin, wrap((req, res) => {
  const { id, name, sort } = req.body;
  if (!name) throw new HttpError(400, 'Name required');
  if (id) db.prepare('UPDATE categories SET name=?, slug=?, sort=? WHERE id=?').run(name, slugify(name), +sort || 0, id);
  else db.prepare('INSERT INTO categories (name, slug, sort) VALUES (?, ?, ?)').run(name, slugify(name), +sort || 0);
  res.json({ ok: true });
}));
app.delete('/api/admin/categories/:id', admin, (req, res) => { db.prepare('DELETE FROM categories WHERE id=?').run(req.params.id); res.json({ ok: true }); });

// --- products + variants ---
app.get('/api/admin/products', admin, (req, res) => {
  const products = db.prepare('SELECT p.*, c.name AS category FROM products p LEFT JOIN categories c ON c.id=p.category_id ORDER BY p.sort, p.id').all();
  const vs = db.prepare(`SELECT v.*, (SELECT COUNT(*) FROM stock_keys k WHERE k.variant_id=v.id AND k.order_id IS NULL) stock,
      (SELECT COUNT(*) FROM stock_keys k WHERE k.variant_id=v.id AND k.order_id IS NOT NULL) sold FROM variants v ORDER BY sort, id`).all();
  products.forEach(p => { p.variants = vs.filter(v => v.product_id === p.id); });
  res.json({ products });
});
app.post('/api/admin/products', admin, wrap((req, res) => {
  const b = req.body;
  if (!b.name) throw new HttpError(400, 'Name required');
  const f = [b.category_id || null, b.name, b.slug ? slugify(b.slug) : slugify(b.name), b.image || '', b.description || '', b.notice || '',
    b.video_url || '', b.file_url || '', ['active', 'maintenance', 'hidden'].includes(b.status) ? b.status : 'active',
    b.delivery === 'manual' ? 'manual' : 'auto', +b.sort || 0];
  let id = b.id;
  const saveVariants = db.transaction(() => {
    if (id) db.prepare(`UPDATE products SET category_id=?, name=?, slug=?, image=?, description=?, notice=?, video_url=?, file_url=?, status=?, delivery=?, sort=? WHERE id=?`).run(...f, id);
    else id = db.prepare(`INSERT INTO products (category_id, name, slug, image, description, notice, video_url, file_url, status, delivery, sort) VALUES (?,?,?,?,?,?,?,?,?,?,?)`).run(...f).lastInsertRowid;
    const keep = [];
    (b.variants || []).forEach((v, i) => {
      if (!v.label || !(Number(v.price) >= 0)) return;
      const rp = v.reseller_price === '' || v.reseller_price == null ? null : Number(v.reseller_price);
      if (v.id) { db.prepare('UPDATE variants SET label=?, price=?, reseller_price=?, sort=? WHERE id=? AND product_id=?').run(v.label, +v.price, rp, i, v.id, id); keep.push(+v.id); }
      else keep.push(db.prepare('INSERT INTO variants (product_id, label, price, reseller_price, sort) VALUES (?,?,?,?,?)').run(id, v.label, +v.price, rp, i).lastInsertRowid);
    });
    const existing = db.prepare('SELECT id FROM variants WHERE product_id=?').all(id).map(r => r.id);
    existing.filter(x => !keep.includes(x)).forEach(x => db.prepare('DELETE FROM variants WHERE id=?').run(x));
  });
  try { saveVariants(); } catch (e) { if (/UNIQUE/.test(e.message)) throw new HttpError(400, 'Slug already used by another product'); throw e; }
  res.json({ ok: true, id });
}));
app.delete('/api/admin/products/:id', admin, (req, res) => { db.prepare('DELETE FROM products WHERE id=?').run(req.params.id); res.json({ ok: true }); });

// --- stock keys ---
app.get('/api/admin/variants/:id/keys', admin, (req, res) => {
  res.json({ keys: db.prepare('SELECT * FROM stock_keys WHERE variant_id=? ORDER BY order_id IS NOT NULL, id DESC LIMIT 500').all(req.params.id) });
});
app.post('/api/admin/variants/:id/keys', admin, wrap((req, res) => {
  const lines = String(req.body.keys || '').split(/\r?\n/).map(s => s.trim()).filter(Boolean);
  if (!lines.length) throw new HttpError(400, 'Paste at least one key (one per line)');
  const ins = db.prepare('INSERT INTO stock_keys (variant_id, value) VALUES (?, ?)');
  db.transaction(() => lines.forEach(l => ins.run(req.params.id, l)))();
  res.json({ ok: true, added: lines.length });
}));
app.delete('/api/admin/keys/:id', admin, (req, res) => { db.prepare('DELETE FROM stock_keys WHERE id=? AND order_id IS NULL').run(req.params.id); res.json({ ok: true }); });

// --- orders ---
app.get('/api/admin/orders', admin, (req, res) => {
  const st = req.query.status;
  const q = `SELECT o.*, u.name AS user_name, u.email FROM orders o JOIN users u ON u.id=o.user_id ${st ? 'WHERE o.status=?' : ''} ORDER BY o.id DESC LIMIT 300`;
  res.json({ orders: st ? db.prepare(q).all(st) : db.prepare(q).all() });
});
app.post('/api/admin/orders/:id/deliver', admin, wrap((req, res) => {
  const text = String(req.body.delivered || '').trim();
  if (!text) throw new HttpError(400, 'Enter what to deliver');
  const r = db.prepare("UPDATE orders SET delivered=?, status='completed' WHERE id=? AND status!='cancelled'").run(text, req.params.id);
  if (!r.changes) throw new HttpError(400, 'Order not found or cancelled');
  res.json({ ok: true });
}));
app.post('/api/admin/orders/:id/refund', admin, wrap((req, res) => { refundOrder(req.params.id); res.json({ ok: true }); }));

// --- top-ups ---
app.get('/api/admin/topups', admin, (req, res) => {
  const st = req.query.status;
  const q = `SELECT t.*, u.name AS user_name, u.email FROM topups t JOIN users u ON u.id=t.user_id ${st ? 'WHERE t.status=?' : ''} ORDER BY t.id DESC LIMIT 300`;
  res.json({ topups: st ? db.prepare(q).all(st) : db.prepare(q).all() });
});
app.post('/api/admin/topups/:id/:action', admin, wrap((req, res) => {
  const { id, action } = req.params;
  if (!['approve', 'reject'].includes(action)) throw new HttpError(400, 'Bad action');
  db.transaction(() => {
    const t = db.prepare("SELECT * FROM topups WHERE id=? AND status='pending'").get(id);
    if (!t) throw new HttpError(400, 'Top-up not found or already processed');
    const amount = action === 'approve' && req.body.amount ? money(req.body.amount) : t.amount; // admin can correct the amount
    db.prepare('UPDATE topups SET status=?, amount=? WHERE id=?').run(action === 'approve' ? 'approved' : 'rejected', amount, id);
    if (action === 'approve') {
      db.prepare('UPDATE users SET balance = balance + ? WHERE id=?').run(amount, t.user_id);
      db.prepare('INSERT INTO transactions (user_id, amount, note) VALUES (?, ?, ?)').run(t.user_id, amount, `Top-up ${t.method} (${t.trx_id})`);
    }
  })();
  res.json({ ok: true });
}));

// --- users ---
app.get('/api/admin/users', admin, (req, res) => {
  const s = `%${req.query.q || ''}%`;
  res.json({ users: db.prepare(`SELECT id, name, email, role, balance, total_spent, banned, api_key IS NOT NULL AS has_api, created_at
    FROM users WHERE name LIKE ? OR email LIKE ? ORDER BY id DESC LIMIT 300`).all(s, s) });
});
app.post('/api/admin/users/:id', admin, wrap((req, res) => {
  const u = getUser(req.params.id);
  if (!u) throw new HttpError(404, 'User not found');
  const { role, banned, adjust, note } = req.body;
  if (u.id === req.user.id && (role && role !== 'admin' || banned)) throw new HttpError(400, "You can't demote or ban yourself");
  db.transaction(() => {
    if (role && ['user', 'reseller', 'admin'].includes(role)) db.prepare('UPDATE users SET role=? WHERE id=?').run(role, u.id);
    if (banned !== undefined) db.prepare('UPDATE users SET banned=? WHERE id=?').run(banned ? 1 : 0, u.id);
    const a = money(adjust || 0);
    if (a) {
      if (u.balance + a < 0) throw new HttpError(400, 'Balance cannot go below zero');
      db.prepare('UPDATE users SET balance = balance + ? WHERE id=?').run(a, u.id);
      db.prepare('INSERT INTO transactions (user_id, amount, note) VALUES (?, ?, ?)').run(u.id, a, note || 'Admin adjustment');
    }
  })();
  res.json({ ok: true });
}));

// --- reviews ---
app.get('/api/admin/reviews', admin, (req, res) => {
  res.json({ reviews: db.prepare('SELECT r.*, u.name FROM reviews r JOIN users u ON u.id=r.user_id ORDER BY r.id DESC LIMIT 300').all() });
});
app.post('/api/admin/reviews/:id', admin, (req, res) => { db.prepare('UPDATE reviews SET approved=? WHERE id=?').run(req.body.approved ? 1 : 0, req.params.id); res.json({ ok: true }); });
app.delete('/api/admin/reviews/:id', admin, (req, res) => { db.prepare('DELETE FROM reviews WHERE id=?').run(req.params.id); res.json({ ok: true }); });

// --- sliders ---
app.get('/api/admin/sliders', admin, (req, res) => res.json({ sliders: db.prepare('SELECT * FROM sliders ORDER BY sort, id').all() }));
app.post('/api/admin/sliders', admin, wrap((req, res) => {
  if (!req.body.image) throw new HttpError(400, 'Image required');
  db.prepare('INSERT INTO sliders (image, link, sort) VALUES (?, ?, ?)').run(req.body.image, req.body.link || '', +req.body.sort || 0);
  res.json({ ok: true });
}));
app.delete('/api/admin/sliders/:id', admin, (req, res) => { db.prepare('DELETE FROM sliders WHERE id=?').run(req.params.id); res.json({ ok: true }); });

// --- settings ---
app.get('/api/admin/settings', admin, (req, res) => res.json({ settings: db.getSettings() }));
app.post('/api/admin/settings', admin, (req, res) => {
  const up = db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value');
  db.transaction(() => Object.entries(req.body || {}).forEach(([k, v]) => up.run(k, String(v))))();
  res.json({ ok: true });
});

// ============================================================
//  RESELLER API  (header: X-API-Key: sk_...)
// ============================================================
const apiLimiter = rateLimit({ windowMs: 60 * 1000, limit: 60, standardHeaders: true, legacyHeaders: false });
app.use('/api/v1', apiLimiter);

app.get('/api/v1/balance', apiKeyAuth, (req, res) => {
  res.json({ success: true, balance: req.user.balance, currency: db.getSettings().currency });
});

app.get('/api/v1/products', apiKeyAuth, (req, res) => {
  const rows = db.prepare(`SELECT v.id AS variant_id, p.name AS product, v.label, v.price, v.reseller_price, p.status, p.delivery,
      (SELECT COUNT(*) FROM stock_keys k WHERE k.variant_id=v.id AND k.order_id IS NULL) AS stock
      FROM variants v JOIN products p ON p.id=v.product_id WHERE p.status != 'hidden' ORDER BY p.sort, p.id, v.sort`).all();
  const reseller = req.user.role === 'reseller';
  res.json({ success: true, products: rows.map(r => ({
    variant_id: r.variant_id, product: r.product, label: r.label,
    price: reseller && r.reseller_price != null ? r.reseller_price : r.price,
    available: r.status === 'active', stock: r.delivery === 'manual' ? null : r.stock,
  })) });
});

app.post('/api/v1/order', apiKeyAuth, (req, res) => {
  try {
    const o = placeOrder(req.user.id, req.body.variant_id, req.body.qty || 1, 'api');
    res.json({ success: true, order: { id: o.id, status: o.status, amount: o.amount, keys: o.delivered ? o.delivered.split('\n') : [] },
      balance: getUser(req.user.id).balance });
  } catch (e) {
    res.status(e.status || 500).json({ success: false, error: e.status ? e.message : 'Server error' });
  }
});

app.get('/api/v1/order/:id', apiKeyAuth, (req, res) => {
  const o = db.prepare('SELECT * FROM orders WHERE id=? AND user_id=?').get(req.params.id, req.user.id);
  if (!o) return res.status(404).json({ success: false, error: 'Order not found' });
  res.json({ success: true, order: { id: o.id, product: o.product_name, label: o.variant_label, qty: o.qty, amount: o.amount,
    status: o.status, keys: o.delivered ? o.delivered.split('\n') : [], created_at: o.created_at } });
});

// ---------- pages & errors ----------
app.get('/product/:slug', (req, res) => res.sendFile(path.join(__dirname, 'public', 'product.html')));
app.get(['/login', '/register'], (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/account', (req, res) => res.sendFile(path.join(__dirname, 'public', 'account.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'index.html')));
app.get('/api-docs', (req, res) => res.sendFile(path.join(__dirname, 'public', 'api-docs.html')));

app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));
app.use((err, req, res, next) => {
  if (!err.status) console.error(err);
  res.status(err.status || 500).json({ error: err.status ? err.message : 'Server error' });
});

app.listen(PORT, () => console.log(`Store running → http://localhost:${PORT}   Admin → http://localhost:${PORT}/admin`));
