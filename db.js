// Database: SQLite (single file, no setup). Tables are created on first run.
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const path = require('path');

const db = new Database(path.join(__dirname, 'store.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',          -- user | reseller | admin
  balance REAL NOT NULL DEFAULT 0,
  total_spent REAL NOT NULL DEFAULT 0,
  api_key TEXT UNIQUE,
  banned INTEGER NOT NULL DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS categories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  slug TEXT UNIQUE NOT NULL,
  sort INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  category_id INTEGER REFERENCES categories(id) ON DELETE SET NULL,
  name TEXT NOT NULL,
  slug TEXT UNIQUE NOT NULL,
  image TEXT,
  description TEXT,
  notice TEXT,
  video_url TEXT,
  file_url TEXT,
  status TEXT NOT NULL DEFAULT 'active',      -- active | maintenance | hidden
  delivery TEXT NOT NULL DEFAULT 'auto',      -- auto (stock keys) | manual (admin delivers)
  sort INTEGER DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS variants (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
  label TEXT NOT NULL,                         -- e.g. "1 Month", "1 Year"
  price REAL NOT NULL,
  reseller_price REAL,
  sort INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS stock_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  variant_id INTEGER NOT NULL REFERENCES variants(id) ON DELETE CASCADE,
  value TEXT NOT NULL,
  order_id INTEGER,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  variant_id INTEGER REFERENCES variants(id) ON DELETE SET NULL,
  product_name TEXT NOT NULL,
  variant_label TEXT NOT NULL,
  qty INTEGER NOT NULL DEFAULT 1,
  amount REAL NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',     -- pending | completed | cancelled
  delivered TEXT,                              -- keys / delivery text
  source TEXT DEFAULT 'web',                   -- web | api
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS topups (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  method TEXT NOT NULL,
  amount REAL NOT NULL,
  sender TEXT NOT NULL,
  trx_id TEXT UNIQUE NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',     -- pending | approved | rejected
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  amount REAL NOT NULL,                        -- + credit, - debit
  note TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS reviews (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  order_id INTEGER UNIQUE REFERENCES orders(id),
  rating INTEGER NOT NULL,
  text TEXT,
  approved INTEGER NOT NULL DEFAULT 1,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS sliders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  image TEXT NOT NULL,
  link TEXT,
  sort INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT
);
`);

// Default settings
const defaults = {
  site_name: 'DIGISHOP',
  currency: '৳',
  notice: 'Welcome! Add money to your wallet, then buy — keys are delivered instantly.',
  bkash_number: '01XXXXXXXXX',
  nagad_number: '01XXXXXXXXX',
  rocket_number: '',
  min_topup: '20',
  support_link: 'https://t.me/yourchannel',
};
const insSetting = db.prepare('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)');
for (const [k, v] of Object.entries(defaults)) insSetting.run(k, v);

// First run: admin account + demo data
if (!db.prepare('SELECT 1 FROM users WHERE role = ?').get('admin')) {
  const email = process.env.ADMIN_EMAIL || 'admin@example.com';
  const pass = process.env.ADMIN_PASSWORD || 'admin123';
  db.prepare('INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)')
    .run('Admin', email, bcrypt.hashSync(pass, 10), 'admin');
  console.log(`\n  Admin created → ${email} / ${pass}  (CHANGE THIS PASSWORD!)\n`);

  const cat = db.prepare('INSERT INTO categories (name, slug, sort) VALUES (?, ?, ?)');
  cat.run('Software', 'software', 1);
  cat.run('Gift Cards', 'gift-cards', 2);
  cat.run('Streaming', 'streaming', 3);
  cat.run('VPN', 'vpn', 4);

  const prod = db.prepare(`INSERT INTO products (category_id, name, slug, image, description, status, sort)
                           VALUES (?, ?, ?, ?, ?, ?, ?)`);
  const variant = db.prepare('INSERT INTO variants (product_id, label, price, reseller_price, sort) VALUES (?, ?, ?, ?, ?)');
  const key = db.prepare('INSERT INTO stock_keys (variant_id, value) VALUES (?, ?)');
  const demo = [
    [1, 'Office Suite License', 'office-suite', '/img/demo1.svg', 'Lifetime license key for an office suite.', 'active', [['1 PC', 450, 400], ['3 PC', 1100, 1000]]],
    [1, 'Antivirus Pro', 'antivirus-pro', '/img/demo2.svg', 'Full protection for one device.', 'active', [['1 Year', 350, 300]]],
    [2, 'Game Store Gift Card', 'game-gift-card', '/img/demo3.svg', 'Digital gift card code.', 'active', [['$5', 650, 620], ['$10', 1280, 1240]]],
    [3, 'Music Premium', 'music-premium', '/img/demo4.svg', 'Premium subscription activation.', 'maintenance', [['1 Month', 120, 100]]],
    [4, 'Secure VPN', 'secure-vpn', '/img/demo5.svg', 'Fast VPN account.', 'active', [['1 Month', 150, 130], ['6 Months', 700, 650]]],
    [2, 'Mobile Recharge Card', 'mobile-card', '/img/demo6.svg', 'Top-up card code.', 'active', [['50 ৳', 52, 51], ['100 ৳', 103, 101]]],
  ];
  demo.forEach(([c, n, s, img, d, st, vars], i) => {
    const pid = prod.run(c, n, s, img, d, st, i).lastInsertRowid;
    vars.forEach(([label, price, rp], j) => {
      const vid = variant.run(pid, label, price, rp, j).lastInsertRowid;
      for (let k = 1; k <= 5; k++) key.run(vid, `DEMO-${s.toUpperCase().slice(0, 4)}-${vid}${k}-${Math.random().toString(36).slice(2, 8).toUpperCase()}`);
    });
  });
  db.prepare('INSERT INTO sliders (image, link, sort) VALUES (?, ?, ?)').run('/img/banner1.svg', '', 0);
  db.prepare('INSERT INTO sliders (image, link, sort) VALUES (?, ?, ?)').run('/img/banner2.svg', '', 1);
}

db.getSettings = () => Object.fromEntries(db.prepare('SELECT key, value FROM settings').all().map(r => [r.key, r.value]));

module.exports = db;
