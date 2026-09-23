# DigiShop — digital products store with wallet, admin panel & reseller API

A complete store in the same style as the site you showed: product cards with category tabs,
wallet top-up by bKash / Nagad / Rocket, instant key delivery, top buyers / recent orders / feedback,
full admin panel, and a reseller API.

Tech: **Node.js + Express + SQLite** (one database file, nothing extra to install).

---

## 1. Run it on your PC (Windows)

1. Install **Node.js 20 or newer** from https://nodejs.org (LTS).
2. Unzip this folder, open it, click the address bar, type `cmd` and press Enter.
3. Run:
   ```
   npm install
   npm start
   ```
4. Open http://localhost:3000 for the shop and http://localhost:3000/admin for the admin panel.

**First admin login:** `admin@example.com` / `admin123`.
Change it right away, from Account → Settings. You can also set your own admin before the first run:
```
set ADMIN_EMAIL=you@gmail.com
set ADMIN_PASSWORD=YourStrongPass
npm start
```
(The admin account is created only once, when `store.db` doesn't exist yet.)

---

## 2. Features

**Store (customer side)**
- Home page: slider, notice bar, category tabs (All / your categories), product cards with price,
  FILE & SETUP button, BUY NOW button, and a MAINTENANCE badge.
- Product page: packages (e.g. 1 Day / 7 Days / 30 Days), quantity, stock count, setup video link, file link.
- Register / login, wallet balance in the header.
- **Add Money**: user sends bKash/Nagad, enters amount + sender number + TrxID → admin approves → wallet credited.
- **Instant delivery**: buying takes money from the wallet and delivers keys from stock right away.
- My Orders (with keys), Wallet History, review after purchase, change password.
- Top Buyers, Recent Orders, and Feedbacks sections on the home page.
- Mobile layout with a bottom navigation bar and a floating support button (Telegram/WhatsApp link).

**Admin panel (`/admin`)**
- Dashboard: revenue, today's sales, 7-day chart, pending counts, low-stock alerts, total wallet balances.
- Top-up requests: approve (you can correct the amount) or reject.
- Orders: filter, deliver manually, refund to wallet.
- Products: add/edit/delete, image upload, status (active / maintenance / hidden), auto or manual delivery,
  packages with normal and reseller prices, **bulk key upload** (paste one key per line).
- Categories, Users (search, role user/reseller/admin, add/deduct balance, ban), Reviews (hide/delete),
  Sliders (upload banner + link), Settings (site name, currency, notice, payment numbers, support link).

**Reseller API** (docs page at `/api-docs`)
- Users make a key in Account → API. Set their role to **reseller** to give them reseller prices.
- `GET /api/v1/balance`, `GET /api/v1/products`, `POST /api/v1/order`, `GET /api/v1/order/:id`
- Header: `X-API-Key: sk_...`

---

## 3. Put it online (VPS, e.g. DigitalOcean / Contabo / any Ubuntu server)

```bash
# on the server
sudo apt update && sudo apt install -y nodejs npm nginx
# upload this folder (or git clone it), then:
cd digishop && npm install
export SESSION_SECRET="some-long-random-text"
export NODE_ENV=production
npx pm2 start server.js --name store && npx pm2 save
```
Point your domain to the server, put Nginx in front of it (proxy to port 3000), and add free HTTPS with
`sudo apt install certbot python3-certbot-nginx && sudo certbot --nginx`.
**Use HTTPS in production.** Login cookies are only sent over HTTPS when `NODE_ENV=production`.

Shared cPanel hosting also works if it has **"Setup Node.js App"**: set the startup file to `server.js`.

**Backups:** everything is in `store.db` plus the `public/uploads` folder. Copy both regularly.

---

## 4. Customising

| What | Where |
|---|---|
| Colours / look | `public/style.css` (`--green`, `--purple` at the top) |
| Home page layout | `public/index.html` |
| Product page | `public/product.html` |
| Customer account pages | `public/account.html` |
| Admin panel | `public/admin/admin.js` |
| All server logic & API | `server.js` |
| Database tables & demo data | `db.js` |

To start fresh, stop the server and delete `store.db`. Demo products are created again on the next start.

### Automatic bKash payment (optional upgrade)
Top-ups here are checked by hand, which needs no merchant account. For automatic crediting you need a
**bKash / Nagad merchant account** (or a gateway such as SSLCommerz, AamarPay, or UddoktaPay). Their callback
would run the same code as the admin "approve" route in `server.js` (`/api/admin/topups/:id/:action`).

---

## 5. Security notes
- Passwords are hashed with bcrypt. API keys are stored hashed and shown only once.
- Every purchase runs as one database transaction, so a user can't spend the same balance twice and a key
  can't be sold twice.
- The same TrxID can't be submitted twice. Always check it in your bKash/Nagad app before approving.
- Login is rate-limited, and the API is limited to 60 requests per minute.
