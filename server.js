/**
 * NOTEVAULT backend — single file.  Node 18+ · Express · Firebase (Auth + Firestore, free Spark plan OK) · direct UPI payments
 *
 * RENDER:  Web Service · Build: `npm install` · Start: `node server.js` · Health check path: /healthz
 *
 * ENV VARS
 *   FIREBASE_SERVICE_ACCOUNT   service-account JSON (raw, or base64 of it)
 *   UPI_ID                     your UPI ID, e.g. nishal@oksbi
 *   UPI_NAME                   optional payee name shown in the UPI app (default NOTEVAULT)
 *   ADMIN_EMAILS               comma-separated admin emails (must be verified in Firebase Auth)
 *   ALLOWED_ORIGINS            comma-separated site origins for CORS, e.g. https://notevault.netlify.app (empty = allow all)
 *   MAX_PDF_MB                 optional, default 10 (PDFs are stored inside Firestore, so keep them modest)
 *   REFERRAL_CONFIG            optional JSON to change referral rewards without editing code, e.g.
 *                              {"percent":10,"welcomePercent":10,"milestones":{"3":{"freeProducts":1},"5":{"freeProducts":2}}}
 *
 * PAYMENT FLOW (no gateway, so no KYC): buyer pays your UPI ID with the order's reference code as the note, then submits the
 * 12-digit UPI reference (UTR). The order waits as "pending" until an admin checks the money in their UPI app and approves it.
 * Only approve after you have seen the payment (right amount, right note/UTR) in your bank/UPI app.
 *
 * FIREBASE RULES:  this server is the only client of Firestore → set its rules to `allow read, write: if false;`
 * PDFs: no Firebase Storage needed — each PDF is split into ~700 KB chunks in Firestore (pdfs/{productId}/c/*) and streamed to buyers.
 *
 * AUTH: clients send `Authorization: Bearer <Firebase ID token>`.
 *
 * PUBLIC   GET  /healthz · /api/config · /api/products · /api/products/:id
 *          POST /api/track  (first-party analytics beacon: text/plain JSON, always 204, 120/min per IP, 2 KB cap, bots ignored → Firestore `analytics_events`, kept 120 days)
 * USER     POST /api/orders {productIds[], coupon?}   → creates an order, returns amount + UPI link (free items are granted instantly)
 *          POST /api/orders/:id/submit {utr}          → buyer submits the 12-digit UPI reference; order becomes "pending"
 *          GET  /api/orders/mine · /api/library · /api/library/:productId/download   (returns the PDF bytes; fetch with the Bearer token and save as a blob)
 * ADMIN    GET  /api/admin/stats · /api/admin/products · /api/admin/orders[?status=pending]
 *          POST /api/admin/products   (multipart: `data` JSON + `pdf` file)   PUT /api/admin/products/:id   DELETE /api/admin/products/:id[?force=1]
 *          POST /api/admin/import     (JSON array exported from the old browser-only admin panel)
 *          POST /api/admin/orders/:id/approve · /reject {reason?} · /revoke
 *          GET  /api/admin/analytics?days=N   (N clamped 1–90, default 7; visitors, sessions, pages, referrers, devices, countries, recent events)
 * REFERRALS (referrals.js)  GET /api/referrals/config · /validate?code= · /me   POST /api/referrals/apply {code} · /quote {productIds[]}
 *          ADMIN  GET /api/admin/referrals
 */
"use strict";
const crypto = require("crypto");
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const multer = require("multer");
const admin = require("firebase-admin");
const createReferrals = require("./referrals");

/* ---------- config ---------- */
const env = process.env;
const need = k => { if (!env[k]) { console.error(`Missing env var ${k}`); process.exit(1); } return env[k]; };
function serviceAccount() {
  const raw = need("FIREBASE_SERVICE_ACCOUNT").trim();
  let j;
  try { j = JSON.parse(raw); } catch {
    try { j = JSON.parse(Buffer.from(raw, "base64").toString("utf8")); }
    catch { console.error("FIREBASE_SERVICE_ACCOUNT must be JSON or base64-encoded JSON"); process.exit(1); }
  }
  if (j.private_key) j.private_key = j.private_key.replace(/\\n/g, "\n");
  return j;
}
admin.initializeApp({ credential: admin.credential.cert(serviceAccount()) });
const db = admin.firestore();
db.settings({ ignoreUndefinedProperties: true });
const UPI_ID = need("UPI_ID"), UPI_NAME = env.UPI_NAME || "NOTEVAULT";
const ADMINS = (env.ADMIN_EMAILS || "").split(",").map(s => s.trim().toLowerCase()).filter(Boolean);
const ORIGINS = (env.ALLOWED_ORIGINS || "").split(",").map(s => s.trim().replace(/\/$/, "")).filter(Boolean);
const MAX_PDF_MB = +env.MAX_PDF_MB || 10;
if (!ADMINS.length) console.warn("ADMIN_EMAILS is empty — admin routes will reject everyone.");
if (!ORIGINS.length) console.warn("ALLOWED_ORIGINS is empty — CORS allows any origin.");

const BOARDS = ["CBSE", "ICSE", "State Board"], SUBJ = ["Mathematics","Science","Social Science","History","Geography","Civics","English","Hindi","Sanskrit","Malayalam","Computer Science","Physics","Chemistry","Biology","Political Science","Economics","Information Technology","Artificial Intelligence","Informatics Practices","Physical Education","Accountancy","Business Studies","Psychology","Sociology","Applied Mathematics","Entrepreneurship","Legal Studies","Home Science","Biotechnology","English Language","English Literature","History & Civics","Computer Applications","Economic Applications","Commercial Studies","Environmental Science","Accounts","Commerce","Arabic","Urdu","Botany","Zoology","Computer Application","Statistics","Social Work","Journalism","Gandhian Studies","Philosophy","Electronics","Music"], LANGS = ["English", "Malayalam", "Hindi", "Bilingual"];
const col = n => db.collection(n);

/* ---------- helpers ---------- */
class HttpError extends Error { constructor(status, msg) { super(msg); this.status = status; } }
const bad = (m, s = 400) => new HttpError(s, m);
const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const refCode = () => "NV" + crypto.randomBytes(4).toString("hex").toUpperCase();
const str = (v, max) => typeof v === "string" ? v.trim().slice(0, max) : "";
const arr = (v, n, max) => (typeof v === "string" ? v.split(/[,\n]/) : Array.isArray(v) ? v : []).map(x => str(String(x ?? ""), max)).filter(Boolean).slice(0, n);
const int = (v, min, max) => { if (v === null || v === undefined || v === "") return null; const n = Math.round(Number(v)); return Number.isFinite(n) && n >= min && n <= max ? n : null; };

function cleanProduct(b) {
  b = b || {};
  const p = {
    title: str(b.title, 200), title_ml: str(b.title_ml, 200) || null,
    cls: int(b.cls, 8, 12), board: b.board, subject: b.subject, type: b.type === "subject" ? "subject" : "chapter",
    chapterNo: str(b.chapterNo, 20) || null, chapter: str(b.chapter, 200) || null,
    price: int(b.price, 0, 100000), mrp: int(b.mrp, 0, 100000),
    status: b.status === "draft" ? "draft" : "published", featured: !!b.featured,
    pages: int(b.pages, 1, 5000), language: LANGS.includes(b.language) ? b.language : "English", author: str(b.author, 100) || null,
    tags: arr(b.tags, 15, 30), desc: str(b.desc, 2000), desc_ml: str(b.desc_ml, 2000) || null,
    toc: arr(b.toc, 100, 200), toc_ml: arr(b.toc_ml, 100, 200)
  };
  if (!p.title) throw bad("Title is required");
  if (p.cls === null) throw bad("Class must be 8–12");
  if (!BOARDS.includes(p.board)) throw bad("Invalid board");
  if (!SUBJ.includes(p.subject)) throw bad("Invalid subject");
  if (p.price === null) throw bad("Price must be a whole number of rupees (0–100000)");
  if (!(p.mrp > p.price)) p.mrp = null;
  return p;
}
const out = (id, d) => { const { pdfChunks, pdfVer, ...rest } = d; return { id, ...rest, hasPdf: !!pdfChunks }; };
const orderOut = o => ({ id: o.id, uid: o.email, email: o.email, items: (o.items || []).map(({ id, title, price }) => ({ id, title, price })), subtotal: o.subtotal ?? o.total, discount: o.discount || 0, coupon: o.coupon || null, total: o.total, status: o.status, at: o.paidAt || o.submittedAt || o.createdAt, ref: o.ref || null, utr: o.utr || null, rejectReason: o.rejectReason || null });

const CHUNK = 700 * 1024; // Firestore documents max out at 1 MiB
const chunksRef = id => col("pdfs").doc(id).collection("c");
async function deleteChunks(id, pred) {
  const refs = (await chunksRef(id).listDocuments()).filter(pred);
  for (let i = 0; i < refs.length; i += 400) { const b = db.batch(); refs.slice(i, i + 400).forEach(r => b.delete(r)); await b.commit(); }
}
async function savePdf(id, buf, name) {
  if (!buf || buf.length < 5 || buf.subarray(0, 5).toString("latin1") !== "%PDF-") throw bad("File is not a valid PDF");
  if (buf.length > MAX_PDF_MB * 1048576) throw bad(`PDF too large (max ${MAX_PDF_MB} MB)`, 413);
  const ver = Date.now().toString(36), n = Math.ceil(buf.length / CHUNK), mine = r => r.id.startsWith(ver + "_");
  try {
    for (let i = 0; i < n; i += 6) { // small batches keep each commit well under Firestore's 10 MiB request limit
      const b = db.batch();
      for (let k = i; k < Math.min(n, i + 6); k++) b.set(chunksRef(id).doc(`${ver}_${String(k).padStart(4, "0")}`), { data: Buffer.from(buf.subarray(k * CHUNK, (k + 1) * CHUNK)) });
      await b.commit();
    }
  } catch (e) { await deleteChunks(id, mine).catch(() => {}); throw e; }
  await deleteChunks(id, r => !mine(r)).catch(e => console.error("Old PDF cleanup failed:", e)); // old version removed only after the new one is safely written
  return { pdfVer: ver, pdfChunks: n, pdfName: str(name, 120) || "notes.pdf", pdfSize: buf.length };
}

/** Marks an order paid and unlocks its items. Safe to call repeatedly. */
async function fulfil(orderId) {
  const ref = col("orders").doc(orderId);
  return db.runTransaction(async tx => {
    const s = await tx.get(ref);
    if (!s.exists) throw bad("Order not found", 404);
    const o = s.data();
    if (!["created", "pending", "rejected"].includes(o.status)) return { ...o, id: orderId };
    const now = Date.now();
    tx.update(ref, { status: "paid", paidAt: now });
    for (const i of o.items) tx.set(col("purchases").doc(`${o.uid}_${i.id}`), { uid: o.uid, email: o.email, productId: i.id, title: i.title, price: i.price, orderId, at: now });
    return { ...o, id: orderId, status: "paid", paidAt: now };
  });
}

/* ---------- auth ---------- */
const isAdmin = u => !!u && u.email_verified === true && ADMINS.includes((u.email || "").toLowerCase());
async function readUser(req) {
  const h = req.headers.authorization || "";
  if (!h.startsWith("Bearer ")) return null;
  try { return await admin.auth().verifyIdToken(h.slice(7)); } catch { return null; }
}
const softAuth = wrap(async (req, res, next) => { req.user = await readUser(req); next(); });
const auth = wrap(async (req, res, next) => { req.user = await readUser(req); if (!req.user) throw bad("Sign in required", 401); next(); });
const adminOnly = (req, res, next) => isAdmin(req.user) ? next() : next(bad("Admin only", 403));

/* ---------- referrals ---------- */
let referralConfig = {};
try { referralConfig = env.REFERRAL_CONFIG ? JSON.parse(env.REFERRAL_CONFIG) : {}; } catch { console.error("REFERRAL_CONFIG is not valid JSON"); process.exit(1); }
const referrals = createReferrals({
  db, admin,
  requireAuth: auth,                              // same Firebase-token auth as the rest of the API (sets req.user)
  isAdmin: async req => isAdmin(req.user),        // same verified-admin rule as the rest of the API
  config: { ...referralConfig, orderFields: { uid: "uid", status: "status", amount: "total", at: "paidAt" } },
});

/* ---------- analytics (helpers) ---------- */
const DAY = 86400000, IST = 330 * 60000, ANALYTICS_TTL = 120 * DAY, ANALYTICS_LIMIT = 20000;
const EVENTS = new Set(["pageview", "signup", "login", "checkout_start", "order_submitted", "order_free", "download", "leave"]);
const BOT_RE = /bot|crawl|spider|slurp|headless|phantom|lighthouse|pagespeed|gtmetrix|pingdom|uptime|monitor|scrape|preview|curl|wget|python|axios|fetch|httpclient|go-http|java\/|libwww/i;
const plain = (v, max) => str(v, max).replace(/[\u0000-\u001f\u007f<>]/g, "");   // no control chars / angle brackets in anything we store
const tok = (v, min) => { const s = str(v, 64); return s.length >= min && /^[\w-]+$/.test(s) ? s : null; };
const hostOf = u => { try { return new URL(u).hostname.replace(/^www\./, ""); } catch { return ""; } };
const istDay = t => new Date(t + IST).toISOString().slice(0, 10);               // YYYY-MM-DD in Asia/Kolkata (fixed +05:30, no DST)
const countryOf = h => [h["cf-ipcountry"], h["x-vercel-ip-country"]].map(v => String(v || "").toUpperCase()).find(c => /^[A-Z]{2}$/.test(c) && c !== "XX" && c !== "T1") || null;
const cleanRef = (v, self) => { const s = plain(v, 200); if (!s) return null; const h = hostOf(s); return h === self && h ? null : h || s.slice(0, 100); }; // URL → host; own site isn't a referrer

function parseUA(ua, w) {
  const has = r => r.test(ua);
  const browser = has(/Edg(?:e|A|iOS)?\//) ? "Edge" : has(/OPR\/|OPiOS|Opera/) ? "Opera" : has(/SamsungBrowser/) ? "Samsung Internet" : has(/Instagram/) ? "Instagram" : has(/FBAN|FBAV/) ? "Facebook"
    : has(/FxiOS|Firefox\//) ? "Firefox" : has(/UCBrowser/) ? "UC Browser" : has(/CriOS|Chrome\//) ? "Chrome" : has(/Safari\//) ? "Safari" : has(/MSIE|Trident\//) ? "IE" : "Other";
  const os = has(/Windows/) ? "Windows" : has(/Android/) ? "Android" : has(/iPhone|iPad|iPod/) ? "iOS" : has(/Mac OS X|Macintosh/) ? "macOS" : has(/CrOS/) ? "ChromeOS" : has(/Linux|X11/) ? "Linux" : "Other";
  let device = has(/iPad|Tablet/) || (has(/Android/) && !has(/Mobile/)) ? "tablet" : has(/Mobi|iPhone|iPod|Android/) ? "mobile" : "desktop";
  if (device === "desktop" && w) device = w < 768 ? "mobile" : os === "macOS" && w < 1100 ? "tablet" : "desktop"; // iPadOS reports a Mac UA; viewport width settles it
  return { browser, os, device };
}

/** Validates a beacon request and returns the Firestore document to store, or null to silently drop it. */
function trackEvent(req) {
  const origin = req.headers.origin, ua = String(req.headers["user-agent"] || "").slice(0, 400);
  if (!ua || BOT_RE.test(ua) || (origin && ORIGINS.length && !ORIGINS.includes(origin))) return null;
  let b; try { b = JSON.parse(req.body); } catch { return null; }
  const type = str(b?.type, 20), vid = tok(b?.vid, 6);
  if (!EVENTS.has(type) || !vid) return null;
  const w = int(b.w, 1, 10000), lang = str(b.lang, 20).toLowerCase(), email = str(b.email, 254).toLowerCase();
  const ev = {
    type, vid, sid: tok(b.sid, 6), path: plain(b.path, 200).split("?")[0], ref: cleanRef(b.ref, hostOf(origin)), w,
    lang: /^[a-z]{2,3}(-[a-z0-9]{2,8})*$/.test(lang) ? lang : null,
    email: /^[^\s@]{1,64}@[^\s@]+\.[^\s@]{2,}$/.test(email) ? email : null,
    dur: int(b.dur, 0, 86400), pages: int(b.pages, 0, 1000), pid: tok(b.pid, 1), amt: int(b.amt, 0, 1000000),
    ...parseUA(ua, w), country: countryOf(req.headers), at: Date.now()   // the IP and the raw user-agent are never stored
  };
  return Object.fromEntries(Object.entries(ev).filter(([, v]) => v !== null && v !== ""));
}

/** Turns raw events (newest first) into the dashboard payload. Visitors/sessions/pages/devices/… are based on pageviews; `leave` only feeds durations. */
function analyticsReport(E, days, now) {
  const keys = Array.from({ length: days }, (_, i) => istDay(now - (days - 1 - i) * DAY)); // today (IST) and the days before it, zeros included
  const daily = new Map(keys.map(k => [k, { vis: new Set(), views: 0 }]));
  const vis = new Set(), live = new Set(), sess = new Map(), maxDur = new Map(), pages = new Map(), entry = new Map(), exit = new Map(), refs = new Map();
  const dim = { devices: new Map(), browsers: new Map(), os: new Map(), countries: new Map() };
  const n = { signup: 0, login: 0, checkout_start: 0, order_submitted: 0, download: 0 }, recent = [];
  let views = 0;
  const bump = (m, k) => m.set(k, (m.get(k) || 0) + 1);
  const uniq = (m, k, vid) => { if (!m.has(k)) m.set(k, new Set()); m.get(k).add(vid); };
  for (const e of E) {
    if (Object.hasOwn(n, e.type)) n[e.type]++;
    if (e.type !== "leave") {
      if (e.at >= now - 5 * 60000) live.add(e.vid);
      if (recent.length < 50) recent.push({ at: e.at, type: e.type, path: e.path || null, vid: e.vid, email: e.email || null, country: e.country || null });
    }
    if (e.sid && typeof e.dur === "number") maxDur.set(e.sid, Math.max(maxDur.get(e.sid) ?? 0, e.dur));
    if (e.type !== "pageview") continue;
    views++; vis.add(e.vid);
    const d = daily.get(istDay(e.at)); if (d) { d.vis.add(e.vid); d.views++; }
    const p = e.path || "(unknown)";
    if (!pages.has(p)) pages.set(p, { v: 0, u: new Set() });
    pages.get(p).v++; pages.get(p).u.add(e.vid);
    uniq(dim.devices, e.device || "Unknown", e.vid); uniq(dim.browsers, e.browser || "Unknown", e.vid);
    uniq(dim.os, e.os || "Unknown", e.vid); uniq(dim.countries, e.country || "Unknown", e.vid);
    if (e.sid) {
      const s = sess.get(e.sid) || { n: 0, first: e, last: e };
      s.n++; if (e.at <= s.first.at) s.first = e; if (e.at > s.last.at) s.last = e;
      sess.set(e.sid, s);
    }
  }
  let dsum = 0, dn = 0, single = 0;
  for (const [sid, s] of sess) {
    if (maxDur.has(sid)) { dsum += maxDur.get(sid); dn++; }  // sessions that never reported a duration don't drag the average to 0
    if (s.n === 1) single++;
    bump(entry, s.first.path || "(unknown)"); bump(exit, s.last.path || "(unknown)"); bump(refs, s.first.ref || "Direct");
  }
  const top = (m, max, f) => [...m].map(([k, x]) => f(k, x)).sort((a, b) => b.v - a.v || (a.k < b.k ? -1 : 1)).slice(0, max);
  const cnt = (k, v) => ({ k, v }), size = (k, s) => ({ k, v: s.size });
  return {
    totals: {
      online: live.size, visitors: vis.size, sessions: sess.size, pageviews: views,
      avgDuration: dn ? Math.round(dsum / dn) : 0, bounceRate: sess.size ? Math.round(single / sess.size * 1000) / 10 : 0,
      signups: n.signup, logins: n.login, checkouts: n.checkout_start, orders: n.order_submitted, downloads: n.download
    },
    daily: keys.map(k => ({ d: k, visitors: daily.get(k).vis.size, views: daily.get(k).views })),
    pages: top(pages, 15, (k, p) => ({ k, v: p.v, u: p.u.size })),
    entry: top(entry, 15, cnt), exit: top(exit, 15, cnt), referrers: top(refs, 15, cnt),
    devices: top(dim.devices, 10, size), browsers: top(dim.browsers, 10, size), os: top(dim.os, 10, size), countries: top(dim.countries, 10, size),
    recent
  };
}

/** Deletes events older than 120 days (≤ 10,000 per run, so the free-tier delete quota is never at risk). */
async function pruneAnalytics() {
  for (let i = 0; i < 25; i++) {
    const s = await col("analytics_events").where("at", "<", Date.now() - ANALYTICS_TTL).select().limit(400).get();
    if (s.empty) return;
    const b = db.batch(); s.docs.forEach(d => b.delete(d.ref)); await b.commit();
    if (s.size < 400) return;
  }
}
function startAnalyticsCleanup() {
  const run = () => pruneAnalytics().catch(e => console.error("Analytics cleanup failed:", e.message));
  setTimeout(run, 60 * 1000).unref(); setInterval(run, DAY).unref();   // once a minute after boot, then daily
}

/* ---------- app ---------- */
const app = express();
app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));
app.use(cors({ origin: (o, cb) => cb(null, !o || !ORIGINS.length || ORIGINS.includes(o)), allowedHeaders: ["Authorization", "Content-Type"], methods: ["GET", "POST", "PUT", "DELETE"], maxAge: 86400 }));
app.get("/healthz", (req, res) => res.json({ ok: true }));

// First-party analytics beacon. Mounted before the global /api limiter and the JSON parser: it has its own limits, doesn't use up
// visitors' API quota, and can only ever answer 204 (rate-limited, oversized, malformed, bot, bad origin — all silently dropped).
const trackLimiter = rateLimit({ windowMs: 60 * 1000, limit: 120, legacyHeaders: false, handler: (req, res) => res.status(204).end() });
const trackText = express.text({ type: "*/*", limit: "2kb" });
app.post("/api/track", trackLimiter, (req, res, next) => trackText(req, res, () => next()), (req, res) => {
  const o = req.headers.origin;
  if (o && (!ORIGINS.length || ORIGINS.includes(o))) res.set("Access-Control-Allow-Credentials", "true"); // sendBeacon always sends with credentials
  res.status(204).end();
  try {
    const ev = trackEvent(req);
    if (ev) col("analytics_events").add(ev).catch(e => console.error("Analytics write failed:", e.message));
  } catch (e) { console.error("Analytics error:", e.message); }
});

app.use("/api", rateLimit({ windowMs: 15 * 60 * 1000, limit: 600, standardHeaders: true, legacyHeaders: false }));

// Bulk import (large JSON incl. base64 PDFs) — own parser, mounted before the small global one.
app.post("/api/admin/import", auth, adminOnly, express.json({ limit: "80mb" }), wrap(async (req, res) => {
  const items = Array.isArray(req.body) ? req.body : [];
  if (!items.length || items.length > 200) throw bad("Send a JSON array of 1–200 notes");
  let imported = 0; const errors = [];
  for (const [i, it] of items.entries()) {
    try {
      const p = cleanProduct(it), ref = col("products").doc();
      let pdf = {};
      const m = typeof it.pdf === "string" && it.pdf.match(/^data:application\/pdf;base64,(.+)$/s);
      if (m) pdf = await savePdf(ref.id, Buffer.from(m[1], "base64"), it.pdfName);
      const now = Date.now();
      await ref.set({ ...p, ...pdf, createdAt: now, updatedAt: now });
      imported++;
    } catch (e) { errors.push({ index: i, title: it?.title, error: e.message }); }
  }
  res.json({ imported, errors });
}));

app.use(express.json({ limit: "1mb" }));
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: MAX_PDF_MB * 1048576, files: 1 } });
const body = req => { if (typeof req.body?.data === "string") { try { return JSON.parse(req.body.data); } catch { throw bad("Invalid JSON in `data`"); } } return req.body; };

/* ---------- public ---------- */
app.get("/api/config", (req, res) => res.json({ upiId: UPI_ID, payeeName: UPI_NAME, currency: "INR", maxPdfMb: MAX_PDF_MB }));

app.get("/api/products", wrap(async (req, res) => {
  const { cls, board, subject, q } = req.query, needle = String(q || "").toLowerCase();
  const snap = await col("products").where("status", "==", "published").get();
  const list = snap.docs.map(d => out(d.id, d.data())).filter(p =>
    (!cls || p.cls == cls) && (!board || p.board === board) && (!subject || p.subject === subject) &&
    (!needle || [p.title, p.title_ml, p.subject, p.chapter, p.desc, p.desc_ml, ...(p.tags || [])].join(" ").toLowerCase().includes(needle)));
  list.sort((a, b) => (!!b.featured - !!a.featured) || b.createdAt - a.createdAt);
  res.json(list);
}));

app.get("/api/products/:id", softAuth, wrap(async (req, res) => {
  const d = await col("products").doc(req.params.id).get();
  if (!d.exists || (d.data().status === "draft" && !isAdmin(req.user))) throw bad("Not found", 404);
  res.json(out(d.id, d.data()));
}));

/* ---------- checkout (direct UPI, manual approval) ---------- */
app.post("/api/orders", rateLimit({ windowMs: 15 * 60 * 1000, limit: 40 }), auth, wrap(async (req, res) => {
  const ids = [...new Set(Array.isArray(req.body?.productIds) ? req.body.productIds.filter(x => typeof x === "string" && x) : [])].slice(0, 20);
  if (!ids.length) throw bad("No notes selected");
  const { uid, email } = req.user;
  const [prods, owned] = await Promise.all([db.getAll(...ids.map(i => col("products").doc(i))), db.getAll(...ids.map(i => col("purchases").doc(`${uid}_${i}`)))]);
  const items = [];
  prods.forEach((d, k) => {
    if (!d.exists || d.data().status !== "published") throw bad("A selected note is not available", 404);
    if (!owned[k].exists) items.push({ id: d.id, title: d.data().title, price: d.data().price });
  });
  if (!items.length) throw bad("You already own these notes", 409);
  const ref = col("orders").doc(), code = refCode();
  let pricing; // { subtotal, discount, total, couponCode } — reserves the coupon for this order atomically
  try { pricing = await referrals.priceOrder({ uid, orderId: ref.id, items, coupon: req.body?.coupon }); }
  catch (e) { if (e instanceof referrals.RefError) throw bad(e.message, e.status); throw e; }
  const total = pricing.total;
  try {
    await ref.set({ uid, email: email || "", items, subtotal: pricing.subtotal, discount: pricing.discount, coupon: pricing.couponCode || null, freeUnits: pricing.freeUnits || 0, total, currency: "INR", ref: code, status: "created", createdAt: Date.now() });
  } catch (e) { if (pricing.couponCode) await referrals.releaseCoupons(ref.id).catch(() => {}); throw e; }
  if (total === 0) { // free (or fully rewarded) order: unlock now and settle the coupon right away
    const paid = await fulfil(ref.id);
    await referrals.reconcileOrder(ref.id, paid).catch(e => console.error("referral reconcile failed", e.message));
    return res.json({ free: true, order: orderOut(paid) });
  }
  res.json({
    orderId: ref.id, ref: code, amount: total, subtotal: pricing.subtotal, discount: pricing.discount, coupon: pricing.couponCode || null, currency: "INR", upiId: UPI_ID, payeeName: UPI_NAME,
    upiLink: `upi://pay?pa=${UPI_ID}&pn=${encodeURIComponent(UPI_NAME)}&am=${total.toFixed(2)}&cu=INR&tn=${code}`,
    items: items.map(i => ({ id: i.id, title: i.title }))
  });
}));

app.post("/api/orders/:id/submit", auth, wrap(async (req, res) => {
  const utr = String(req.body?.utr || "").replace(/\s/g, "");
  if (!/^\d{12}$/.test(utr)) throw bad("Enter the 12-digit UPI reference number (UTR) from your payment app");
  const ref = col("orders").doc(req.params.id), s = await ref.get();
  if (!s.exists || s.data().uid !== req.user.uid) throw bad("Order not found", 404);
  const st = s.data().status;
  if (st === "paid") throw bad("Already paid", 409);
  if (st === "pending") throw bad("Already submitted — waiting for approval", 409);
  if (st !== "created" && st !== "rejected") throw bad("This order can no longer be paid", 409);
  const dup = await col("orders").where("utr", "==", utr).limit(1).get();
  if (!dup.empty && dup.docs[0].id !== ref.id) throw bad("This reference number was already used", 409);
  try { await referrals.confirmOrderCoupon(ref.id, s.data()); } // the reward on this order must still be reserved for it
  catch (e) { if (e instanceof referrals.RefError) throw bad(e.message, e.status); throw e; }
  await ref.update({ status: "pending", utr, submittedAt: Date.now(), rejectReason: admin.firestore.FieldValue.delete() });
  res.json({ ok: true, status: "pending" });
}));

app.get("/api/orders/mine", auth, wrap(async (req, res) => {
  const s = await col("orders").where("uid", "==", req.user.uid).get();
  res.json(s.docs.map(d => orderOut({ id: d.id, ...d.data() })).filter(o => o.status !== "created").sort((a, b) => b.at - a.at));
}));

app.get("/api/library", auth, wrap(async (req, res) => {
  const s = await col("purchases").where("uid", "==", req.user.uid).get();
  const rows = s.docs.map(d => d.data());
  const prods = rows.length ? await db.getAll(...rows.map(r => col("products").doc(r.productId))) : [];
  res.json(rows.map((r, i) => ({ productId: r.productId, title: r.title, at: r.at, orderId: r.orderId, product: prods[i].exists ? out(prods[i].id, prods[i].data()) : null })).sort((a, b) => b.at - a.at));
}));

app.get("/api/library/:id/download", auth, wrap(async (req, res) => {
  const [own, prod] = await db.getAll(col("purchases").doc(`${req.user.uid}_${req.params.id}`), col("products").doc(req.params.id));
  if (!own.exists) throw bad("You have not purchased this note", 403);
  const p = prod.exists && prod.data();
  if (!p || !p.pdfChunks) throw bad("File not available yet", 404);
  const snap = await chunksRef(prod.id).get();
  const parts = snap.docs.filter(d => d.id.startsWith(p.pdfVer + "_")).sort((x, y) => (x.id < y.id ? -1 : 1));
  if (parts.length !== p.pdfChunks) throw bad("File is being updated, try again shortly", 503);
  const name = (p.title || "notes").replace(/[^\w\- ]+/g, "").trim().slice(0, 60) || "notes";
  res.set({ "Content-Type": "application/pdf", "Content-Disposition": `attachment; filename="${name}.pdf"`, "Cache-Control": "private, no-store" });
  res.end(Buffer.concat(parts.map(d => d.get("data"))));
}));

/* ---------- admin ---------- */
const adm = [auth, adminOnly];

app.get("/api/admin/products", ...adm, wrap(async (req, res) => {
  const s = await col("products").get();
  res.json(s.docs.map(d => out(d.id, d.data())).sort((a, b) => b.createdAt - a.createdAt));
}));

app.post("/api/admin/products", ...adm, upload.single("pdf"), wrap(async (req, res) => {
  const p = cleanProduct(body(req)), ref = col("products").doc(), now = Date.now();
  const pdf = req.file ? await savePdf(ref.id, req.file.buffer, req.file.originalname) : {};
  const doc = { ...p, ...pdf, createdAt: now, updatedAt: now };
  await ref.set(doc);
  res.status(201).json(out(ref.id, doc));
}));

app.put("/api/admin/products/:id", ...adm, upload.single("pdf"), wrap(async (req, res) => {
  const ref = col("products").doc(req.params.id), cur = await ref.get();
  if (!cur.exists) throw bad("Not found", 404);
  const raw = body(req), p = cleanProduct(raw), upd = { ...p, updatedAt: Date.now() };
  if (req.file) Object.assign(upd, await savePdf(ref.id, req.file.buffer, req.file.originalname));
  else if (raw.removePdf === true && cur.data().pdfChunks) {
    await deleteChunks(ref.id, () => true);
    const del = admin.firestore.FieldValue.delete();
    Object.assign(upd, { pdfChunks: del, pdfVer: del, pdfName: del, pdfSize: del });
  }
  await ref.update(upd);
  const fresh = await ref.get();
  res.json(out(fresh.id, fresh.data()));
}));

app.delete("/api/admin/products/:id", ...adm, wrap(async (req, res) => {
  const ref = col("products").doc(req.params.id), cur = await ref.get();
  if (!cur.exists) throw bad("Not found", 404);
  const sold = await col("purchases").where("productId", "==", ref.id).limit(1).get();
  if (!sold.empty && req.query.force !== "1") throw bad("This note has buyers — unpublish it instead, or add ?force=1 to delete anyway", 409);
  if (cur.data().pdfChunks) await deleteChunks(ref.id, () => true);
  await ref.delete();
  res.json({ ok: true });
}));

app.get("/api/admin/orders", ...adm, wrap(async (req, res) => {
  const s = await col("orders").orderBy("createdAt", "desc").limit(500).get();
  const q = req.query.status, all = s.docs.map(d => orderOut({ id: d.id, ...d.data() }));
  res.json(all.filter(o => q ? o.status === q : o.status !== "created"));
}));

app.get("/api/admin/stats", ...adm, wrap(async (req, res) => {
  const [ps, os, pn] = await Promise.all([col("products").get(), col("orders").where("status", "==", "paid").get(), col("orders").where("status", "==", "pending").get()]);
  const P = ps.docs.map(d => d.data()), O = os.docs.map(d => d.data()), sales = {};
  O.forEach(o => o.items.forEach(i => sales[i.id] = (sales[i.id] || 0) + 1));
  res.json({
    products: P.length, published: P.filter(p => p.status !== "draft").length, drafts: P.filter(p => p.status === "draft").length, withPdf: P.filter(p => p.pdfChunks).length,
    orders: O.length, pendingOrders: pn.size, revenue: O.reduce((a, o) => a + o.total, 0),
    bestSellers: Object.entries(sales).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([id, n]) => ({ id, title: ps.docs.find(d => d.id === id)?.data().title || id, sales: n }))
  });
}));

const analyticsCache = new Map(); // days → { t, data } — 30 s, so refreshing the dashboard can't burn the free-tier read quota
app.get("/api/admin/analytics", ...adm, wrap(async (req, res) => {
  const q = Math.round(Number(req.query.days)), days = Number.isFinite(q) ? Math.min(90, Math.max(1, q)) : 7, now = Date.now();
  const hit = analyticsCache.get(days);
  if (hit && now - hit.t < 30000) return res.json(hit.data);
  const snap = await col("analytics_events").where("at", ">=", now - days * DAY).orderBy("at", "desc").limit(ANALYTICS_LIMIT)
    .select("type", "vid", "sid", "path", "ref", "dur", "email", "browser", "os", "device", "country", "at").get();
  if (snap.size >= ANALYTICS_LIMIT) console.warn(`Analytics: hit the ${ANALYTICS_LIMIT}-event cap for ${days} days — oldest events were left out`);
  const data = analyticsReport(snap.docs.map(d => d.data()), days, now);
  analyticsCache.set(days, { t: now, data });
  res.json(data);
}));

app.post("/api/admin/orders/:id/approve", ...adm, wrap(async (req, res) => res.json({ ok: true, order: orderOut(await fulfil(req.params.id)) })));

app.post("/api/admin/orders/:id/reject", ...adm, wrap(async (req, res) => {
  const ref = col("orders").doc(req.params.id), s = await ref.get();
  if (!s.exists) throw bad("Not found", 404);
  if (!["created", "pending"].includes(s.data().status)) throw bad("Only unpaid orders can be rejected", 409);
  await ref.update({ status: "rejected", rejectReason: str(req.body?.reason, 200) || "Payment not found", rejectedAt: Date.now() });
  res.json({ ok: true });
}));

app.post("/api/admin/orders/:id/revoke", ...adm, wrap(async (req, res) => {
  const ref = col("orders").doc(req.params.id), s = await ref.get();
  if (!s.exists) throw bad("Not found", 404);
  const o = s.data();
  if (o.status !== "paid") throw bad("Only paid orders can be revoked", 409);
  const batch = db.batch();
  batch.update(ref, { status: "revoked", revokedAt: Date.now() });
  o.items.forEach(i => batch.delete(col("purchases").doc(`${o.uid}_${i.id}`)));
  await batch.commit();
  res.json({ ok: true });
}));

/* ---------- referrals routes (/api/referrals/*, /api/admin/referrals) ---------- */
app.use(referrals.router);

/* ---------- errors ---------- */
app.use((req, res) => res.status(404).json({ error: "Not found" }));
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) return res.status(err.code === "LIMIT_FILE_SIZE" ? 413 : 400).json({ error: err.code === "LIMIT_FILE_SIZE" ? `PDF too large (max ${MAX_PDF_MB} MB)` : "Upload error" });
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Invalid JSON" });
  if (err.type === "entity.too.large") return res.status(413).json({ error: "Request too large" });
  const status = err.status >= 400 && err.status < 600 ? err.status : 500;
  if (status >= 500 && !(err instanceof HttpError)) console.error(err);
  res.status(status).json({ error: status >= 500 && !(err instanceof HttpError) ? "Server error" : err.message });
});

app.listen(env.PORT || 10000, "0.0.0.0", () => { console.log(`NOTEVAULT backend listening on ${env.PORT || 10000}`); referrals.start(); startAnalyticsCleanup(); }); // referrals.start(): auto-tracks approvals / rejections / revokes
