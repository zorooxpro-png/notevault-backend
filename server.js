/**
 * NOTEVAULT backend — single file.  Node 18+ · Express · Firebase (Auth + Firestore, free Spark plan OK) · Razorpay
 *
 * RENDER:  Web Service · Build: `npm install` · Start: `node server.js` · Health check path: /healthz
 *
 * ENV VARS
 *   FIREBASE_SERVICE_ACCOUNT   service-account JSON (raw, or base64 of it)
 *   RAZORPAY_KEY_ID            rzp_test_… / rzp_live_…
 *   RAZORPAY_KEY_SECRET
 *   RAZORPAY_WEBHOOK_SECRET    secret you set on the webhook in the Razorpay dashboard
 *   ADMIN_EMAILS               comma-separated admin emails (must be verified in Firebase Auth)
 *   ALLOWED_ORIGINS            comma-separated site origins for CORS, e.g. https://notevault.netlify.app (empty = allow all)
 *   MAX_PDF_MB                 optional, default 10 (PDFs are stored inside Firestore, so keep them modest)
 *
 * RAZORPAY WEBHOOK: URL https://<your-service>.onrender.com/api/webhooks/razorpay · events: payment.captured, order.paid
 * FIREBASE RULES:  this server is the only client of Firestore → set its rules to `allow read, write: if false;`
 * PDFs: no Firebase Storage needed — each PDF is split into ~700 KB chunks in Firestore (pdfs/{productId}/c/*) and streamed to buyers.
 *
 * AUTH: clients send `Authorization: Bearer <Firebase ID token>`.
 *
 * PUBLIC   GET  /healthz · /api/config · /api/products · /api/products/:id
 * USER     POST /api/orders {productIds[]}            → starts Razorpay checkout (free items are granted instantly)
 *          POST /api/orders/verify {razorpay_*}       → verifies signature, unlocks notes
 *          GET  /api/orders/mine · /api/library · /api/library/:productId/download   (returns the PDF bytes; fetch with the Bearer token and save as a blob)
 * ADMIN    GET  /api/admin/stats · /api/admin/products · /api/admin/orders
 *          POST /api/admin/products   (multipart: `data` JSON + `pdf` file)   PUT /api/admin/products/:id   DELETE /api/admin/products/:id[?force=1]
 *          POST /api/admin/import     (JSON array exported from the old browser-only admin panel)
 *          POST /api/admin/orders/:id/revoke {refund?:true}
 */
"use strict";
const crypto = require("crypto");
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const multer = require("multer");
const admin = require("firebase-admin");
const Razorpay = require("razorpay");

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
const RZP_KEY = need("RAZORPAY_KEY_ID"), RZP_SECRET = need("RAZORPAY_KEY_SECRET");
const rzp = new Razorpay({ key_id: RZP_KEY, key_secret: RZP_SECRET });
const WEBHOOK_SECRET = env.RAZORPAY_WEBHOOK_SECRET || "";
const ADMINS = (env.ADMIN_EMAILS || "").split(",").map(s => s.trim().toLowerCase()).filter(Boolean);
const ORIGINS = (env.ALLOWED_ORIGINS || "").split(",").map(s => s.trim().replace(/\/$/, "")).filter(Boolean);
const MAX_PDF_MB = +env.MAX_PDF_MB || 10;
if (!ADMINS.length) console.warn("ADMIN_EMAILS is empty — admin routes will reject everyone.");
if (!ORIGINS.length) console.warn("ALLOWED_ORIGINS is empty — CORS allows any origin.");
if (!WEBHOOK_SECRET) console.warn("RAZORPAY_WEBHOOK_SECRET is empty — webhook disabled (clients must call /api/orders/verify).");

const BOARDS = ["CBSE", "ICSE", "State Board"], SUBJ = ["Mathematics", "Science", "Physics", "Chemistry", "Biology", "English", "Social Science"], LANGS = ["English", "Malayalam", "Bilingual"];
const col = n => db.collection(n);

/* ---------- helpers ---------- */
class HttpError extends Error { constructor(status, msg) { super(msg); this.status = status; } }
const bad = (m, s = 400) => new HttpError(s, m);
const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const hmac = (key, data) => crypto.createHmac("sha256", key).update(data).digest("hex");
const safeEq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };
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
const orderOut = o => ({ id: o.id, uid: o.email, email: o.email, items: (o.items || []).map(({ id, title, price }) => ({ id, title, price })), total: o.total, status: o.status, at: o.paidAt || o.createdAt, paymentId: o.paymentId || null, razorpayOrderId: o.razorpayOrderId || null });

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

/** Marks an order paid and unlocks its items. Safe to call repeatedly (checkout verify + webhook). */
async function fulfil(orderId, paymentId) {
  const ref = col("orders").doc(orderId);
  return db.runTransaction(async tx => {
    const s = await tx.get(ref);
    if (!s.exists) throw bad("Order not found", 404);
    const o = s.data();
    if (o.status !== "created") return { ...o, id: orderId };
    const now = Date.now();
    tx.update(ref, { status: "paid", paymentId: paymentId || null, paidAt: now });
    for (const i of o.items) tx.set(col("purchases").doc(`${o.uid}_${i.id}`), { uid: o.uid, email: o.email, productId: i.id, title: i.title, price: i.price, orderId, at: now });
    return { ...o, id: orderId, status: "paid", paidAt: now, paymentId: paymentId || null };
  });
}
const orderByRzp = async rid => { const q = await col("orders").where("razorpayOrderId", "==", rid).limit(1).get(); return q.empty ? null : q.docs[0]; };

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

/* ---------- app ---------- */
const app = express();
app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));
app.use(cors({ origin: (o, cb) => cb(null, !o || !ORIGINS.length || ORIGINS.includes(o)), allowedHeaders: ["Authorization", "Content-Type"], methods: ["GET", "POST", "PUT", "DELETE"], maxAge: 86400 }));
app.get("/healthz", (req, res) => res.json({ ok: true }));

// Razorpay webhook — needs the raw body, so it is mounted before any JSON parser.
app.post("/api/webhooks/razorpay", express.raw({ type: "*/*", limit: "1mb" }), wrap(async (req, res) => {
  if (!WEBHOOK_SECRET) throw bad("Webhook not configured", 503);
  const sig = req.headers["x-razorpay-signature"];
  if (!Buffer.isBuffer(req.body) || !sig || !safeEq(hmac(WEBHOOK_SECRET, req.body), sig)) throw bad("Bad signature");
  const ev = JSON.parse(req.body.toString("utf8"));
  if (ev.event === "payment.captured" || ev.event === "order.paid") {
    const pay = ev.payload?.payment?.entity, ord = ev.payload?.order?.entity;
    const rid = pay?.order_id || ord?.id;
    const od = rid && await orderByRzp(rid);
    if (od) {
      const paid = pay?.amount ?? ord?.amount_paid;
      if (paid === undefined || paid >= od.data().amount) await fulfil(od.id, pay?.id);
    }
  }
  res.json({ ok: true });
}));

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
app.get("/api/config", (req, res) => res.json({ razorpayKeyId: RZP_KEY, currency: "INR", maxPdfMb: MAX_PDF_MB }));

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

/* ---------- checkout ---------- */
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
  const total = items.reduce((a, i) => a + i.price, 0);
  const ref = col("orders").doc();
  await ref.set({ uid, email: email || "", items, total, amount: total * 100, currency: "INR", status: "created", createdAt: Date.now() });
  if (total === 0) { const o = await fulfil(ref.id, null); return res.json({ free: true, order: orderOut(o) }); }
  try {
    const ro = await rzp.orders.create({ amount: total * 100, currency: "INR", receipt: ref.id, notes: { orderId: ref.id, uid } });
    await ref.update({ razorpayOrderId: ro.id });
    res.json({ orderId: ref.id, razorpayOrderId: ro.id, amount: ro.amount, currency: ro.currency, keyId: RZP_KEY, items: items.map(i => ({ id: i.id, title: i.title })) });
  } catch (e) { console.error("Razorpay order failed:", e?.error || e); await ref.delete(); throw bad("Could not start payment, try again", 502); }
}));

app.post("/api/orders/verify", auth, wrap(async (req, res) => {
  const { razorpay_order_id: ro, razorpay_payment_id: rp, razorpay_signature: sig } = req.body || {};
  if (![ro, rp, sig].every(x => typeof x === "string" && x)) throw bad("Missing payment details");
  const od = await orderByRzp(ro);
  if (!od) throw bad("Order not found", 404);
  if (od.data().uid !== req.user.uid) throw bad("Not your order", 403);
  if (!safeEq(hmac(RZP_SECRET, `${ro}|${rp}`), sig)) throw bad("Payment verification failed");
  res.json({ ok: true, order: orderOut(await fulfil(od.id, rp)) });
}));

app.get("/api/orders/mine", auth, wrap(async (req, res) => {
  const s = await col("orders").where("uid", "==", req.user.uid).get();
  res.json(s.docs.map(d => orderOut({ id: d.id, ...d.data() })).filter(o => o.status === "paid").sort((a, b) => b.at - a.at));
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
  res.json(s.docs.map(d => orderOut({ id: d.id, ...d.data() })));
}));

app.get("/api/admin/stats", ...adm, wrap(async (req, res) => {
  const [ps, os] = await Promise.all([col("products").get(), col("orders").where("status", "==", "paid").get()]);
  const P = ps.docs.map(d => d.data()), O = os.docs.map(d => d.data()), sales = {};
  O.forEach(o => o.items.forEach(i => sales[i.id] = (sales[i.id] || 0) + 1));
  res.json({
    products: P.length, published: P.filter(p => p.status !== "draft").length, drafts: P.filter(p => p.status === "draft").length, withPdf: P.filter(p => p.pdfChunks).length,
    orders: O.length, revenue: O.reduce((a, o) => a + o.total, 0),
    bestSellers: Object.entries(sales).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([id, n]) => ({ id, title: ps.docs.find(d => d.id === id)?.data().title || id, sales: n }))
  });
}));

app.post("/api/admin/orders/:id/revoke", ...adm, wrap(async (req, res) => {
  const ref = col("orders").doc(req.params.id), s = await ref.get();
  if (!s.exists) throw bad("Not found", 404);
  const o = s.data();
  if (o.status !== "paid") throw bad("Only paid orders can be revoked", 409);
  if (req.body?.refund === true) {
    if (!o.paymentId) throw bad("No payment to refund", 409);
    try { await rzp.payments.refund(o.paymentId, { speed: "normal", notes: { orderId: ref.id } }); }
    catch (e) { console.error("Refund failed:", e?.error || e); throw bad("Razorpay refund failed — check the dashboard", 502); }
  }
  const batch = db.batch();
  batch.update(ref, { status: "refunded", revokedAt: Date.now() });
  o.items.forEach(i => batch.delete(col("purchases").doc(`${o.uid}_${i.id}`)));
  await batch.commit();
  res.json({ ok: true, refunded: req.body?.refund === true });
}));

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

app.listen(env.PORT || 10000, "0.0.0.0", () => console.log(`NOTEVAULT backend listening on ${env.PORT || 10000}`));
