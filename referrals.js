'use strict';
/**
 * NOTEVAULT Refer & Earn — backend module (Express + Firebase Admin / Firestore).
 *
 *   const referrals = require('./referrals')({ db, admin, config: {...} });
 *   app.use(referrals.router);           // adds /api/referrals/* and /api/admin/referrals
 *   referrals.start();                   // auto-tracks order status changes
 *   // inside POST /api/orders:  const pricing = await referrals.priceOrder({...})
 *
 * Rewards (all configurable, see DEFAULTS):
 *   invited friend  -> `welcomePercent`% off their first purchase
 *   every successful referral -> `percent`% coupon for the inviter
 *   milestones { 3: {freeProducts: 1}, 5: {freeProducts: 2} } -> TOTAL free products earned at that tier (tiers replace
 *   each other, they do not stack: reaching 5 tops you up from 1 to 2 in total). Each milestone is granted once.
 */
const crypto = require('crypto');

class RefError extends Error {
  constructor(message, status = 400) { super(message); this.status = status; this.expose = true; }
}
class RetryCode extends Error {}

const DEFAULTS = {
  codePrefix: 'NV',
  percent: 10,                 // inviter reward per successful referral (% off one order)
  welcomePercent: 10,          // invited user's first-purchase discount
  welcomeDays: 30,             // welcome coupon validity
  rewardDays: 180,             // reward coupon validity
  minQualifyingAmount: 1,      // INR the invitee must actually pay (after discounts) for a referral to count
  newUserMaxAgeDays: 7,        // referral code can only be applied by accounts created within this window
  requireVerifiedEmail: false, // set true to require a verified email to apply a code
  applyAttemptsPerHour: 10,
  staleReservationMinutes: 120,
  // successful-referral count -> TOTAL free products earned at that tier (must increase with the count).
  // Replaces (not merges with) any `config.milestones` you pass.
  milestones: {
    3: { freeProducts: 1 },
    5: { freeProducts: 2 },
  },
  collections: {
    profiles: 'referral_profiles', codes: 'referral_codes', referrals: 'referrals',
    coupons: 'coupons', orders: 'orders', products: 'products',
  },
  // How your existing order documents are shaped (used to track purchases)
  orderFields: { uid: 'uid', status: 'status', amount: 'total', at: 'at' },
};

const ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no 0/O/1/I
const rnd = n => Array.from({ length: n }, () => ALPHA[crypto.randomInt(ALPHA.length)]).join('');
const DAY = 86400000;

function merge(a, b) {
  const o = { ...a };
  for (const k of Object.keys(b || {})) {
    o[k] = b[k] && typeof b[k] === 'object' && !Array.isArray(b[k]) && a[k] && typeof a[k] === 'object' ? merge(a[k], b[k]) : b[k];
  }
  return o;
}

function normEmail(e) {
  e = String(e || '').trim().toLowerCase();
  const at = e.lastIndexOf('@');
  if (at < 1) return e;
  let local = e.slice(0, at), dom = e.slice(at + 1);
  local = local.split('+')[0];
  if (dom === 'gmail.com' || dom === 'googlemail.com') { local = local.replace(/\./g, ''); dom = 'gmail.com'; }
  return local + '@' + dom;
}
function maskEmail(e) {
  e = String(e || ''); const at = e.indexOf('@');
  if (at < 1) return '***';
  return e.slice(0, Math.min(2, at)) + '***' + e.slice(at);
}
const normCode = c => String(c || '').trim().toUpperCase().replace(/\s+/g, '');
const CODE_RE = /^[A-Z0-9-]{4,16}$/;

const freeLabel = n => (n === 1 ? '1 free product' : n + ' free products');

/** Fails fast on a bad reward configuration and normalises milestones. */
function validateConfig(cfg) {
  const pct = v => Number.isFinite(Number(v)) && Number(v) >= 0 && Number(v) <= 100;
  if (!pct(cfg.percent) || !pct(cfg.welcomePercent)) throw new Error('referrals: percent and welcomePercent must be between 0 and 100');
  const ms = {};
  for (const [k, d] of Object.entries(cfg.milestones || {})) {
    const at = Number(k), n = Number(d && d.freeProducts);
    if (!Number.isInteger(at) || at < 1 || !Number.isInteger(n) || n < 1) {
      throw new Error('referrals: milestone "' + k + '" needs a whole-number referral count >= 1 and freeProducts >= 1');
    }
    ms[at] = { freeProducts: n, label: (d && d.label) || freeLabel(n) };
  }
  let prev = 0;
  for (const at of Object.keys(ms).map(Number).sort((a, b) => a - b)) {
    if (ms[at].freeProducts <= prev) throw new Error('referrals: milestone totals must increase with the referral count (tier ' + at + ' has ' + ms[at].freeProducts + ', previous tier has ' + prev + ')');
    prev = ms[at].freeProducts;
  }
  cfg.milestones = ms;
}

module.exports = function createReferrals(opts) {
  const { db, admin } = opts;
  if (!db) throw new Error('referrals: `db` (Firestore) is required');
  const userCfg = opts.config || {};
  const cfg = merge(DEFAULTS, { ...userCfg, milestones: undefined });
  cfg.milestones = userCfg.milestones || DEFAULTS.milestones;
  validateConfig(cfg);
  const C = cfg.collections, OF = cfg.orderFields;
  const now = () => Date.now();
  const log = opts.logger || console;

  const orderUid = o => o && (o[OF.uid] || o.uid || o.userId || o.userUid || null);
  const orderAmount = o => { const v = Number(o && (o[OF.amount] ?? o.total ?? o.amount ?? o.totalAmount)); return Number.isFinite(v) ? v : 0; };
  const orderAt = o => Number(o && (o[OF.at] ?? o.at ?? o.createdAt)) || 0;

  /* ---------------- helpers ---------------- */
  const hits = new Map();
  function limit(key, max, windowMs) {
    const t = now(), arr = (hits.get(key) || []).filter(x => t - x < windowMs);
    if (arr.length >= max) { hits.set(key, arr); return false; }
    arr.push(t); hits.set(key, arr);
    if (hits.size > 5000) for (const [k, v] of hits) if (!v.length || t - v[v.length - 1] > windowMs) hits.delete(k);
    return true;
  }

  async function userCreatedAt(uid) {
    if (opts.getUserMeta) return opts.getUserMeta(uid);
    const u = await admin.auth().getUser(uid);
    return Date.parse(u.metadata.creationTime) || 0;
  }

  /* ---------------- profiles & codes ---------------- */
  async function ensureProfile(uid, email) {
    const ref = db.collection(C.profiles).doc(uid);
    const snap = await ref.get();
    if (snap.exists) return snap.data();
    for (let i = 0; i < 12; i++) {
      const code = cfg.codePrefix + rnd(6);
      const codeRef = db.collection(C.codes).doc(code);
      try {
        return await db.runTransaction(async tx => {
          const [p, c] = await Promise.all([tx.get(ref), tx.get(codeRef)]);
          if (p.exists) return p.data();
          if (c.exists) throw new RetryCode();
          const prof = {
            uid, email: String(email || '').toLowerCase(), emailNorm: normEmail(email), code,
            createdAt: now(), registered: 0, successful: 0, milestones: {}, referredBy: null,
          };
          tx.set(codeRef, { uid, code, createdAt: now() });
          tx.set(ref, prof);
          return prof;
        });
      } catch (e) { if (e instanceof RetryCode) continue; throw e; }
    }
    throw new RefError('Could not create your referral code, please retry', 500);
  }

  /* ---------------- coupons ---------------- */
  // Coupons issued by the first version of this module used free_subject / free_any: treat them as "1 free product".
  const freeCountOf = c => (c.type === 'free_products' ? Number(c.freeCount) || 0 : (c.type === 'free_subject' || c.type === 'free_any') ? 1 : 0);
  // Free-product coupons are credits: "2 free products" can be spent over two separate orders (the site sells one note per order).
  const freeLeftOf = c => (c.type === 'free_products' ? Number(c.freeRemaining ?? c.freeCount) || 0 : freeCountOf(c));
  const couponLabel = c => c.label || (c.type === 'percent' ? c.percent + '% off' : freeLabel(freeCountOf(c) || 1));

  // Tiers replace each other: the coupon issued at a tier is only the top-up from the previous tier's total.
  const tiers = Object.keys(cfg.milestones).map(Number).sort((a, b) => a - b);
  const tierGrant = k => {
    const i = tiers.indexOf(Number(k));
    return cfg.milestones[k].freeProducts - (i > 0 ? cfg.milestones[tiers[i - 1]].freeProducts : 0);
  };

  function buildCoupon({ code, uid, type, source, label, percent, freeCount, referralId, days }) {
    const t = now();
    return {
      code, uid, type, source, label, percent: percent || 0, freeCount: freeCount || 0, freeRemaining: freeCount || 0,
      referralId: referralId || null, status: 'active', reservedOrderId: null,
      createdAt: t, expiresAt: t + days * DAY,
    };
  }
  const freshCode = prefix => prefix + '-' + rnd(6);

  /** -> { discount, units }  (units = how many free products this order consumes from a free-product coupon) */
  function applyCoupon(c, items) {
    const prices = items.map(i => i.price);
    const subtotal = prices.reduce((a, b) => a + b, 0);
    if (!items.length || subtotal <= 0) return { discount: 0, units: 0 };
    if (c.type === 'percent') return { discount: Math.min(subtotal, Math.round(subtotal * c.percent / 100)), units: 0 };
    const free = prices.filter(x => x > 0).sort((a, b) => b - a).slice(0, freeLeftOf(c)); // the most expensive products are the free ones
    return { discount: free.reduce((a, b) => a + b, 0), units: free.length };
  }
  const computeDiscount = (c, items) => applyCoupon(c, items).discount;

  function normItems(items) {
    if (!Array.isArray(items) || !items.length) throw new RefError('No items to price');
    return items.map(i => {
      const price = Number(i && i.price);
      if (!i || !i.id || !Number.isFinite(price) || price < 0) throw new RefError('Invalid item');
      return { id: String(i.id), price };
    });
  }

  async function couponUsable(uid, c, orderId) {
    if (!c || c.uid !== uid) return 'Coupon not found';
    if (!(c.status === 'active' || (c.status === 'reserved' && orderId && c.reservedOrderId === orderId))) {
      return c.status === 'used' ? 'This coupon has already been used' : 'This coupon is not available';
    }
    if (c.expiresAt && c.expiresAt < now()) return 'This coupon has expired';
    if (c.source === 'welcome') {
      const r = await db.collection(C.referrals).doc(uid).get();
      if (!r.exists || r.data().status !== 'registered') return 'The welcome discount is only valid on your first purchase';
    }
    return null;
  }

  async function activeCoupons(uid) {
    const q = await db.collection(C.coupons).where('uid', '==', uid).where('status', '==', 'active').get();
    return q.docs.map(d => d.data()).filter(c => !c.expiresAt || c.expiresAt >= now());
  }

  /** Price an order. Optionally reserves the coupon for `orderId` atomically. */
  async function priceOrder({ uid, orderId, items, coupon, reserve = true }) {
    const list = normItems(items);
    const subtotal = list.reduce((a, i) => a + i.price, 0);
    const code = normCode(coupon);
    if (!code) return { subtotal, discount: 0, total: subtotal, couponCode: null, couponType: null, free: subtotal === 0 };
    await releaseAbandoned(uid);
    const ref = db.collection(C.coupons).doc(code);
    const snap = await ref.get();
    const c = snap.exists ? snap.data() : null;
    const bad = await couponUsable(uid, c, orderId);
    if (bad) throw new RefError(bad);
    const { discount, units } = applyCoupon(c, list);
    if (discount <= 0) throw new RefError('This coupon does not apply to your cart');
    if (reserve) {
      if (!orderId) throw new RefError('orderId is required to reserve a coupon', 500);
      await db.runTransaction(async tx => {
        const s = await tx.get(ref);
        const d = s.exists ? s.data() : null;
        if (!d || d.uid !== uid) throw new RefError('Coupon not found');
        if (d.status === 'reserved' && d.reservedOrderId === orderId) return;
        if (d.status !== 'active') throw new RefError('This coupon was just used on another order');
        if (d.expiresAt && d.expiresAt < now()) throw new RefError('This coupon has expired');
        tx.update(ref, { status: 'reserved', reservedOrderId: orderId, reservedAt: now(), reservedDiscount: discount, reservedUnits: units });
      });
    }
    const total = Math.max(0, subtotal - discount);
    return { subtotal, discount, total, couponCode: code, couponType: c.type, freeUnits: units, free: total === 0 };
  }

  async function quote({ uid, items }) {
    const list = normItems(items);
    const subtotal = list.reduce((a, i) => a + i.price, 0);
    const out = [];
    if (subtotal > 0) {
      await releaseAbandoned(uid);
      for (const c of await activeCoupons(uid)) {
        if (await couponUsable(uid, c, null)) continue;
        const discount = computeDiscount(c, list);
        if (discount > 0) out.push({ code: c.code, type: c.type, source: c.source, label: couponLabel(c), percent: c.percent, freeCount: freeCountOf(c), freeRemaining: freeLeftOf(c), discount, total: subtotal - discount, expiresAt: c.expiresAt });
      }
    }
    out.sort((a, b) => b.discount - a.discount);
    return { subtotal, options: out, best: out[0] ? out[0].code : null };
  }

  async function setCouponsForOrder(orderId, from, mutate) {
    const q = await db.collection(C.coupons).where('reservedOrderId', '==', orderId).get();
    for (const d of q.docs) {
      await db.runTransaction(async tx => {
        const s = await tx.get(d.ref);
        if (!s.exists) return;
        const c = s.data();
        if (c.status !== from || c.reservedOrderId !== orderId) return;
        tx.update(d.ref, mutate(c));
      });
    }
  }
  /** Spends a coupon on a paid order. Percent coupons are single-use; free-product coupons stay active while credits remain. */
  function spend(c, orderId, units) {
    const clear = { reservedOrderId: null, reservedAt: null, reservedDiscount: null, reservedUnits: null };
    if (c.type !== 'free_products') return { status: 'used', usedAt: now(), usedOrderId: orderId, ...clear };
    const left = Math.max(0, freeLeftOf(c) - Math.max(1, units || 1));
    return { freeRemaining: left, status: left > 0 ? 'active' : 'used', lastOrderId: orderId, usedAt: now(), ...(left > 0 ? {} : { usedOrderId: orderId }), ...clear };
  }

  /** Called when an order is paid. `order.coupon` also covers an order that was rejected (coupon released) and then approved. */
  async function markCouponUsed(orderId, order) {
    const q = await db.collection(C.coupons).where('reservedOrderId', '==', orderId).get();
    for (const d of q.docs) {
      await db.runTransaction(async tx => {
        const s = await tx.get(d.ref);
        if (!s.exists) return;
        const c = s.data();
        if (c.status !== 'reserved' || c.reservedOrderId !== orderId) return;
        tx.update(d.ref, spend(c, orderId, c.reservedUnits));
      });
    }
    const code = normCode(order && order.coupon);
    if (!code) return;
    const ref = db.collection(C.coupons).doc(code);
    await db.runTransaction(async tx => {
      const s = await tx.get(ref);
      if (!s.exists) return;
      const c = s.data();
      if (c.uid === orderUid(order) && c.status === 'active' && c.lastOrderId !== orderId && c.usedOrderId !== orderId) tx.update(ref, spend(c, orderId, order.freeUnits));
    });
  }
  const releaseCoupons = orderId => setCouponsForOrder(orderId, 'reserved', c => (
    c.expiresAt && c.expiresAt < now() ? { status: 'expired' } : { status: 'active', reservedOrderId: null, reservedAt: null, reservedDiscount: null, reservedUnits: null }));

  /** Frees coupons held by this user's orders that were never submitted for payment (user closed the pay screen). */
  async function releaseAbandoned(uid) {
    const q = await db.collection(C.coupons).where('uid', '==', uid).where('status', '==', 'reserved').get();
    for (const d of q.docs) {
      const c = d.data();
      if (!c.reservedOrderId) continue;
      const o = await db.collection(C.orders).doc(c.reservedOrderId).get();
      const abandoned = o.exists ? o.data()[OF.status] === 'created' : now() - (c.reservedAt || 0) > 120000;
      if (abandoned) await releaseCoupons(c.reservedOrderId);
    }
  }

  /**
   * Call before an order moves to "pending" (UTR submitted): the order's coupon must still belong to it.
   * Re-reserves it if it was released meanwhile; throws a RefError if another order took it.
   */
  async function confirmOrderCoupon(orderId, order) {
    const code = normCode(order && order.coupon);
    if (!code) return;
    const ref = db.collection(C.coupons).doc(code);
    await db.runTransaction(async tx => {
      const s = await tx.get(ref), c = s.exists ? s.data() : null;
      const gone = new RefError('The reward on this order is no longer available. Please place a new order.', 409);
      if (!c || c.uid !== orderUid(order)) throw gone;
      if (c.status === 'reserved' && c.reservedOrderId === orderId) return;
      const units = Number(order.freeUnits) || 0;
      if (c.status === 'active' && !(c.expiresAt && c.expiresAt < now()) && (c.type !== 'free_products' || freeLeftOf(c) >= units)) {
        tx.update(ref, { status: 'reserved', reservedOrderId: orderId, reservedAt: now(), reservedUnits: units });
        return;
      }
      throw gone;
    });
  }

  /* ---------------- applying a referral code ---------------- */
  async function eligibility(uid) {
    const ex = await db.collection(C.referrals).doc(uid).get();
    if (ex.exists) return 'You have already used a referral code';
    const paid = await db.collection(C.orders).where(OF.uid, '==', uid).get();
    if (paid.docs.some(d => d.data()[OF.status] === 'paid' && orderAmount(d.data()) > 0)) return 'Referral codes are for new customers only';
    const created = await userCreatedAt(uid);
    if (created && now() - created > cfg.newUserMaxAgeDays * DAY) return 'Referral codes can only be added within ' + cfg.newUserMaxAgeDays + ' days of creating your account';
    return null;
  }

  async function applyCode({ uid, email, verified, code }) {
    if (!limit('apply:' + uid, cfg.applyAttemptsPerHour, 3600000)) throw new RefError('Too many attempts. Please try again later.', 429);
    code = normCode(code);
    if (!CODE_RE.test(code)) throw new RefError('That referral code is not valid');
    if (cfg.requireVerifiedEmail && !verified) throw new RefError('Please verify your email before using a referral code');
    const owner = await db.collection(C.codes).doc(code).get();
    if (!owner.exists) throw new RefError('That referral code is not valid');
    const inviterUid = owner.data().uid;
    if (inviterUid === uid) throw new RefError('You cannot use your own referral code');
    const [inviter, me] = await Promise.all([db.collection(C.profiles).doc(inviterUid).get(), ensureProfile(uid, email)]);
    if (!inviter.exists) throw new RefError('That referral code is not valid');
    const inv = inviter.data();
    if (inv.emailNorm && inv.emailNorm === me.emailNorm) throw new RefError('You cannot use your own referral code');
    if (inv.referredBy && inv.referredBy.uid === uid) throw new RefError('This referral code cannot be used');
    const bad = await eligibility(uid);
    if (bad) throw new RefError(bad);

    const welcomeCode = freshCode('NVW');
    await db.runTransaction(async tx => {
      const refRef = db.collection(C.referrals).doc(uid);
      const meRef = db.collection(C.profiles).doc(uid), invRef = db.collection(C.profiles).doc(inviterUid);
      const wRef = db.collection(C.coupons).doc(welcomeCode);
      const [r, m, i, w] = await Promise.all([tx.get(refRef), tx.get(meRef), tx.get(invRef), tx.get(wRef)]);
      if (r.exists) throw new RefError('You have already used a referral code');
      if (w.exists) throw new RefError('Please try again');
      tx.set(refRef, {
        inviteeUid: uid, inviteeEmail: me.email, inviteeEmailMasked: maskEmail(me.email),
        inviterUid, code, status: 'registered', createdAt: now(), purchasedAt: null, orderId: null,
      });
      tx.update(meRef, { referredBy: { uid: inviterUid, code, at: now() } });
      tx.update(invRef, { registered: (i.data().registered || 0) + 1 });
      if (cfg.welcomePercent > 0) tx.set(wRef, buildCoupon({
        code: welcomeCode, uid, type: 'percent', source: 'welcome', label: cfg.welcomePercent + '% welcome discount',
        percent: cfg.welcomePercent, referralId: uid, days: cfg.welcomeDays,
      }));
    });
    return { ok: true, welcomeCoupon: cfg.welcomePercent > 0 ? welcomeCode : null, percent: cfg.welcomePercent };
  }

  /* ---------------- purchase tracking ---------------- */
  async function qualifyOrder(orderId, order) {
    const inviteeUid = orderUid(order);
    if (!inviteeUid || !(orderAmount(order) >= cfg.minQualifyingAmount)) return null;
    const refRef = db.collection(C.referrals).doc(inviteeUid);
    const pre = await refRef.get();
    if (!pre.exists || pre.data().status !== 'registered') return null;
    const inviterUid = pre.data().inviterUid;
    const profRef = db.collection(C.profiles).doc(inviterUid);
    const welcomeQ = await db.collection(C.coupons).where('uid', '==', inviteeUid).where('source', '==', 'welcome').where('status', '==', 'active').get();

    for (let attempt = 0; attempt < 5; attempt++) {
      const rewardCode = freshCode('NVR');
      const msCodes = {};
      for (const k of Object.keys(cfg.milestones)) msCodes[k] = freshCode('NVG');
      try {
        return await db.runTransaction(async tx => {
          const rewardRef = db.collection(C.coupons).doc(rewardCode);
          const msRefs = Object.fromEntries(Object.entries(msCodes).map(([k, c]) => [k, db.collection(C.coupons).doc(c)]));
          const [rs, ps, rw, ...rest] = await Promise.all([
            tx.get(refRef), tx.get(profRef), tx.get(rewardRef),
            ...Object.values(msRefs).map(r => tx.get(r)),
            ...welcomeQ.docs.map(d => tx.get(d.ref)),
          ]);
          const nMs = Object.keys(msRefs).length;
          const msSnaps = rest.slice(0, nMs), wSnaps = rest.slice(nMs);
          if (!rs.exists || rs.data().status !== 'registered') return null;
          if (rw.exists || msSnaps.some(s => s.exists)) throw new RetryCode();
          if (!ps.exists) return null;
          const prof = ps.data(), n = (prof.successful || 0) + 1, granted = [];
          tx.update(refRef, { status: 'purchased', purchasedAt: now(), orderId, amount: orderAmount(order) });
          if (cfg.percent > 0) {
            tx.set(rewardRef, buildCoupon({
              code: rewardCode, uid: inviterUid, type: 'percent', source: 'referral_reward',
              label: cfg.percent + '% referral reward', percent: cfg.percent, referralId: inviteeUid, days: cfg.rewardDays,
            }));
            granted.push(rewardCode);
          }
          const ms = { ...(prof.milestones || {}) };
          for (const [k, def] of Object.entries(cfg.milestones)) {
            if (n >= Number(k) && !ms[k]) {
              tx.set(msRefs[k], buildCoupon({
                code: msCodes[k], uid: inviterUid, type: 'free_products', source: 'milestone_' + k,
                label: def.label + ' (' + k + ' referrals)', freeCount: tierGrant(k), referralId: inviteeUid, days: cfg.rewardDays,
              }));
              ms[k] = msCodes[k]; granted.push(msCodes[k]);
            }
          }
          tx.update(profRef, { successful: n, milestones: ms });
          wSnaps.forEach(s => { if (s.exists && s.data().status === 'active') tx.update(s.ref, { status: 'void', voidReason: 'first_purchase_made' }); });
          return { granted, successful: n };
        });
      } catch (e) { if (e instanceof RetryCode) continue; throw e; }
    }
    throw new Error('qualifyOrder: could not allocate coupon codes');
  }

  async function reverseOrder(orderId) {
    const q = await db.collection(C.referrals).where('orderId', '==', orderId).get();
    for (const rd of q.docs) {
      const r0 = rd.data();
      if (r0.status !== 'purchased') continue;
      const profRef = db.collection(C.profiles).doc(r0.inviterUid);
      const rc = await db.collection(C.coupons).where('referralId', '==', r0.inviteeUid).where('source', '==', 'referral_reward').get();
      await db.runTransaction(async tx => {
        const [rs, ps] = await Promise.all([tx.get(rd.ref), tx.get(profRef)]);
        if (!rs.exists || rs.data().status !== 'purchased' || !ps.exists) return;
        const prof = ps.data(), n = Math.max(0, (prof.successful || 0) - 1), ms = { ...(prof.milestones || {}) };
        const msRefs = Object.entries(ms).map(([k, code]) => [k, db.collection(C.coupons).doc(code)]);
        const rcSnaps = await Promise.all(rc.docs.map(d => tx.get(d.ref)));
        const msSnaps = await Promise.all(msRefs.map(([, r]) => tx.get(r)));
        tx.update(rd.ref, { status: 'reversed', reversedAt: now() });
        rcSnaps.forEach(s => { if (s.exists && (s.data().status === 'active' || s.data().status === 'reserved')) tx.update(s.ref, { status: 'void', voidReason: 'order_reversed' }); });
        msRefs.forEach(([k], idx) => {
          const s = msSnaps[idx];
          if (n < Number(k) && s.exists && s.data().status === 'active') {
            const c = s.data(), untouched = freeLeftOf(c) === freeCountOf(c);
            tx.update(s.ref, { status: 'void', voidReason: 'milestone_lost' });
            if (untouched) delete ms[k]; // partly spent rewards stay "claimed" so they can never be earned twice
          }
        });
        tx.update(profRef, { successful: n, milestones: ms });
      });
    }
  }

  async function reconcileOrder(orderId, order) {
    if (!order) return;
    const st = order[OF.status];
    if (st === 'paid') { await markCouponUsed(orderId, order); await qualifyOrder(orderId, order); }
    else if (st === 'rejected' || st === 'revoked') { await releaseCoupons(orderId); await reverseOrder(orderId); }
  }

  /** Safety net: fixes anything missed while the server was down. Idempotent. */
  async function reconcileAll() {
    const res = await db.collection(C.coupons).where('status', '==', 'reserved').get();
    for (const d of res.docs) {
      const c = d.data(), o = await db.collection(C.orders).doc(c.reservedOrderId).get();
      if (o.exists) await reconcileOrder(o.id, o.data());
      else if (now() - (c.reservedAt || 0) > cfg.staleReservationMinutes * 60000) await releaseCoupons(c.reservedOrderId);
    }
    const reg = await db.collection(C.referrals).where('status', '==', 'registered').get();
    for (const d of reg.docs) {
      const os = await db.collection(C.orders).where(OF.uid, '==', d.id).get();
      const paid = os.docs.filter(x => x.data()[OF.status] === 'paid').sort((a, b) => orderAt(a.data()) - orderAt(b.data()));
      for (const o of paid) if ((await qualifyOrder(o.id, o.data()))) break;
    }
    const pur = await db.collection(C.referrals).where('status', '==', 'purchased').get();
    for (const d of pur.docs) {
      const o = await db.collection(C.orders).doc(d.data().orderId).get();
      if (o.exists && ['rejected', 'revoked'].includes(o.data()[OF.status])) await reverseOrder(o.id);
    }
  }

  let chain = Promise.resolve(), timer = null, unsub = null, stopped = false;
  function start() {
    stopped = false;
    const run = () => reconcileAll().catch(e => log.error('[referrals] reconcileAll failed', e && e.message));
    run();
    timer = setInterval(run, 10 * 60000); if (timer.unref) timer.unref();
    const listen = () => {
      let first = true;
      try {
        unsub = db.collection(C.orders).onSnapshot(snap => {
          if (first) { first = false; return; } // baseline; reconcileAll covers existing state
          snap.docChanges().forEach(ch => {
            if (ch.type === 'removed') return;
            const id = ch.doc.id, data = ch.doc.data();
            chain = chain.then(() => reconcileOrder(id, data)).catch(e => log.error('[referrals] reconcile failed', id, e && e.message));
          });
        }, err => { log.error('[referrals] order listener error', err && err.message); if (!stopped) setTimeout(listen, 30000).unref?.(); });
      } catch (e) { log.error('[referrals] cannot attach order listener', e && e.message); }
    };
    listen();
  }
  function stop() { stopped = true; if (timer) clearInterval(timer); if (unsub) unsub(); }

  /* ---------------- dashboard payload ---------------- */
  const publicConfig = () => ({
    percent: cfg.percent, welcomePercent: cfg.welcomePercent, rewardDays: cfg.rewardDays, welcomeDays: cfg.welcomeDays,
    milestones: Object.keys(cfg.milestones).map(Number).sort((a, b) => a - b).map(at => ({ at, freeProducts: cfg.milestones[at].freeProducts, label: cfg.milestones[at].label })),
  });
  async function getMe({ uid, email }) {
    const prof = await ensureProfile(uid, email);
    const [rq, cq] = await Promise.all([
      db.collection(C.referrals).where('inviterUid', '==', uid).get(),
      db.collection(C.coupons).where('uid', '==', uid).get(),
    ]);
    const refs = rq.docs.map(d => d.data()).sort((a, b) => b.createdAt - a.createdAt);
    const t = now();
    const coupons = cq.docs.map(d => d.data()).map(c => ({
      code: c.code, type: c.type, source: c.source, label: couponLabel(c), percent: c.percent, freeCount: freeCountOf(c), freeRemaining: freeLeftOf(c),
      status: (c.status === 'active' && c.expiresAt && c.expiresAt < t) ? 'expired' : c.status,
      createdAt: c.createdAt, expiresAt: c.expiresAt,
    })).sort((a, b) => b.createdAt - a.createdAt);
    const successful = prof.successful || 0;
    const thresholds = Object.keys(cfg.milestones).map(Number).sort((a, b) => a - b);
    const milestones = thresholds.map(at => ({
      at, freeProducts: cfg.milestones[at].freeProducts, label: cfg.milestones[at].label,
      reached: successful >= at, couponCode: (prof.milestones || {})[at] || null,
    }));
    const next = thresholds.find(x => x > successful);
    let canApply = false, applyReason = null;
    if (!prof.referredBy) { applyReason = await eligibility(uid).catch(() => 'Not available'); canApply = !applyReason; }
    else applyReason = 'You have already used a referral code';
    return {
      code: prof.code,
      stats: {
        invited: refs.length,
        successful,
        pending: refs.filter(r => r.status === 'registered').length,
        couponsAvailable: coupons.filter(c => c.status === 'active').length,
        couponsUsed: coupons.filter(c => c.status === 'used').length,
      },
      nextMilestone: next ? { at: next, remaining: next - successful } : null,
      milestones,
      referredBy: !!prof.referredBy,
      canApply, applyReason: canApply ? null : applyReason,
      referrals: refs.slice(0, 100).map(r => ({ who: r.inviteeEmailMasked, status: r.status, at: r.createdAt, purchasedAt: r.purchasedAt })),
      coupons,
      config: publicConfig(),
    };
  }

  /* ---------------- HTTP ---------------- */
  const express = require('express');
  const router = express.Router();
  const json = express.json({ limit: '20kb' });

  async function defaultAuth(req, res, next) {
    const m = /^Bearer (.+)$/.exec(req.headers.authorization || '');
    if (!m) return res.status(401).json({ error: 'Sign in required' });
    try {
      const d = await admin.auth().verifyIdToken(m[1]);
      req.refUser = { uid: d.uid, email: String(d.email || '').toLowerCase(), verified: !!d.email_verified };
      next();
    } catch { res.status(401).json({ error: 'Session expired. Please sign in again.' }); }
  }
  const auth = opts.requireAuth ? (req, res, next) => opts.requireAuth(req, res, err => {
    if (err) return next(err);
    const u = req.user || req.auth || {};
    req.refUser = { uid: u.uid || u.id || u.localId, email: String(u.email || '').toLowerCase(), verified: !!(u.email_verified ?? u.emailVerified) };
    if (!req.refUser.uid) return res.status(401).json({ error: 'Sign in required' });
    next();
  }) : defaultAuth;
  const adminOnly = (req, res, next) => auth(req, res, async err => {
    if (err) return next(err);
    const ok = opts.isAdmin ? await opts.isAdmin(req) : String(process.env.ADMIN_EMAILS || '').toLowerCase().split(',').map(s => s.trim()).filter(Boolean).includes(req.refUser.email);
    ok ? next() : res.status(403).json({ error: 'Admins only' });
  });
  const h = fn => (req, res) => fn(req, res).catch(e => {
    if (e instanceof RefError) return res.status(e.status).json({ error: e.message });
    log.error('[referrals]', e); res.status(500).json({ error: 'Something went wrong. Please try again.' });
  });

  async function getItems(ids) {
    if (opts.getItems) return opts.getItems(ids);
    const out = [];
    for (const id of ids) {
      const s = await db.collection(C.products).doc(String(id)).get();
      if (!s.exists || s.data().status === 'draft') throw new RefError('Note not found');
      const d = s.data(); out.push({ id: s.id, price: Number(d.price) });
    }
    return out;
  }

  router.get('/api/referrals/validate', h(async (req, res) => {
    if (!limit('val:' + req.ip, 30, 60000)) throw new RefError('Too many requests', 429);
    const code = normCode(req.query.code);
    if (!CODE_RE.test(code)) return res.json({ valid: false });
    const s = await db.collection(C.codes).doc(code).get();
    res.json({ valid: s.exists, percent: cfg.welcomePercent });
  }));
  router.get('/api/referrals/config', (req, res) => res.json(publicConfig()));
  router.get('/api/referrals/me', auth, h(async (req, res) => res.json(await getMe(req.refUser))));
  router.post('/api/referrals/apply', auth, json, h(async (req, res) => {
    res.json(await applyCode({ ...req.refUser, code: req.body && req.body.code }));
  }));
  router.post('/api/referrals/quote', auth, json, h(async (req, res) => {
    const ids = req.body && req.body.productIds;
    if (!Array.isArray(ids) || !ids.length || ids.length > 20) throw new RefError('Invalid request');
    res.json(await quote({ uid: req.refUser.uid, items: await getItems(ids) }));
  }));
  router.get('/api/admin/referrals', adminOnly, h(async (req, res) => {
    const q = await db.collection(C.referrals).get();
    const rows = q.docs.map(d => d.data()).sort((a, b) => b.createdAt - a.createdAt).slice(0, 500);
    const emails = {};
    for (const r of rows) if (!emails[r.inviterUid]) { const p = await db.collection(C.profiles).doc(r.inviterUid).get(); emails[r.inviterUid] = p.exists ? p.data().email : ''; }
    res.json({
      totals: ['registered', 'purchased', 'reversed'].reduce((o, k) => (o[k] = rows.filter(r => r.status === k).length, o), {}),
      referrals: rows.map(r => ({ inviter: emails[r.inviterUid], invitee: r.inviteeEmail, code: r.code, status: r.status, at: r.createdAt, purchasedAt: r.purchasedAt, orderId: r.orderId })),
    });
  }));

  return {
    router, start, stop, priceOrder, quote, applyCode, getMe, ensureProfile,
    reconcileOrder, reconcileAll, releaseCoupons, markCouponUsed, confirmOrderCoupon, releaseAbandoned, RefError,
    _cfg: cfg,
  };
};
module.exports.RefError = RefError;
module.exports.normEmail = normEmail;
