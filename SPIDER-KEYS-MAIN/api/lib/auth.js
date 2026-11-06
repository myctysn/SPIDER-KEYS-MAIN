'use strict';

const crypto = require('crypto');

const ADMIN_TTL = 12 * 60 * 60 * 1000;
const RESELLER_TTL = 24 * 60 * 60 * 1000;
const MAX_ATTEMPTS = 8;
const WINDOW_MS = 10 * 60 * 1000;

const hits = new Map();

function secret() {
  return process.env.SESSION_SECRET || process.env.ADMIN_TOKEN || '';
}

function adminPassword() {
  return process.env.ADMIN_PASSWORD || process.env.ADMIN_TOKEN || '';
}

function configured() {
  return Boolean(secret() && adminPassword());
}

function bearer(req) {
  const header = req.headers.authorization || req.headers.Authorization || '';
  if (typeof header !== 'string' || !header.startsWith('Bearer ')) return '';
  return header.slice(7).trim();
}

function safeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return `scrypt$${salt}$${hash}`;
}

/** Accepts scrypt hashes and legacy plaintext records. */
function verifyPassword(password, record) {
  if (!record) return { ok: false, legacy: false };
  if (typeof record.password_hash === 'string') {
    const parts = record.password_hash.split('$');
    if (parts.length !== 3 || parts[0] !== 'scrypt') return { ok: false, legacy: false };
    const calc = crypto.scryptSync(String(password), parts[1], 64);
    const known = Buffer.from(parts[2], 'hex');
    const ok = known.length === calc.length && crypto.timingSafeEqual(known, calc);
    return { ok, legacy: false };
  }
  if (typeof record.password === 'string' && record.password.length > 0) {
    return { ok: safeEqual(password, record.password), legacy: true };
  }
  return { ok: false, legacy: false };
}

function signToken(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', secret()).update(body).digest('base64url');
  return `${body}.${sig}`;
}

function verifyToken(token) {
  if (typeof token !== 'string' || token.split('.').length !== 2) return null;
  const [body, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', secret()).update(body).digest('base64url');
  const given = Buffer.from(sig);
  const want = Buffer.from(expected);
  if (given.length !== want.length || !crypto.timingSafeEqual(given, want)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (!payload || typeof payload.exp !== 'number' || Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

function issue(role, sub, extra, ttl) {
  const exp = Date.now() + ttl;
  const token = signToken({ role, sub, ...extra, iat: Date.now(), exp });
  return { token, expires_at: new Date(exp).toISOString() };
}

function recentHits(key, windowMs) {
  const now = Date.now();
  return (hits.get(key) || []).filter((t) => now - t < windowMs);
}

function isRateLimited(key, max = MAX_ATTEMPTS, windowMs = WINDOW_MS) {
  return recentHits(key, windowMs).length >= max;
}

function recordFailure(key) {
  const recent = recentHits(key, WINDOW_MS);
  recent.push(Date.now());
  hits.set(key, recent);
  if (hits.size > 800) hits.clear();
}

function clearFailures(key) {
  hits.delete(key);
}

function clientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  const ip = Array.isArray(forwarded) ? forwarded[0] : String(forwarded || '').split(',')[0];
  return (ip || req.socket?.remoteAddress || 'unknown').trim();
}

module.exports = {
  ADMIN_TTL,
  RESELLER_TTL,
  adminPassword,
  bearer,
  clientIp,
  configured,
  clearFailures,
  hashPassword,
  isRateLimited,
  issue,
  recordFailure,
  safeEqual,
  verifyPassword,
  verifyToken,
};
