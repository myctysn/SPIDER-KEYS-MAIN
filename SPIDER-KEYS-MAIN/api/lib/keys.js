'use strict';

const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

function block() {
  let out = '';
  for (let i = 0; i < 5; i++) out += ALPHABET[Math.floor(Math.random() * ALPHABET.length)];
  return out;
}

const PREFIX = { normal: 'SPIDER-N', mod_menu: 'SPIDER-MM', vortex: 'SPIDER-VX' };

function makeKey(type = 'normal') {
  const prefix = PREFIX[type] || PREFIX.normal;
  return `${prefix}-${block()}-${block()}`;
}

const LEGACY_FULL = /^[A-Z0-9]{5}(?:-[A-Z0-9]{5}){3}$/;
const SPIDER = /^SPIDER-(?:N|MM|VX)-[A-Z0-9]{5}-[A-Z0-9]{5}$/;

function looksLikeKey(key) {
  const value = String(key || '').trim();
  if (!value) return false;
  return (
    SPIDER.test(value) ||
    LEGACY_FULL.test(value) ||
    value.startsWith('H4X_MODZ_NORMAL_') ||
    value.startsWith('H4X_MODZ_') ||
    value.startsWith('vortexexclusive_') ||
    value.startsWith('AURA_')
  );
}

function currentMonth() {
  const now = new Date();
  return `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, '0')}`;
}

function num(value, fallback = 0) {
  const parsed = parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function resellerProfile(slug, record) {
  const r = record || {};
  const limits = r.limits || {};
  const month = currentMonth();
  return {
    username: slug,
    name: r.name || slug,
    credits: num(r.credits),
    max_credits: num(r.max_credits),
    monthly_limit: num(r.monthly_limit),
    month,
    month_count: r.month === month ? num(r.month_count) : 0,
    limits: {
      normal: num(limits.normal),
      mod_menu: num(limits.mod_menu),
      vortex: num(limits.vortex),
    },
    allow_normal: r.allow_normal !== false,
    allow_mod_menu: r.allow_mod_menu === true,
    allow_vortex: r.allow_vortex === true,
    active: r.active !== false,
    created_at: r.created_at || null,
    last_login: r.last_login || null,
    total_keys_generated: num(r.total_keys_generated),
  };
}

/** Public shape of a reseller record: never exposes password material. */
function publicReseller(slug, record) {
  return {
    ...resellerProfile(slug, record),
    session_version: num(record?.session_version, 1),
  };
}

module.exports = {
  currentMonth,
  looksLikeKey,
  makeKey,
  num,
  publicReseller,
  resellerProfile,
};
