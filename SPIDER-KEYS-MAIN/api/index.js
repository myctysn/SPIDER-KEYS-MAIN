'use strict';

const { read, mutate, FILES } = require('./lib/store');
const auth = require('./lib/auth');
const { looksLikeKey, makeKey, num, resellerProfile, publicReseller, currentMonth } = require('./lib/keys');

const ACTIVITY_LIMIT = 400;

function ok(res, data = {}) {
  res.json({ success: true, ...data });
}

function fail(res, message, status = 200, code) {
  res.status(status).json({ success: false, message, ...(code ? { code } : {}) });
}

async function logActivity(actor, action, detail) {
  try {
    await mutate(
      FILES.activity,
      (data) => {
        if (!Array.isArray(data.entries)) data.entries = [];
        data.entries.unshift({ ts: new Date().toISOString(), actor, action, detail: detail || '' });
        if (data.entries.length > ACTIVITY_LIMIT) data.entries.length = ACTIVITY_LIMIT;
      },
      `Log: ${action}`
    );
  } catch {
    /* logging must never break the request */
  }
}

function buildValidateResponse(record, type, version) {
  const locked = new Set(Array.isArray(version.locked_mods) ? version.locked_mods : []);
  const mods = version.mods || {};
  const features = version.mod_features || {};
  const modId = type === 'mod_menu' || type === 'vortex' ? 'mod_menu' : 'room';
  const allowedMods = {};
  const allowedFeatures = {};
  if (mods[modId] && !locked.has(modId)) allowedMods[modId] = mods[modId];
  if (features[modId]) allowedFeatures[modId] = features[modId];
  return {
    success: true,
    label: record.label || 'User',
    expires_at: record.expires_at || null,
    key_type: type,
    mods: allowedMods,
    mod_features: allowedFeatures,
    zip_password: process.env.ZIP_PASSWORD || '8190iwiej82uduud',
    auth_file: modId === 'mod_menu' ? 'woman_tianlin_@tianlin_swittchbs4.ab' : 'woman_tianlin_@tianlin_swittchbs5.ab',
    auth_dir: '/sdcard/Android/data/com.herogame.gplay.lastdayrulessurvival/files/res/effect/',
    locked_mods: [...locked],
  };
}

async function requireReseller(req, res) {
  const payload = auth.verifyToken(auth.bearer(req));
  if (!payload || payload.role !== 'reseller' || !payload.sub) {
    fail(res, 'Session expired. Please log in again.', 401, 'AUTH');
    return null;
  }
  const { data: resellers } = await read(FILES.resellers);
  const record = resellers[payload.sub];
  if (!record) {
    fail(res, 'Reseller not found.', 401, 'AUTH');
    return null;
  }
  if (record.active === false) {
    fail(res, 'Account suspended. Contact admin.', 403, 'BANNED');
    return null;
  }
  if (num(record.session_version, 1) !== num(payload.sv, 1)) {
    fail(res, 'Session revoked. Please log in again.', 401, 'AUTH');
    return null;
  }
  return { slug: payload.sub, record };
}

function requireAdmin(req, res) {
  const payload = auth.verifyToken(auth.bearer(req));
  if (!payload || payload.role !== 'admin') {
    fail(res, 'Unauthorized.', 401, 'AUTH');
    return null;
  }
  return payload;
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return;
  }

  let body = req.body || {};
  if (typeof body === 'string') {
    try {
      body = JSON.parse(body);
    } catch {
      body = {};
    }
  }
  const action = (req.query && req.query.action) || body.action;

  try {
    /* ───────────── app key validation (public) ───────────── */
    if (action === 'validate') {
      const key = String(body.key || '').trim();
      const device = body.device_id ? String(body.device_id).trim() : '';
      if (!key) return fail(res, 'Key required!');
      if (!looksLikeKey(key)) return fail(res, 'Invalid key format!');

      const { data: version } = await read(FILES.version);
      if (version.maintenance) {
        return fail(res, version.maintenance_msg || 'App under maintenance!');
      }

      const { data: keys } = await read(FILES.keys);
      const keyId = keys[key] ? key : keys[key.toUpperCase()] ? key.toUpperCase() : null;
      if (!keyId) return fail(res, 'Invalid key!');

      let payload = null;
      let error = null;
      await mutate(
        FILES.keys,
        (data) => {
          payload = null;
          error = null;
          const record = data[keyId];
          if (!record) {
            error = 'Invalid key!';
            return false;
          }
          if (record.active === false) {
            error = 'Key disabled!';
            return false;
          }
          const type = record.key_type || 'normal';
          const expires = record.expires_at && record.expires_at !== 'null' ? new Date(record.expires_at) : null;
          if (expires && Date.now() > expires.getTime()) {
            error = 'Key expired!';
            return false;
          }
          const maxDevices = type === 'vortex' ? 9999 : num(record.max_devices, 1) || 1;
          if (!Array.isArray(record.connected_devices)) record.connected_devices = [];
          record.connected_devices = record.connected_devices.filter(Boolean);
          if (device && type !== 'vortex' && record.connected_devices.length >= maxDevices && !record.connected_devices.includes(device)) {
            error = `Max devices reached! (${maxDevices})`;
            return false;
          }
          payload = buildValidateResponse(record, type, version);
          if (device && !record.connected_devices.includes(device)) {
            record.connected_devices.push(device);
            record.device_id = device;
            record.locked_at = new Date().toISOString();
            return true;
          }
          return false;
        },
        `Device locked: ${device || 'none'}`
      );
      if (error) return fail(res, error);
      res.json(payload);
      return;
    }

    /* ───────────── admin login ───────────── */
    if (action === 'admin_login') {
      if (!auth.configured()) {
        return fail(res, 'Server not configured. Set ADMIN_PASSWORD and SESSION_SECRET in Vercel.', 500, 'CONFIG');
      }
      const adminLimit = `admin:${auth.clientIp(req)}`;
      if (auth.isRateLimited(adminLimit)) {
        return fail(res, 'Too many attempts. Try again in 10 minutes.', 429, 'RATE');
      }
      const password = String(body.password || '');
      if (!password) return fail(res, 'Password required!', 400);
      if (!auth.safeEqual(password, auth.adminPassword())) {
        auth.recordFailure(adminLimit);
        return fail(res, 'Invalid password!', 401);
      }
      auth.clearFailures(adminLimit);
      const session = auth.issue('admin', 'admin', {}, auth.ADMIN_TTL);
      await logActivity('admin', 'login', auth.clientIp(req));
      return ok(res, { ...session, role: 'admin', name: 'Administrator' });
    }

    /* ───────────── reseller login ───────────── */
    if (action === 'reseller_login') {
      const username = String(body.username || '').trim().toLowerCase();
      const password = String(body.password || '');
      if (!username || !password) return fail(res, 'Username and password required!', 400);
      const resLimit = `res:${username}:${auth.clientIp(req)}`;
      if (auth.isRateLimited(resLimit)) {
        return fail(res, 'Too many attempts. Try again in 10 minutes.', 429, 'RATE');
      }
      const { data: resellers } = await read(FILES.resellers);
      const record = resellers[username];
      if (!record) return fail(res, 'Reseller not found!', 401);
      if (record.active === false) return fail(res, 'Account suspended. Contact admin.', 403, 'BANNED');
      const check = auth.verifyPassword(password, record);
      if (!check.ok) {
        auth.recordFailure(resLimit);
        return fail(res, 'Wrong password!', 401);
      }
      auth.clearFailures(resLimit);

      if (check.legacy) {
        await mutate(
          FILES.resellers,
          (data) => {
            const rec = data[username];
            if (!rec || rec.password === undefined) return false;
            rec.password_hash = auth.hashPassword(password);
            delete rec.password;
          },
          `Upgrade password hash: ${username}`
        ).catch(() => {});
      }

      const sv = num(record.session_version, 1);
      const session = auth.issue('reseller', username, { sv }, auth.RESELLER_TTL);
      await mutate(
        FILES.resellers,
        (data) => {
          const rec = data[username];
          if (!rec) return false;
          rec.last_login = new Date().toISOString();
        },
        `Login: ${username}`
      ).catch(() => {});
      await logActivity(username, 'login', auth.clientIp(req));
      return ok(res, { ...session, role: 'reseller', reseller: resellerProfile(username, record) });
    }

    /* ───────────── reseller session ───────────── */
    if (action === 'reseller_session') {
      const ctx = await requireReseller(req, res);
      if (!ctx) return;
      return ok(res, { reseller: resellerProfile(ctx.slug, ctx.record) });
    }

    /* ───────────── reseller actions ───────────── */
    if (action === 'reseller_change_password') {
      const ctx = await requireReseller(req, res);
      if (!ctx) return;
      const current = String(body.current_password || '');
      const next = String(body.new_password || '');
      if (!auth.verifyPassword(current, ctx.record).ok) return fail(res, 'Current password is wrong.', 401);
      if (next.length < 8) return fail(res, 'New password must be at least 8 characters.', 400);
      const sv = num(ctx.record.session_version, 1) + 1;
      await mutate(
        FILES.resellers,
        (data) => {
          const rec = data[ctx.slug];
          if (!rec) return false;
          rec.password_hash = auth.hashPassword(next);
          delete rec.password;
          rec.session_version = sv;
        },
        `Password changed: ${ctx.slug}`
      );
      await logActivity(ctx.slug, 'password changed', 'self service');
      const session = auth.issue('reseller', ctx.slug, { sv }, auth.RESELLER_TTL);
      return ok(res, { ...session, reseller: resellerProfile(ctx.slug, { ...ctx.record, session_version: sv }) });
    }

    if (action === 'reseller_generate_key') {
      const ctx = await requireReseller(req, res);
      if (!ctx) return;
      const type = ['normal', 'mod_menu', 'vortex'].includes(body.key_type) ? body.key_type : 'normal';
      const record = ctx.record;

      if (type === 'normal' && record.allow_normal === false) return fail(res, 'Normal key generation is not allowed for your account.', 403);
      if (type === 'mod_menu' && record.allow_mod_menu !== true) return fail(res, 'Mod Menu key generation is not allowed for your account.', 403);
      if (type === 'vortex' && record.allow_vortex !== true) return fail(res, 'Vortex key generation is not allowed for your account.', 403);
      if (num(record.credits) <= 0) return fail(res, 'No credits left. Contact admin to top up.', 403);

      const month = currentMonth();
      const usedThisMonth = record.month === month ? num(record.month_count) : 0;
      const monthlyLimit = num(record.monthly_limit);
      if (monthlyLimit > 0 && usedThisMonth >= monthlyLimit) {
        return fail(res, `Monthly limit reached (${monthlyLimit} keys).`, 403);
      }

      let expiresAt = null;
      if (body.expires_at) {
        const parsed = new Date(body.expires_at);
        if (Number.isNaN(parsed.getTime())) return fail(res, 'Invalid expiry date.', 400);
        expiresAt = parsed.toISOString();
      }
      const label = String(body.label || '').trim().slice(0, 60) || record.name || ctx.slug;
      const limits = record.limits || {};
      const typeLimit = num(limits[type]);

      let newKey = null;
      let limitError = null;
      await mutate(
        FILES.keys,
        (data) => {
          newKey = null;
          limitError = null;
          if (typeLimit > 0) {
            const used = Object.values(data).filter((k) => k && k.reseller === ctx.slug && (k.key_type || 'normal') === type).length;
            if (used >= typeLimit) {
              limitError = `Limit reached for ${type} keys (${typeLimit}).`;
              return false;
            }
          }
          do {
            newKey = makeKey(type);
          } while (data[newKey]);
          data[newKey] = {
            label,
            created_at: new Date().toISOString(),
            expires_at: expiresAt,
            duration: '',
            device_id: null,
            locked_at: null,
            active: true,
            reseller: ctx.slug,
            max_devices: type === 'vortex' ? 9999 : 1,
            connected_devices: [],
            key_type: type,
            created_by: ctx.slug,
          };
          return true;
        },
        `Key by reseller: ${ctx.slug}`
      );
      if (limitError) return fail(res, limitError, 403);
      if (!newKey) return fail(res, 'Could not create key. Try again.', 500);

      let creditsLeft = num(record.credits) - 1;
      try {
        await mutate(
          FILES.resellers,
          (data) => {
            const rec = data[ctx.slug];
            if (!rec) return false;
            rec.credits = Math.max(0, num(rec.credits) - 1);
            rec.total_keys_generated = num(rec.total_keys_generated) + 1;
            if (rec.month === month) rec.month_count = num(rec.month_count) + 1;
            else {
              rec.month = month;
              rec.month_count = 1;
            }
            creditsLeft = rec.credits;
          },
          `Credit used by: ${ctx.slug}`
        );
      } catch {
        /* key exists; credit deduction can be reconciled by admin */
      }
      await logActivity(ctx.slug, 'key generated', `${newKey} (${type})`);
      return ok(res, { key: newKey, credits_left: creditsLeft, expires_at: expiresAt, key_type: type, label });
    }

    if (action === 'reseller_get_keys') {
      const ctx = await requireReseller(req, res);
      if (!ctx) return;
      const { data: keys } = await read(FILES.keys);
      const mine = {};
      for (const [key, value] of Object.entries(keys)) {
        if (value && value.reseller === ctx.slug) mine[key] = value;
      }
      return ok(res, { keys: mine, reseller: resellerProfile(ctx.slug, ctx.record) });
    }

    if (action === 'reseller_delete_key') {
      const ctx = await requireReseller(req, res);
      if (!ctx) return;
      const key = String(body.key || '').trim().toUpperCase();
      if (!key) return fail(res, 'Key required!', 400);
      let found = false;
      await mutate(
        FILES.keys,
        (data) => {
          found = false;
          const id = data[key] ? key : Object.keys(data).find((k) => k.toUpperCase() === key);
          if (!id) return false;
          if (data[id].reseller !== ctx.slug) {
            found = false;
            return false;
          }
          delete data[id];
          found = true;
          return true;
        },
        `Key deleted by reseller: ${ctx.slug}`
      );
      if (!found) return fail(res, 'Key not found on your account.', 404);
      await logActivity(ctx.slug, 'key deleted', key);
      return ok(res, { message: 'Deleted!' });
    }

    if (action === 'reseller_reset_device') {
      return fail(res, 'Device reset has been disabled.', 403);
    }

    /* ───────────── admin-only actions ───────────── */
    const admin = requireAdmin(req, res);
    if (!admin) return;

    if (action === 'admin_session') {
      return ok(res, { role: 'admin', name: 'Administrator' });
    }

    if (action === 'get_overview') {
      const [{ data: keys }, { data: resellers }, { data: version }] = await Promise.all([
        read(FILES.keys),
        read(FILES.resellers),
        read(FILES.version),
      ]);
      const now = Date.now();
      let valid = 0;
      let expired = 0;
      let locked = 0;
      let lifetime = 0;
      const types = { normal: 0, mod_menu: 0, vortex: 0 };
      const recent = [];
      for (const [key, record] of Object.entries(keys)) {
        if (!record) continue;
        const exp = record.expires_at && record.expires_at !== 'null' ? new Date(record.expires_at).getTime() : null;
        const isValid = !exp || now < exp;
        if (isValid) valid++;
        else expired++;
        if (!exp) lifetime++;
        if (record.device_id || (Array.isArray(record.connected_devices) && record.connected_devices.length)) locked++;
        const type = record.key_type || 'normal';
        types[type] = (types[type] || 0) + 1;
        recent.push({ key, ...record });
      }
      recent.sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0));
      const resellerList = Object.entries(resellers).map(([slug, record]) => publicReseller(slug, record));
      resellerList.sort((a, b) => b.total_keys_generated - a.total_keys_generated || a.username.localeCompare(b.username));
      return ok(res, {
        stats: {
          total: Object.keys(keys).length,
          valid,
          expired,
          locked,
          lifetime,
          resellers: resellerList.length,
          banned: resellerList.filter((r) => !r.active).length,
          credits: resellerList.reduce((sum, r) => sum + r.credits, 0),
        },
        types,
        recent: recent.slice(0, 8),
        top_resellers: resellerList.slice(0, 5),
        maintenance: Boolean(version.maintenance),
        version: version.version || '',
        locked_mods: Array.isArray(version.locked_mods) ? version.locked_mods : [],
        mods: version.mods || {},
      });
    }

    if (action === 'get_keys') {
      const { data: keys } = await read(FILES.keys);
      return ok(res, { keys });
    }

    if (action === 'add_key') {
      const type = ['normal', 'mod_menu', 'vortex'].includes(body.key_type) ? body.key_type : 'normal';
      const qty = Math.min(Math.max(num(body.qty, 1), 1), 50);
      const label = String(body.label || '').trim().slice(0, 60) || 'No Label';
      let expiresAt = null;
      if (body.expires_at) {
        const parsed = new Date(body.expires_at);
        if (Number.isNaN(parsed.getTime())) return fail(res, 'Invalid expiry date.', 400);
        expiresAt = parsed.toISOString();
      }
      const maxDevices = type === 'vortex' ? 9999 : Math.max(1, Math.min(num(body.max_devices, 1) || 1, 1000));
      const created = [];
      await mutate(
        FILES.keys,
        (data) => {
          created.length = 0;
          for (let i = 0; i < qty; i++) {
            let key = makeKey(type);
            while (data[key]) key = makeKey(type);
            data[key] = {
              label,
              created_at: new Date().toISOString(),
              expires_at: expiresAt,
              duration: '',
              device_id: null,
              locked_at: null,
              active: true,
              reseller: null,
              max_devices: maxDevices,
              connected_devices: [],
              key_type: type,
              created_by: 'admin',
            };
            created.push(key);
          }
        },
        `Admin generated ${qty} key(s)`
      );
      await logActivity('admin', 'keys generated', `${qty}x ${type} ${label}`);
      return ok(res, { keys: created, key: created[0], count: created.length });
    }

    if (action === 'delete_key') {
      const key = String(body.key || '').trim();
      if (!key) return fail(res, 'Key required!', 400);
      let deleted = null;
      await mutate(
        FILES.keys,
        (data) => {
          deleted = data[key] ? key : Object.keys(data).find((k) => k.toUpperCase() === key.toUpperCase()) || null;
          if (!deleted) return false;
          delete data[deleted];
        },
        `Key deleted: ${key}`
      );
      if (!deleted) return fail(res, 'Key not found!', 404);
      await logActivity('admin', 'key deleted', deleted);
      return ok(res, { message: 'Deleted!', key: deleted });
    }

    if (action === 'delete_expired_keys') {
      const now = Date.now();
      let deleted = [];
      await mutate(
        FILES.keys,
        (data) => {
          deleted = [];
          for (const [key, record] of Object.entries(data)) {
            if (!record || !record.expires_at || record.expires_at === 'null') continue;
            const expires = new Date(record.expires_at).getTime();
            if (Number.isFinite(expires) && expires < now) {
              delete data[key];
              deleted.push(key);
            }
          }
          return deleted.length > 0;
        },
        'Delete expired keys'
      );
      if (!deleted.length) return ok(res, { deleted: 0 });
      await logActivity('admin', 'expired keys deleted', `${deleted.length} key(s)`);
      return ok(res, { deleted: deleted.length });
    }

    if (action === 'reset_device') {
      const key = String(body.key || '').trim();
      if (!key) return fail(res, 'Key required!', 400);
      let reset = null;
      await mutate(
        FILES.keys,
        (data) => {
          reset = data[key] ? key : Object.keys(data).find((k) => k.toUpperCase() === key.toUpperCase()) || null;
          if (!reset) return false;
          data[reset].device_id = null;
          data[reset].locked_at = null;
          data[reset].connected_devices = [];
        },
        `Device reset: ${key}`
      );
      if (!reset) return fail(res, 'Key not found!', 404);
      await logActivity('admin', 'device reset', reset);
      return ok(res, { message: 'Reset!' });
    }

    if (action === 'get_maintenance') {
      const { data: version } = await read(FILES.version);
      return ok(res, { maintenance: Boolean(version.maintenance) });
    }

    if (action === 'set_maintenance') {
      const maintenance = Boolean(body.maintenance);
      await mutate(
        FILES.version,
        (data) => {
          data.maintenance = maintenance;
        },
        maintenance ? 'Maintenance ON' : 'Maintenance OFF'
      );
      await logActivity('admin', 'maintenance', maintenance ? 'ON' : 'OFF');
      return ok(res, { maintenance });
    }

    if (action === 'get_mod_locks') {
      const { data: version } = await read(FILES.version);
      return ok(res, { locked_mods: Array.isArray(version.locked_mods) ? version.locked_mods : [], mods: version.mods || {} });
    }

    if (action === 'set_mod_lock') {
      const modKey = String(body.mod_key || '').trim();
      const locked = Boolean(body.locked);
      if (!modKey) return fail(res, 'mod_key required!', 400);
      let updated = [];
      await mutate(
        FILES.version,
        (data) => {
          if (!Array.isArray(data.locked_mods)) data.locked_mods = [];
          if (locked && !data.locked_mods.includes(modKey)) data.locked_mods.push(modKey);
          if (!locked) data.locked_mods = data.locked_mods.filter((m) => m !== modKey);
          updated = data.locked_mods;
        },
        `Mod lock updated: ${modKey}`
      );
      await logActivity('admin', 'mod lock', `${modKey} ${locked ? 'locked' : 'unlocked'}`);
      return ok(res, { locked_mods: updated });
    }

    if (action === 'get_mod_features') {
      const { data: version } = await read(FILES.version);
      return ok(res, { mod_features: version.mod_features || {}, mods: version.mods || {} });
    }

    if (action === 'set_mod_features') {
      const features = body.mod_features;
      if (!features || typeof features !== 'object') return fail(res, 'mod_features required!', 400);
      const clean = {};
      for (const [key, value] of Object.entries(features)) clean[String(key)] = String(value || '').slice(0, 4000);
      await mutate(
        FILES.version,
        (data) => {
          data.mod_features = clean;
        },
        'Mod features updated'
      );
      await logActivity('admin', 'features updated', Object.keys(clean).join(', '));
      return ok(res, {});
    }

    if (action === 'get_activity') {
      const { data } = await read(FILES.activity);
      const entries = Array.isArray(data.entries) ? data.entries : [];
      const limit = Math.min(Math.max(num(body.limit, 100), 1), ACTIVITY_LIMIT);
      return ok(res, { entries: entries.slice(0, limit), total: entries.length });
    }

    /* ───────────── admin: reseller management ───────────── */
    if (action === 'get_resellers') {
      const { data: resellers } = await read(FILES.resellers);
      const list = {};
      for (const [slug, record] of Object.entries(resellers)) list[slug] = publicReseller(slug, record);
      return ok(res, { resellers: list });
    }

    if (action === 'create_reseller') {
      const slug = String(body.username || '').trim().toLowerCase().replace(/[^a-z0-9]/g, '');
      const password = String(body.password || '');
      if (!slug) return fail(res, 'Invalid username. Use letters and numbers only.', 400);
      if (password.length < 8) return fail(res, 'Password must be at least 8 characters.', 400);
      const name = String(body.name || '').trim().slice(0, 40) || slug;
      const credits = Math.max(0, num(body.credits));
      let created = false;
      await mutate(
        FILES.resellers,
        (data) => {
          created = false;
          if (data[slug]) return false;
          data[slug] = {
            name,
            password_hash: auth.hashPassword(password),
            credits,
            max_credits: Math.max(0, num(body.max_credits)),
            monthly_limit: Math.max(0, num(body.monthly_limit)),
            month: currentMonth(),
            month_count: 0,
            limits: { normal: 0, mod_menu: 0, vortex: 0 },
            created_at: new Date().toISOString(),
            total_keys_generated: 0,
            active: true,
            allow_normal: true,
            allow_mod_menu: false,
            allow_vortex: false,
            session_version: 1,
          };
          created = true;
          return true;
        },
        `Reseller created: ${slug}`
      );
      if (!created) return fail(res, 'Reseller already exists!', 409);
      await logActivity('admin', 'reseller created', slug);
      return ok(res, { message: 'Reseller created!', slug });
    }

    if (action === 'update_reseller') {
      const slug = String(body.username || '').trim().toLowerCase();
      if (!slug) return fail(res, 'Username required!', 400);
      let updated = false;
      await mutate(
        FILES.resellers,
        (data) => {
          updated = false;
          const record = data[slug];
          if (!record) return false;
          if (body.name !== undefined) record.name = String(body.name).trim().slice(0, 40) || slug;
          if (body.max_credits !== undefined) record.max_credits = Math.max(0, num(body.max_credits));
          if (body.monthly_limit !== undefined) record.monthly_limit = Math.max(0, num(body.monthly_limit));
          if (body.limits && typeof body.limits === 'object') {
            record.limits = {
              normal: Math.max(0, num(body.limits.normal)),
              mod_menu: Math.max(0, num(body.limits.mod_menu)),
              vortex: Math.max(0, num(body.limits.vortex)),
            };
          }
          updated = true;
          return true;
        },
        `Reseller updated: ${slug}`
      );
      if (!updated) return fail(res, 'Reseller not found!', 404);
      await logActivity('admin', 'reseller updated', slug);
      return ok(res, { message: 'Saved!' });
    }

    if (action === 'delete_reseller') {
      const slug = String(body.username || '').trim().toLowerCase();
      let deleted = false;
      await mutate(
        FILES.resellers,
        (data) => {
          deleted = false;
          if (!data[slug]) return false;
          delete data[slug];
          deleted = true;
          return true;
        },
        `Reseller deleted: ${slug}`
      );
      if (!deleted) return fail(res, 'Reseller not found!', 404);
      await logActivity('admin', 'reseller deleted', slug);
      return ok(res, { message: 'Reseller deleted!' });
    }

    if (action === 'add_credits' || action === 'remove_credits') {
      const slug = String(body.username || '').trim().toLowerCase();
      const amount = Math.abs(num(body.credits));
      if (!slug) return fail(res, 'Username required!', 400);
      if (!amount) return fail(res, 'Amount required!', 400);
      let credits = 0;
      let found = false;
      await mutate(
        FILES.resellers,
        (data) => {
          found = false;
          const record = data[slug];
          if (!record) return false;
          if (action === 'add_credits') {
            const cap = num(record.max_credits);
            record.credits = num(record.credits) + amount;
            if (cap > 0) record.credits = Math.min(cap, record.credits);
          } else {
            record.credits = Math.max(0, num(record.credits) - amount);
          }
          credits = record.credits;
          found = true;
          return true;
        },
        `${action === 'add_credits' ? 'Credits added to' : 'Credits removed from'}: ${slug}`
      );
      if (!found) return fail(res, 'Reseller not found!', 404);
      await logActivity('admin', action === 'add_credits' ? 'credits added' : 'credits removed', `${slug} ±${amount}`);
      return ok(res, { message: 'Credits updated!', credits });
    }

    if (action === 'change_reseller_password') {
      const slug = String(body.username || '').trim().toLowerCase();
      const password = String(body.new_password || '');
      if (password.length < 8) return fail(res, 'Password must be at least 8 characters.', 400);
      let changed = false;
      await mutate(
        FILES.resellers,
        (data) => {
          changed = false;
          const record = data[slug];
          if (!record) return false;
          record.password_hash = auth.hashPassword(password);
          delete record.password;
          record.session_version = num(record.session_version, 1) + 1;
          changed = true;
          return true;
        },
        `Password reset: ${slug}`
      );
      if (!changed) return fail(res, 'Reseller not found!', 404);
      await logActivity('admin', 'password reset', `${slug} (sessions revoked)`);
      return ok(res, { message: 'Password changed. All sessions revoked.' });
    }

    if (action === 'revoke_reseller_sessions') {
      const slug = String(body.username || '').trim().toLowerCase();
      let revoked = false;
      await mutate(
        FILES.resellers,
        (data) => {
          revoked = false;
          const record = data[slug];
          if (!record) return false;
          record.session_version = num(record.session_version, 1) + 1;
          revoked = true;
          return true;
        },
        `Sessions revoked: ${slug}`
      );
      if (!revoked) return fail(res, 'Reseller not found!', 404);
      await logActivity('admin', 'sessions revoked', slug);
      return ok(res, { message: 'All sessions revoked.' });
    }

    const toggleMap = {
      toggle_reseller_normal: 'allow_normal',
      toggle_reseller_mod_menu: 'allow_mod_menu',
      toggle_reseller_vortex: 'allow_vortex',
      toggle_reseller_active: 'active',
    };
    if (toggleMap[action]) {
      const field = toggleMap[action];
      const slug = String(body.username || '').trim().toLowerCase();
      const allow = body.allow === true;
      let value = allow;
      let found = false;
      await mutate(
        FILES.resellers,
        (data) => {
          found = false;
          const record = data[slug];
          if (!record) return false;
          record[field] = allow;
          value = record[field];
          found = true;
          return true;
        },
        `${field} = ${allow} for ${slug}`
      );
      if (!found) return fail(res, 'Reseller not found!', 404);
      await logActivity('admin', field, `${slug} → ${allow}`);
      return ok(res, { [field]: value });
    }

    if (action === 'bulk_reseller') {
      const op = String(body.op || '');
      const list = Array.isArray(body.usernames) ? body.usernames.map((u) => String(u).toLowerCase()) : [];
      if (!list.length) return fail(res, 'Select at least one reseller.', 400);
      const amount = Math.abs(num(body.amount));
      let touched = 0;
      const out = await mutate(
        FILES.resellers,
        (data) => {
          touched = 0;
          for (const slug of list) {
            const record = data[slug];
            if (!record) continue;
            if (op === 'delete') {
              delete data[slug];
              touched++;
              continue;
            }
            if (op === 'ban') {
              record.active = false;
              touched++;
              continue;
            }
            if (op === 'unban') {
              record.active = true;
              touched++;
              continue;
            }
            if (op === 'revoke_sessions') {
              record.session_version = num(record.session_version, 1) + 1;
              touched++;
              continue;
            }
            if (op === 'add_credits') {
              const cap = num(record.max_credits);
              record.credits = num(record.credits) + amount;
              if (cap > 0) record.credits = Math.min(cap, record.credits);
              touched++;
              continue;
            }
            if (op === 'remove_credits') {
              record.credits = Math.max(0, num(record.credits) - amount);
              touched++;
              continue;
            }
            const flags = { allow_normal: true, allow_mod_menu: false, allow_vortex: false, deny_normal: 'allow_normal', deny_mod_menu: 'allow_mod_menu', deny_vortex: 'allow_vortex' };
            if (op.startsWith('allow_')) {
              record[op] = true;
              touched++;
            } else if (op.startsWith('deny_')) {
              record[flags[op]] = false;
              touched++;
            }
          }
          return touched > 0;
        },
        `Bulk ${op} (${list.length})`
      );
      if (!out.ok || !touched) return fail(res, 'No matching resellers.', 404);
      await logActivity('admin', `bulk ${op}`, `${touched} account(s)`);
      return ok(res, { affected: touched });
    }

    if (action === 'get_reseller_stats') {
      const [{ data: keys }, { data: resellers }] = await Promise.all([read(FILES.keys), read(FILES.resellers)]);
      const stats = {};
      for (const [slug, record] of Object.entries(resellers)) {
        stats[slug] = { ...publicReseller(slug, record), total_keys: 0, valid: 0, expired: 0, locked: 0 };
      }
      const now = Date.now();
      for (const record of Object.values(keys)) {
        if (!record) continue;
        const slug = record.reseller || 'admin';
        if (!stats[slug]) stats[slug] = { username: slug, name: slug, credits: 0, total_keys: 0, valid: 0, expired: 0, locked: 0 };
        stats[slug].total_keys++;
        const exp = record.expires_at && record.expires_at !== 'null' ? new Date(record.expires_at).getTime() : null;
        if (!exp || now < exp) stats[slug].valid++;
        else stats[slug].expired++;
        if (record.device_id || (Array.isArray(record.connected_devices) && record.connected_devices.length)) stats[slug].locked++;
      }
      return ok(res, { stats });
    }

    return fail(res, 'Unknown action!', 404);
  } catch (err) {
    res.status(500).json({ success: false, message: `Server error: ${err.message}` });
  }
};

module.exports._helpers = { buildValidateResponse, requireAdmin, requireReseller, logActivity };
