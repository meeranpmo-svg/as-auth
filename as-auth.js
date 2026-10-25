/* Arabian Shield — Security, Operations & GRC Center : sign-in gate (Node stdlib only, Node 12 safe).
   nginx auth_request -> /auth/verify. A signed HMAC session cookie carries the identity; /auth/verify returns X-Auth-Role /
   X-Auth-User to nginx, which forwards them to the platform services.
   Sign-in methods
   · Single sign-on — OpenID Connect (Microsoft Entra ID, ADFS 2019+, Okta …): authorization code + PKCE, id_token signature
     verified against the provider's JWKS (RS256), issuer / audience / expiry / nonce checked, MFA required through the `amr`
     (or `acr`) claim, roles or groups mapped to admin / operator / viewer.
   · Standalone — local accounts (PBKDF2-SHA256, 120k) with authenticator-app MFA (TOTP, RFC 6238), QR enrolment on first
     sign-in, one-time recovery codes, lockout after repeated failures. Break-glass accounts always keep local sign-in.
   Config: /etc/arabianshield-auth.json (chmod 600). TOTP secrets and the SSO client secret are AES-256-GCM encrypted with a
   key derived from the config secret. Every sign-in event is appended to /var/log/arabianshield-auth.log.
   · On-premises Active Directory (LDAPS) — config block `ldap` (see AD-SETUP.md). "DOMAIN\user", "user@<upnSuffix>" or a
     plain name that is not a local account is checked against AD over LDAPS (ldap-client.js): service bind → user search →
     disabled / expired / locked refused → bind as the user → role from mapped groups (nested via IN_CHAIN). The account
     then lives on as a local SHADOW record {source:"ad", dn, role, no password} so sessions, TOTP enrolment, throttling
     and audit are the same code paths as local accounts. The AD password is never stored or logged; the service-account
     password is stored enc()-encrypted (as-auth-ldap.js --set-bind-password).
   · Sessions — every session is also a server-side record (AS_AUTH_SESS), so sign-out, an admin revoke, an idle timeout or a
     disabled account ends it at once; admin sessions are shorter; single sign-on sessions are re-checked with the identity
     provider every few minutes (refresh-token grant) and end when the provider refuses them (see "server-side sessions"). */
'use strict';
const http = require('http'), https = require('https'), crypto = require('crypto'), fs = require('fs');
const CFG_FILE = process.env.AS_AUTH_CFG || '/etc/arabianshield-auth.json', LOG_FILE = process.env.AS_AUTH_LOG || '/var/log/arabianshield-auth.log', PORT = +process.env.AS_AUTH_PORT || 9098;
let CFG = JSON.parse(fs.readFileSync(CFG_FILE, 'utf8'));
CFG.sso = CFG.sso || { enabled: false, provider: 'Microsoft Entra ID', issuer: '', clientId: '', clientSecret: '', redirectUri: '', scopes: 'openid profile email', roleClaim: 'roles', roleMap: {}, defaultRole: 'none', requireMfa: true, allowedDomains: '' };
CFG.mfaPolicy = CFG.mfaPolicy || 'admins';           // all | admins | optional  (local accounts)
CFG.localLogin = CFG.localLogin || 'all';            // all | breakglass  (breakglass: only accounts flagged break-glass)
/* MFA MANDATE — two-step verification is required for EVERY local and AD sign-in before a full session is granted. The old
   "skip enrolment" bypass is gone. CFG.mfaRequired (default true) is the effective mandate; an admin may set it false only to
   fall back to the legacy per-account CFG.mfaPolicy. CFG.mfaGraceDays (default 7) is the enrolment grace window: until it runs
   out a not-yet-enrolled user may still be admitted (audited grace-admit) but is pushed to the enrolment screen; after it runs
   out no session is issued until TOTP is enrolled. CFG.mfaPolicyActivated marks when the mandate was last turned on. */
if (CFG.mfaRequired === undefined) CFG.mfaRequired = true;
if (CFG.mfaGraceDays === undefined) CFG.mfaGraceDays = 7;
CFG.mfaPolicyActivated = CFG.mfaPolicyActivated || null;
const HOURS = CFG.hours || 12;
/* the `ldap` block is edited on disk by as-auth-ldap.js while the service runs: pick up such edits (mtime) before using the
   block and before every save(), so the service never writes back a stale copy over the helper's change */
let CFG_MTIME = 0; try { CFG_MTIME = fs.statSync(CFG_FILE).mtimeMs; } catch (e) {}
function syncLdapFromDisk() {
  try { const m = fs.statSync(CFG_FILE).mtimeMs; if (m === CFG_MTIME) return; const disk = JSON.parse(fs.readFileSync(CFG_FILE, 'utf8')); CFG_MTIME = m; if (disk.ldap) CFG.ldap = disk.ldap; else delete CFG.ldap; } catch (e) {}
}
function save() { syncLdapFromDisk(); const tmp = CFG_FILE + '.tmp'; fs.writeFileSync(tmp, JSON.stringify(CFG, null, 1), { mode: 0o600 }); fs.renameSync(tmp, CFG_FILE); try { CFG_MTIME = fs.statSync(CFG_FILE).mtimeMs; } catch (e) {} }

/* ─────────── primitives ─────────── */
function hashPw(pw, salt) { return crypto.pbkdf2Sync(String(pw), salt, 120000, 32, 'sha256').toString('hex'); }
function eqHex(a, b) { try { return crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex')); } catch (e) { return false; } }
function b64u(buf) { return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function ub64u(s) { s = String(s).replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; return Buffer.from(s, 'base64'); }
function sign(d) { return crypto.createHmac('sha256', CFG.secret).update(d).digest('hex'); }
const EKEY = crypto.createHash('sha256').update('as-auth-enc|' + CFG.secret).digest();
function enc(txt) { const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', EKEY, iv), d = Buffer.concat([c.update(String(txt), 'utf8'), c.final()]); return b64u(Buffer.concat([iv, c.getAuthTag(), d])); }
function dec(s) { try { const b = ub64u(s), c = crypto.createDecipheriv('aes-256-gcm', EKEY, b.slice(0, 12)); c.setAuthTag(b.slice(12, 28)); return Buffer.concat([c.update(b.slice(28)), c.final()]).toString('utf8'); } catch (e) { return null; } }
function signed(obj, mins) { const p = b64u(JSON.stringify(Object.assign({ exp: Date.now() + mins * 60e3 }, obj))); return p + '.' + sign(p); }
function unsign(v) { if (!v) return null; const i = v.lastIndexOf('.'); if (i < 0) return null; const p = v.slice(0, i), s = v.slice(i + 1); let ok = false; try { ok = crypto.timingSafeEqual(Buffer.from(s), Buffer.from(sign(p))); } catch (e) { return null; } if (!ok) return null; let o; try { o = JSON.parse(ub64u(p).toString()); } catch (e) { return null; } return o.exp && o.exp > Date.now() ? o : null; }
function cookie(hdr, name) { const m = new RegExp('(?:^|;\\s*)' + name + '=([^;]+)').exec(hdr || ''); return m ? m[1] : null; }
function setCookie(name, val, secs) { return name + '=' + val + '; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=' + secs; }
function clearCookie(name) { return name + '=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0'; }
/* ─────────── server-side sessions ───────────
   Every session also lives in a server-side table (sid → record), so it can END before its cookie does: sign-out, an admin's
   revoke, an idle timeout, a disabled / deleted account, or - for single sign-on - the identity provider refusing it. A cookie
   whose sid is not in the table is not a session (this also ends every cookie issued before the table existed: one new
   sign-in after the upgrade). Single sign-on sessions are re-checked with the identity provider every CFG.session.
   ssoRecheckMinutes (refresh-token grant, offline_access): a disabled / deleted / revoked account or a removed role ends the
   session at the next check instead of up to CFG.hours later. An identity provider that cannot be reached is tolerated for
   ssoOutageMinutes, then the session ends (fail closed). Without a refresh token an SSO session lasts ssoNoRefreshMinutes.
   The table is kept in AS_AUTH_SESS (default next to the config, chmod 600); refresh tokens in it are enc()-encrypted and
   never logged. */
const SESS_FILE = process.env.AS_AUTH_SESS || CFG_FILE.replace(/\.json$/, '') + '.sessions.json';
const SESSION_DEFAULTS = { idleMinutes: 60, adminHours: 8, ssoRecheckMinutes: 15, ssoOutageMinutes: 60, ssoNoRefreshMinutes: 60 };
const SESSION_LIMITS = { idleMinutes: [5, 720], adminHours: [1, 24], ssoRecheckMinutes: [5, 60], ssoOutageMinutes: [0, 240], ssoNoRefreshMinutes: [15, 720] };
function sessCfg() { const c = Object.assign({}, SESSION_DEFAULTS, CFG.session || {}); Object.keys(SESSION_LIMITS).forEach(function (k) { const n = Number(c[k]), l = SESSION_LIMITS[k]; c[k] = isFinite(n) ? Math.min(l[1], Math.max(l[0], Math.floor(n))) : SESSION_DEFAULTS[k]; }); return c; }
let SIDS = {};
try { SIDS = JSON.parse(fs.readFileSync(SESS_FILE, 'utf8')) || {}; } catch (e) { SIDS = {}; }   /* no table yet (first start) → no sessions */
let SESS_TIMER = null;
function saveSessions(now) {
  const write = function () { SESS_TIMER = null; try { const tmp = SESS_FILE + '.tmp'; fs.writeFileSync(tmp, JSON.stringify(SIDS), { mode: 0o600 }); fs.renameSync(tmp, SESS_FILE); } catch (e) { console.log('[as-auth] session table save failed: ' + e.message); } };
  if (now) { if (SESS_TIMER) { clearTimeout(SESS_TIMER); SESS_TIMER = null; } return write(); }
  if (!SESS_TIMER) { SESS_TIMER = setTimeout(write, 5000); if (SESS_TIMER.unref) SESS_TIMER.unref(); }
}
function pruneSessions() { const t = Date.now(); let n = 0; Object.keys(SIDS).forEach(function (k) { if (!SIDS[k] || SIDS[k].exp < t) { delete SIDS[k]; n++; } }); if (n) saveSessions(true); }
setInterval(pruneSessions, 10 * 60e3).unref();
function endSession(sid, reason, by) {
  const r = SIDS[sid]; if (!r) return false; delete SIDS[sid]; saveSessions(true);
  audit({ event: 'session-ended', user: r.u, method: r.m, reason: reason + (by ? ' · by ' + by : '') });
  return true;
}
function endUserSessions(user, reason, by) { let n = 0; Object.keys(SIDS).forEach(function (k) { if (SIDS[k] && SIDS[k].u === user && endSession(k, reason, by)) n++; }); return n; }
function ssoDue(sid) { const r = SIDS[sid]; return !!(r && r.m === 'sso' && Date.now() >= (r.chk || 0)); }
/* a session is valid while its server-side record exists, it has not been idle too long and (local / AD) the account still
   exists and is enabled; its role follows the current account record, or for SSO the role the identity provider last gave */
function session(req) {
  const s = unsign(cookie(req.headers.cookie, 'as_session')); if (!s || !s.sid) return null;
  const rec = SIDS[s.sid], t = Date.now(), sc = sessCfg();
  if (!rec || rec.u !== s.u || rec.exp < t) return null;
  if (t - (rec.last || rec.iat) > sc.idleMinutes * 60e3) { endSession(s.sid, 'idle for more than ' + sc.idleMinutes + ' min'); return null; }
  if (t - (rec.last || 0) > 60e3) { rec.last = t; saveSessions(); }
  if (s.m === 'sso') {
    if (!ssoOn()) { endSession(s.sid, 'single sign-on switched off'); return null; }
    s.r = rec.r || s.r;
    if (ssoDue(s.sid)) ssoRecheck(s.sid);   /* in the background; /auth/verify waits for it */
    return s;
  }
  const u = (CFG.users || []).filter(function (x) { return x.user === s.u; })[0];
  if (!u || u.disabled) return null;
  if (u.source === 'ad' && (u.adBlocked || !ldapOn())) return null;   /* AD said no / directory sign-in switched off → sessions end */
  if (u.pwChanged && s.iat && s.iat < Date.parse(u.pwChanged)) return null;
  s.r = u.role || s.r; s.name = u.name || s.name;
  if (s.mfaPending) s.r = 'viewer';   /* enrolment grace: read-only until two-step verification is set up */
  return s;
}
function makeSession(id, extra) {
  pruneSessions();
  const t = Date.now(), sc = sessCfg(), hours = id.r === 'admin' ? Math.min(HOURS, sc.adminHours) : HOURS, sid = b64u(crypto.randomBytes(18));
  const rec = { u: id.u, m: id.m, r: id.r, iat: t, last: t, exp: t + hours * 3600e3, ip: (extra && extra.ip) || '' };
  if (id.m === 'sso') { rec.sub = (extra && extra.sub) || ''; rec.rt = extra && extra.rt ? enc(extra.rt) : ''; rec.chk = t + (rec.rt ? sc.ssoRecheckMinutes : sc.ssoNoRefreshMinutes) * 60e3; }
  SIDS[sid] = rec; saveSessions(true);
  return setCookie('as_session', signed(Object.assign({ iat: t, sid: sid }, id), hours * 60), hours * 3600);
}
/* the single sign-on re-check: refresh-token grant at the identity provider. A refusal (4xx: invalid_grant - account disabled,
   deleted, password reset, sessions revoked - or interaction_required) or a role no longer granted ends the session at once;
   an outage is tolerated for ssoOutageMinutes, re-tried every minute, then the session ends. One check per session at a time. */
const RECHECK = {};
function ssoRecheck(sid) {
  if (RECHECK[sid]) return RECHECK[sid];
  const rec = SIDS[sid]; if (!rec) return Promise.resolve(false);
  const sc = sessCfg(), t0 = Date.now();
  const p = (async function () {
    if (!rec.rt) { endSession(sid, 'single sign-on session reached ' + sc.ssoNoRefreshMinutes + ' min without a refresh token - sign in again'); return false; }
    const rt = dec(rec.rt); if (!rt) { endSession(sid, 'stored refresh token unreadable'); return false; }
    try {
      const d = await discovery();
      const body = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: rt, client_id: CFG.sso.clientId, scope: ssoScopes() });
      const secret = CFG.sso.clientSecret ? dec(CFG.sso.clientSecret) : null; if (secret) body.set('client_secret', secret);
      const tk = await httpsJSON(d.token_endpoint, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }, body.toString());
      if (!SIDS[sid]) return false;                                   /* signed out while we asked */
      if (tk.id_token) {
        const c = await verifyIdToken(tk.id_token, null, { refresh: true });
        if (rec.sub && c.sub !== rec.sub) { endSession(sid, 'identity provider returned a different subject'); return false; }
        const role = mapRole(c);
        if (!role) { endSession(sid, 'role no longer granted by the identity provider'); return false; }
        if (role !== rec.r) { audit({ event: 'role-changed', user: rec.u, role: role, method: 'sso', reason: rec.r + ' → ' + role + ' (identity provider)' }); rec.r = role; }
      }
      if (tk.refresh_token) rec.rt = enc(tk.refresh_token);
      delete rec.fail; rec.chk = Date.now() + sc.ssoRecheckMinutes * 60e3; saveSessions();
      return true;
    } catch (e) {
      if (e.status >= 400 && e.status < 500) { endSession(sid, 'identity provider refused the session (' + String(e.oauth || e.status) + ')'); return false; }
      if (!SIDS[sid]) return false;
      rec.fail = rec.fail || t0;
      if (Date.now() - rec.fail >= sc.ssoOutageMinutes * 60e3) { endSession(sid, 'identity provider could not be reached for ' + sc.ssoOutageMinutes + ' min (' + String(e.message).slice(0, 120) + ')'); return false; }
      rec.chk = Date.now() + 60e3; saveSessions();
      if (!rec.warned) { rec.warned = 1; audit({ event: 'sso-recheck-error', user: rec.u, method: 'sso', reason: String(e.message).slice(0, 200) + ' - retrying; the session ends after ' + sc.ssoOutageMinutes + ' min' }); }
      return true;
    }
  })();
  RECHECK[sid] = p;
  return p.then(function (v) { delete RECHECK[sid]; return v; }, function (e) { delete RECHECK[sid]; console.log('[as-auth] SSO re-check failed: ' + e.message); endSession(sid, 'SSO re-check failed'); return false; });
}
function ssoScopes() { const s = String(CFG.sso.scopes || 'openid profile email'); return /\boffline_access\b/.test(s) ? s : s + ' offline_access'; }
function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
function json(res, code, obj) { res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(obj)); }
function readBody(req, cb) { let b = ''; req.on('data', function (c) { b += c; if (b.length > 65536) req.destroy(); }); req.on('end', function () { cb(b); }); }
function ipOf(req) { return String(req.headers['x-real-ip'] || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim(); }
function audit(ev) { try { fs.appendFileSync(LOG_FILE, JSON.stringify(Object.assign({ at: new Date().toISOString() }, ev)) + '\n', { mode: 0o600 }); } catch (e) {} console.log('[as-auth] ' + ev.event + ' ' + (ev.user || '') + ' ' + (ev.method || '') + (ev.reason ? ' — ' + ev.reason : '')); }
function recentEvents(n) { try { return fs.readFileSync(LOG_FILE, 'utf8').trim().split('\n').slice(-n).reverse().map(function (l) { try { return JSON.parse(l); } catch (e) { return null; } }).filter(Boolean); } catch (e) { return []; } }
function userOf(name) { return (CFG.users || []).filter(function (x) { return x.user === String(name || '').toLowerCase().trim(); })[0] || null; }

/* ─────────── TOTP (RFC 6238 · SHA-1 · 30 s · 6 digits) ─────────── */
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function b32enc(buf) { let bits = '', out = ''; for (let i = 0; i < buf.length; i++) bits += buf[i].toString(2).padStart(8, '0'); for (let i = 0; i + 5 <= bits.length; i += 5) out += B32[parseInt(bits.substr(i, 5), 2)]; if (bits.length % 5) out += B32[parseInt(bits.substr(bits.length - bits.length % 5).padEnd(5, '0'), 2)]; return out; }
function b32dec(s) { let bits = ''; String(s).replace(/=+$/, '').toUpperCase().split('').forEach(function (ch) { const v = B32.indexOf(ch); if (v >= 0) bits += v.toString(2).padStart(5, '0'); }); const out = []; for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.substr(i, 8), 2)); return Buffer.from(out); }
function hotp(key, counter) { const b = Buffer.alloc(8); b.writeUInt32BE(Math.floor(counter / 4294967296), 0); b.writeUInt32BE(counter % 4294967296, 4); const h = crypto.createHmac('sha1', key).update(b).digest(), o = h[h.length - 1] & 15; return String(((h.readUInt32BE(o) & 0x7fffffff) % 1000000)).padStart(6, '0'); }
function totpCheck(secretB32, code, lastStep) {
  code = String(code || '').replace(/\s/g, ''); if (!/^\d{6}$/.test(code)) return -1;
  const key = b32dec(secretB32), step = Math.floor(Date.now() / 30000);
  for (let w = -1; w <= 1; w++) { const s = step + w; if (s <= (lastStep || 0)) continue; if (crypto.timingSafeEqual(Buffer.from(hotp(key, s)), Buffer.from(code))) return s; }
  return -1;
}
/* the mandate wins over everything; the per-user setting (u.mfa 'on'|'off') and CFG.mfaPolicy only apply once an admin turns
   the mandate off. u.mfa='off' can therefore NEVER bypass MFA while the mandate is on. */
function mfaMandatory() { return CFG.mfaRequired !== false; }
function mfaRequired(u) {
  if (mfaMandatory()) return true;                                          /* mandatory for everyone — local AND AD */
  if (u.source === 'ad' && ldapCfg().requireMfa !== false) return true;
  if (u.mfa === 'on') return true;
  if (u.mfa === 'off') return false;
  return CFG.mfaPolicy === 'all' || (CFG.mfaPolicy === 'admins' && u.role === 'admin');
}
function graceDays() { const n = Number(CFG.mfaGraceDays); return (isFinite(n) && n >= 0) ? Math.floor(n) : 7; }
/* enrolment status for an account under the current policy → enrolled | exempt | grace | expired (+ deadline when anchored).
   The grace clock is anchored per user (u.mfaGraceStart) the first time the account is seen un-enrolled under the mandate. */
function mfaStatus(u) {
  if (u.totp) return { state: 'enrolled', deadline: null };
  if (!mfaRequired(u)) return { state: 'exempt', deadline: null };
  if (!u.mfaGraceStart) return { state: 'grace', deadline: null };          /* not yet anchored — first encounter is still grace */
  const deadline = Date.parse(u.mfaGraceStart) + graceDays() * 86400000;
  if (Date.now() > deadline) return { state: 'expired', deadline: new Date(deadline).toISOString() };
  return { state: 'grace', deadline: new Date(deadline).toISOString() };
}
function graceLeft(deadline) { if (!deadline) return graceDays(); const ms = Date.parse(deadline) - Date.now(); return ms <= 0 ? 0 : Math.ceil(ms / 86400000); }
const ROLES = ['admin', 'operator', 'viewer'];
function pwProblem(pw) { pw = String(pw || ''); if (pw.length < 10) return 'the password needs at least 10 characters'; if (!/[A-Za-z]/.test(pw) || !/\d/.test(pw)) return 'the password needs letters and digits'; return null; }
function enabledAdmins(except) { return (CFG.users || []).filter(function (u) { return u.role === 'admin' && !u.disabled && u.user !== except; }).length; }

/* ─────────── brute-force protection ─────────── */
const FAIL = {}, IPFAIL = {};
function locked(u) { const f = FAIL[u]; return !!(f && f.until && f.until > Date.now()); }
function failed(u, ip) { const f = FAIL[u] || (FAIL[u] = { n: 0 }); f.n++; if (f.n >= 5) { f.until = Date.now() + 15 * 60e3; f.n = 0; audit({ event: 'lockout', user: u, ip: ip, reason: '5 failed attempts — locked for 15 minutes' }); } (IPFAIL[ip] = IPFAIL[ip] || []).push(Date.now()); }
function ipBlocked(ip) { const g = (IPFAIL[ip] || []).filter(function (t) { return Date.now() - t < 10 * 60e3; }); IPFAIL[ip] = g; return g.length >= 25; }

/* ─────────── on-premises Active Directory (LDAPS) ─────────── */
const LDAP_DEFAULTS = { enabled: false, servers: [], caFile: '', baseDN: '', bindDN: '', bindPassword: '', netbios: [], upnSuffix: [], userAttr: 'sAMAccountName', groupRoles: {}, nested: true, requireMfa: true, timeoutMs: 8000, hint: '' };
const AD_USER_ATTRS = ['sAMAccountName', 'userPrincipalName', 'displayName', 'mail', 'userAccountControl', 'msDS-User-Account-Control-Computed', 'accountExpires', 'lockoutTime', 'memberOf'];
const RANK = { admin: 3, operator: 2, viewer: 1 };
let LDAPLIB = null, LOCKDUR = { at: 0, ms: null };
function ldapLib() { if (!LDAPLIB) LDAPLIB = require('./ldap-client.js'); return LDAPLIB; }
function strList(v) { return [].concat(v == null ? [] : v).map(function (x) { return String(x).trim(); }).filter(Boolean); }
function ldapCfg() { syncLdapFromDisk(); const l = Object.assign({}, LDAP_DEFAULTS, CFG.ldap || {}); l.servers = [].concat(l.servers || []); l.netbios = strList(l.netbios); l.upnSuffix = strList(l.upnSuffix).map(function (x) { return x.toLowerCase(); }); return l; }
function ldapOn() { const l = ldapCfg(); return !!(l.enabled && l.servers.length && l.baseDN && l.bindDN); }
function domainLabel() { const l = ldapCfg(); return l.netbios[0] || l.upnSuffix[0] || 'directory'; }
function ldapLog(level, msg, meta) { if (level === 'warn' || level === 'error') console.log('[as-auth] ' + msg + ' ' + JSON.stringify(meta || {})); }   /* meta: server + error text only */
/* "ASIC-HQ\alice" | "alice@asic-hq.com" | "alice" → {attr, value} for the user search; null = not a name for this domain */
function adIdentity(raw) {
  const l = ldapCfg(), s = String(raw || '').trim();
  if (!s || s.length > 256 || /[\u0000-\u001f]/.test(s)) return null;
  const m = /^([^\\]+)\\([^\\]+)$/.exec(s);
  if (m) { const d = m[1].toLowerCase(); if (!l.netbios.some(function (n) { return n.toLowerCase() === d; }) && l.upnSuffix.indexOf(d) < 0) return null; return { attr: l.userAttr, value: m[2] }; }
  if (s.indexOf('\\') >= 0) return null;
  const at = s.lastIndexOf('@');
  if (at >= 0) return at > 0 && l.upnSuffix.indexOf(s.slice(at + 1).toLowerCase()) >= 0 ? { attr: 'userPrincipalName', value: s } : null;
  return { attr: l.userAttr, value: s };
}
function shadowKey(sam) { return String(sam).toLowerCase() + '@' + (ldapCfg().upnSuffix[0] || 'ad'); }
function provisionalKey(id) { return id.attr === 'userPrincipalName' ? id.value.toLowerCase() : shadowKey(id.value); }
function normDN(dn) { return String(dn || '').toLowerCase().replace(/\s*,\s*/g, ',').replace(/\s*=\s*/g, '=').trim(); }
async function lockoutDuration(conn, l) {
  if (Date.now() - LOCKDUR.at < 3600e3) return LOCKDUR.ms;
  let ms = null;
  try { const r = await conn.search(l.baseDN, { scope: 'base', filter: '(objectClass=*)', attributes: ['lockoutDuration'] }); if (r.entries[0]) ms = ldapLib().ad.intervalToMs(ldapLib().ad.first(r.entries[0], 'lockoutDuration')); } catch (e) { if (e.transport) throw e; }
  LOCKDUR = { at: Date.now(), ms: ms }; return ms;
}
/* role = highest role among the mapped groups the user belongs to (nested: one IN_CHAIN query limited to the mapped DNs) */
async function adGroupRoles(conn, l, entry) {
  const lib = ldapLib(), map = {};
  Object.keys(l.groupRoles || {}).forEach(function (dn) { const r = l.groupRoles[dn]; if (RANK[r]) map[normDN(dn)] = { dn: dn, role: r }; });
  const keys = Object.keys(map); if (!keys.length) return { role: null, matched: [] };
  let dns;
  if (l.nested !== false) {
    const f = '(&(objectClass=group)(member:' + lib.OID.IN_CHAIN + ':=' + lib.escapeFilter(entry.dn) + ')(|' + keys.map(function (k) { return '(distinguishedName=' + lib.escapeFilter(map[k].dn) + ')'; }).join('') + '))';
    dns = (await conn.search(l.baseDN, { scope: 'sub', filter: f, attributes: ['distinguishedName'], pageSize: 1000 })).entries.map(function (x) { return x.dn; });
  } else dns = lib.ad.all(entry, 'memberOf');
  const matched = []; let best = null;
  dns.forEach(function (dn) { const m = map[normDN(dn)]; if (m) { matched.push({ dn: m.dn, role: m.role }); if (!best || RANK[m.role] > RANK[best]) best = m.role; } });
  return { role: best, matched: matched };
}
/* → {ok, reason, unauthorised?, pwChange?, info:{dn, sam, upn, name, mail, flags, groups, role}}; throws when the directory is unusable */
async function adAuthenticate(id, password) {
  const l = ldapCfg(), lib = ldapLib(), A = lib.ad;
  const bindPw = l.bindPassword ? dec(l.bindPassword) : null;
  if (!bindPw) throw new Error('the LDAP service-account password is not set or cannot be decrypted (as-auth-ldap.js --set-bind-password)');
  const client = lib.createClient({ servers: l.servers, caFile: l.caFile, timeoutMs: l.timeoutMs, log: ldapLog });
  return client.run(async function (conn) {
    try { await conn.bind(l.bindDN, bindPw); } catch (e) { if (e.transport) throw e; throw new Error('the LDAP service account could not bind: ' + e.message); }
    let r;
    try { r = await conn.search(l.baseDN, { scope: 'sub', filter: '(&(objectCategory=person)(objectClass=user)(' + id.attr + '=' + lib.escapeFilter(id.value) + '))', attributes: AD_USER_ATTRS, sizeLimit: 2 }); } catch (e) { if (e.code === 4) return { ok: false, reason: 'ambiguous account name' }; throw e; }
    const e = r.entries[0];
    if (!e) return { ok: false, reason: 'no such account' };
    if (r.entries.length > 1) return { ok: false, reason: 'ambiguous account name' };
    const now = Date.now(), info = { dn: e.dn, sam: A.first(e, 'sAMAccountName'), upn: A.first(e, 'userPrincipalName'), name: A.first(e, 'displayName') || A.first(e, 'sAMAccountName'), mail: A.first(e, 'mail') };
    if (!info.sam) return { ok: false, reason: 'account has no sAMAccountName', info: info };
    const uac = parseInt(A.first(e, 'userAccountControl'), 10) || 0, comp = parseInt(A.first(e, 'msDS-User-Account-Control-Computed'), 10) || 0;
    const expires = A.fileTimeToMs(A.first(e, 'accountExpires')), lockedAt = A.fileTimeToMs(A.first(e, 'lockoutTime'));
    const dur = lockedAt && !(comp & A.UAC.LOCKOUT) ? await lockoutDuration(conn, l) : null;
    info.flags = { disabled: !!(uac & A.UAC.ACCOUNTDISABLE), expired: !!(expires && expires <= now), expires: expires ? new Date(expires).toISOString() : 'never',
      locked: !!(comp & A.UAC.LOCKOUT) || !!(lockedAt && dur !== null && (dur === Infinity || lockedAt + dur > now)), lockoutTime: lockedAt ? new Date(lockedAt).toISOString() : null,
      passwordExpired: !!(comp & A.UAC.PASSWORD_EXPIRED), userAccountControl: uac };
    const g = await adGroupRoles(conn, l, e); info.groups = g.matched; info.role = g.role;
    if (info.flags.disabled) return { ok: false, reason: 'account disabled in AD', info: info };
    if (info.flags.expired) return { ok: false, reason: 'account expired in AD', info: info };
    if (info.flags.locked) return { ok: false, reason: 'account locked out in AD', info: info };
    try { await conn.bind(e.dn, password); } catch (err) {
      if (err.transport) throw err;
      if (err.code === 'EMPTY_PASSWORD') return { ok: false, reason: 'empty password refused', info: info };
      const c = err.adCode || '';
      if (c === '532' || c === '773') return { ok: false, pwChange: true, reason: c === '532' ? 'AD password expired' : 'AD password must be changed', info: info };
      return { ok: false, reason: 'AD rejected the password' + (c ? ' (data ' + c + ')' : ' (result ' + err.code + ')'), info: info };
    }
    info.bind = 'ok';
    if (!info.role) return { ok: false, unauthorised: true, reason: 'not in any mapped AD group', info: info };
    return { ok: true, info: info };
  });
}
/* local shadow record of an AD account: no password, role from AD groups, TOTP + throttling + audit reuse the local code */
function upsertShadow(info) {
  const key = shadowKey(info.sam); let u = userOf(key);
  if (u && u.source !== 'ad') return null;                 /* never take over a local account */
  const now = new Date().toISOString();
  if (!u) { u = { user: key, source: 'ad', created: now, createdBy: 'active-directory' }; CFG.users = CFG.users || []; CFG.users.push(u); audit({ event: 'user-provisioned', user: key, role: info.role, method: 'ad', reason: 'first AD sign-in · ' + info.dn }); }
  else if (u.role && u.role !== info.role) audit({ event: 'role-changed', user: key, role: info.role, method: 'ad', reason: u.role + ' → ' + info.role + ' (AD group membership)' });
  u.dn = info.dn; u.role = info.role; u.name = String(info.name || info.sam).slice(0, 80); u.upn = info.upn || ''; u.mail = info.mail || ''; u.adSeen = now;
  delete u.salt; delete u.passHash; delete u.breakglass; delete u.adBlocked;
  return u;
}
function adLogin(res, name, pw, ip) {
  const id = adIdentity(name), key = id ? provisionalKey(id) : (name || '?');
  const generic = function () { return page(res, 401, loginPage('Incorrect username or password.')); };
  if (locked(key)) { audit({ event: 'denied', user: key, ip: ip, method: 'ad', reason: 'account locked' }); return page(res, 423, loginPage('This account is temporarily locked after repeated failures. Try again in 15 minutes.')); }
  if (!id) { failed(key, ip); audit({ event: 'failure', user: key, ip: ip, method: 'ad', reason: 'domain not accepted' }); return generic(); }
  if (!pw) { failed(key, ip); audit({ event: 'failure', user: key, ip: ip, method: 'ad', reason: 'empty password refused' }); return generic(); }
  return adAuthenticate(id, pw).then(function (r) {
    const k = r.info && r.info.sam ? shadowKey(r.info.sam) : key;
    if (k !== key && locked(k)) { audit({ event: 'denied', user: k, ip: ip, method: 'ad', reason: 'account locked' }); return page(res, 423, loginPage('This account is temporarily locked after repeated failures. Try again in 15 minutes.')); }
    if (!r.ok) {
      const sh = r.info && r.info.sam ? userOf(k) : null;  /* AD says no longer allowed → end that account's sessions here too */
      if (sh && sh.source === 'ad' && (r.unauthorised || r.info.flags.disabled || r.info.flags.expired)) { sh.adBlocked = r.reason; saveLogged(); }
      if (r.unauthorised) { audit({ event: 'denied', user: k, ip: ip, method: 'ad', reason: r.reason }); return page(res, 403, loginPage('Your account has not been given access to this platform. Ask an administrator to add you to a SOC group.')); }
      failed(k, ip); audit({ event: 'failure', user: k, ip: ip, method: 'ad', reason: r.reason });
      if (r.pwChange) return page(res, 401, loginPage('Your ' + domainLabel() + ' password has expired or must be changed. Change it on a domain computer, then sign in again.'));
      return generic();
    }
    const u = upsertShadow(r.info);
    if (!u) { audit({ event: 'denied', user: k, ip: ip, method: 'ad', reason: 'a local account already uses this name' }); return generic(); }
    if (u.disabled) { saveLogged(); audit({ event: 'denied', user: u.user, ip: ip, method: 'ad', reason: 'account disabled on this platform' }); return page(res, 403, loginPage('This account is disabled. Contact an administrator.')); }
    delete FAIL[key]; delete FAIL[u.user]; save();
    return beginMfa(res, u, ip);
  }).catch(function (e) {
    audit({ event: 'ad-error', user: key, ip: ip, method: 'ad', reason: String((e && e.message) || e).slice(0, 300) });
    page(res, 503, loginPage('The ' + domainLabel() + ' directory cannot be reached right now. Try again shortly.'));
  });
}
function saveLogged() { try { save(); } catch (e) { console.log('[as-auth] config save failed: ' + e.message); } }
function methodFor(u, m) { return u && u.source === 'ad' ? String(m).replace(/^password/, 'ad') : m; }

/* ─────────── OpenID Connect ─────────── */
function httpsJSON(url, opts, body) {
  return new Promise(function (resolve, reject) {
    let u; try { u = new URL(url); } catch (e) { return reject(new Error('invalid URL')); }
    if (u.protocol !== 'https:') return reject(new Error('the identity provider must use HTTPS'));
    const req = https.request({ method: (opts && opts.method) || 'GET', hostname: u.hostname, port: u.port || 443, path: u.pathname + u.search, headers: Object.assign({ Accept: 'application/json' }, (opts && opts.headers) || {}), timeout: 10000 }, function (res) {
      let d = ''; res.on('data', function (c) { d += c; if (d.length > 2e6) req.destroy(); });
      res.on('end', function () { let j; try { j = JSON.parse(d); } catch (e) { return reject(new Error('invalid response from ' + u.hostname)); } if (res.statusCode >= 400) return reject(Object.assign(new Error(String(j.error_description || j.error || ('HTTP ' + res.statusCode)).slice(0, 300)), { status: res.statusCode, oauth: String(j.error || '').slice(0, 60) })); resolve(j); });
    });
    req.on('timeout', function () { req.destroy(new Error('identity provider timeout')); }); req.on('error', reject);
    if (body) req.write(body); req.end();
  });
}
let DISC = null, DISC_AT = 0, JWKS = null, JWKS_AT = 0;
async function discovery(force) {
  if (!force && DISC && Date.now() - DISC_AT < 3600e3 && DISC._iss === CFG.sso.issuer) return DISC;
  const d = await httpsJSON(String(CFG.sso.issuer || '').replace(/\/$/, '') + '/.well-known/openid-configuration');
  d._iss = CFG.sso.issuer; DISC = d; DISC_AT = Date.now(); JWKS = null; return d;
}
async function jwks(force) { if (!force && JWKS && Date.now() - JWKS_AT < 3600e3) return JWKS; const d = await discovery(); JWKS = await httpsJSON(d.jwks_uri); JWKS_AT = Date.now(); return JWKS; }
/* RSA JWK → PEM by hand: crypto.createPublicKey({ format: 'jwk' }) does not exist in Node 12 */
function derLen(n) { if (n < 128) return Buffer.from([n]); const b = []; while (n) { b.unshift(n & 255); n = n >>> 8; } return Buffer.from([0x80 | b.length].concat(b)); }
function der(tag, body) { return Buffer.concat([Buffer.from([tag]), derLen(body.length), body]); }
function derInt(buf) { if (buf[0] & 0x80) buf = Buffer.concat([Buffer.from([0]), buf]); return der(0x02, buf); }
function jwkToPem(k) {
  const rsaKey = der(0x30, Buffer.concat([derInt(ub64u(k.n)), derInt(ub64u(k.e))]));
  const algo = der(0x30, Buffer.concat([der(0x06, Buffer.from([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01])), Buffer.from([0x05, 0x00])]));
  const spki = der(0x30, Buffer.concat([algo, der(0x03, Buffer.concat([Buffer.from([0]), rsaKey]))]));
  return '-----BEGIN PUBLIC KEY-----\n' + spki.toString('base64').match(/.{1,64}/g).join('\n') + '\n-----END PUBLIC KEY-----\n';
}
async function verifyIdToken(tok, nonce, opts) {   /* opts.refresh: a token from the refresh-token grant carries no new nonce */
  const parts = String(tok || '').split('.'); if (parts.length !== 3) throw new Error('malformed id_token');
  const h = JSON.parse(ub64u(parts[0]).toString()), p = JSON.parse(ub64u(parts[1]).toString());
  if (h.alg !== 'RS256') throw new Error('unsupported token algorithm ' + h.alg);
  let set = await jwks(), key = (set.keys || []).filter(function (k) { return k.kid === h.kid; })[0];
  if (!key) { set = await jwks(true); key = (set.keys || []).filter(function (k) { return k.kid === h.kid; })[0]; }
  if (!key || key.kty !== 'RSA') throw new Error('signing key not found');
  if (!crypto.createVerify('RSA-SHA256').update(parts[0] + '.' + parts[1]).verify(jwkToPem(key), ub64u(parts[2]))) throw new Error('id_token signature invalid');
  const d = await discovery(), now = Math.floor(Date.now() / 1000);
  if (p.iss !== d.issuer) throw new Error('issuer mismatch');
  if (!(p.aud === CFG.sso.clientId || (Array.isArray(p.aud) && p.aud.indexOf(CFG.sso.clientId) >= 0))) throw new Error('audience mismatch');
  if (!p.exp || p.exp < now - 60) throw new Error('id_token expired');
  if (p.nbf && p.nbf > now + 60) throw new Error('id_token not yet valid');
  if (!(opts && opts.refresh) && p.nonce !== nonce) throw new Error('nonce mismatch');
  return p;
}
function mapRole(claims) {
  const vals = [].concat(claims[CFG.sso.roleClaim || 'roles'] || []), map = CFG.sso.roleMap || {}, rank = { admin: 3, operator: 2, viewer: 1 };
  let best = null; vals.forEach(function (v) { const r = map[v]; if (r && (!best || rank[r] > rank[best])) best = r; });
  return best || (CFG.sso.defaultRole && CFG.sso.defaultRole !== 'none' ? CFG.sso.defaultRole : null);
}
function hasMfa(c) { const amr = [].concat(c.amr || []); return amr.indexOf('mfa') >= 0 || amr.indexOf('otp') >= 0 || amr.indexOf('hwk') >= 0 || amr.indexOf('fido') >= 0 || /mfa|multi/i.test(String(c.acr || '')); }

/* ─────────── pages ─────────── */
function shell(inner, extraHead) {
  return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Arabian Shield — Sign in</title>' +
    '<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">' + (extraHead || '') + '<style>' +
    '*{box-sizing:border-box}html,body{margin:0;height:100%}body{font-family:Inter,system-ui,sans-serif;color:#E8EEF7;display:grid;grid-template-columns:1.15fr .85fr;min-height:100vh;background:#03100A}' +
    '.hero{position:relative;overflow:hidden;padding:56px 60px;display:flex;flex-direction:column;justify-content:center;background:radial-gradient(900px 520px at 70% -10%,rgba(129,165,63,.18),transparent 60%),radial-gradient(760px 480px at -10% 20%,rgba(0,96,47,.30),transparent 55%),linear-gradient(150deg,#00602F,#04120A 72%)}' +
    '.hero canvas{position:absolute;inset:0;width:100%;height:100%;opacity:.5}.hero .inner{position:relative;z-index:2;max-width:560px}.aslogo{width:250px;max-width:70%;background:#fff;border-radius:11px;padding:11px 14px;box-shadow:0 10px 26px rgba(0,0,0,.35);display:block}' +
    '.kicker{font-size:10.5px;letter-spacing:.22em;text-transform:uppercase;color:#9BC257;font-weight:700;margin:30px 0 14px}h1{font-size:34px;line-height:1.2;font-weight:800;margin:0 0 16px}.lead{color:#A9BFAE;font-size:14px;line-height:1.65;margin:0 0 26px}' +
    '.feat{display:flex;gap:14px;margin-bottom:13px;font-size:12.5px;color:#C3D2E6}.feat .lbl{flex:0 0 118px;color:#9BC257;font-weight:700}' +
    '.pane{display:grid;place-items:center;padding:40px;background:#050F0A;border-left:1px solid #14301F}form,.box{width:360px;max-width:90vw}h2{font-size:20px;font-weight:800;margin:0 0 4px}.sub{color:#7F93B3;font-size:11.5px;margin-bottom:22px}' +
    'label{font-size:11px;color:#8FA3C0;font-weight:600;display:block;margin:14px 0 6px}input{width:100%;background:#08170F;border:1px solid #1C3B27;border-radius:10px;padding:12px 13px;color:#E8EEF7;font-size:14px;font-family:inherit}' +
    'input:focus{outline:none;border-color:#81A53F;box-shadow:0 0 0 3px rgba(129,165,63,.2)}.otp{letter-spacing:.5em;text-align:center;font-size:22px;font-weight:800}' +
    'button,.btn{display:block;width:100%;margin-top:20px;background:linear-gradient(180deg,#81A53F,#00602F);border:none;border-radius:11px;padding:13px;color:#fff;font-size:14px;font-weight:800;cursor:pointer;text-align:center;text-decoration:none;box-shadow:0 8px 20px rgba(0,96,47,.38);font-family:inherit}' +
    '.sso{display:flex;align-items:center;justify-content:center;gap:10px;background:#fff;color:#1b1b1b;box-shadow:0 8px 20px rgba(0,0,0,.35)}.sso svg{width:18px;height:18px}' +
    '.or{display:flex;align-items:center;gap:10px;color:#56698A;font-size:11px;margin:20px 0 4px}.or:before,.or:after{content:"";flex:1;height:1px;background:#1C3B27}' +
    '.link{background:none!important;box-shadow:none!important;color:#9BC257;font-weight:600;font-size:12px;padding:6px;margin-top:10px}.alt{background:#10261a!important;box-shadow:none!important;border:1px solid #1C3B27}' +
    '.err{background:rgba(255,92,120,.12);border:1px solid rgba(255,92,120,.4);color:#FF9DB0;font-size:12px;padding:10px 12px;border-radius:9px;margin-bottom:8px}' +
    '.ok{background:rgba(129,165,63,.12);border:1px solid rgba(129,165,63,.4);color:#C9E7A0;font-size:12px;padding:10px 12px;border-radius:9px;margin-bottom:8px}' +
    '.qr{background:#fff;padding:12px;border-radius:12px;width:212px;min-height:212px;margin:10px auto}.mono{font-family:ui-monospace,Consolas,monospace;font-size:12.5px;word-break:break-all;background:#08170F;border:1px solid #1C3B27;border-radius:8px;padding:8px 10px;text-align:center}' +
    '.codes{display:grid;grid-template-columns:1fr 1fr;gap:6px;margin:8px 0}.codes span{font-family:ui-monospace,Consolas,monospace;background:#08170F;border:1px solid #1C3B27;border-radius:7px;padding:6px;text-align:center;font-size:13px}' +
    '.foot{text-align:center;color:#56698A;font-size:10.5px;margin-top:18px;line-height:1.7}.demo{display:inline-block;margin-top:6px;padding:3px 9px;border-radius:999px;background:rgba(129,165,63,.18);color:#9BC257;font-size:9.5px;font-weight:800;letter-spacing:.09em}' +
    '.steps{font-size:12px;color:#A9BFAE;line-height:1.7;margin:0 0 6px;padding-left:18px}.badges{display:flex;gap:6px;flex-wrap:wrap;justify-content:center;margin-top:12px}.badges span{font-size:10px;padding:3px 8px;border-radius:999px;border:1px solid #1C3B27;color:#8FA3C0}' +
    '@media(max-width:900px){body{grid-template-columns:1fr}.hero{display:none}}</style></head><body>' +
    '<div class="hero"><canvas id="rdr"></canvas><div class="inner"><img class="aslogo" src="/logo.webp" alt="Arabian Shield Cooperative Insurance"><div class="kicker">Insurance · Regulated by SAMA &amp; the Insurance Authority</div>' +
    '<h1>One window over every branch,<br>every control, every risk.</h1><p class="lead">Continuous monitoring of the head office, the data centres, the DR site and every branch — with SAMA CSF, IA, NCA ECC, NDMO, PDPL and ISO 27001 evidence produced as you operate.</p>' +
    '<div class="feat"><span class="lbl">Single sign-on</span><span>Your corporate identity with multi-factor authentication.</span></div>' +
    '<div class="feat"><span class="lbl">Zero trust</span><span>Every session verified; privileged actions pass the guardrails and a second approver.</span></div>' +
    '<div class="feat"><span class="lbl">Autopilot</span><span>Agents watch the estate around the clock and act within the policy you set.</span></div></div></div>' +
    '<div class="pane">' + inner + '</div><script>(function(){var c=document.getElementById("rdr");if(!c||!c.getContext)return;var x=c.getContext("2d"),w,h,t=0;function s(){w=c.width=c.offsetWidth;h=c.height=c.offsetHeight}s();addEventListener("resize",s);var p=[];for(var i=0;i<34;i++)p.push({x:Math.random(),y:Math.random(),s:.15+Math.random()*.5});' +
    '(function l(){t+=.004;x.clearRect(0,0,w,h);for(var i=0;i<p.length;i++){var a=p[i],ax=(a.x+Math.sin(t*a.s)*.02)*w,ay=(a.y+Math.cos(t*a.s)*.02)*h;for(var j=i+1;j<p.length;j++){var b=p[j],bx=(b.x+Math.sin(t*b.s)*.02)*w,by=(b.y+Math.cos(t*b.s)*.02)*h,d=Math.hypot(ax-bx,ay-by);if(d<w*.16){x.strokeStyle="rgba(129,165,63,"+(.1*(1-d/(w*.16)))+")";x.beginPath();x.moveTo(ax,ay);x.lineTo(bx,by);x.stroke()}}x.fillStyle="rgba(143,180,217,.5)";x.beginPath();x.arc(ax,ay,1.6,0,6.3);x.fill()}requestAnimationFrame(l)})()})();</script></body></html>';
}
const MS = '<svg viewBox="0 0 23 23"><path fill="#f35325" d="M1 1h10v10H1z"/><path fill="#81bc06" d="M12 1h10v10H12z"/><path fill="#05a6f0" d="M1 12h10v10H1z"/><path fill="#ffba08" d="M12 12h10v10H12z"/></svg>';
function ssoOn() { return !!(CFG.sso.enabled && CFG.sso.issuer && CFG.sso.clientId && CFG.sso.redirectUri); }
function adPlaceholder() { const l = ldapCfg(); return (l.netbios[0] ? l.netbios[0] + '\\username' : 'username') + (l.upnSuffix[0] ? ' or username@' + l.upnSuffix[0] : ''); }
function loginPage(err, info) {
  const sso = ssoOn(), local = CFG.localLogin !== 'breakglass', ad = ldapOn();
  return shell('<form method="POST" action="/login" autocomplete="on"><img class="aslogo" style="width:200px;margin:0 0 18px" src="/logo.webp" alt="Arabian Shield"><h2>Sign in</h2><div class="sub">Authorized personnel only · multi-factor authentication</div>' +
    (err ? '<div class="err">' + esc(err) + '</div>' : '') + (info ? '<div class="ok">' + esc(info) + '</div>' : '') +
    (sso ? '<a class="btn sso" href="/auth/sso/start">' + (/microsoft|entra|azure/i.test(CFG.sso.provider) ? MS : '🔐') + ' Sign in with ' + esc(CFG.sso.provider || 'single sign-on') + '</a><div class="or">' + (local ? 'or use a local account' : 'break-glass account') + '</div>' : '') +
    (ad ? '<div class="sub" style="margin:-10px 0 12px;color:#9BC257;font-weight:600">' + esc(ldapCfg().hint || ('Sign in with your ' + domainLabel() + ' account')) + '</div>' : '') +
    '<label>Username</label><input name="user" autocomplete="username"' + (ad ? ' placeholder="' + esc(adPlaceholder()) + '"' : '') + (sso ? '' : ' autofocus') + '><label>Password</label><input name="pass" type="password" autocomplete="current-password">' +
    '<button type="submit"' + (sso ? ' class="alt"' : '') + '>Sign in' + (sso ? (ad ? ' with your ' + esc(domainLabel()) + ' account' : ' with a local account') : '') + '</button>' +
    '<div class="badges"><span>🔐 ' + (sso ? 'SSO · ' + esc(CFG.sso.provider) : ad ? esc(domainLabel()) + ' directory' : 'Local accounts') + '</span><span>📱 MFA ' + esc(mfaMandatory() ? 'required for everyone' : CFG.mfaPolicy === 'all' ? 'for everyone' : CFG.mfaPolicy === 'admins' ? 'for administrators' : 'available') + '</span><span>🛡️ Lockout after 5 failures</span></div>' +
    '<div class="foot">Arabian Shield Cooperative Insurance<br><span class="demo">POC ENVIRONMENT · SAMPLE DATA</span></div></form>');
}
function otpPage(err) {
  return shell('<form method="POST" action="/login/otp" autocomplete="off"><h2>Two-step verification</h2><div class="sub">Enter the 6-digit code from your authenticator app</div>' + (err ? '<div class="err">' + esc(err) + '</div>' : '') +
    '<label>Verification code</label><input class="otp" name="code" inputmode="numeric" maxlength="7" autocomplete="one-time-code" autofocus>' +
    '<button type="submit">Verify</button><div class="or">lost your phone?</div><label>Recovery code</label><input name="recovery" placeholder="xxxx-xxxx" autocomplete="off"><button class="link" type="submit">Use a recovery code</button>' +
    '<a class="btn link" href="/login">Cancel</a></form>');
}
function enrolPage(user, secret, err, grace) {
  const uri = 'otpauth://totp/' + encodeURIComponent('Arabian Shield:' + user) + '?secret=' + secret + '&issuer=' + encodeURIComponent('Arabian Shield') + '&algorithm=SHA1&digits=6&period=30';
  const banner = grace ? '<div class="ok">Two-step verification is now required for every account. You have ' + grace.left + ' day' + (grace.left === 1 ? '' : 's') + ' left to set it up — after that you will not be able to sign in until it is on.</div>' : '';
  /* the grace "continue for now" control is a time-boxed, audited admit — not the old unconditional skip. The server
     re-checks the window on POST /login/grace, so it cannot be used once the window has closed. */
  const cont = grace ? '<form method="POST" action="/login/grace" autocomplete="off" style="margin:0"><button class="link" type="submit">Continue for now — set it up later</button></form>' : '';
  return shell('<form method="POST" action="/login/enrol" autocomplete="off"><h2>Set up two-step verification</h2><div class="sub">' + (err ? '' : 'Protect your account with your phone') + '</div>' + banner + (err ? '<div class="err">' + esc(err) + '</div>' : '') +
    '<ol class="steps"><li>Open Microsoft Authenticator, Google Authenticator or any TOTP app.</li><li>Scan the code — or enter the key below.</li><li>Type the 6-digit code it shows.</li></ol>' +
    '<div class="qr" id="qr"></div><div class="mono">' + esc(secret.replace(/(.{4})/g, '$1 ').trim()) + '</div>' +
    '<label>Verification code</label><input class="otp" name="code" inputmode="numeric" maxlength="7" autocomplete="one-time-code" autofocus><button type="submit">Turn on two-step verification</button></form>' + cont + '<a class="btn link" href="/login">Cancel</a>',
    '<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script><script>addEventListener("DOMContentLoaded",function(){try{new QRCode(document.getElementById("qr"),{text:' + JSON.stringify(uri) + ',width:188,height:188,correctLevel:QRCode.CorrectLevel.M})}catch(e){}});</script>');
}
function codesPage(codes) {
  return shell('<div class="box"><h2>Save your recovery codes</h2><div class="sub">Each code works once if you lose your authenticator. They will not be shown again.</div><div class="ok">Two-step verification is on.</div>' +
    '<div class="codes">' + codes.map(function (c) { return '<span>' + esc(c) + '</span>'; }).join('') + '</div><a class="btn" href="/">Continue to the platform</a></div>');
}

/* ─────────── sign-in completion ─────────── */
function page(res, code, html, cookies) { const h = { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer' }; if (cookies) h['Set-Cookie'] = cookies; res.writeHead(code, h); res.end(html); }
function finish(res, u, method, mfa, ip) {
  method = methodFor(u, method);
  u.lastLogin = new Date().toISOString(); u.lastMethod = method; try { save(); } catch (e) {}
  audit({ event: 'sign-in', user: u.user, role: u.role, method: method, mfa: !!mfa, ip: ip });
  res.writeHead(302, { 'Set-Cookie': [makeSession({ u: u.user, r: u.role || 'operator', name: u.name || u.user, m: method, mfa: !!mfa }, { ip: ip }), clearCookie('as_pend')], Location: '/' }); res.end();
}
function newCodes(u) { const codes = []; u.recovery = []; for (let i = 0; i < 8; i++) { const c = crypto.randomBytes(4).toString('hex').replace(/^(.{4})/, '$1-'); codes.push(c); u.recovery.push(crypto.createHash('sha256').update(c).digest('hex')); } return codes; }
/* every successful password / AD bind lands here. Enrolled → TOTP code. Not enrolled and MFA required → enrolment screen,
   with a bounded grace admit offered while the window is open. Exempt (only when an admin turned the mandate off) → straight
   in. The method 'password' is rewritten to 'ad' by methodFor() for directory accounts. */
function beginMfa(res, u, ip) {
  if (u.totp) return page(res, 200, otpPage(''), setCookie('as_pend', signed({ u: u.user, s: 'otp' }, 5), 300));
  if (!mfaRequired(u)) return finish(res, u, 'password', false, ip);
  if (!u.mfaGraceStart) { u.mfaGraceStart = new Date().toISOString(); saveLogged(); }
  const st = mfaStatus(u), sec = b32enc(crypto.randomBytes(20));
  const grace = st.state === 'grace' ? { left: graceLeft(st.deadline), deadline: st.deadline } : null;
  const pend = { u: u.user, s: 'enrol', k: enc(sec), g: grace ? 1 : undefined };
  return page(res, 200, enrolPage(u.user, sec, '', grace), setCookie('as_pend', signed(pend, 10), 600));
}
function sameOrigin(req) { const o = req.headers.origin || req.headers.referer || ''; if (!o) return true; try { return new URL(o).host === req.headers.host; } catch (e) { return false; } }

const server = http.createServer(function (req, res) {
  const url = req.url.split('?')[0], qs = new URLSearchParams(req.url.split('?')[1] || ''), sess = session(req), ip = ipOf(req);

  if (url === '/auth/verify') {
    const ok = function (s) { res.writeHead(200, { 'X-Auth-Role': s.r || 'viewer', 'X-Auth-User': s.u || '' }); res.end('ok'); }, no = function () { res.writeHead(401); res.end('no'); };
    if (!sess) return no();
    if (sess.m === 'sso' && (ssoDue(sess.sid) || RECHECK[sess.sid])) return ssoRecheck(sess.sid).then(function (alive) { const r = SIDS[sess.sid]; if (!alive || !r) return no(); sess.r = r.r || sess.r; ok(sess); });   /* a due check answers before the request goes through */
    return ok(sess);
  }
  if (url === '/logout' || url === '/auth/logout') { if (sess) { audit({ event: 'sign-out', user: sess.u, ip: ip }); endSession(sess.sid, 'signed out'); } res.writeHead(302, { 'Set-Cookie': clearCookie('as_session'), Location: '/login' }); return res.end(); }
  if (url === '/auth/whoami') { if (!sess) return json(res, 401, { error: 'not signed in' }); const u = userOf(sess.u); const ms = u ? mfaStatus(u) : null; return json(res, 200, { user: sess.u, role: sess.r, name: sess.name, method: sess.m || 'password', mfa: !!sess.mfa, mfaPending: !!sess.mfaPending, mfaEnrolled: !!(u && u.totp), mfaState: ms ? ms.state : (sess.m === 'sso' ? 'sso' : 'enrolled'), mfaDeadline: ms ? ms.deadline : null, local: !!u, source: u ? (u.source || 'local') : (sess.m === 'sso' ? 'sso' : 'local'), org: 'Arabian Shield Cooperative Insurance' }); }

  /* ── standalone sign-in ── */
  if (url === '/login' && req.method !== 'POST') return page(res, 200, loginPage(''));
  if (url === '/login' && req.method === 'POST') {
    return readBody(req, function (b) {
      const p = new URLSearchParams(b), name = String(p.get('user') || '').toLowerCase().trim(), u = userOf(name);
      if (ipBlocked(ip)) { audit({ event: 'blocked', user: name, ip: ip, reason: 'too many failures from this address' }); return page(res, 429, loginPage('Too many attempts from this address. Try again in a few minutes.')); }
      if (u ? u.source === 'ad' : (ldapOn() && !!adIdentity(name))) {          /* Active Directory account */
        if (ldapOn()) return adLogin(res, name, p.get('pass') || '', ip);
        failed(name, ip); audit({ event: 'failure', user: name, ip: ip, method: 'ad', reason: 'directory sign-in is disabled' }); return page(res, 401, loginPage('Incorrect username or password.'));
      }
      if (u && locked(u.user)) { audit({ event: 'denied', user: name, ip: ip, reason: 'account locked' }); return page(res, 423, loginPage('This account is temporarily locked after repeated failures. Try again in 15 minutes.')); }
      if (!u || !u.passHash || !eqHex(hashPw(p.get('pass') || '', u.salt), u.passHash)) { failed(name || '?', ip); audit({ event: 'failure', user: name, ip: ip, method: 'password' }); return page(res, 401, loginPage('Incorrect username or password.')); }
      if (u.disabled) { audit({ event: 'denied', user: name, ip: ip, reason: 'account disabled' }); return page(res, 403, loginPage('This account is disabled. Contact an administrator.')); }
      if (CFG.localLogin === 'breakglass' && !u.breakglass) { audit({ event: 'denied', user: name, ip: ip, reason: 'local sign-in limited to break-glass accounts' }); return page(res, 403, loginPage('Please sign in with single sign-on.')); }
      delete FAIL[u.user];
      return beginMfa(res, u, ip);
    });
  }
  if (url === '/login/otp' && req.method === 'POST') {
    return readBody(req, function (b) {
      const pend = unsign(cookie(req.headers.cookie, 'as_pend')), p = new URLSearchParams(b);
      if (!pend || pend.s !== 'otp') return page(res, 401, loginPage('Your sign-in expired — start again.'));
      const u = userOf(pend.u); if (!u || !u.totp || u.disabled || u.adBlocked) return page(res, 401, loginPage('Sign-in failed.'));
      if (locked(u.user)) return page(res, 423, loginPage('This account is temporarily locked after repeated failures.'));
      const rec = String(p.get('recovery') || '').trim().toLowerCase();
      if (rec) {
        const h = crypto.createHash('sha256').update(rec).digest('hex'), i = (u.recovery || []).indexOf(h);
        if (i >= 0) { u.recovery.splice(i, 1); audit({ event: 'recovery-code-used', user: u.user, ip: ip, reason: u.recovery.length + ' left' }); return finish(res, u, 'password+recovery', true, ip); }
        failed(u.user, ip); audit({ event: 'mfa-fail', user: u.user, ip: ip, method: 'recovery-code' }); return page(res, 401, otpPage('That recovery code is not valid.'));
      }
      const secret = dec(u.totp), step = secret ? totpCheck(secret, p.get('code'), u.totpStep) : -1;
      if (step < 0) { failed(u.user, ip); audit({ event: 'mfa-fail', user: u.user, ip: ip, method: 'totp' }); return page(res, 401, otpPage('That code is not right — check the time on your phone and try again.')); }
      u.totpStep = step; audit({ event: 'mfa-pass', user: u.user, ip: ip, method: 'totp' }); finish(res, u, 'password+totp', true, ip);
    });
  }
  if (url === '/login/enrol' && req.method === 'POST') {
    return readBody(req, function (b) {
      const pend = unsign(cookie(req.headers.cookie, 'as_pend')), p = new URLSearchParams(b);
      if (!pend || pend.s !== 'enrol') return page(res, 401, loginPage('The set-up expired — sign in again.'));
      const u = userOf(pend.u), sec = dec(pend.k); if (!u || !sec || u.disabled || u.adBlocked) return page(res, 401, loginPage('Set-up failed.'));
      if (locked(u.user)) return page(res, 423, loginPage('This account is temporarily locked after repeated failures. Try again in 15 minutes.'));
      const step = totpCheck(sec, p.get('code'), 0);
      if (step < 0) {
        failed(u.user, ip); audit({ event: 'mfa-fail', user: u.user, ip: ip, method: 'totp-enrol' });
        const gs = mfaStatus(u), g2 = gs.state === 'grace' ? { left: graceLeft(gs.deadline), deadline: gs.deadline } : null;
        return page(res, 401, enrolPage(u.user, sec, 'That code is not right — try the next one your app shows.', g2), setCookie('as_pend', signed({ u: u.user, s: 'enrol', k: pend.k, g: g2 ? 1 : undefined }, 10), 600));
      }
      delete u.mfaGraceStart; u.totp = enc(sec); u.totpStep = step; u.mfaSince = new Date().toISOString(); const codes = newCodes(u);
      const mth = methodFor(u, 'password+totp'); u.lastLogin = new Date().toISOString(); u.lastMethod = mth; save();
      audit({ event: 'mfa-enrol', user: u.user, ip: ip, method: 'totp' }); audit({ event: 'sign-in', user: u.user, role: u.role, method: mth, mfa: true, ip: ip });
      return page(res, 200, codesPage(codes), [makeSession({ u: u.user, r: u.role || 'operator', name: u.name || u.user, m: mth, mfa: true }), clearCookie('as_pend')]);
    });
  }
  /* bounded enrolment-grace admit: issues a session WITHOUT TOTP, but only while the grace window is still open and only
     straight after a successful password / AD bind (the as_pend 'enrol' cookie with g=1). The window is re-checked here on
     the server, so a stale cookie cannot be used once grace has closed. */
  if (url === '/login/grace' && req.method === 'POST') {
    return readBody(req, function () {
      const pend = unsign(cookie(req.headers.cookie, 'as_pend'));
      if (!pend || pend.s !== 'enrol' || !pend.g) return page(res, 401, loginPage('Your sign-in expired — start again.'));
      const u = userOf(pend.u); if (!u || u.disabled || u.adBlocked || u.totp) return page(res, 401, loginPage('Sign-in failed.'));
      const st = mfaStatus(u);
      if (st.state !== 'grace') { audit({ event: 'mfa-fail', user: u.user, ip: ip, method: 'grace', reason: 'grace window closed — enrolment required' }); return beginMfa(res, u, ip); }
      const mth = methodFor(u, 'password');
      u.lastLogin = new Date().toISOString(); u.lastMethod = mth + '+grace'; saveLogged();
      audit({ event: 'grace-admit', user: u.user, role: u.role, method: mth, ip: ip, reason: graceLeft(st.deadline) + ' day(s) left · enrol by ' + st.deadline });
      res.writeHead(302, { 'Set-Cookie': [makeSession({ u: u.user, r: u.role || 'operator', name: u.name || u.user, m: mth, mfa: false, mfaPending: true }), clearCookie('as_pend')], Location: '/' }); res.end();
    });
  }
  if (url === '/auth/mfa/setup') {
    if (!sess) { res.writeHead(302, { Location: '/login' }); return res.end(); }
    const u = userOf(sess.u); if (!u) return page(res, 400, loginPage('Single sign-on accounts use the MFA of your identity provider.'));
    const sec = b32enc(crypto.randomBytes(20)); return page(res, 200, enrolPage(u.user, sec, ''), setCookie('as_pend', signed({ u: u.user, s: 'enrol', k: enc(sec) }, 10), 600));
  }

  /* ── single sign-on (OpenID Connect) ── */
  if (url === '/auth/sso/start') {
    if (!ssoOn()) return page(res, 400, loginPage('Single sign-on is not configured.'));
    return discovery().then(function (d) {
      const state = b64u(crypto.randomBytes(18)), nonce = b64u(crypto.randomBytes(18)), verifier = b64u(crypto.randomBytes(32)), challenge = b64u(crypto.createHash('sha256').update(verifier).digest());
      const q = new URLSearchParams({ client_id: CFG.sso.clientId, response_type: 'code', redirect_uri: CFG.sso.redirectUri, scope: ssoScopes(), state: state, nonce: nonce, code_challenge: challenge, code_challenge_method: 'S256', response_mode: 'query' });
      if (CFG.sso.requireMfa && /microsoft|entra|azure/i.test(CFG.sso.provider || '')) q.set('claims', JSON.stringify({ id_token: { amr: { essential: true } } }));
      res.writeHead(302, { 'Set-Cookie': setCookie('as_sso', signed({ st: state, n: nonce, v: verifier }, 10), 600), Location: d.authorization_endpoint + '?' + q.toString() }); res.end();
    }).catch(function (e) { audit({ event: 'sso-error', ip: ip, reason: e.message }); page(res, 502, loginPage('Could not reach the identity provider: ' + e.message)); });
  }
  if (url === '/auth/sso/callback') {
    const st = unsign(cookie(req.headers.cookie, 'as_sso'));
    if (qs.get('error')) { const why = String(qs.get('error_description') || qs.get('error')).slice(0, 160); audit({ event: 'sso-denied', ip: ip, reason: why }); return page(res, 401, loginPage('Single sign-on was not completed: ' + why), clearCookie('as_sso')); }
    if (!st || !qs.get('code') || qs.get('state') !== st.st) { audit({ event: 'sso-denied', ip: ip, reason: 'state mismatch or expired' }); return page(res, 401, loginPage('Single sign-on expired — try again.'), clearCookie('as_sso')); }
    let tok = null;
    return discovery().then(function (d) {
      const body = new URLSearchParams({ grant_type: 'authorization_code', code: qs.get('code'), redirect_uri: CFG.sso.redirectUri, client_id: CFG.sso.clientId, code_verifier: st.v });
      const secret = CFG.sso.clientSecret ? dec(CFG.sso.clientSecret) : null; if (secret) body.set('client_secret', secret);
      return httpsJSON(d.token_endpoint, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }, body.toString());
    }).then(function (t) { tok = t; return verifyIdToken(t.id_token, st.n); }).then(function (c) {
      const email = String(c.preferred_username || c.email || c.upn || c.sub || '').toLowerCase();
      const dom = String(CFG.sso.allowedDomains || '').split(/[,\s]+/).filter(Boolean);
      if (dom.length && !dom.some(function (x) { return email.slice(-x.length - 1) === '@' + x.toLowerCase(); })) { audit({ event: 'sso-denied', user: email, ip: ip, reason: 'domain not allowed' }); return page(res, 403, loginPage('Your organisation is not allowed to sign in here.'), clearCookie('as_sso')); }
      if (CFG.sso.requireMfa && !hasMfa(c)) { audit({ event: 'sso-denied', user: email, ip: ip, reason: 'no MFA in token (amr ' + JSON.stringify(c.amr || []) + ')' }); return page(res, 403, loginPage('Multi-factor authentication is required. Sign in again and complete MFA with your identity provider.'), clearCookie('as_sso')); }
      const role = mapRole(c);
      if (!role) { audit({ event: 'sso-denied', user: email, ip: ip, reason: 'no role assigned' }); return page(res, 403, loginPage('Your account has not been given access to this platform. Ask an administrator to assign you a role.'), clearCookie('as_sso')); }
      audit({ event: 'sign-in', user: email, role: role, method: 'sso', mfa: hasMfa(c), ip: ip });
      res.writeHead(302, { 'Set-Cookie': [makeSession({ u: email, r: role, name: c.name || email, m: 'sso', mfa: hasMfa(c) }, { sub: c.sub, rt: tok.refresh_token, ip: ip }), clearCookie('as_sso')], Location: '/' }); res.end();
    }).catch(function (e) { audit({ event: 'sso-error', ip: ip, reason: e.message }); page(res, 401, loginPage('Single sign-on failed: ' + e.message), clearCookie('as_sso')); });
  }

  /* ── patch-ss-org: organisation settings and records store ── */
  if (url === '/auth/org' && req.method === 'GET') {
    if (!sess) return json(res, 401, { error: 'not signed in' });
    const o = CFG.org || {};
    return json(res, 200, { modules: Array.isArray(o.modules) ? o.modules : null, edition: o.edition || '', resp: o.resp || {}, roles: o.roles || [], assign: o.assign || {}, updated: o.updated || null, by: o.by || '' });
  }
  const sm = /^\/auth\/store\/([a-z0-9-]{2,40})$/.exec(url);
  if (sm) {
    if (!sess) return json(res, 401, { error: 'not signed in' });
    const dir = '/var/lib/arabianshield-auth/store'; try { fs.mkdirSync(dir, { recursive: true, mode: 0o700 }); } catch (e) {}
    const F = dir + '/' + sm[1] + '.json';
    const readS = function () { try { return JSON.parse(fs.readFileSync(F, 'utf8')); } catch (e) { return { updated: null, by: '', data: null, log: [] }; } };
    if (req.method === 'GET') return json(res, 200, readS());
    if (req.method !== 'POST') return json(res, 405, { error: 'method not allowed' });
    if (sess.r !== 'admin' && sess.r !== 'operator') return json(res, 403, { error: 'operators and administrators only' });
    if (!sameOrigin(req)) return json(res, 403, { error: 'cross-origin request refused' });
    let raw = '', big = false;
    req.on('data', function (c) { raw += c; if (raw.length > 900000) { big = true; req.destroy(); } });
    return req.on('end', function () {
      if (big) return json(res, 413, { error: 'too large' });
      let b = {}; try { b = JSON.parse(raw || '{}'); } catch (e) { return json(res, 400, { error: 'bad JSON' }); }
      const cur = readS();
      if (cur.updated && b.base !== cur.updated) return json(res, 409, { error: 'changed', current: cur });
      const now = new Date().toISOString(), t = function (x, n) { return String(x == null ? '' : x).slice(0, n); };
      const ch = [].concat(b.change || []).filter(function (c) { return c && typeof c === 'object'; }).slice(0, 20).map(function (c) { return { at: now, by: sess.u, action: t(c.action, 60), target: t(c.target, 120), detail: t(c.detail, 300) }; });
      const rec = { updated: now, by: sess.u, data: b.data === undefined ? null : b.data, log: (Array.isArray(cur.log) ? cur.log : []).concat(ch).slice(-1000) };
      try { fs.writeFileSync(F + '.tmp', JSON.stringify(rec), { mode: 0o600 }); fs.renameSync(F + '.tmp', F); } catch (e) { return json(res, 500, { error: 'write failed' }); }
      audit({ event: 'store-update', user: sess.u, ip: ip, reason: sm[1] + ': ' + ch.map(function (c) { return c.action + ' ' + c.target; }).join('; ').slice(0, 200) });
      return json(res, 200, { ok: true, doc: rec });
    });
  }

  /* ── administration (admin session, same origin) ── */
  if (url.indexOf('/auth/admin/') === 0) {
    if (!sess || sess.r !== 'admin') return json(res, 403, { error: 'admin only' });
    if (req.method === 'GET' && url === '/auth/admin/config') {
      const s = CFG.sso;
      return json(res, 200, { sso: { enabled: !!s.enabled, provider: s.provider, issuer: s.issuer, clientId: s.clientId, hasSecret: !!s.clientSecret, redirectUri: s.redirectUri || ('https://' + req.headers.host + '/auth/sso/callback'), scopes: s.scopes, roleClaim: s.roleClaim, roleMap: s.roleMap || {}, defaultRole: s.defaultRole, requireMfa: s.requireMfa !== false, allowedDomains: s.allowedDomains || '' },
        mfaPolicy: CFG.mfaPolicy, mfaRequired: mfaMandatory(), mfaGraceDays: graceDays(), mfaPolicyActivated: CFG.mfaPolicyActivated || null, localLogin: CFG.localLogin, hours: HOURS,
        users: (CFG.users || []).map(function (u) { const ms = mfaStatus(u); return { user: u.user, name: u.name, role: u.role, mfa: !!u.totp, mfaSetting: u.mfa || 'policy', mfaRequired: mfaRequired(u), mfaState: ms.state, mfaGraceStart: u.mfaGraceStart || null, mfaDeadline: ms.deadline, disabled: !!u.disabled, created: u.created || null, createdBy: u.createdBy || null, mfaSince: u.mfaSince || null, recoveryLeft: (u.recovery || []).length, breakglass: !!u.breakglass, lastLogin: u.lastLogin || null, lastMethod: u.lastMethod || null, locked: locked(u.user), source: u.source || 'local', dn: u.dn || undefined, adBlocked: u.adBlocked || undefined }; }),
        ldap: (function () { const l = ldapCfg(); return { enabled: !!l.enabled, active: ldapOn(), servers: l.servers, caFile: l.caFile, baseDN: l.baseDN, bindDN: l.bindDN, hasBindPassword: !!l.bindPassword, netbios: l.netbios, upnSuffix: l.upnSuffix, userAttr: l.userAttr, groupRoles: l.groupRoles || {}, nested: l.nested !== false, requireMfa: l.requireMfa !== false }; })(),
        session: sessCfg(), sessionsActive: Object.keys(SIDS).length,
        events: recentEvents(150), me: sess.u });
    }
    if (req.method === 'GET' && url === '/auth/admin/sessions') {   /* who is signed in now - never the tokens */
      const t = Date.now();
      return json(res, 200, { settings: sessCfg(), sessions: Object.keys(SIDS).filter(function (k) { return SIDS[k] && SIDS[k].exp > t; }).map(function (k) { const r = SIDS[k];
        return { id: k.slice(0, 8), user: r.u, method: r.m, role: r.r, ip: r.ip || '', since: new Date(r.iat).toISOString(), lastSeen: new Date(r.last || r.iat).toISOString(), expires: new Date(r.exp).toISOString(),
          sso: r.m === 'sso' ? { refresh: !!r.rt, nextCheck: r.chk ? new Date(r.chk).toISOString() : null, failingSince: r.fail ? new Date(r.fail).toISOString() : null } : undefined, current: k === sess.sid }; }) });
    }
    if (req.method !== 'POST') return json(res, 405, { error: 'method not allowed' });
    if (!sameOrigin(req)) return json(res, 403, { error: 'cross-origin request refused' });
    return readBody(req, function (raw) {
      let b = {}; try { b = JSON.parse(raw || '{}'); } catch (e) { return json(res, 400, { error: 'bad JSON' }); }
      if (url === '/auth/admin/org') {                        /* patch-ss-org: module subscription + responsibilities */
        const cur = CFG.org || {};
        if (cur.updated && b.base !== cur.updated) return json(res, 409, { error: 'changed', current: { modules: Array.isArray(cur.modules) ? cur.modules : null, edition: cur.edition || '', resp: cur.resp || {}, roles: cur.roles || [], assign: cur.assign || {}, updated: cur.updated, by: cur.by || '' } });
        let modules = null;
        if (Array.isArray(b.modules)) modules = Array.from(new Set(b.modules.map(String))).filter(function (x) { return /^[a-z0-9-]{2,40}$/.test(x); }).slice(0, 300);
        const resp = {}, rin = (b.resp && typeof b.resp === 'object') ? b.resp : {};
        Object.keys(rin).slice(0, 400).forEach(function (k) { if (!/^[a-z0-9:_.-]{1,60}$/.test(k)) return; const v = rin[k] || {}, t = function (x) { return String(x == null ? '' : x).slice(0, 300); };
          const e = { r: t(v.r), a: t(v.a), c: t(v.c), i: t(v.i) }; if (e.r || e.a || e.c || e.i) resp[k] = e; });
        const t9=function(x,n){ return String(x==null?'':x).slice(0,n); };
    const LV={none:1,view:1,edit:1,approve:1}; const roles=[]; const seenR={};
    (Array.isArray(b.roles)?b.roles:[]).slice(0,50).forEach(function(r){ if(!r||typeof r!=='object') return; const id=t9(r.id,40); if(!/^[a-z0-9-]{2,40}$/.test(id)||seenR[id]) return; seenR[id]=1;
      const perms={}; const pin=(r.perms&&typeof r.perms==='object')?r.perms:{}; Object.keys(pin).slice(0,300).forEach(function(m){ if(/^[a-z0-9-]{2,40}$/.test(m)&&LV[pin[m]]) perms[m]=pin[m]; });
      roles.push({ id:id, name:t9(r.name,60)||id, base:(r.base==='operator'?'operator':'viewer'), desc:t9(r.desc,200), perms:perms }); });
    const assign={}; const ain=(b.assign&&typeof b.assign==='object')?b.assign:{};
    Object.keys(ain).slice(0,2000).forEach(function(u){ const rid=String(ain[u]||''); if(u.length<=200&&seenR[rid]) assign[u]=rid; });
        CFG.org = { modules: modules, edition: String(b.edition || '').slice(0, 30), resp: resp, roles: roles, assign: assign, updated: new Date().toISOString(), by: sess.u }; save();
        audit({ event: 'org-updated', user: sess.u, ip: ip, reason: (modules ? modules.length + ' modules' : 'all modules') + (CFG.org.edition ? ' · ' + CFG.org.edition : '') + ' · ' + Object.keys(resp).length + ' responsibilities · ' + roles.length + ' custom roles · ' + Object.keys(assign).length + ' assignments' });
        return json(res, 200, { ok: true, doc: { modules: CFG.org.modules, edition: CFG.org.edition, resp: CFG.org.resp, roles: CFG.org.roles, assign: CFG.org.assign, updated: CFG.org.updated, by: CFG.org.by } });
      }
      if (url === '/auth/admin/sso') {
        const s = CFG.sso;
        if (b.issuer != null) { if (b.issuer && !/^https:\/\/\S+$/.test(b.issuer)) return json(res, 400, { error: 'the issuer must be an https URL' }); s.issuer = String(b.issuer).trim(); }
        if (b.redirectUri != null) { if (b.redirectUri && !/^https:\/\/\S+\/auth\/sso\/callback$/.test(b.redirectUri)) return json(res, 400, { error: 'the redirect URI must be https://<host>/auth/sso/callback' }); s.redirectUri = String(b.redirectUri).trim(); }
        ['provider', 'clientId', 'scopes', 'roleClaim', 'allowedDomains'].forEach(function (k) { if (b[k] != null) s[k] = String(b[k]).trim().slice(0, 300); });
        if (b.clientSecret) s.clientSecret = enc(String(b.clientSecret));
        if (b.defaultRole != null) { if (['none', 'viewer', 'operator'].indexOf(b.defaultRole) < 0) return json(res, 400, { error: 'the default role must be none, viewer or operator' }); s.defaultRole = b.defaultRole; }
        if (b.roleMap != null) { if (typeof b.roleMap !== 'object') return json(res, 400, { error: 'roleMap must be an object' }); const m = {}; const ks = Object.keys(b.roleMap).slice(0, 50); for (let i = 0; i < ks.length; i++) { const r = b.roleMap[ks[i]]; if (['admin', 'operator', 'viewer'].indexOf(r) < 0) return json(res, 400, { error: 'roles are admin, operator or viewer' }); m[String(ks[i]).slice(0, 120)] = r; } s.roleMap = m; }
        if (b.requireMfa != null) s.requireMfa = !!b.requireMfa;
        if (b.enabled != null) { if (b.enabled && !(s.issuer && s.clientId && s.redirectUri)) return json(res, 400, { error: 'set the issuer, client ID and redirect URI before enabling single sign-on' }); s.enabled = !!b.enabled; }
        if (!s.enabled && CFG.localLogin === 'breakglass') CFG.localLogin = 'all';
        DISC = null; save(); audit({ event: 'config', user: sess.u, ip: ip, reason: 'single sign-on settings changed' + (b.enabled != null ? (b.enabled ? ' · enabled' : ' · disabled') : '') });
        return json(res, 200, { ok: true });
      }
      if (url === '/auth/admin/sso/test') {
        if (!CFG.sso.issuer) return json(res, 400, { error: 'set the issuer first' });
        return discovery(true).then(function (d) { return jwks(true).then(function (k) { json(res, 200, { ok: true, issuer: d.issuer, authorization: d.authorization_endpoint, token: d.token_endpoint, keys: (k.keys || []).length, amrSupported: (d.claims_supported || []).indexOf('amr') >= 0 }); }); })
          .catch(function (e) { json(res, 502, { error: e.message }); });
      }
      if (url === '/auth/admin/sessions/revoke') {          /* {user} ends every session of that account, {id} one session (first 8 characters from the list) */
        const who = String(b.user || '').toLowerCase().trim(), id = String(b.id || '');
        if (!who && !/^[A-Za-z0-9_-]{8}$/.test(id)) return json(res, 400, { error: 'give user, or id (the 8-character session id from the list)' });
        let n = 0;
        if (who) n = endUserSessions(who, 'revoked by an administrator', sess.u);
        else Object.keys(SIDS).forEach(function (k) { if (k.slice(0, 8) === id && endSession(k, 'revoked by an administrator', sess.u)) n++; });
        audit({ event: 'session-revoke', user: who || id, ip: ip, reason: n + ' session(s) ended · by ' + sess.u });
        return json(res, n ? 200 : 404, n ? { ok: true, ended: n } : { error: 'no active session matched' });
      }
      if (url === '/auth/admin/policy') {
        if (b.mfaRequired != null) {
          const want = !!b.mfaRequired;
          if (want && !CFG.mfaPolicyActivated) CFG.mfaPolicyActivated = new Date().toISOString();   /* stamp when the mandate is (re)activated */
          else if (want && CFG.mfaRequired === false) CFG.mfaPolicyActivated = new Date().toISOString();
          CFG.mfaRequired = want;
        }
        if (b.mfaGraceDays != null) { const n = Number(b.mfaGraceDays); if (!isFinite(n) || n < 0 || n > 3650) return json(res, 400, { error: 'mfaGraceDays must be a whole number of days between 0 and 3650' }); CFG.mfaGraceDays = Math.floor(n); }
        if (b.session != null) {
          if (typeof b.session !== 'object' || Array.isArray(b.session)) return json(res, 400, { error: 'session must be an object' });
          const cur = Object.assign({}, CFG.session || {});
          const ks = Object.keys(b.session); for (let i = 0; i < ks.length; i++) { const k = ks[i], l = SESSION_LIMITS[k]; if (!l) return json(res, 400, { error: 'unknown session setting ' + String(k).slice(0, 40) });
            const n = Number(b.session[k]); if (!isFinite(n) || Math.floor(n) !== n || n < l[0] || n > l[1]) return json(res, 400, { error: 'session.' + k + ' must be a whole number between ' + l[0] + ' and ' + l[1] }); cur[k] = n; }
          CFG.session = cur;
        }
        if (b.mfaPolicy != null) { if (['all', 'admins', 'optional'].indexOf(b.mfaPolicy) < 0) return json(res, 400, { error: 'MFA policy is all, admins or optional' }); CFG.mfaPolicy = b.mfaPolicy; }
        if (b.localLogin != null) {
          if (['all', 'breakglass'].indexOf(b.localLogin) < 0) return json(res, 400, { error: 'local sign-in is all or breakglass' });
          if (b.localLogin === 'breakglass') {
            if (!ssoOn()) return json(res, 400, { error: 'enable single sign-on before limiting local sign-in' });
            if (!(CFG.users || []).some(function (u) { return u.breakglass && u.role === 'admin' && u.totp; })) return json(res, 400, { error: 'flag at least one admin account with MFA as break-glass first' });
          }
          CFG.localLogin = b.localLogin;
        }
        save(); const sc = sessCfg(); audit({ event: 'config', user: sess.u, ip: ip, reason: 'policy: MFA ' + (mfaMandatory() ? 'mandatory' : 'legacy/' + CFG.mfaPolicy) + ', grace ' + graceDays() + 'd, local sign-in ' + CFG.localLogin + ', idle ' + sc.idleMinutes + ' min, admin ' + sc.adminHours + ' h, SSO re-check ' + sc.ssoRecheckMinutes + ' min' }); return json(res, 200, { ok: true, mfaRequired: mfaMandatory(), mfaGraceDays: graceDays(), mfaPolicyActivated: CFG.mfaPolicyActivated || null, mfaPolicy: CFG.mfaPolicy, localLogin: CFG.localLogin, session: sessCfg() });
      }
      if (url === '/auth/admin/users') {                      /* create a local account */
        const name = String(b.user || '').toLowerCase().trim();
        if (!/^[a-z0-9._-]{3,40}$/.test(name)) return json(res, 400, { error: 'username: 3–40 characters — letters, digits, dot, dash or underscore' });
        if (userOf(name)) return json(res, 409, { error: 'that username already exists' });
        if (ROLES.indexOf(b.role) < 0) return json(res, 400, { error: 'role must be admin, operator or viewer' });
        const bad = pwProblem(b.password); if (bad) return json(res, 400, { error: bad });
        if (b.mfa != null && ['on', 'off', 'policy'].indexOf(b.mfa) < 0) return json(res, 400, { error: 'MFA must be on, off or policy' });
        const salt = crypto.randomBytes(16).toString('hex'), u = { user: name, name: String(b.name || name).slice(0, 80), role: b.role, salt: salt, passHash: hashPw(b.password, salt), created: new Date().toISOString(), createdBy: sess.u };
        if (b.mfa === 'on' || b.mfa === 'off') u.mfa = b.mfa; if (b.disabled) u.disabled = true;
        CFG.users = CFG.users || []; CFG.users.push(u); save();
        audit({ event: 'user-created', user: name, role: u.role, ip: ip, reason: 'by ' + sess.u + (u.mfa ? ' · MFA ' + u.mfa : '') });
        return json(res, 200, { ok: true });
      }
      const um = /^\/auth\/admin\/users\/([a-z0-9._@-]+)\/(update|delete)$/.exec(url);
      if (um) {
        const u = userOf(um[1]); if (!u) return json(res, 404, { error: 'no such local account' });
        if (um[2] === 'delete') {
          if (u.user === sess.u) return json(res, 400, { error: 'you cannot delete your own account' });
          if (u.role === 'admin' && !u.disabled && enabledAdmins(u.user) < 1) return json(res, 400, { error: 'keep at least one enabled administrator' });
          CFG.users = CFG.users.filter(function (x) { return x.user !== u.user; }); delete FAIL[u.user]; save(); endUserSessions(u.user, 'account deleted', sess.u);
          audit({ event: 'user-deleted', user: u.user, ip: ip, reason: 'by ' + sess.u }); return json(res, 200, { ok: true });
        }
        const changes = [];
        if (b.name != null) { u.name = String(b.name).slice(0, 80); changes.push('name'); }
        if (u.source === 'ad' && (b.role != null || b.password)) return json(res, 400, { error: 'directory accounts take their role from AD groups and their password from AD' });
        if (b.role != null) {
          if (ROLES.indexOf(b.role) < 0) return json(res, 400, { error: 'role must be admin, operator or viewer' });
          if (u.role === 'admin' && b.role !== 'admin' && (u.user === sess.u || enabledAdmins(u.user) < 1)) return json(res, 400, { error: u.user === sess.u ? 'you cannot remove your own administrator role' : 'keep at least one enabled administrator' });
          if (b.role !== 'admin') u.breakglass = false;
          u.role = b.role; changes.push('role ' + b.role);
        }
        if (b.disabled != null) {
          if (b.disabled && u.user === sess.u) return json(res, 400, { error: 'you cannot disable your own account' });
          if (b.disabled && u.role === 'admin' && enabledAdmins(u.user) < 1) return json(res, 400, { error: 'keep at least one enabled administrator' });
          u.disabled = !!b.disabled; if (!u.disabled) delete u.disabled; changes.push(b.disabled ? 'disabled' : 'enabled');
        }
        if (b.password) { const bad = pwProblem(b.password); if (bad) return json(res, 400, { error: bad }); u.salt = crypto.randomBytes(16).toString('hex'); u.passHash = hashPw(b.password, u.salt); u.pwChanged = new Date().toISOString(); delete FAIL[u.user]; changes.push('password reset'); }
        if (b.mfa != null) {
          if (['on', 'off', 'policy'].indexOf(b.mfa) < 0) return json(res, 400, { error: 'MFA must be on, off or policy' });
          if (b.mfa === 'policy') delete u.mfa; else u.mfa = b.mfa;
          if (b.mfa === 'off') { delete u.totp; delete u.totpStep; delete u.recovery; delete u.mfaSince; }
          changes.push('MFA ' + b.mfa);
        }
        if (!changes.length) return json(res, 400, { error: 'nothing to change' });
        save(); if (u.disabled || b.password) endUserSessions(u.user, u.disabled ? 'account disabled' : 'password reset', sess.u);
        audit({ event: 'user-updated', user: u.user, ip: ip, reason: changes.join(', ') + ' · by ' + sess.u }); return json(res, 200, { ok: true });
      }
      const m = /^\/auth\/admin\/users\/([a-z0-9._@-]+)\/(reset-mfa|unlock|breakglass)$/.exec(url);
      if (m) {
        const u = userOf(m[1]); if (!u) return json(res, 404, { error: 'no such local account' });
        if (m[2] === 'reset-mfa') { if (u.user === sess.u && CFG.mfaPolicy !== 'optional') return json(res, 400, { error: 'ask another administrator to reset your own MFA' }); delete u.totp; delete u.totpStep; delete u.recovery; delete u.mfaSince; }
        if (m[2] === 'unlock') delete FAIL[u.user];
        if (m[2] === 'breakglass') { if (u.source === 'ad' && b.on) return json(res, 400, { error: 'only local accounts can be break-glass' }); if (u.role !== 'admin' && b.on) return json(res, 400, { error: 'only admin accounts can be break-glass' }); u.breakglass = !!b.on; }
        save(); audit({ event: m[2], user: u.user, ip: ip, reason: 'by ' + sess.u }); return json(res, 200, { ok: true });
      }
      return json(res, 404, { error: 'not found' });
    });
  }
  res.writeHead(404); res.end('not found');
});
if (require.main === module) server.listen(PORT, '127.0.0.1', function () { console.log('[as-auth] Arabian Shield sign-in gate on 127.0.0.1:' + PORT + ' · SSO ' + (ssoOn() ? 'on (' + CFG.sso.provider + ')' : 'off') + ' · MFA ' + (mfaMandatory() ? 'mandatory (grace ' + graceDays() + 'd)' : 'policy ' + CFG.mfaPolicy) + ' · AD ' + (ldapOn() ? 'on (' + domainLabel() + ')' : 'off')); });
module.exports = { server: server, _t: { hotp: hotp, b32enc: b32enc, b32dec: b32dec, totpCheck: totpCheck, jwkToPem: jwkToPem, verifyIdToken: verifyIdToken, sessions: function () { return SIDS; }, SESS_FILE: SESS_FILE, enc: enc, dec: dec, mapRole: mapRole, hasMfa: hasMfa,
  ldapCfg: ldapCfg, ldapOn: ldapOn, adIdentity: adIdentity, adAuthenticate: adAuthenticate, shadowKey: shadowKey, CFG_FILE: CFG_FILE,
  mfaMandatory: mfaMandatory, mfaRequired: mfaRequired, mfaStatus: mfaStatus, graceDays: graceDays } };
