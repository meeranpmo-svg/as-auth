'use strict';
// FOUR-EYES FOR WEAKENING TWO-STEP VERIFICATION — switching the mandate off, a longer enrolment grace, a weaker legacy policy
// and MFA "off" for an account are only REQUESTED by one administrator and take effect when a DIFFERENT administrator, signed
// in with two-step verification, approves. Verifies: strengthening applies at once; weakening is pending and changes nothing;
// the requester cannot approve; an operator cannot approve; an approver without MFA on their own session is refused; a
// reject needs a reason and is audited; approval applies and is audited with both names; a request expires after 24 h; an
// account created with MFA "off" is created under the policy with the "off" pending. Synthetic local accounts, fake clock.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const crypto = require('node:crypto');

const SECRET = crypto.randomBytes(32).toString('hex');
const realNow = Date.now; let skew = 0; Date.now = () => realNow() + skew;
let tmp, cfgFile, logFile, auth, port;
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function b32enc(buf) { let bits = '', out = ''; for (let i = 0; i < buf.length; i++) bits += buf[i].toString(2).padStart(8, '0'); for (let i = 0; i + 5 <= bits.length; i += 5) out += B32[parseInt(bits.substr(i, 5), 2)]; if (bits.length % 5) out += B32[parseInt(bits.substr(bits.length - bits.length % 5).padEnd(5, '0'), 2)]; return out; }
function encLike(txt) { const key = crypto.createHash('sha256').update('as-auth-enc|' + SECRET).digest(), iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', key, iv), d = Buffer.concat([c.update(txt, 'utf8'), c.final()]); return Buffer.concat([iv, c.getAuthTag(), d]).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function localUser(user, role, pw, extra) { const salt = crypto.randomBytes(16).toString('hex'); return Object.assign({ user, name: user, role, salt, passHash: crypto.pbkdf2Sync(pw, salt, 120000, 32, 'sha256').toString('hex') }, extra || {}); }
const TOTP = { a1: b32enc(crypto.randomBytes(20)), a2: b32enc(crypto.randomBytes(20)), ops1: b32enc(crypto.randomBytes(20)) };

function req(method, p, { form, json, cookies = {} } = {}) {
  return new Promise((resolve, reject) => {
    const body = form ? new URLSearchParams(form).toString() : json ? JSON.stringify(json) : '';
    const h = { Cookie: Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join('; ') };
    if (form) h['Content-Type'] = 'application/x-www-form-urlencoded'; if (json) h['Content-Type'] = 'application/json';
    if (body) h['Content-Length'] = Buffer.byteLength(body);
    const r = http.request({ host: '127.0.0.1', port, method, path: p, headers: h }, (res) => {
      let d = ''; res.on('data', (c) => { d += c; });
      res.on('end', () => { const jar = Object.assign({}, cookies); for (const sc of [].concat(res.headers['set-cookie'] || [])) { const m = /^([^=]+)=([^;]*)/.exec(sc); if (m) { if (m[2]) jar[m[1]] = m[2]; else delete jar[m[1]]; } }
        let j = null; try { j = JSON.parse(d); } catch (e) { /* an HTML page */ } resolve({ status: res.statusCode, body: d, json: j, cookies: jar }); });
    });
    r.on('error', reject); r.end(body);
  });
}
const cfg = () => JSON.parse(fs.readFileSync(cfgFile, 'utf8'));
const log = () => fs.readFileSync(logFile, 'utf8');
const S = {};
async function signIn(user, pass, secret) {   // password, then TOTP (a different step each time: no replay)
  const r1 = await req('POST', '/login', { form: { user, pass } });
  if (!secret) { assert.equal(r1.status, 302, r1.body); return { as_session: r1.cookies.as_session }; }
  skew += 31e3;
  const r2 = await req('POST', '/login/otp', { form: { code: auth._t.hotp(auth._t.b32dec(secret), Math.floor(Date.now() / 30000)) }, cookies: r1.cookies });
  assert.equal(r2.status, 302, r2.body); return { as_session: r2.cookies.as_session };
}
const policy = (who, body) => req('POST', '/auth/admin/policy', { cookies: S[who], json: body });
const approve = (who, id) => req('POST', `/auth/admin/mfa-changes/${id}/approve`, { cookies: S[who], json: {} });

test.before(async () => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'as-auth-4eyes-'));
  cfgFile = path.join(tmp, 'arabianshield-auth.json'); logFile = path.join(tmp, 'auth.log');
  fs.writeFileSync(cfgFile, JSON.stringify({ secret: SECRET, mfaRequired: true, mfaGraceDays: 7, mfaPolicy: 'all', hours: 12, users: [
    localUser('a1', 'admin', 'Admin-One-Pass-1', { totp: encLike(TOTP.a1), totpStep: 0 }),
    localUser('a2', 'admin', 'Admin-Two-Pass-1', { totp: encLike(TOTP.a2), totpStep: 0 }),
    localUser('a3', 'admin', 'Admin-Three-Pass-1', { mfa: 'off' }),
    localUser('ops1', 'operator', 'Ops-One-Pass-1', { totp: encLike(TOTP.ops1), totpStep: 0 }),
  ] }, null, 1));
  process.env.AS_AUTH_CFG = cfgFile; process.env.AS_AUTH_LOG = logFile;
  auth = require('../as-auth.js');
  await new Promise((r) => auth.server.listen(0, '127.0.0.1', r)); port = auth.server.address().port;
  S.a1 = await signIn('a1', 'Admin-One-Pass-1', TOTP.a1); S.a2 = await signIn('a2', 'Admin-Two-Pass-1', TOTP.a2); S.ops1 = await signIn('ops1', 'Ops-One-Pass-1', TOTP.ops1);
});
test.after(() => { auth.server.close(); Date.now = realNow; });

test('a shorter grace applies at once; a longer one waits for a second administrator, who applies it', async () => {
  const s = await policy('a1', { mfaGraceDays: 3 });
  assert.equal(s.status, 200); assert.equal(s.json.mfaGraceDays, 3); assert.equal(s.json.pending, undefined);
  const w = await policy('a1', { mfaGraceDays: 30 });
  assert.equal(w.status, 200); assert.equal(w.json.mfaGraceDays, 3, 'unchanged while pending'); assert.ok(w.json.pending.id);
  assert.equal(cfg().mfaGraceDays, 3);
  assert.equal((await approve('a1', w.json.pending.id)).status, 403, 'the requester cannot approve');
  assert.equal((await approve('ops1', w.json.pending.id)).status, 403, 'an operator cannot approve');
  const a = await approve('a2', w.json.pending.id);
  assert.equal(a.status, 200); assert.equal(a.json.mfaGraceDays, 30); assert.equal(cfg().mfaGraceDays, 30);
  assert.match(log(), /"event":"mfa-change-approved","user":"a2".*mfaGraceDays → 30 · request [0-9a-f]{12} by a1 · approved by a2/);
  assert.equal((await approve('a2', w.json.pending.id)).status, 404, 'a request is used once');
});

test('a weaker legacy policy waits; a stronger one and other settings in the same call apply at once', async () => {
  const w = await policy('a1', { mfaPolicy: 'optional', mfaGraceDays: 7 });
  assert.ok(w.json.pending && w.json.pending.changes.mfaPolicy === 'optional'); assert.equal(w.json.mfaPolicy, 'all');
  assert.equal(w.json.mfaGraceDays, 7, 'the shorter grace in the same call applied');
  const rj = await req('POST', `/auth/admin/mfa-changes/${w.json.pending.id}/reject`, { cookies: S.a2, json: { reason: 'not agreed by the CISO' } });
  assert.equal(rj.status, 200); assert.equal(cfg().mfaPolicy, 'all');
  assert.match(log(), /"event":"mfa-change-rejected","user":"a2".*mfaPolicy → optional.*by a1 · not agreed by the CISO/);
});

test('MFA "off" for an account waits for approval; approval removes the enrolment', async () => {
  const r = await req('POST', '/auth/admin/users/ops1/update', { cookies: S.a1, json: { mfa: 'off' } });
  assert.equal(r.status, 202); assert.ok(r.json.pending.id);
  assert.ok(cfg().users.find((u) => u.user === 'ops1').totp, 'still enrolled while pending');
  assert.equal((await approve('a2', r.json.pending.id)).status, 200);
  const u = cfg().users.find((x) => x.user === 'ops1'); assert.equal(u.mfa, 'off'); assert.equal(u.totp, undefined);
  // created with MFA "off": the account exists under the policy, the "off" is a pending request
  const c = await req('POST', '/auth/admin/users', { cookies: S.a1, json: { user: 'newops', role: 'operator', password: 'New-Ops-Pass-12', mfa: 'off' } });
  assert.equal(c.status, 200); assert.equal(cfg().users.find((x) => x.user === 'newops').mfa, undefined);
  assert.ok(cfg().mfaChanges.some((x) => x.kind === 'user-mfa-off' && x.target === 'newops' && x.by === 'a1'));
});

test('switching the mandate off: pending, approved by the other admin; an approver without MFA on their session is refused; requests expire', async () => {
  const w = await policy('a2', { mfaRequired: false });
  assert.equal(w.json.mfaRequired, true); assert.ok(w.json.pending);
  assert.equal((await approve('a1', w.json.pending.id)).status, 200);
  assert.equal(cfg().mfaRequired, false);
  // a3 has MFA "off": now admitted with a password only (no two-step verification on that session)
  S.a3 = await signIn('a3', 'Admin-Three-Pass-1');
  assert.equal((await policy('a2', { mfaRequired: true })).json.mfaRequired, true, 'turning it back on is immediate');
  const w2 = await policy('a1', { mfaGraceDays: 60 });
  const n = await approve('a3', w2.json.pending.id);
  assert.equal(n.status, 403); assert.match(n.json.error, /two-step verification/);
  skew += 25 * 3600e3;                                                         // a day later the request has expired
  S.a2 = await signIn('a2', 'Admin-Two-Pass-1', TOTP.a2);
  assert.equal((await approve('a2', w2.json.pending.id)).status, 404);
  assert.notEqual(cfg().mfaGraceDays, 60);
});
