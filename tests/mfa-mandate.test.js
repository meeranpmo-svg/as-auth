'use strict';
// MFA MANDATE — two-step verification is mandatory for BOTH sign-in paths (local username+password AND direct-LDAPS Active
// Directory), with an admin-configurable enrolment grace window. Verifies: un-enrolled users are forced to enrolment (never
// straight in, even with the legacy u.mfa='off' set); within grace a bounded, audited grace-admit issues a session; after
// grace no session until TOTP is enrolled; enrolled users must pass TOTP; wrong codes fail + audit + rate-limit/lock; the
// admin policy endpoint changes behaviour; and there is no 'Skip for now' bypass. Synthetic only — in-process fake ASIC-HQ
// AD over LDAPS (first DC a dead port → every AD sign-in also exercises failover), no real network, no real AD.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const crypto = require('node:crypto');
const { makeCA, makeServerCert } = require('./helpers/x509');
const { startFakeLdap, deadPort } = require('./helpers/fake-ldap');
const { buildDirectory, DN, PASSWORDS, BASE } = require('./helpers/ad-fixture');

const DC = 'asdc-hqa.asic-hq.com';
const SECRET = crypto.randomBytes(32).toString('hex');
const DAY = 86400000;
let tmp, cfgFile, logFile, srv, fx, auth, port, deadP;
let ADMIN_SECRET, CODE_SECRET;

// --- same constructions as as-auth.js, computed here so the config can be written BEFORE as-auth.js is required ---
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function b32enc(buf) { let bits = '', out = ''; for (let i = 0; i < buf.length; i++) bits += buf[i].toString(2).padStart(8, '0'); for (let i = 0; i + 5 <= bits.length; i += 5) out += B32[parseInt(bits.substr(i, 5), 2)]; if (bits.length % 5) out += B32[parseInt(bits.substr(bits.length - bits.length % 5).padEnd(5, '0'), 2)]; return out; }
function encLike(secret, txt) {
  const key = crypto.createHash('sha256').update('as-auth-enc|' + secret).digest();
  const iv = crypto.randomBytes(12); const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const d = Buffer.concat([c.update(txt, 'utf8'), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), d]).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function pbkdf(pw, salt) { return crypto.pbkdf2Sync(pw, salt, 120000, 32, 'sha256').toString('hex'); }
function localUser(user, role, pw, extra) {
  const salt = crypto.randomBytes(16).toString('hex');
  return Object.assign({ user, name: user, role, salt, passHash: pbkdf(pw, salt) }, extra || {});
}
function ldapBlock(servers) {
  return { enabled: true, servers, caFile: path.join(tmp, 'asic-ca.pem'), baseDN: BASE, bindDN: DN.svc, bindPassword: encLike(SECRET, PASSWORDS.svc),
    netbios: ['ASIC-HQ'], upnSuffix: ['asic-hq.com'], userAttr: 'sAMAccountName', nested: true, requireMfa: true, timeoutMs: 3000,
    groupRoles: { [DN.socAdmins]: 'admin', [DN.socAnalysts]: 'operator', [DN.socViewers]: 'viewer' } };
}

function req(method, p, { form, cookies = {}, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const body = form ? new URLSearchParams(form).toString() : '';
    const h = Object.assign({ Cookie: Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join('; ') }, headers);
    if (form) { h['Content-Type'] = 'application/x-www-form-urlencoded'; h['Content-Length'] = Buffer.byteLength(body); }
    const r = http.request({ host: '127.0.0.1', port, method, path: p, headers: h }, (res) => {
      let d = ''; res.on('data', (c) => { d += c; });
      res.on('end', () => {
        const jar = Object.assign({}, cookies);
        for (const sc of [].concat(res.headers['set-cookie'] || [])) { const m = /^([^=]+)=([^;]*)/.exec(sc); if (m) { if (m[2]) jar[m[1]] = m[2]; else delete jar[m[1]]; } }
        resolve({ status: res.statusCode, headers: res.headers, body: d, cookies: jar });
      });
    });
    r.on('error', reject); r.end(body);
  });
}
function reqJson(p, obj, cookies = {}) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(obj || {});
    const h = { Cookie: Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join('; '), 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) };
    const r = http.request({ host: '127.0.0.1', port, method: 'POST', path: p, headers: h }, (res) => { let d = ''; res.on('data', (c) => { d += c; }); res.on('end', () => resolve({ status: res.statusCode, body: d })); });
    r.on('error', reject); r.end(body);
  });
}
const errText = (html) => { const m = /<div class="err">([^<]*)<\/div>/.exec(html); return m ? m[1] : ''; };
const secretOf = (html) => /<div class="mono">([A-Z2-7 ]+)<\/div>/.exec(html)[1].replace(/ /g, '');
const totp = (secret, step) => auth._t.hotp(auth._t.b32dec(secret), step === undefined ? Math.floor(Date.now() / 30000) : step);
const cfg = () => JSON.parse(fs.readFileSync(cfgFile, 'utf8'));
const log = () => fs.readFileSync(logFile, 'utf8');
const whoami = async (cookies) => JSON.parse((await req('GET', '/auth/whoami', { cookies })).body);

let ADMIN;                                    // acquired once and reused: a TOTP code cannot be replayed within its 30s window
async function adminSession() {               // poladmin is pre-enrolled and used by no other test
  if (ADMIN) return ADMIN;
  const r1 = await req('POST', '/login', { form: { user: 'poladmin', pass: 'Pol-Admin-Pass-1' } });
  assert.match(r1.body, /Two-step verification/, 'admin lands on the OTP page');
  const r2 = await req('POST', '/login/otp', { form: { code: totp(ADMIN_SECRET, Math.floor(Date.now() / 30000) + 1) }, cookies: r1.cookies });
  assert.equal(r2.status, 302); assert.ok(r2.cookies.as_session, 'admin session issued');
  ADMIN = r2.cookies; return ADMIN;
}

test.before(async () => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'as-auth-mfa-'));
  const ca = makeCA('Synthetic Asic Microsoft CA');
  const sc = makeServerCert(ca, { cn: DC, dns: [DC, 'localhost'], ip: ['127.0.0.1'] });
  fs.writeFileSync(path.join(tmp, 'asic-ca.pem'), ca.cert);
  fx = buildDirectory();
  srv = await startFakeLdap({ key: sc.key, cert: sc.cert, dir: fx.dir, passwords: fx.passwords });
  deadP = await deadPort();
  ADMIN_SECRET = b32enc(crypto.randomBytes(20));
  CODE_SECRET = b32enc(crypto.randomBytes(20));
  cfgFile = path.join(tmp, 'arabianshield-auth.json'); logFile = path.join(tmp, 'auth.log');
  fs.writeFileSync(cfgFile, JSON.stringify({
    secret: SECRET, mfaRequired: true, mfaGraceDays: 7, mfaPolicy: 'admins', hours: 12,
    users: [
      localUser('enrolladmin', 'admin', 'Admin-Pass-Longer-1', { breakglass: true, mfa: 'off', totp: encLike(SECRET, ADMIN_SECRET), totpStep: 0, recovery: [] }),
      localUser('poladmin', 'admin', 'Pol-Admin-Pass-1', { breakglass: true, totp: encLike(SECRET, ADMIN_SECRET), totpStep: 0, recovery: [] }),
      localUser('codeuser', 'operator', 'Code-User-Pass-1', { totp: encLike(SECRET, CODE_SECRET), totpStep: 0, recovery: [] }),
      localUser('offuser', 'operator', 'Off-User-Pass-1', { mfa: 'off' }),                                   // legacy "never asked" — must NOT bypass the mandate
      localUser('graceuser', 'operator', 'Grace-User-Pass-1', {}),                                           // fresh → within grace
      localUser('lateuser', 'operator', 'Late-User-Pass-1', { mfaGraceStart: new Date(Date.now() - 30 * DAY).toISOString() }), // anchored 30d ago → past the 7d window
    ],
    ldap: ldapBlock([{ url: `ldaps://${DC}:${deadP}`, ip: '127.0.0.1' }, { url: `ldaps://${DC}:${srv.port}`, ip: '127.0.0.1' }]),
  }, null, 1));
  process.env.AS_AUTH_CFG = cfgFile; process.env.AS_AUTH_LOG = logFile;
  auth = require('../as-auth.js');
  await new Promise((r) => auth.server.listen(0, '127.0.0.1', r));
  port = auth.server.address().port;
});
test.after(async () => { auth.server.close(); await srv.close(); });

test('mandate on by default; un-enrolled local user (even with mfa:"off") is forced to enrolment, not let straight in', async () => {
  const r = await req('POST', '/login', { form: { user: 'offuser', pass: 'Off-User-Pass-1' } });
  assert.equal(r.status, 200);
  assert.ok(!r.cookies.as_session, 'no session is issued on a correct password alone');
  assert.match(r.body, /Set up two-step verification/);
  assert.match(r.body, /required for every account/, 'the mandate is explained');
  assert.equal(auth._t.mfaRequired({ user: 'offuser', role: 'operator', mfa: 'off' }), true, 'mfa:"off" no longer exempts while the mandate is on');
});

test('no "Skip for now" bypass exists; the only no-TOTP path is the bounded grace admit', async () => {
  const r = await req('POST', '/login', { form: { user: 'offuser', pass: 'Off-User-Pass-1' } });
  assert.doesNotMatch(r.body, /skip/i, 'no skip control anywhere on the enrolment page');
  assert.match(r.body, /Continue for now/, 'while in grace, only the audited grace admit is offered');
});

test('local grace user: grace-admit issues a session but flags it mfaPending; audited grace-admit', async () => {
  const r1 = await req('POST', '/login', { form: { user: 'graceuser', pass: 'Grace-User-Pass-1' } });
  assert.equal(r1.status, 200); assert.match(r1.body, /Continue for now/);
  const r2 = await req('POST', '/login/grace', { form: {}, cookies: r1.cookies });
  assert.equal(r2.status, 302); assert.ok(r2.cookies.as_session, 'grace admit issues a session');
  const who = await whoami(r2.cookies);
  assert.equal(who.mfa, false); assert.equal(who.mfaPending, true); assert.equal(who.mfaEnrolled, false); assert.equal(who.mfaState, 'grace');
  assert.match(log(), /"event":"grace-admit","user":"graceuser"/);
  // without two-step verification the session is read-only: the operator account is passed to the platform as viewer
  const v = await req('GET', '/auth/verify', { cookies: r2.cookies });
  assert.equal(v.status, 200); assert.equal(v.headers['x-auth-role'], 'viewer', 'a grace session never carries the full role');
});

test('local user past the grace window: no grace control, grace admit refused, only enrolment completes sign-in', async () => {
  const r1 = await req('POST', '/login', { form: { user: 'lateuser', pass: 'Late-User-Pass-1' } });
  assert.equal(r1.status, 200); assert.match(r1.body, /Set up two-step verification/);
  assert.doesNotMatch(r1.body, /Continue for now/, 'the grace control is gone once the window closed');
  const g = await req('POST', '/login/grace', { form: {}, cookies: r1.cookies });
  assert.equal(g.status, 401); assert.ok(!g.cookies.as_session, 'expired grace cannot admit');
  const secret = secretOf(r1.body);
  const r2 = await req('POST', '/login/enrol', { form: { code: totp(secret) }, cookies: r1.cookies });
  assert.equal(r2.status, 200); assert.ok(r2.cookies.as_session, 'session only after TOTP is enrolled');
  const who = await whoami(r2.cookies);
  assert.equal(who.mfaEnrolled, true); assert.equal(who.mfa, true); assert.equal(who.mfaState, 'enrolled');
  assert.match(log(), /"event":"mfa-enrol","user":"lateuser"/);
});

test('enrolled user must pass TOTP; a correct code grants the session', async () => {
  const r1 = await req('POST', '/login', { form: { user: 'enrolladmin', pass: 'Admin-Pass-Longer-1' } });
  assert.equal(r1.status, 200); assert.match(r1.body, /Two-step verification/);
  assert.ok(!r1.cookies.as_session, 'password alone does not sign an enrolled user in');
  const r2 = await req('POST', '/login/otp', { form: { code: totp(ADMIN_SECRET, Math.floor(Date.now() / 30000) + 1) }, cookies: r1.cookies });
  assert.equal(r2.status, 302); assert.ok(r2.cookies.as_session);
  const who = await whoami(r2.cookies);
  assert.equal(who.mfa, true); assert.equal(who.mfaState, 'enrolled'); assert.match(log(), /"event":"mfa-pass","user":"enrolladmin"/);
});

test('wrong TOTP → mfa-fail audit + rate-limit: the account locks after repeated bad codes', async () => {
  const r1 = await req('POST', '/login', { form: { user: 'codeuser', pass: 'Code-User-Pass-1' } });
  assert.match(r1.body, /Two-step verification/);
  let last;
  for (let i = 0; i < 5; i++) last = await req('POST', '/login/otp', { form: { code: '000000' }, cookies: r1.cookies });
  assert.equal(last.status, 401);
  const locked = await req('POST', '/login/otp', { form: { code: '000000' }, cookies: r1.cookies });
  assert.equal(locked.status, 423, 'locked out after 5 failures');
  const l = log();
  assert.match(l, /"event":"mfa-fail","user":"codeuser","ip":"[^"]*","method":"totp"/);
  assert.match(l, /"event":"lockout","user":"codeuser"/);
  assert.ok(!l.includes('"code"') && !l.includes('000000'), 'no codes are ever written to the audit log');
});

test('admin policy endpoint: set grace + toggle the mandate; config surfaces policy and per-user enrolment state', async () => {
  const admin = await adminSession();
  const cfg0 = JSON.parse((await req('GET', '/auth/admin/config', { cookies: admin })).body);
  assert.equal(cfg0.mfaRequired, true); assert.equal(cfg0.mfaGraceDays, 7);
  assert.ok(cfg0.users.every((u) => ['enrolled', 'grace', 'expired', 'exempt'].includes(u.mfaState)), 'every account carries an enrolment state');
  assert.equal(cfg0.users.find((u) => u.user === 'enrolladmin').mfaState, 'enrolled');
  const gu = cfg0.users.find((u) => u.user === 'graceuser');
  assert.equal(gu.mfaState, 'grace'); assert.ok(gu.mfaGraceStart && gu.mfaDeadline, 'per-user grace anchor + deadline surfaced');
  // change the grace window
  const set = await reqJson('/auth/admin/policy', { mfaRequired: true, mfaGraceDays: 3 }, admin);
  assert.equal(set.status, 200); assert.equal(JSON.parse(set.body).mfaGraceDays, 3);
  assert.ok(JSON.parse(set.body).mfaPolicyActivated, 'activation timestamp stamped once the mandate is set via the endpoint');
  assert.equal(JSON.parse((await req('GET', '/auth/admin/config', { cookies: admin })).body).mfaGraceDays, 3);
  // only an admin may call it
  const anon = await reqJson('/auth/admin/policy', { mfaGraceDays: 9 }, {});
  assert.equal(anon.status, 403);
  // bad grace value rejected
  assert.equal((await reqJson('/auth/admin/policy', { mfaGraceDays: -1 }, admin)).status, 400);
  // turning the mandate OFF restores the legacy per-account policy: now mfa:"off" is admitted straight in...
  assert.equal((await reqJson('/auth/admin/policy', { mfaRequired: false }, admin)).status, 200);
  const off = await req('POST', '/login', { form: { user: 'offuser', pass: 'Off-User-Pass-1' } });
  assert.equal(off.status, 302, 'with the mandate off, mfa:"off" is exempt again'); assert.ok(off.cookies.as_session);
  // ...and turning it back ON re-mandates MFA for that same account
  assert.equal((await reqJson('/auth/admin/policy', { mfaRequired: true, mfaGraceDays: 7 }, admin)).status, 200);
  const on = await req('POST', '/login', { form: { user: 'offuser', pass: 'Off-User-Pass-1' } });
  assert.equal(on.status, 200); assert.ok(!on.cookies.as_session); assert.match(on.body, /Set up two-step verification/);
});

test('AD user (LDAPS bind OK) with no TOTP takes the same grace path: grace-admit as source=ad, method=ad', async () => {
  // carol is a mapped AD viewer; first AD sign-in anchors her grace clock
  const r1 = await req('POST', '/login', { form: { user: 'carol', pass: PASSWORDS.user } });
  assert.equal(r1.status, 200); assert.match(r1.body, /Set up two-step verification/); assert.match(r1.body, /Continue for now/);
  const r2 = await req('POST', '/login/grace', { form: {}, cookies: r1.cookies });
  assert.equal(r2.status, 302); assert.ok(r2.cookies.as_session);
  const who = await whoami(r2.cookies);
  assert.equal(who.source, 'ad'); assert.equal(who.method, 'ad'); assert.equal(who.mfaPending, true); assert.equal(who.mfaState, 'grace');
  assert.match(log(), /"event":"grace-admit","user":"carol@asic-hq.com","role":"viewer","method":"ad"/);
});

test('AD user past the grace window is blocked until enrolment, exactly like a local user', async () => {
  const admin = await adminSession();
  assert.equal((await reqJson('/auth/admin/policy', { mfaRequired: true, mfaGraceDays: 0 }, admin)).status, 200); // 0-day window → carol (already anchored) is now past it
  try {
    const r = await req('POST', '/login', { form: { user: 'carol', pass: PASSWORDS.user } });
    assert.equal(r.status, 200); assert.match(r.body, /Set up two-step verification/);
    assert.doesNotMatch(r.body, /Continue for now/, 'no grace admit once the window is zero/closed');
    const g = await req('POST', '/login/grace', { form: {}, cookies: r.cookies });
    assert.equal(g.status, 401); assert.ok(!g.cookies.as_session);
  } finally {
    await reqJson('/auth/admin/policy', { mfaRequired: true, mfaGraceDays: 7 }, admin);
  }
});
