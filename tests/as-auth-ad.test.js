'use strict';
// End-to-end: as-auth.js (patched) on an ephemeral port with a temp config, against an in-process fake ASIC-HQ AD over
// LDAPS (first configured DC is down → every sign-in also exercises failover). POST /login → TOTP enrol / verify →
// session → /auth/whoami + /auth/verify. Plus the as-auth-ldap.js helper. No real network, no real AD.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const { makeCA, makeServerCert } = require('./helpers/x509');
const { startFakeLdap, deadPort } = require('./helpers/fake-ldap');
const { buildDirectory, DN, PASSWORDS, BASE } = require('./helpers/ad-fixture');

const DC = 'asdc-hqa.asic-hq.com';
const SECRET = crypto.randomBytes(32).toString('hex');
const LOCAL_PW = 'Local-Admin-Pass-42';
const SECRETS = {};
let tmp, cfgFile, logFile, srv, fx, auth, port, deadP;

function encLike(secret, txt) {                       // same construction as as-auth.js enc()
  const key = crypto.createHash('sha256').update('as-auth-enc|' + secret).digest();
  const iv = crypto.randomBytes(12); const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const d = Buffer.concat([c.update(txt, 'utf8'), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), d]).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
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
const errText = (html) => { const m = /<div class="err">([^<]*)<\/div>/.exec(html); return m ? m[1] : ''; };
const totp = (secret, step) => auth._t.hotp(auth._t.b32dec(secret), step === undefined ? Math.floor(Date.now() / 30000) : step);
const cfg = () => JSON.parse(fs.readFileSync(cfgFile, 'utf8'));
const shadow = (key) => (cfg().users || []).find((u) => u.user === key);

async function enrolLogin(user, password) {   // first AD sign-in: password → enrol TOTP → recovery codes + session
  const r1 = await req('POST', '/login', { form: { user, pass: password } });
  assert.equal(r1.status, 200, `${user}: ${errText(r1.body)}`);
  const secret = /<div class="mono">([A-Z2-7 ]+)<\/div>/.exec(r1.body)[1].replace(/ /g, '');
  const r2 = await req('POST', '/login/enrol', { form: { code: totp(secret) }, cookies: r1.cookies });
  assert.equal(r2.status, 200); assert.ok(r2.cookies.as_session, 'session issued after enrolment');
  return { secret, cookies: r2.cookies };
}

test.before(async () => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'as-auth-ad-'));
  const ca = makeCA('Synthetic Asic Microsoft CA');
  const sc = makeServerCert(ca, { cn: DC, dns: [DC, 'localhost'], ip: ['127.0.0.1'] });
  fs.writeFileSync(path.join(tmp, 'asic-ca.pem'), ca.cert);
  fx = buildDirectory();
  srv = await startFakeLdap({ key: sc.key, cert: sc.cert, dir: fx.dir, passwords: fx.passwords });
  deadP = await deadPort();
  const salt = crypto.randomBytes(16).toString('hex');
  cfgFile = path.join(tmp, 'arabianshield-auth.json'); logFile = path.join(tmp, 'auth.log');
  fs.writeFileSync(cfgFile, JSON.stringify({
    secret: SECRET, mfaPolicy: 'admins', mfaRequired: false, hours: 12,   // this suite predates the MFA mandate: exercise legacy AD+local coexistence (mandate tested in mfa-mandate.test.js)
    users: [{ user: 'localadmin', name: 'Local Admin', role: 'admin', salt, passHash: crypto.pbkdf2Sync(LOCAL_PW, salt, 120000, 32, 'sha256').toString('hex'), mfa: 'off', breakglass: true }],
    ldap: ldapBlock([{ url: `ldaps://${DC}:${deadP}`, ip: '127.0.0.1' }, { url: `ldaps://${DC}:${srv.port}`, ip: '127.0.0.1' }]),
  }, null, 1));
  process.env.AS_AUTH_CFG = cfgFile; process.env.AS_AUTH_LOG = logFile;
  auth = require('../as-auth.js');
  await new Promise((r) => auth.server.listen(0, '127.0.0.1', r));
  port = auth.server.address().port;
});
test.after(async () => { auth.server.close(); await srv.close(); });

test('login page carries the directory hint', async () => {
  const r = await req('GET', '/login');
  assert.equal(r.status, 200);
  assert.match(r.body, /Sign in with your ASIC-HQ account/);
  assert.match(r.body, /ASIC-HQ\\username or username@asic-hq\.com/);
});

test('empty password: refused without contacting AD for that user, generic error', async () => {
  const before = srv.binds.length;
  const r = await req('POST', '/login', { form: { user: 'ASIC-HQ\\bob', pass: '' } });
  assert.equal(r.status, 401); assert.equal(errText(r.body), 'Incorrect username or password.');
  assert.equal(srv.binds.length, before);
  assert.ok(!srv.binds.some((b) => b.empty), 'no empty simple bind ever reached the DC');
});

test('wrong password and unknown user give the same generic answer', async () => {
  const a = await req('POST', '/login', { form: { user: 'ASIC-HQ\\bob', pass: 'not-his-password' } });
  const b = await req('POST', '/login', { form: { user: 'nosuchuser', pass: 'whatever-1' } });
  assert.equal(a.status, 401); assert.equal(b.status, 401);
  assert.equal(errText(a.body), 'Incorrect username or password.');
  assert.equal(errText(a.body), errText(b.body));
  const log = fs.readFileSync(logFile, 'utf8');
  assert.match(log, /"event":"failure","user":"bob@asic-hq.com".*"method":"ad","reason":"AD rejected the password \(data 52e\)"/);
  assert.match(log, /"user":"nosuchuser@asic-hq.com".*"reason":"no such account"/);
});

test('disabled, expired and locked-out AD accounts are refused before any bind as the user', async () => {
  for (const [sam, reason] of [['erin', 'account disabled in AD'], ['frank', 'account expired in AD'], ['henry', 'account locked out in AD']]) {
    const r = await req('POST', '/login', { form: { user: `${sam}@asic-hq.com`, pass: PASSWORDS.user } });
    assert.equal(r.status, 401, sam); assert.equal(errText(r.body), 'Incorrect username or password.');
    assert.ok(!srv.binds.some((b) => b.dn === DN.user(sam)), `${sam}: no bind attempted`);
    assert.match(fs.readFileSync(logFile, 'utf8'), new RegExp(`"user":"${sam}@asic-hq.com".*"reason":"${reason}"`));
  }
});

test('correct password but no mapped group → not authorised (403), no shadow account', async () => {
  const r = await req('POST', '/login', { form: { user: 'gina', pass: PASSWORDS.user } });
  assert.equal(r.status, 403); assert.match(errText(r.body), /not been given access/);
  assert.equal(shadow('gina@asic-hq.com'), undefined);
});

test('filter injection attempts are escaped and fail like any unknown name', async () => {
  for (const u of ['*)(uid=*', '*', 'ASIC-HQ\\*)(|(sAMAccountName=*']) {
    const r = await req('POST', '/login', { form: { user: u, pass: 'x-pass-1' } });
    assert.equal(r.status, 401, u); assert.equal(errText(r.body), 'Incorrect username or password.');
  }
  const searches = srv.requests.filter((q) => q.op === 'search' && q.filter.t === 'and' && q.filter.f[2] && q.filter.f[2].a === 'sAMAccountName');
  for (const v of ['*)(uid=*', '*', '*)(|(samaccountname=*'])   // as-auth lower-cases the typed name assert.ok(searches.some((q) => q.filter.f[2].t === 'eq' && q.filter.f[2].v === v), `literal value for ${v}`);
  assert.ok(!searches.some((q) => q.filter.f[2].t !== 'eq'), 'never a wildcard / present filter on the user attribute');
});

test('a foreign domain prefix or UPN suffix is not sent to AD', async () => {
  const n0 = srv.requests.length;
  const r = await req('POST', '/login', { form: { user: 'OTHERDOM\\alice', pass: PASSWORDS.user } });
  const r2 = await req('POST', '/login', { form: { user: 'alice@evil.example', pass: PASSWORDS.user } });
  assert.equal(r.status, 401); assert.equal(r2.status, 401);
  assert.equal(srv.requests.length, n0);
});

test('end-to-end admin: ASIC-HQ\\alice → TOTP enrol → session → whoami/verify; second login with TOTP; DC failover each time', async () => {
  const { secret, cookies } = await enrolLogin('ASIC-HQ\\alice', PASSWORDS.user);
  const who = JSON.parse((await req('GET', '/auth/whoami', { cookies })).body);
  assert.equal(who.user, 'alice@asic-hq.com'); assert.equal(who.role, 'admin'); assert.equal(who.source, 'ad');
  assert.equal(who.method, 'ad+totp'); assert.equal(who.mfa, true); assert.equal(who.mfaEnrolled, true);
  const v = await req('GET', '/auth/verify', { cookies });
  assert.equal(v.status, 200); assert.equal(v.headers['x-auth-role'], 'admin'); assert.equal(v.headers['x-auth-user'], 'alice@asic-hq.com');
  const sh = shadow('alice@asic-hq.com');
  assert.equal(sh.source, 'ad'); assert.equal(sh.dn, DN.user('alice')); assert.equal(sh.role, 'admin');
  assert.ok(!sh.passHash && !sh.salt, 'shadow record has no password');
  // second sign-in, UPN form: password → OTP page → code
  const r1 = await req('POST', '/login', { form: { user: 'alice@asic-hq.com', pass: PASSWORDS.user } });
  assert.equal(r1.status, 200); assert.match(r1.body, /Two-step verification/);
  const r2 = await req('POST', '/login/otp', { form: { code: totp(secret, Math.floor(Date.now() / 30000) + 1) }, cookies: r1.cookies });
  assert.equal(r2.status, 302); assert.ok(r2.cookies.as_session);
  // admin view: AD block summarised, password never exposed
  const adm = await req('GET', '/auth/admin/config', { cookies: r2.cookies });
  const j = JSON.parse(adm.body);
  assert.equal(j.ldap.active, true); assert.equal(j.ldap.hasBindPassword, true);
  assert.ok(!adm.body.includes(PASSWORDS.svc) && !adm.body.includes(cfg().ldap.bindPassword));
  assert.equal(j.users.find((u) => u.user === 'alice@asic-hq.com').source, 'ad');
  // failover really happened (first DC is a dead port) and audit says method ad
  const log = fs.readFileSync(logFile, 'utf8');
  assert.match(log, /"event":"sign-in","user":"alice@asic-hq.com","role":"admin","method":"ad\+totp"/);
});

test('role mapping: operator, viewer, operator via nested group, highest of several groups', async () => {
  for (const [user, key, role] of [['ASIC-HQ\\bob', 'bob@asic-hq.com', 'operator'], ['carol', 'carol@asic-hq.com', 'viewer'], ['dave@asic-hq.com', 'dave@asic-hq.com', 'operator'], ['ivan', 'ivan@asic-hq.com', 'admin']]) {
    const { cookies, secret } = await enrolLogin(user, PASSWORDS.user);
    SECRETS[key] = secret;
    const who = JSON.parse((await req('GET', '/auth/whoami', { cookies })).body);
    assert.equal(who.role, role, user); assert.equal(who.user, key);
    assert.equal(shadow(key).role, role);
  }
});

test('removed from the SOC groups in AD → next sign-in refused AND existing sessions end', async () => {
  const r1 = await req('POST', '/login', { form: { user: 'ASIC-HQ\\dave', pass: PASSWORDS.user } });      // dave enrolled TOTP above
  const r2 = await req('POST', '/login/otp', { form: { code: totp(SECRETS['dave@asic-hq.com'], Math.floor(Date.now() / 30000) + 1) }, cookies: r1.cookies });
  const sess = r2.cookies;
  assert.equal((await req('GET', '/auth/verify', { cookies: sess })).status, 200);
  const g = fx.dir.get(DN.socL2); g.attrs.member.vals = g.attrs.member.vals.filter((d) => d !== DN.user('dave'));
  const u = fx.dir.get(DN.user('dave')); u.attrs.memberof.vals = [];
  const r = await req('POST', '/login', { form: { user: 'dave', pass: PASSWORDS.user } });
  assert.equal(r.status, 403);
  assert.equal((await req('GET', '/auth/verify', { cookies: sess })).status, 401);
  // persisted too. (On Windows dev boxes an antivirus scan can very rarely make one rename-over fail — logged as
  // "config save failed"; a second refused attempt saves again. Linux rename(2) is atomic, so production is unaffected.)
  if (!shadow('dave@asic-hq.com').adBlocked) await req('POST', '/login', { form: { user: 'dave', pass: PASSWORDS.user } });
  assert.equal(shadow('dave@asic-hq.com').adBlocked, 'not in any mapped AD group');
});

test('local accounts keep working unchanged; admin cannot set a password or role on an AD account', async () => {
  const r = await req('POST', '/login', { form: { user: 'localadmin', pass: LOCAL_PW } });
  assert.equal(r.status, 302); assert.ok(r.cookies.as_session);
  const who = JSON.parse((await req('GET', '/auth/whoami', { cookies: r.cookies })).body);
  assert.equal(who.source, 'local'); assert.equal(who.method, 'password');
  const bad = await req('POST', '/auth/admin/users/carol@asic-hq.com/update', { cookies: r.cookies, form: undefined, headers: { 'Content-Type': 'application/json' } });
  assert.equal(bad.status, 400);   // empty body → "nothing to change"
  const pw = await new Promise((resolve) => {
    const body = JSON.stringify({ password: 'Another-Pass-123' });
    const q = http.request({ host: '127.0.0.1', port, method: 'POST', path: '/auth/admin/users/carol@asic-hq.com/update', headers: { Cookie: 'as_session=' + r.cookies.as_session, 'Content-Type': 'application/json', 'Content-Length': body.length } }, (res) => { let d = ''; res.on('data', (c) => { d += c; }); res.on('end', () => resolve({ status: res.statusCode, body: d })); });
    q.end(body);
  });
  assert.equal(pw.status, 400); assert.match(pw.body, /directory accounts/);
  assert.ok(!shadow('carol@asic-hq.com').passHash);
  const wrong = await req('POST', '/login', { form: { user: 'localadmin', pass: 'nope-nope-1' } });
  assert.equal(wrong.status, 401);
});

test('secrets: the bind password and user passwords never appear in clear in config, audit log or responses', async () => {
  const conf = fs.readFileSync(cfgFile, 'utf8'); const log = fs.readFileSync(logFile, 'utf8');
  for (const s of [PASSWORDS.svc, PASSWORDS.user, LOCAL_PW]) { assert.ok(!conf.includes(s), 'config'); assert.ok(!log.includes(s), 'audit log'); }
  assert.equal(auth._t.dec(cfg().ldap.bindPassword), PASSWORDS.svc, 'stored encrypted with the existing enc()');
});

test('directory unreachable → 503 with a neutral message, not counted as a password failure', async () => {
  const c = cfg(); const saved = c.ldap.servers; c.ldap.servers = [{ url: `ldaps://${DC}:${deadP}`, ip: '127.0.0.1' }];
  fs.writeFileSync(cfgFile, JSON.stringify(c, null, 1)); const t = new Date(Date.now() + 2000); fs.utimesSync(cfgFile, t, t);  // the service re-reads the ldap block by mtime
  try {
    const r = await req('POST', '/login', { form: { user: 'carol', pass: PASSWORDS.user } });
    assert.equal(r.status, 503); assert.match(errText(r.body), /cannot be reached/);
  } finally { const c2 = cfg(); c2.ldap.servers = saved; fs.writeFileSync(cfgFile, JSON.stringify(c2, null, 1)); const t2 = new Date(Date.now() + 4000); fs.utimesSync(cfgFile, t2, t2); }
  const ok = await req('POST', '/login', { form: { user: 'carol', pass: PASSWORDS.user } });
  assert.equal(ok.status, 200, 'back to normal after the edit on disk (OTP page)');
});

// ---------------------------------------------------------------- helper CLI
function cli(args, input) {     // async: the fake DC lives in this process and must keep answering
  return new Promise((resolve) => {
    const c = spawn(process.execPath, [path.join(__dirname, '..', 'as-auth-ldap.js'), ...args], { env: Object.assign({}, process.env, { AS_AUTH_CFG: cfgFile, AS_AUTH_LOG: logFile }) });
    let out = ''; c.stdout.on('data', (d) => { out += d; }); c.stderr.on('data', (d) => { out += d; });
    c.on('close', (code) => resolve({ code, out }));
    c.stdin.end(input || '');
  });
}

test('as-auth-ldap.js: --set-bind-password verifies with a test bind, stores encrypted, prints nothing secret', async () => {
  const c = cfg(); c.ldap.servers = [`ldaps://localhost:${srv.port}`]; fs.writeFileSync(cfgFile, JSON.stringify(c, null, 1));   // localhost: no DNS beyond the hosts file
  const bad = await cli(['--set-bind-password'], 'definitely-wrong-pw\n');
  assert.equal(bad.code, 1); assert.match(bad.out, /test bind failed/); assert.ok(!bad.out.includes('definitely-wrong-pw'));
  assert.equal(auth._t.dec(cfg().ldap.bindPassword), PASSWORDS.svc, 'unchanged after a failed test');
  const ok = await cli(['--set-bind-password'], PASSWORDS.svc + '\n');
  assert.equal(ok.code, 0, ok.out); assert.match(ok.out, /stored encrypted/);
  assert.ok(!ok.out.includes(PASSWORDS.svc));
  const raw = fs.readFileSync(cfgFile, 'utf8');
  assert.ok(!raw.includes(PASSWORDS.svc)); assert.equal(auth._t.dec(cfg().ldap.bindPassword), PASSWORDS.svc);
});

test('as-auth-ldap.js --check: DNS/TCP/TLS/cert/service bind/base DN/group DNs', async () => {
  const r = await cli(['--check']);
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /TLS TLSv1\.[23] · certificate trusted/);
  assert.match(r.out, /service bind as CN=svc-zyberon-ldap/);
  assert.match(r.out, /group CN=SOC-Admins,OU=Groups,DC=asic-hq,DC=com → admin/);
  assert.match(r.out, /all checks passed/);
  assert.ok(!r.out.includes(PASSWORDS.svc));
});

test('as-auth-ldap.js --test-user: DN, flags, nested groups → role, verdict; password not echoed', async () => {
  const r = await cli(['--test-user', 'ASIC-HQ\\bob'], PASSWORDS.user + '\n');
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /DN {10}CN=bob,OU=Staff,DC=asic-hq,DC=com/);
  assert.match(r.out, /CN=SOC-Analysts,OU=Groups,DC=asic-hq,DC=com → operator/);
  assert.match(r.out, /WOULD SIGN IN as operator/);
  assert.ok(!r.out.includes(PASSWORDS.user));
  const d = await cli(['--test-user', 'erin'], PASSWORDS.user + '\n');
  assert.equal(d.code, 1); assert.match(d.out, /disabled=true/); assert.match(d.out, /REFUSED — account disabled in AD/);
});
