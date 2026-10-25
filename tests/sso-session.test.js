'use strict';
// SESSIONS — server-side session table and the single sign-on re-check. Verifies: SSO sign-in asks for offline_access and
// keeps the refresh token only encrypted; the identity provider is asked again every ssoRecheckMinutes (refresh-token
// grant) and a disabled / revoked account (invalid_grant) or a removed role ends the session at the next check; a role
// change follows; an unreachable provider is tolerated for ssoOutageMinutes, then the session ends (fail closed); without a
// refresh token an SSO session lasts ssoNoRefreshMinutes; sign-out ends the session on the server (the old cookie is
// refused); a cookie without a server-side record is refused; idle timeout; admin sessions are shorter; admins list and
// revoke sessions (operator refused, validation names the field), session settings are bounded and audited; disabling an
// account ends its sessions. Synthetic only — an in-process fake OpenID provider over HTTPS (throw-away CA), a fake clock.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const https = require('node:https');
const crypto = require('node:crypto');
const { makeCA, makeServerCert } = require('./helpers/x509');

const SECRET = crypto.randomBytes(32).toString('hex');
const realNow = Date.now; let skew = 0; Date.now = () => realNow() + skew;   // the gate reads the clock through Date.now
const MIN = 60e3;
let tmp, cfgFile, logFile, sessFile, auth, port, idp, idpPort;

// ---- the fake OpenID provider -------------------------------------------------------------------------------------------
const KEYS = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const KID = 'synthetic-key-1';
const IDP = { disabled: false, roles: ['Portal.Ops'], down: false, issueRefresh: true, refreshCalls: 0, scopes: [], codes: {}, rts: new Set() };
const b64u = (b) => Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
function idToken(claims) {
  const now = Math.floor(Date.now() / 1000), h = b64u(JSON.stringify({ alg: 'RS256', kid: KID, typ: 'JWT' }));
  const p = b64u(JSON.stringify(Object.assign({ iss: `https://127.0.0.1:${idpPort}`, aud: 'synthetic-client', iat: now, exp: now + 3600, sub: 'sub-alice', preferred_username: 'alice@synthetic.test', name: 'Alice Synthetic', amr: ['pwd', 'mfa'], roles: IDP.roles }, claims)));
  return h + '.' + p + '.' + b64u(crypto.sign('RSA-SHA256', Buffer.from(h + '.' + p), KEYS.privateKey));
}
function newRt() { const rt = 'rt-' + crypto.randomBytes(6).toString('hex'); IDP.rts.add(rt); return rt; }
function idpHandler(req, res) {
  const send = (code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); };
  const base = `https://127.0.0.1:${idpPort}`;
  if (req.url === '/.well-known/openid-configuration') return send(200, { issuer: base, authorization_endpoint: base + '/authorize', token_endpoint: base + '/token', jwks_uri: base + '/jwks' });
  if (req.url === '/jwks') { const j = KEYS.publicKey.export({ format: 'jwk' }); return send(200, { keys: [Object.assign({ kid: KID, use: 'sig', alg: 'RS256' }, j)] }); }
  if (req.url === '/token') {
    let b = ''; req.on('data', (c) => { b += c; });
    req.on('end', () => {
      const p = new URLSearchParams(b);
      if (p.get('grant_type') === 'authorization_code') {
        const nonce = IDP.codes[p.get('code')]; if (!nonce) return send(400, { error: 'invalid_grant' });
        return send(200, Object.assign({ id_token: idToken({ nonce }), access_token: 'at', token_type: 'Bearer' }, IDP.issueRefresh ? { refresh_token: newRt() } : {}));
      }
      if (p.get('grant_type') === 'refresh_token') {
        IDP.refreshCalls++; IDP.scopes.push(p.get('scope'));
        if (IDP.down) { res.writeHead(503); return res.end('{"error":"temporarily_unavailable"}'); }
        if (IDP.disabled || !IDP.rts.has(p.get('refresh_token'))) return send(400, { error: 'invalid_grant', error_description: 'AADSTS50057: The user account is disabled.' });
        IDP.rts.delete(p.get('refresh_token'));
        return send(200, { id_token: idToken({}), access_token: 'at', refresh_token: newRt() });
      }
      return send(400, { error: 'unsupported_grant_type' });
    });
    return;
  }
  send(404, { error: 'not found' });
}

// ---- client helpers -----------------------------------------------------------------------------------------------------
function req(method, p, { form, json, cookies = {} } = {}) {
  return new Promise((resolve, reject) => {
    const body = form ? new URLSearchParams(form).toString() : json ? JSON.stringify(json) : '';
    const h = { Cookie: Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join('; ') };
    if (form) h['Content-Type'] = 'application/x-www-form-urlencoded'; if (json) h['Content-Type'] = 'application/json';
    if (body) h['Content-Length'] = Buffer.byteLength(body);
    const r = http.request({ host: '127.0.0.1', port, method, path: p, headers: h }, (res) => {
      let d = ''; res.on('data', (c) => { d += c; });
      res.on('end', () => {
        const jar = Object.assign({}, cookies);
        for (const sc of [].concat(res.headers['set-cookie'] || [])) { const m = /^([^=]+)=([^;]*)/.exec(sc); if (m) { if (m[2]) jar[m[1]] = m[2]; else delete jar[m[1]]; } }
        resolve({ status: res.statusCode, headers: res.headers, body: d, cookies: jar, setCookie: [].concat(res.headers['set-cookie'] || []) });
      });
    });
    r.on('error', reject); r.end(body);
  });
}
const verify = (cookies) => req('GET', '/auth/verify', { cookies });
const log = () => fs.readFileSync(logFile, 'utf8');
async function ssoSignIn() {
  const s = await req('GET', '/auth/sso/start');
  assert.equal(s.status, 302, s.body);
  const q = new URL(s.headers.location).searchParams, code = 'code-' + crypto.randomBytes(4).toString('hex');
  IDP.codes[code] = q.get('nonce');
  const cb = await req('GET', `/auth/sso/callback?code=${code}&state=${q.get('state')}`, { cookies: s.cookies });
  assert.equal(cb.status, 302, cb.body); assert.ok(cb.cookies.as_session, 'SSO session issued');
  return { cookies: { as_session: cb.cookies.as_session }, scope: q.get('scope') };
}
function pbkdf(pw, salt) { return crypto.pbkdf2Sync(pw, salt, 120000, 32, 'sha256').toString('hex'); }
function localUser(user, role, pw) { const salt = crypto.randomBytes(16).toString('hex'); return { user, name: user, role, salt, passHash: pbkdf(pw, salt) }; }
const localSignIn = async (user, pass) => { const r = await req('POST', '/login', { form: { user, pass } }); assert.equal(r.status, 302, r.body); return { cookies: { as_session: r.cookies.as_session }, setCookie: r.setCookie }; };

test.before(async () => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'as-auth-sess-'));
  const ca = makeCA('Synthetic IdP CA'), sc = makeServerCert(ca, { cn: 'localhost', dns: ['localhost'], ip: ['127.0.0.1'] });
  https.globalAgent.options.ca = ca.cert;                    // the gate's https.request uses the global agent
  idp = https.createServer({ key: sc.key, cert: sc.cert }, idpHandler);
  await new Promise((r) => idp.listen(0, '127.0.0.1', r)); idpPort = idp.address().port;
  cfgFile = path.join(tmp, 'arabianshield-auth.json'); logFile = path.join(tmp, 'auth.log'); sessFile = path.join(tmp, 'arabianshield-auth.sessions.json');
  fs.writeFileSync(cfgFile, JSON.stringify({
    secret: SECRET, mfaRequired: false, mfaPolicy: 'optional', hours: 12,
    users: [localUser('admin1', 'admin', 'Admin-One-Pass-1'), localUser('ops1', 'operator', 'Ops-One-Pass-1'), localUser('ops2', 'operator', 'Ops-Two-Pass-1')],
    sso: { enabled: true, provider: 'Synthetic IdP', issuer: `https://127.0.0.1:${idpPort}`, clientId: 'synthetic-client', clientSecret: '', redirectUri: 'https://portal.synthetic.test/auth/sso/callback',
      scopes: 'openid profile email', roleClaim: 'roles', roleMap: { 'Portal.Admin': 'admin', 'Portal.Ops': 'operator' }, defaultRole: 'none', requireMfa: true, allowedDomains: '' },
  }, null, 1));
  process.env.AS_AUTH_CFG = cfgFile; process.env.AS_AUTH_LOG = logFile;
  auth = require('../as-auth.js');
  await new Promise((r) => auth.server.listen(0, '127.0.0.1', r)); port = auth.server.address().port;
});
test.after(() => { auth.server.close(); idp.close(); Date.now = realNow; });
test.beforeEach(() => { Object.assign(IDP, { disabled: false, roles: ['Portal.Ops'], down: false, issueRefresh: true }); });

test('SSO sign-in asks for offline_access; the refresh token is stored only encrypted, never logged', async () => {
  const s = await ssoSignIn();
  assert.match(s.scope, /\boffline_access\b/);
  const v = await verify(s.cookies); assert.equal(v.status, 200); assert.equal(v.headers['x-auth-role'], 'operator');
  const table = fs.readFileSync(sessFile, 'utf8');
  for (const rt of IDP.rts) { assert.ok(!table.includes(rt), 'refresh token not in clear in the session table'); assert.ok(!log().includes(rt), 'refresh token not in the log'); }
  assert.equal((fs.statSync(sessFile).mode & 0o777).toString(8), '600');
});

test('the identity provider is asked again after the re-check interval; a role change follows', async () => {
  const s = await ssoSignIn(); const before = IDP.refreshCalls;
  skew += 5 * MIN; assert.equal((await verify(s.cookies)).status, 200); assert.equal(IDP.refreshCalls, before, 'no check before it is due');
  IDP.roles = ['Portal.Admin'];
  skew += 11 * MIN;
  const v = await verify(s.cookies);
  assert.equal(v.status, 200); assert.equal(IDP.refreshCalls, before + 1, 'refresh-token grant at the due check'); assert.match(IDP.scopes.at(-1), /offline_access/);
  assert.equal(v.headers['x-auth-role'], 'admin', 'the role the provider gives now');
  assert.match(log(), /"event":"role-changed","user":"alice@synthetic.test","role":"admin","method":"sso"/);
});

test('an account disabled at the identity provider loses its session at the next check (was: up to 12 h)', async () => {
  const s = await ssoSignIn();
  assert.equal((await verify(s.cookies)).status, 200);
  IDP.disabled = true;
  skew += 16 * MIN;
  assert.equal((await verify(s.cookies)).status, 401, 'refused at the check');
  assert.equal((await verify(s.cookies)).status, 401, 'and stays refused');
  assert.match(log(), /"event":"session-ended","user":"alice@synthetic.test","method":"sso","reason":"identity provider refused the session \(invalid_grant\)"/);
});

test('a role removed at the identity provider ends the session', async () => {
  const s = await ssoSignIn(); IDP.roles = [];
  skew += 16 * MIN;
  assert.equal((await verify(s.cookies)).status, 401);
  assert.match(log(), /role no longer granted by the identity provider/);
});

test('an unreachable provider is tolerated for the outage window, then the session ends (fail closed)', async () => {
  const s = await ssoSignIn(); IDP.down = true;
  skew += 16 * MIN; assert.equal((await verify(s.cookies)).status, 200, 'first failure: still in');
  assert.match(log(), /"event":"sso-recheck-error","user":"alice@synthetic.test"/);
  skew += 30 * MIN; assert.equal((await verify(s.cookies)).status, 200, '30 min into the outage: still in');
  skew += 31 * MIN; assert.equal((await verify(s.cookies)).status, 401, 'past 60 min: ended');
  assert.match(log(), /identity provider could not be reached for 60 min/);
});

test('without a refresh token an SSO session lasts the no-refresh limit', async () => {
  IDP.issueRefresh = false; const s = await ssoSignIn();
  skew += 30 * MIN; assert.equal((await verify(s.cookies)).status, 200);
  skew += 31 * MIN; assert.equal((await verify(s.cookies)).status, 401);
  assert.match(log(), /without a refresh token - sign in again/);
});

test('sign-out ends the session on the server: the old cookie is refused even if kept', async () => {
  const s = await ssoSignIn();
  const out = await req('GET', '/logout', { cookies: s.cookies }); assert.equal(out.status, 302);
  assert.equal((await verify(s.cookies)).status, 401, 'a copied cookie no longer works');
  const l = await localSignIn('ops1', 'Ops-One-Pass-1');
  await req('GET', '/logout', { cookies: l.cookies });
  assert.equal((await verify(l.cookies)).status, 401, 'local sessions too');
});

test('a validly signed cookie with no server-side record is refused (sessions from before the upgrade, forged sid)', async () => {
  const payload = b64u(JSON.stringify({ exp: Date.now() + 3600e3, iat: Date.now(), u: 'ops1', r: 'operator', m: 'password' }));
  const sig = crypto.createHmac('sha256', SECRET).update(payload).digest('hex');
  assert.equal((await verify({ as_session: payload + '.' + sig })).status, 401);
  const p2 = b64u(JSON.stringify({ exp: Date.now() + 3600e3, iat: Date.now(), u: 'ops1', r: 'operator', m: 'password', sid: 'not-a-real-session-id' }));
  assert.equal((await verify({ as_session: p2 + '.' + crypto.createHmac('sha256', SECRET).update(p2).digest('hex') })).status, 401);
});

test('idle timeout: activity keeps a session alive, an hour without any ends it', async () => {
  const l = await localSignIn('ops1', 'Ops-One-Pass-1');
  for (let i = 0; i < 3; i++) { skew += 40 * MIN; assert.equal((await verify(l.cookies)).status, 200, 'active every 40 min'); }
  skew += 61 * MIN; assert.equal((await verify(l.cookies)).status, 401, 'idle 61 min');
  assert.match(log(), /"event":"session-ended","user":"ops1","method":"password","reason":"idle for more than 60 min"/);
});

test('admin sessions are shorter (8 h) than other sessions (12 h)', async () => {
  const a = await localSignIn('admin1', 'Admin-One-Pass-1'), o = await localSignIn('ops2', 'Ops-Two-Pass-1');
  const age = (sc) => Number(/Max-Age=(\d+)/.exec(sc.find((x) => x.startsWith('as_session=')))[1]);
  assert.equal(age(a.setCookie), 8 * 3600); assert.equal(age(o.setCookie), 12 * 3600);
});

test('admins list and revoke sessions; operators refused; validation names the field; disabling an account ends its sessions', async () => {
  const a = await localSignIn('admin1', 'Admin-One-Pass-1'), o = await localSignIn('ops2', 'Ops-Two-Pass-1'), s = await ssoSignIn();
  assert.equal((await req('GET', '/auth/admin/sessions', { cookies: o.cookies })).status, 403, 'operator refused');
  const list = await req('GET', '/auth/admin/sessions', { cookies: a.cookies });
  assert.equal(list.status, 200); const L = JSON.parse(list.body);
  const mine = L.sessions.find((x) => x.user === 'alice@synthetic.test');
  assert.ok(mine && mine.sso.refresh === true && mine.id.length === 8, 'SSO session listed');
  assert.ok(!/rt-|refresh_token|"rt"/.test(list.body), 'no token in the list');
  assert.equal((await req('POST', '/auth/admin/sessions/revoke', { cookies: a.cookies, json: {} })).status, 400);
  assert.equal((await req('POST', '/auth/admin/sessions/revoke', { cookies: o.cookies, json: { user: 'admin1' } })).status, 403);
  const rv = await req('POST', '/auth/admin/sessions/revoke', { cookies: a.cookies, json: { user: 'alice@synthetic.test' } });
  assert.equal(rv.status, 200); assert.ok(JSON.parse(rv.body).ended >= 1);
  assert.equal((await verify(s.cookies)).status, 401, 'revoked SSO session ends at once');
  assert.match(log(), /"event":"session-revoke","user":"alice@synthetic.test".*by admin1/);
  // session settings: bounded and audited
  const bad = await req('POST', '/auth/admin/policy', { cookies: a.cookies, json: { session: { idleMinutes: 2 } } });
  assert.equal(bad.status, 400); assert.match(JSON.parse(bad.body).error, /session\.idleMinutes/);
  assert.equal((await req('POST', '/auth/admin/policy', { cookies: a.cookies, json: { session: { tokenLifetime: 9 } } })).status, 400);
  const good = await req('POST', '/auth/admin/policy', { cookies: a.cookies, json: { session: { idleMinutes: 30, ssoRecheckMinutes: 10 } } });
  assert.equal(good.status, 200); assert.equal(JSON.parse(good.body).session.idleMinutes, 30);
  assert.match(log(), /idle 30 min, admin 8 h, SSO re-check 10 min/);
  // disabling a local account ends its live session
  assert.equal((await verify(o.cookies)).status, 200);
  assert.equal((await req('POST', '/auth/admin/users/ops2/update', { cookies: a.cookies, json: { disabled: true } })).status, 200);
  assert.equal((await verify(o.cookies)).status, 401);
  assert.match(log(), /"event":"session-ended","user":"ops2","method":"password","reason":"account disabled · by admin1"/);
});
