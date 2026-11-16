'use strict';
// setup-ad-signin.sh driven through a pseudo-terminal (tests/setup-ad-signin-pty.py) against a temporary config and the real
// as-auth-ldap.js: --init adds the block once, a malformed DN is refused and asked again, Enter keeps a value, the config is
// backed up and keeps its mode, the connection check failing (no DC here) stops the script with AD sign-in still OFF.
// SYNTHETIC config only. Run: node --test tests/setup-ad-signin.test.js
const test = require('node:test'), assert = require('node:assert/strict'), fs = require('fs'), os = require('os'), path = require('path'), { spawnSync } = require('child_process');
const ROOT = path.join(__dirname, '..');
test('guided AD setup: DNs validated and saved, check failure leaves AD sign-in off', { skip: process.getuid && process.getuid() !== 0 ? 'needs root (the script refuses to run otherwise)' : false }, () => {
  const S = fs.mkdtempSync(path.join(os.tmpdir(), 'adsetup-')); fs.mkdirSync(S + '/src'); fs.mkdirSync(S + '/dest');
  for (const f of ['as-auth.js', 'ldap-client.js', 'as-auth-ldap.js', 'install-ad.sh', 'setup-ad-signin.sh']) fs.copyFileSync(path.join(ROOT, f), path.join(S, 'src', f));
  for (const f of ['as-auth.js', 'ldap-client.js', 'as-auth-ldap.js']) fs.copyFileSync(path.join(ROOT, f), path.join(S, 'dest', f));
  fs.writeFileSync(S + '/cfg.json', '{"users":{},"secret":"synthetic"}\n', { mode: 0o600 });
  const B = 'CN=svc-syn,OU=Service Accounts,DC=asic-hq,DC=com', A = 'CN=SYN-Admins,OU=Groups,DC=asic-hq,DC=com';
  const r = spawnSync('python3', [path.join(__dirname, 'setup-ad-signin-pty.py'), S, 'y', 'not a dn', B, A, '', '', 'n'], { encoding: 'utf8', timeout: 90000 });
  const outp = r.stdout || '';
  assert.match(outp, /not a DN like/, 'a malformed DN is refused'); assert.match(outp, /backup: /); assert.match(outp, /\[FAIL\]/);
  assert.match(outp, /AD sign-in is still off/); assert.match(outp, /EXIT 1/);
  const c = JSON.parse(fs.readFileSync(S + '/cfg.json', 'utf8'));
  assert.equal(c.ldap.enabled, false); assert.equal(c.ldap.bindDN, B); assert.equal(c.ldap.groupRoles[A], 'admin');
  assert.equal(Object.values(c.ldap.groupRoles).filter((x) => x === 'operator').length, 1, 'Enter kept the operator group');
  assert.equal(fs.statSync(S + '/cfg.json').mode & 0o777, 0o600, 'mode kept'); assert.equal(c.secret, 'synthetic', 'other settings untouched');
  fs.rmSync(S, { recursive: true, force: true });
});
