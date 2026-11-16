'use strict';
// as-auth-ldap.js --set-bind-password in a real terminal (pseudo-terminal, tests/helpers/pty-run.py): a line break left over from
// the previous answer (a Windows terminal over SSH sends CR LF) is ignored instead of ending the prompt with an empty password;
// each character shows as *; the password never appears on the screen; it is stored encrypted. SYNTHETIC config and password.
const test = require('node:test'), assert = require('node:assert/strict'), fs = require('fs'), os = require('os'), path = require('path'), { spawnSync } = require('child_process');
test('hidden prompt: a stray CR LF is ignored, * per character, the password never echoed, stored encrypted', () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'hp-')), cfg = path.join(d, 'auth.json');
  fs.writeFileSync(cfg, JSON.stringify({ secret: 'synthetic-secret-0123456789', users: [], ldap: { enabled: false, servers: [], baseDN: 'DC=syn,DC=test', bindDN: 'CN=svc,DC=syn,DC=test' } }), { mode: 0o600 });
  const PW = 'Synthetic-Bind-Pass-77';
  // what a Windows terminal sends: the CR LF of the previous answer arrives first, then the password and Enter, twice
  const r = spawnSync('python3', [path.join(__dirname, 'helpers', 'pty-run.py'), JSON.stringify(['\r\n', PW + '\r', PW + '\r']), process.execPath, path.join(__dirname, '..', 'as-auth-ldap.js'), '--set-bind-password', '--no-verify', '--config', cfg], { encoding: 'utf8', timeout: 30000 });
  const out = r.stdout || '';
  assert.doesNotMatch(out, /password is empty/, 'the stray line break did not end the prompt: ' + out);
  assert.ok(!out.includes(PW), 'the password never appears on the screen');
  assert.match(out, /\*{10,}/, 'a * per character');
  const c = JSON.parse(fs.readFileSync(cfg, 'utf8'));
  assert.ok(c.ldap.bindPassword && !c.ldap.bindPassword.includes(PW), 'stored, encrypted');
  fs.rmSync(d, { recursive: true, force: true });
});
