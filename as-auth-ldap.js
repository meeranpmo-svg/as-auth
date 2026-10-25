#!/usr/bin/env node
/* Arabian Shield sign-in gate — Active Directory (LDAPS) helper. Installed next to as-auth.js in /opt/arabianshield-auth.
   Run as root (it reads/writes /etc/arabianshield-auth.json). Passwords are read without echo and are never printed.

     node as-auth-ldap.js --init                 add a disabled `ldap` block with the ASIC-HQ defaults (only if none exists)
     node as-auth-ldap.js --set-bind-password    prompt for the service-account password, test it, store it enc()-encrypted
                          [--no-verify]          store without the test bind (e.g. DC not reachable yet)
     node as-auth-ldap.js --check                DNS / TCP / TLS + certificate / service bind / base DN / mapped group DNs
     node as-auth-ldap.js --test-user <name>     prompt for that user's password; show DN, flags, groups → role, verdict
     node as-auth-ldap.js --enable | --disable   switch AD sign-in on / off (the running service picks it up, no restart)
     options: --config <file> (default $AS_AUTH_CFG or /etc/arabianshield-auth.json)
   Without a TTY the password(s) are read from stdin, one per line (for automation: printf '%s\n' "$PW" | …).     */
'use strict';
const path = require('path');
const fs = require('fs');
const dns = require('dns');
const net = require('net');
const tls = require('tls');

const argv = process.argv.slice(2);
function opt(name) { const i = argv.indexOf(name); return i >= 0 ? (argv[i + 1] || '') : null; }
if (opt('--config')) process.env.AS_AUTH_CFG = opt('--config');
const CFG_FILE = process.env.AS_AUTH_CFG || '/etc/arabianshield-auth.json';
const out = function (s) { process.stdout.write(s + '\n'); };
const OK = '  [ok]   ', BAD = '  [FAIL] ', INFO = '  [..]   ';

function usage() { out(fs.readFileSync(__filename, 'utf8').split('\n').slice(1, 13).join('\n').replace(/^\/\* ?|\s*\*\/$/gm, '')); process.exit(2); }

/* ── hidden input ── */
let stdinLines = null;
function readStdinLines() {
  if (stdinLines) return Promise.resolve(stdinLines);
  return new Promise(function (resolve) {
    let buf = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', function (c) { buf += c; });
    process.stdin.on('end', function () { stdinLines = buf.split(/\r?\n/); resolve(stdinLines); });
  });
}
function promptHidden(label) {
  if (!process.stdin.isTTY) return readStdinLines().then(function (l) { return l.length ? l.shift() : ''; });
  return new Promise(function (resolve) {
    const stdin = process.stdin;
    let pw = '';
    process.stderr.write(label);
    stdin.setRawMode(true); stdin.resume(); stdin.setEncoding('utf8');
    function cleanup() { stdin.setRawMode(false); stdin.pause(); stdin.removeListener('data', on); }
    function on(chunk) {
      for (const c of chunk) {
        if (c === '\r' || c === '\n') { cleanup(); process.stderr.write('\n'); return resolve(pw); }
        if (c === '\u0003') { cleanup(); process.stderr.write('\n'); process.exit(130); }
        if (c === '\u007f' || c === '\b') pw = pw.slice(0, -1); else pw += c;
      }
    }
    stdin.on('data', on);
  });
}

/* ── config file (read-modify-write of the raw JSON: the running service picks the change up by mtime) ── */
function readCfg() { return JSON.parse(fs.readFileSync(CFG_FILE, 'utf8')); }
function writeCfg(obj) {
  const st = fs.statSync(CFG_FILE), tmp = CFG_FILE + '.tmp-ldap-' + process.pid;
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 1), { mode: 0o600 });
  try { if (process.getuid && process.getuid() === 0) fs.chownSync(tmp, st.uid, st.gid); } catch (e) { /* not root */ }
  fs.renameSync(tmp, CFG_FILE);
}
const ASIC_DEFAULTS = {
  enabled: false,
  servers: ['ldaps://asdc-hqa.asic-hq.com:636'],
  caFile: '/etc/ssl/asic-hq/asic-microsoft-ca.pem',
  baseDN: 'DC=asic-hq,DC=com',
  bindDN: 'CN=svc-zyberon-ldap,OU=Service Accounts,DC=asic-hq,DC=com',
  bindPassword: '',
  netbios: ['ASIC-HQ'],
  upnSuffix: ['asic-hq.com'],
  userAttr: 'sAMAccountName',
  groupRoles: {
    'CN=SOC-Admins,OU=Groups,DC=asic-hq,DC=com': 'admin',
    'CN=SOC-Analysts,OU=Groups,DC=asic-hq,DC=com': 'operator',
    'CN=SOC-Viewers,OU=Groups,DC=asic-hq,DC=com': 'viewer',
  },
  nested: true,
  requireMfa: true,
  timeoutMs: 8000,
  hint: 'Sign in with your ASIC-HQ account',
};

function load() {
  const auth = require(path.join(__dirname, 'as-auth.js'))._t;      // same config + the same enc()/dec() key
  const lib = require(path.join(__dirname, 'ldap-client.js'));
  return { auth: auth, lib: lib, l: auth.ldapCfg() };
}

async function cmdInit() {
  const c = readCfg();
  if (c.ldap) { out('an ldap block already exists in ' + CFG_FILE + ' — nothing changed'); return 0; }
  c.ldap = ASIC_DEFAULTS; writeCfg(c);
  out('added a DISABLED ldap block with the ASIC-HQ defaults to ' + CFG_FILE);
  out('next: check bindDN / groupRoles DNs, then --set-bind-password, --check, --test-user <name>, --enable');
  return 0;
}

async function cmdSetBindPassword() {
  const x = load();
  if (!x.l.bindDN) { out('set ldap.bindDN first (as-auth-ldap.js --init writes a template)'); return 1; }
  const pw = await promptHidden('Password for ' + x.l.bindDN + ': ');
  if (!pw || !pw.trim()) { out('refused: the password is empty'); return 1; }
  if (process.stdin.isTTY) { const again = await promptHidden('Repeat the password: '); if (again !== pw) { out('the two entries differ — nothing stored'); return 1; } }
  if (argv.indexOf('--no-verify') < 0) {
    if (!x.l.servers.length || !x.l.caFile) { out('servers / caFile not set — cannot test the password (use --no-verify to store it anyway)'); return 1; }
    try {
      const client = x.lib.createClient({ servers: x.l.servers, caFile: x.l.caFile, timeoutMs: x.l.timeoutMs });
      await client.run(function (conn) { return conn.bind(x.l.bindDN, pw); });
      out(OK + 'test bind as the service account succeeded');
    } catch (e) {
      out(BAD + 'test bind failed: ' + e.message);
      out('nothing stored (fix the password, or use --no-verify if the directory is not reachable yet)');
      return 1;
    }
  }
  const c = readCfg();
  c.ldap = Object.assign({}, ASIC_DEFAULTS, { enabled: false }, c.ldap || {});
  c.ldap.bindPassword = x.auth.enc(pw);
  writeCfg(c);
  out('service-account password stored encrypted in ' + CFG_FILE + ' (ldap.bindPassword)');
  return 0;
}

async function cmdEnable(on) {
  const c = readCfg();
  if (!c.ldap) { out('no ldap block — run --init first'); return 1; }
  if (on) {
    const miss = ['servers', 'caFile', 'baseDN', 'bindDN', 'bindPassword'].filter(function (k) { return !c.ldap[k] || (Array.isArray(c.ldap[k]) && !c.ldap[k].length); });
    if (miss.length) { out('cannot enable — missing: ' + miss.join(', ')); return 1; }
    if (!c.ldap.groupRoles || !Object.keys(c.ldap.groupRoles).length) { out('cannot enable — ldap.groupRoles maps no group to a role'); return 1; }
  }
  c.ldap.enabled = !!on; writeCfg(c);
  out('AD sign-in ' + (on ? 'ENABLED' : 'disabled') + ' (the running service picks this up on the next request)');
  return 0;
}

function tcpProbe(host, port, ms) {
  return new Promise(function (resolve) {
    const s = net.connect({ host: host, port: port });
    const t = setTimeout(function () { s.destroy(); resolve('timeout after ' + ms + ' ms'); }, ms);
    s.once('connect', function () { clearTimeout(t); s.destroy(); resolve(null); });
    s.once('error', function (e) { clearTimeout(t); resolve(e.code || e.message); });
  });
}
/* diagnostics only: show which certificate the server presents when verification FAILED. Nothing is sent over it. */
function peekCert(host, port, servername, ms) {
  return new Promise(function (resolve) {
    const o = { host: host, port: port, rejectUnauthorized: false };
    if (!net.isIP(servername)) o.servername = servername;
    const s = tls.connect(o);
    const t = setTimeout(function () { s.destroy(); resolve(null); }, ms);
    s.once('secureConnect', function () { clearTimeout(t); const c = s.getPeerCertificate(); s.destroy(); resolve(c); });
    s.once('error', function () { clearTimeout(t); resolve(null); });
  });
}
function certLine(c) { return 'subject CN=' + ((c.subject && c.subject.CN) || '?') + ' · issuer CN=' + ((c.issuer && c.issuer.CN) || '?') + ' · valid to ' + c.valid_to + (c.subjectaltname ? ' · ' + c.subjectaltname : ''); }

async function cmdCheck() {
  const x = load(), l = x.l;
  let bad = 0;
  out('AD sign-in: ' + (l.enabled ? 'enabled' : 'DISABLED') + ' · base ' + (l.baseDN || '(unset)') + ' · bind ' + (l.bindDN || '(unset)') + ' · password ' + (l.bindPassword ? 'stored (encrypted)' : 'NOT SET'));
  if (!l.servers.length) { out(BAD + 'no servers configured'); return 1; }
  try { const pem = fs.readFileSync(l.caFile, 'utf8'); const n = (pem.match(/BEGIN CERTIFICATE/g) || []).length; if (!n) throw new Error('no PEM certificate inside'); out(OK + 'CA file ' + l.caFile + ' (' + n + ' certificate' + (n > 1 ? 's' : '') + ')'); } catch (e) { out(BAD + 'CA file ' + (l.caFile || '(unset)') + ': ' + e.message); bad++; }
  let usable = null;
  for (const raw of l.servers) {
    let s; try { s = x.lib.parseServer(raw); } catch (e) { out(BAD + e.message); bad++; continue; }
    out('server ' + s.url + (s.ip ? ' (dial ' + s.ip + ')' : ''));
    try { const a = await dns.promises.lookup(s.host, { all: true }); out(OK + 'DNS ' + s.host + ' → ' + a.map(function (r) { return r.address; }).join(', ')); } catch (e) { out((s.ip ? INFO : BAD) + 'DNS ' + s.host + ': ' + e.code + (s.ip ? ' (ip override in use)' : '')); if (!s.ip) { bad++; continue; } }
    const dial = s.ip || s.host, tcp = await tcpProbe(dial, s.port, l.timeoutMs);
    if (tcp) { out(BAD + 'TCP ' + dial + ':' + s.port + ' — ' + tcp + ' (firewall 10.100.12.134 → DC TCP ' + s.port + '?)'); bad++; continue; }
    out(OK + 'TCP ' + dial + ':' + s.port + ' open');
    try {
      const client = x.lib.createClient({ servers: [raw], caFile: l.caFile, timeoutMs: l.timeoutMs });
      const conn = await client.connect();
      const c = conn.sock.getPeerCertificate();
      out(OK + 'TLS ' + conn.sock.getProtocol() + ' · certificate trusted and valid for ' + s.servername + ' · ' + certLine(c));
      const days = Math.floor((Date.parse(c.valid_to) - Date.now()) / 86400000);
      if (days < 30) out(INFO + 'certificate expires in ' + days + ' days');
      conn.close();
      if (!usable) usable = raw;
    } catch (e) {
      out(BAD + 'TLS: ' + e.message); bad++;
      const c = await peekCert(dial, s.port, s.servername, l.timeoutMs);
      if (c && c.subject) out(INFO + 'the server presents: ' + certLine(c) + ' — export THAT issuer\'s root CA as Base-64 into ' + l.caFile);
    }
  }
  if (!usable) { out(BAD + 'no server passed the TLS checks — stopping'); return 1; }
  const pw = l.bindPassword ? x.auth.dec(l.bindPassword) : null;
  if (!pw) { out(BAD + 'service-account password not set or not decryptable (--set-bind-password)'); return 1; }
  const client = x.lib.createClient({ servers: [usable], caFile: l.caFile, timeoutMs: l.timeoutMs });
  try {
    await client.run(async function (conn) {
      const root = await conn.rootDSE();
      if (root) out(OK + 'RootDSE: defaultNamingContext ' + x.lib.ad.first(root, 'defaultNamingContext') + ' · ' + (x.lib.ad.first(root, 'dnsHostName') || x.lib.ad.first(root, 'ldapServiceName')));
      if (root && l.baseDN && x.lib.ad.first(root, 'defaultNamingContext').toLowerCase() !== l.baseDN.toLowerCase()) out(INFO + 'baseDN ' + l.baseDN + ' differs from the domain root (fine if it is an OU inside it)');
      try { await conn.bind(l.bindDN, pw); out(OK + 'service bind as ' + l.bindDN); } catch (e) { out(BAD + 'service bind: ' + e.message); bad++; return; }
      try { await conn.search(l.baseDN, { scope: 'base', filter: '(objectClass=*)', attributes: ['distinguishedName'] }); out(OK + 'base DN ' + l.baseDN + ' exists'); } catch (e) { out(BAD + 'base DN ' + l.baseDN + ': ' + e.message); bad++; }
      const groups = Object.keys(l.groupRoles || {});
      if (!groups.length) { out(BAD + 'groupRoles is empty — nobody could sign in'); bad++; }
      for (const g of groups) {
        try { const r = await conn.search(g, { scope: 'base', filter: '(objectClass=group)', attributes: ['sAMAccountName'] }); if (!r.entries.length) throw new Error('exists but is not a group'); out(OK + 'group ' + g + ' → ' + l.groupRoles[g]); } catch (e) { out(BAD + 'group ' + g + ': ' + e.message); bad++; }
      }
    });
  } catch (e) { out(BAD + e.message); bad++; }
  out(bad ? bad + ' problem(s) found' : 'all checks passed');
  return bad ? 1 : 0;
}

async function cmdTestUser(name) {
  const x = load();
  if (!name) { out('usage: --test-user <ASIC-HQ\\user | user@asic-hq.com | user>'); return 2; }
  const id = x.auth.adIdentity(name);
  if (!id) { out('"' + name + '" is not a name of the configured domain (netbios ' + x.l.netbios.join('/') + ', UPN suffix ' + x.l.upnSuffix.join('/') + ')'); return 1; }
  const pw = await promptHidden('Password for ' + name + ' (one real bind — a wrong password counts towards the AD lockout): ');
  let r;
  try { r = await x.auth.adAuthenticate(id, pw); } catch (e) { out(BAD + 'directory error: ' + e.message); return 1; }
  const i = r.info || {};
  out('search      (' + id.attr + '=' + id.value + ') under ' + x.l.baseDN);
  if (i.dn) {
    out('DN          ' + i.dn);
    out('account     ' + i.sam + (i.upn ? ' · ' + i.upn : '') + (i.name ? ' · ' + i.name : '') + ' → platform user ' + x.auth.shadowKey(i.sam));
    const f = i.flags || {};
    out('flags       disabled=' + !!f.disabled + ' expired=' + !!f.expired + ' (expires ' + f.expires + ') locked=' + !!f.locked + (f.lockoutTime ? ' (lockoutTime ' + f.lockoutTime + ')' : '') + ' passwordExpired=' + !!f.passwordExpired + ' userAccountControl=0x' + Number(f.userAccountControl || 0).toString(16));
    out('groups      ' + ((i.groups || []).length ? i.groups.map(function (g) { return g.dn + ' → ' + g.role; }).join('\n            ') : '(no mapped group' + (x.l.nested !== false ? ', nested membership included' : '') + ')'));
    out('role        ' + (i.role || 'none'));
    out('password    ' + (i.bind === 'ok' ? 'accepted by AD' : 'not verified'));
  }
  out('verdict     ' + (r.ok ? 'WOULD SIGN IN as ' + i.role + (x.l.requireMfa !== false ? ' (TOTP required)' : '') : 'REFUSED — ' + r.reason));
  return r.ok ? 0 : 1;
}

async function main() {
  if (!argv.length || argv.indexOf('-h') >= 0 || argv.indexOf('--help') >= 0) usage();
  if (!fs.existsSync(CFG_FILE)) { out('config not found: ' + CFG_FILE); return 1; }
  if (argv.indexOf('--init') >= 0) return cmdInit();
  if (argv.indexOf('--set-bind-password') >= 0) return cmdSetBindPassword();
  if (argv.indexOf('--check') >= 0) return cmdCheck();
  if (opt('--test-user') !== null) return cmdTestUser(opt('--test-user'));
  if (argv.indexOf('--enable') >= 0) return cmdEnable(true);
  if (argv.indexOf('--disable') >= 0) return cmdEnable(false);
  usage();
  return 2;
}
main().then(function (code) { process.exitCode = code || 0; }, function (e) { process.stderr.write('as-auth-ldap: ' + e.message + '\n'); process.exitCode = 1; });
