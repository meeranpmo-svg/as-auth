#!/usr/bin/env node
'use strict';
// as-auth-passwd.js — reset a LOCAL portal account's password from the server console (Arabian Shield sign-in gate).
//   sudo /usr/bin/node /opt/arabianshield-auth/as-auth-passwd.js <username>
// Prompts twice for the new password with no echo, checks the gate's own policy (10+ chars, letters and digits),
// writes a fresh salt + PBKDF2-SHA256 hash (same parameters as as-auth.js: 120000 rounds, 32 bytes) into
// /etc/arabianshield-auth.json after backing it up, clears lockout counters, and restarts as-auth.
// AD accounts (source "ad") have no local password and are refused. Nothing is printed except the outcome.
const fs = require('fs'), crypto = require('crypto'), cp = require('child_process');

const CFG = process.env.AS_AUTH_CONFIG || '/etc/arabianshield-auth.json';
const name = String(process.argv[2] || '').trim();
if (!name) { console.error('usage: as-auth-passwd.js <username>'); process.exit(2); }

function hashPw(pw, salt) { return crypto.pbkdf2Sync(String(pw), salt, 120000, 32, 'sha256').toString('hex'); }
function pwProblem(pw) {
  pw = String(pw || '');
  if (pw.length < 10) return 'the password needs at least 10 characters';
  if (!/[A-Za-z]/.test(pw) || !/\d/.test(pw)) return 'the password needs letters and digits';
  return null;
}
function askHidden(prompt) {
  return new Promise(function (resolve, reject) {
    if (!process.stdin.isTTY) return reject(new Error('run this from an interactive terminal'));
    process.stdout.write(prompt);
    const stdin = process.stdin; let buf = '';
    stdin.setRawMode(true); stdin.resume(); stdin.setEncoding('utf8');
    function done(err, val) { stdin.setRawMode(false); stdin.pause(); stdin.removeListener('data', onData); process.stdout.write('\n'); err ? reject(err) : resolve(val); }
    function onData(ch) {
      for (const c of ch) {
        if (c === '\u0003') return done(new Error('cancelled'));
        if (c === '\r' || c === '\n') return done(null, buf);
        if (c === '\u007f' || c === '\b') { buf = buf.slice(0, -1); continue; }
        buf += c;
      }
    }
    stdin.on('data', onData);
  });
}

(async function main() {
  let cfg;
  try { cfg = JSON.parse(fs.readFileSync(CFG, 'utf8')); } catch (e) { console.error('cannot read ' + CFG + ': ' + e.message); process.exit(1); }
  const users = Array.isArray(cfg.users) ? cfg.users : [];
  const u = users.find(function (x) { return x && String(x.user || '').toLowerCase() === name.toLowerCase(); });
  if (!u) { console.error('no local account named "' + name + '"'); process.exit(1); }
  if (u.source === 'ad') { console.error('"' + name + '" is an Active Directory account — reset its password in AD, not here'); process.exit(1); }

  const p1 = await askHidden('New password for ' + u.user + ': ');
  const bad = pwProblem(p1); if (bad) { console.error('refused: ' + bad); process.exit(1); }
  const p2 = await askHidden('Repeat the new password: ');
  if (p1 !== p2) { console.error('the two entries differ — nothing changed'); process.exit(1); }

  const ts = new Date().toISOString().replace(/[-:]/g, '').slice(0, 15);
  fs.copyFileSync(CFG, CFG + '.bak-passwd-' + ts);
  u.salt = crypto.randomBytes(16).toString('hex');
  u.passHash = hashPw(p1, u.salt);
  u.pwChanged = new Date().toISOString();
  delete u.failed; delete u.lockedUntil; delete u.lockUntil; delete u.fails;   // clear any lockout state
  const tmp = CFG + '.tmp-' + process.pid;
  fs.writeFileSync(tmp, JSON.stringify(cfg, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, CFG);
  try { fs.chmodSync(CFG, 0o600); } catch (e) {}

  let restarted = 'not restarted (run: systemctl restart as-auth)';
  try { cp.execFileSync('systemctl', ['restart', 'as-auth'], { stdio: 'ignore' }); restarted = 'as-auth restarted'; } catch (e) {}
  console.log('password for "' + u.user + '" updated; ' + restarted + '; backup ' + CFG + '.bak-passwd-' + ts);
})().catch(function (e) { console.error(e.message); process.exit(1); });
