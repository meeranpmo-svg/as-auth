'use strict';
// Test-only X.509 builder (Node has no certificate-generation API): a throw-away root CA and server certificates signed
// by it, RSA-2048 / SHA-256, DER assembled by hand. Used by the fake LDAPS server — nothing here is shipped.
//   makeCA(cn) → {cert (PEM), key (KeyObject), keyPem, cn, ski}
//   makeServerCert(ca, {cn, dns:[…], ip:[…], days}) → {cert, key (PEM)}
const crypto = require('crypto');

function len(n) {
  if (n < 128) return Buffer.from([n]);
  const b = [];
  while (n > 0) { b.unshift(n & 255); n = Math.floor(n / 256); }
  return Buffer.from([0x80 | b.length].concat(b));
}
function der(tag, ...parts) { const c = Buffer.concat(parts); return Buffer.concat([Buffer.from([tag]), len(c.length), c]); }
const seq = (...p) => der(0x30, ...p);
const set = (...p) => der(0x31, ...p);
function oid(s) {
  const a = s.split('.').map(Number);
  const out = [40 * a[0] + a[1]];
  for (const n of a.slice(2)) {
    const b = [n & 0x7f];
    let v = Math.floor(n / 128);
    while (v > 0) { b.unshift((v & 0x7f) | 0x80); v = Math.floor(v / 128); }
    out.push(...b);
  }
  return der(0x06, Buffer.from(out));
}
function uint(buf) { if (buf[0] & 0x80) buf = Buffer.concat([Buffer.from([0]), buf]); return der(0x02, buf); }
const utf8 = (s) => der(0x0c, Buffer.from(s, 'utf8'));
const octet = (b) => der(0x04, b);
const bool = (v) => der(0x01, Buffer.from([v ? 0xff : 0]));
function time(d) {
  const p = (n) => String(n).padStart(2, '0');
  return der(0x17, Buffer.from(`${p(d.getUTCFullYear() % 100)}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`));
}
const name = (cn) => seq(set(seq(oid('2.5.4.3'), utf8(cn))));
const ALG = seq(oid('1.2.840.113549.1.1.11'), Buffer.from([0x05, 0x00]));
function ext(id, critical, value) { return critical ? seq(oid(id), bool(true), octet(value)) : seq(oid(id), octet(value)); }
function keyId(pub) { return crypto.createHash('sha1').update(pub.export({ type: 'spki', format: 'der' })).digest(); }
function pem(d) { return '-----BEGIN CERTIFICATE-----\n' + d.toString('base64').match(/.{1,64}/g).join('\n') + '\n-----END CERTIFICATE-----\n'; }

function build({ subject, issuer, pub, signKey, isCA, dns = [], ip = [], days = 30, aki }) {
  const now = Date.now();
  const exts = [];
  if (isCA) {
    exts.push(ext('2.5.29.19', true, seq(bool(true))));
    exts.push(ext('2.5.29.15', true, der(0x03, Buffer.from([0x01, 0x06]))));          // keyCertSign | cRLSign
  } else {
    exts.push(ext('2.5.29.19', true, seq()));
    exts.push(ext('2.5.29.15', true, der(0x03, Buffer.from([0x05, 0xa0]))));          // digitalSignature | keyEncipherment
    exts.push(ext('2.5.29.37', false, seq(oid('1.3.6.1.5.5.7.3.1'))));                // serverAuth
    const sans = dns.map((d) => der(0x82, Buffer.from(d))).concat(ip.map((a) => der(0x87, Buffer.from(a.split('.').map(Number)))));
    if (sans.length) exts.push(ext('2.5.29.17', false, seq(...sans)));
  }
  exts.push(ext('2.5.29.14', false, octet(keyId(pub))));
  if (aki) exts.push(ext('2.5.29.35', false, seq(der(0x80, aki))));
  const tbs = seq(
    der(0xa0, der(0x02, Buffer.from([2]))),
    uint(crypto.randomBytes(12)),
    ALG, name(issuer),
    seq(time(new Date(now - 3600e3)), time(new Date(now + days * 86400e3))),
    name(subject),
    pub.export({ type: 'spki', format: 'der' }),
    der(0xa3, seq(...exts)),
  );
  const sig = crypto.sign('sha256', tbs, signKey);
  return pem(seq(tbs, ALG, der(0x03, Buffer.concat([Buffer.from([0]), sig]))));
}

function makeCA(cn = 'Synthetic Test Root CA') {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const cert = build({ subject: cn, issuer: cn, pub: publicKey, signKey: privateKey, isCA: true, days: 365 });
  return { cert, key: privateKey, keyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }), cn, ski: keyId(publicKey) };
}

function makeServerCert(ca, { cn = 'localhost', dns = ['localhost'], ip = ['127.0.0.1'], days = 30 } = {}) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const cert = build({ subject: cn, issuer: ca.cn, pub: publicKey, signKey: ca.key, isCA: false, dns, ip, days, aki: ca.ski });
  return { cert, key: privateKey.export({ type: 'pkcs8', format: 'pem' }) };
}

module.exports = { makeCA, makeServerCert };
