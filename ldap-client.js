/* Arabian Shield — minimal LDAPv3 client over TLS (Node stdlib only; ES2019 / Node 12 safe — no ?. / ?? / class fields).
   Shared by the sign-in gate (/opt/arabianshield-auth/ldap-client.js) and the SIEM (engine/ad/ldap-client.js) —
   keep the two copies identical.

   Transport   ldaps://host:636 (TLS from the first byte) or ldap://host:389 + StartTLS (1.3.6.1.4.1.1466.20037).
               There is NO cleartext mode: an ldap:// server is always upgraded with StartTLS before anything else.
               Certificate verification is always on (rejectUnauthorized cannot be turned off); the CA comes from a
               PEM file (the AD CS root) and the certificate must name the server's DNS name. A server entry may carry
               an `ip` to dial while the certificate is still checked against the DNS name in the URL.
   Operations  simple Bind (an EMPTY password is refused client-side: RFC 4513 §5.1.2 "unauthenticated bind" would
               otherwise succeed without checking anything), Search (and/or/not/equality/substrings/>=/<=/~=/present/
               extensible incl. 1.2.840.113556.1.4.1941 LDAP_MATCHING_RULE_IN_CHAIN), paged results control
               1.2.840.113556.1.4.319 (page size capped at AD's MaxPageSize 1000), Unbind.
   Failover    servers are tried in order; client.run(fn) re-runs fn on the next server after a transport failure
               (connect error, TLS error, timeout, connection lost). LDAP result errors (e.g. 49) are NOT retried.
   Logging     opts.log(level, msg, meta) receives server URLs, operations and result codes — never DNs of binds,
               never passwords.

   API
     const { createClient, escapeFilter, escapeDN, parseFilter, ad } = require('./ldap-client');
     const c = createClient({ servers: ['ldaps://dc1.example.com:636', { url: 'ldaps://dc2.example.com', ip: '10.0.0.2' }],
                              caFile: '/etc/ssl/ad-root.pem', timeoutMs: 8000 });
     await c.run(async (conn) => { await conn.bind(dn, pw); return conn.search(baseDN, { filter, attributes, pageSize: 1000 }); });
     → search result { entries: [{ dn, attrs: {lowercasename: [string]}, raw: {lowercasename: [Buffer]} }], references: [] }  */
'use strict';
const net = require('net');
const tls = require('tls');
const fs = require('fs');

const OID = {
  PAGED: '1.2.840.113556.1.4.319',
  IN_CHAIN: '1.2.840.113556.1.4.1941',
  STARTTLS: '1.3.6.1.4.1.1466.20037',
};
const RESULT = { 0: 'success', 1: 'operationsError', 2: 'protocolError', 3: 'timeLimitExceeded', 4: 'sizeLimitExceeded', 7: 'authMethodNotSupported',
  8: 'strongerAuthRequired', 10: 'referral', 11: 'adminLimitExceeded', 12: 'unavailableCriticalExtension', 13: 'confidentialityRequired',
  32: 'noSuchObject', 34: 'invalidDNSyntax', 48: 'inappropriateAuthentication', 49: 'invalidCredentials', 50: 'insufficientAccessRights',
  51: 'busy', 52: 'unavailable', 53: 'unwillingToPerform', 80: 'other' };
const MAX_PAGE = 1000;                 // AD MaxPageSize default

class LdapError extends Error {
  constructor(message, props) {
    super(message);
    this.name = 'LdapError';
    if (props) Object.keys(props).forEach(function (k) { this[k] = props[k]; }, this);
  }
}

/* ───────────── BER (the definite-length DER subset LDAP uses) ───────────── */
function lenBytes(n) {
  if (n < 0x80) return Buffer.from([n]);
  const b = [];
  while (n > 0) { b.unshift(n & 0xff); n = Math.floor(n / 256); }
  return Buffer.from([0x80 | b.length].concat(b));
}
function tlv(tag, content) {
  const c = Buffer.isBuffer(content) ? content : Buffer.concat(content);
  return Buffer.concat([Buffer.from([tag]), lenBytes(c.length), c]);
}
function intBytes(n) {                  // two's complement, minimal length (32-bit range is all LDAP needs)
  n = Math.trunc(Number(n) || 0);
  const out = [];
  for (;;) {
    const byte = n & 0xff;
    out.unshift(byte);
    n = n >> 8;
    if ((n === 0 && !(byte & 0x80)) || (n === -1 && (byte & 0x80))) break;
  }
  return Buffer.from(out);
}
function berInt(n, tag) { return tlv(tag || 0x02, intBytes(n)); }
function berEnum(n) { return tlv(0x0a, intBytes(n)); }
function berBool(b, tag) { return tlv(tag || 0x01, Buffer.from([b ? 0xff : 0x00])); }
function berStr(s, tag) { return tlv(tag || 0x04, Buffer.isBuffer(s) ? s : Buffer.from(String(s == null ? '' : s), 'utf8')); }

/* readTLV(buf, off) → {tag, start, end, next} | null when the buffer does not yet hold the whole element */
function readTLV(buf, off, limit) {
  const end0 = limit === undefined ? buf.length : limit;
  if (off + 2 > end0) return null;
  const tag = buf[off];
  let len = buf[off + 1], p = off + 2;
  if (len & 0x80) {
    const nb = len & 0x7f;
    if (nb === 0 || nb > 4) throw new LdapError('BER: unsupported length encoding', { transport: true });
    if (p + nb > end0) return null;
    len = 0;
    for (let i = 0; i < nb; i++) len = len * 256 + buf[p + i];
    p += nb;
  }
  if (p + len > end0) return null;
  return { tag: tag, start: p, end: p + len, next: p + len };
}
function mustTLV(buf, off, limit) {
  const t = readTLV(buf, off, limit);
  if (!t) throw new LdapError('BER: truncated element', { transport: true });
  return t;
}
function children(buf, t) {
  const out = [];
  let p = t.start;
  while (p < t.end) { const c = mustTLV(buf, p, t.end); out.push(c); p = c.next; }
  return out;
}
function readInt(buf, t) {
  let n = 0;
  if (t.end - t.start > 6) throw new LdapError('BER: integer too large', { transport: true });
  for (let i = t.start; i < t.end; i++) n = n * 256 + buf[i];
  if (t.end > t.start && (buf[t.start] & 0x80)) n -= Math.pow(256, t.end - t.start);
  return n;
}
function readStr(buf, t) { return buf.toString('utf8', t.start, t.end); }
function readBuf(buf, t) { return Buffer.from(buf.slice(t.start, t.end)); }

/* ───────────── escaping ───────────── */
/* RFC 4515 §3: a value placed inside a filter — \ * ( ) NUL are escaped as \XX. Everything a user typed goes through this. */
function escapeFilter(v) {
  return String(v == null ? '' : v).replace(/[\\*()\0]/g, function (c) { return '\\' + ('0' + c.charCodeAt(0).toString(16)).slice(-2); });
}
/* RFC 4514 §2.4: an attribute value placed inside a DN */
function escapeDN(v) {
  let s = String(v == null ? '' : v).replace(/[\\,+"<>;=]/g, function (c) { return '\\' + c; }).replace(/\0/g, '\\00');
  if (/^[ #]/.test(s)) s = '\\' + s;
  if (/ $/.test(s) && !/\\ $/.test(s)) s = s.slice(0, -1) + '\\ ';
  return s;
}

/* ───────────── filters (RFC 4515 string → AST → BER) ───────────── */
const ATTR_RE = /^[A-Za-z0-9][A-Za-z0-9;.-]*$/;
const OID_RE = /^([0-9]+(\.[0-9]+)+|[A-Za-z][A-Za-z0-9-]*)$/;

function unescapeValue(s) {
  const out = [];
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch === '\\') {
      const hex = s.substr(i + 1, 2);
      if (!/^[0-9a-fA-F]{2}$/.test(hex)) throw new LdapError('invalid filter: bad escape near "' + s.slice(i, i + 3) + '"');
      out.push(Buffer.from([parseInt(hex, 16)]));
      i += 2;
    } else if (ch === '(' || ch === ')' || ch === '*' || ch === '\0') {
      throw new LdapError('invalid filter: unescaped "' + ch + '" in a value');
    } else out.push(Buffer.from(ch, 'utf8'));
  }
  return Buffer.concat(out);
}

function parseItem(body) {
  const eq = body.indexOf('=');
  if (eq < 1) throw new LdapError('invalid filter item: "' + body + '"');
  const before = body[eq - 1];
  const value = body.slice(eq + 1);
  if (before === ':') {                                    // extensible: attr[:dn][:rule]:=value  |  [:dn]:rule:=value
    const left = body.slice(0, eq - 1).split(':');
    const attr = left.shift();
    let dnAttributes = false, rule = '';
    left.forEach(function (p) { if (p.toLowerCase() === 'dn') dnAttributes = true; else if (p) rule = p; else throw new LdapError('invalid extensible filter'); });
    if (attr && !ATTR_RE.test(attr)) throw new LdapError('invalid attribute "' + attr + '"');
    if (rule && !OID_RE.test(rule)) throw new LdapError('invalid matching rule "' + rule + '"');
    if (!attr && !rule) throw new LdapError('invalid extensible filter: attribute or rule required');
    return { type: 'ext', attr: attr, rule: rule, dnAttributes: dnAttributes, value: unescapeValue(value) };
  }
  let type = 'eq', attr = body.slice(0, eq);
  if (before === '>' || before === '<' || before === '~') { type = before === '>' ? 'ge' : before === '<' ? 'le' : 'approx'; attr = body.slice(0, eq - 1); }
  if (!ATTR_RE.test(attr)) throw new LdapError('invalid attribute "' + attr + '"');
  if (type === 'eq' && value === '*') return { type: 'present', attr: attr };
  if (type === 'eq' && value.indexOf('*') >= 0) {
    const parts = value.split('*');
    return { type: 'substr', attr: attr, initial: parts[0] ? unescapeValue(parts[0]) : null,
      any: parts.slice(1, -1).filter(Boolean).map(unescapeValue), final: parts[parts.length - 1] ? unescapeValue(parts[parts.length - 1]) : null };
  }
  return { type: type, attr: attr, value: unescapeValue(value) };
}

function parseFilter(str) {
  const s0 = String(str || '').trim();
  if (!s0) throw new LdapError('empty filter');
  const s = s0[0] === '(' ? s0 : '(' + s0 + ')';
  let i = 0;
  function one() {
    if (s[i] !== '(') throw new LdapError('invalid filter: expected "(" at ' + i);
    i++;
    const op = s[i];
    let node;
    if (op === '&' || op === '|') {
      i++;
      const list = [];
      while (s[i] === '(') list.push(one());
      node = { type: op === '&' ? 'and' : 'or', filters: list };
    } else if (op === '!') {
      i++;
      node = { type: 'not', filter: one() };
    } else {
      const close = s.indexOf(')', i);
      if (close < 0) throw new LdapError('invalid filter: missing ")"');
      node = parseItem(s.slice(i, close));
      i = close;
    }
    if (s[i] !== ')') throw new LdapError('invalid filter: expected ")" at ' + i);
    i++;
    return node;
  }
  const node = one();
  if (i !== s.length) throw new LdapError('invalid filter: trailing characters at ' + i);
  return node;
}

function encodeFilter(f) {
  if (typeof f === 'string') f = parseFilter(f);
  switch (f.type) {
    case 'and': return tlv(0xa0, f.filters.map(encodeFilter));
    case 'or': return tlv(0xa1, f.filters.map(encodeFilter));
    case 'not': return tlv(0xa2, encodeFilter(f.filter));
    case 'eq': return tlv(0xa3, [berStr(f.attr), berStr(f.value)]);
    case 'ge': return tlv(0xa5, [berStr(f.attr), berStr(f.value)]);
    case 'le': return tlv(0xa6, [berStr(f.attr), berStr(f.value)]);
    case 'approx': return tlv(0xa8, [berStr(f.attr), berStr(f.value)]);
    case 'present': return berStr(f.attr, 0x87);
    case 'substr': {
      const subs = [];
      if (f.initial) subs.push(berStr(f.initial, 0x80));
      (f.any || []).forEach(function (a) { subs.push(berStr(a, 0x81)); });
      if (f.final) subs.push(berStr(f.final, 0x82));
      return tlv(0xa4, [berStr(f.attr), tlv(0x30, subs)]);
    }
    case 'ext': {
      const parts = [];
      if (f.rule) parts.push(berStr(f.rule, 0x81));
      if (f.attr) parts.push(berStr(f.attr, 0x82));
      parts.push(berStr(f.value, 0x83));
      if (f.dnAttributes) parts.push(berBool(true, 0x84));
      return tlv(0xa9, parts);
    }
    default: throw new LdapError('unknown filter type ' + f.type);
  }
}

/* ───────────── protocol messages ───────────── */
const SCOPE = { base: 0, one: 1, onelevel: 1, sub: 2, subtree: 2 };
function message(id, op, controls) {
  const parts = [berInt(id), op];
  if (controls && controls.length) parts.push(tlv(0xa0, controls));
  return tlv(0x30, parts);
}
function control(oid, critical, value) {
  const parts = [berStr(oid)];
  if (critical) parts.push(berBool(true));
  if (value) parts.push(berStr(value));
  return tlv(0x30, parts);
}
function pagedControl(size, cookie) { return control(OID.PAGED, false, tlv(0x30, [berInt(size), berStr(cookie || Buffer.alloc(0))])); }
function bindRequest(dn, password) { return tlv(0x60, [berInt(3), berStr(dn), berStr(password, 0x80)]); }
function searchRequest(base, o) {
  return tlv(0x63, [berStr(base), berEnum(o.scope), berEnum(o.deref || 0), berInt(o.sizeLimit || 0), berInt(o.timeLimit || 0), berBool(false),
    encodeFilter(o.filter), tlv(0x30, (o.attributes || []).map(function (a) { return berStr(a); }))]);
}
function extendedRequest(oid, value) { const p = [berStr(oid, 0x80)]; if (value) p.push(berStr(value, 0x81)); return tlv(0x77, p); }
const UNBIND = Buffer.from([0x42, 0x00]);

function parseResult(buf, op) {
  const k = children(buf, op);
  const r = { code: readInt(buf, k[0]), matchedDN: readStr(buf, k[1]), diagnostic: readStr(buf, k[2]), referrals: [] };
  for (let i = 3; i < k.length; i++) {
    if (k[i].tag === 0xa3) r.referrals = children(buf, k[i]).map(function (t) { return readStr(buf, t); });
    if (k[i].tag === 0x8a) r.responseName = readStr(buf, k[i]);
    if (k[i].tag === 0x8b) r.responseValue = readBuf(buf, k[i]);
  }
  return r;
}
function parseEntry(buf, op) {
  const k = children(buf, op);
  const e = { dn: readStr(buf, k[0]), attrs: {}, raw: {} };
  if (k[1]) children(buf, k[1]).forEach(function (pa) {
    const pk = children(buf, pa);
    let name = readStr(buf, pk[0]).toLowerCase();
    const rng = /^([^;]+);range=/.exec(name);              // AD ranged retrieval (> MaxValRange values): keep the base name
    if (rng) { name = rng[1]; e.ranged = true; }
    const vals = pk[1] ? children(buf, pk[1]).map(function (t) { return readBuf(buf, t); }) : [];
    e.raw[name] = (e.raw[name] || []).concat(vals);
    e.attrs[name] = (e.attrs[name] || []).concat(vals.map(function (v) { return v.toString('utf8'); }));
  });
  return e;
}
function parseMessage(buf) {
  const top = mustTLV(buf, 0);
  const k = children(buf, top);
  if (k.length < 2 || k[0].tag !== 0x02) throw new LdapError('malformed LDAP message', { transport: true });
  const m = { id: readInt(buf, k[0]), tag: k[1].tag, op: k[1], buf: buf, controls: [] };
  if (k[2] && k[2].tag === 0xa0) {
    m.controls = children(buf, k[2]).map(function (c) {
      const ck = children(buf, c), out = { oid: readStr(buf, ck[0]), critical: false, value: null };
      for (let i = 1; i < ck.length; i++) { if (ck[i].tag === 0x01) out.critical = buf[ck[i].start] !== 0; if (ck[i].tag === 0x04) out.value = readBuf(buf, ck[i]); }
      return out;
    });
  }
  return m;
}
function resultError(op, r) {
  const name = RESULT[r.code] || 'resultCode ' + r.code;
  const m = /\bdata ([0-9a-f]{3,8})\b/i.exec(r.diagnostic || '');
  return new LdapError(op + ' failed: ' + name + ' (' + r.code + ')' + (r.diagnostic ? ' — ' + String(r.diagnostic).slice(0, 200) : ''),
    { code: r.code, resultName: name, diagnostic: r.diagnostic || '', adCode: m ? m[1].toLowerCase() : '' });
}

/* ───────────── one connection ───────────── */
function Conn(sock, server, opts, firstId) {
  this.sock = sock; this.server = server; this.opts = opts;
  this.nextId = firstId || 1; this.pending = new Map(); this.buf = Buffer.alloc(0); this.closed = false;
  this._d = this._data.bind(this);
  this._e = this._fail.bind(this);
  this._c = function () { this._fail(new LdapError('connection closed by ' + server.url, { transport: true, code: 'CLOSED' })); }.bind(this);
  sock.on('data', this._d); sock.on('error', this._e); sock.on('close', this._c);
}
Conn.prototype.detach = function () { this.sock.removeListener('data', this._d); this.sock.removeListener('error', this._e); this.sock.removeListener('close', this._c); };
Conn.prototype._data = function (chunk) {
  this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : chunk;
  try {
    for (;;) {
      const t = readTLV(this.buf, 0);
      if (!t) { if (this.buf.length > (this.opts.maxMessageBytes || 32 * 1048576)) throw new LdapError('LDAP message too large', { transport: true }); break; }
      const msg = this.buf.slice(0, t.next);
      this.buf = this.buf.slice(t.next);
      this._dispatch(parseMessage(msg));
    }
  } catch (e) { e.transport = true; this._fail(e); }
};
Conn.prototype._dispatch = function (m) {
  if (m.id === 0) throw new LdapError('server sent a notice of disconnection', { transport: true, code: 'DISCONNECT' });
  const p = this.pending.get(m.id);
  if (!p) return;
  if (m.tag === 0x64) { p.entries.push(parseEntry(m.buf, m.op)); if (p.entries.length > p.maxEntries) this._finish(m.id, new LdapError('search returned more than ' + p.maxEntries + ' entries', { code: 4 })); return; }
  if (m.tag === 0x73) { p.references = p.references.concat(children(m.buf, m.op).map(function (t) { return readStr(m.buf, t); })); return; }
  if (m.tag === 0x61 || m.tag === 0x65 || m.tag === 0x78) { const r = parseResult(m.buf, m.op); r.controls = m.controls; this._finish(m.id, null, r); return; }
  this._finish(m.id, new LdapError('unexpected LDAP response tag 0x' + m.tag.toString(16), { transport: true }));
};
Conn.prototype._finish = function (id, err, r) {
  const p = this.pending.get(id);
  if (!p) return;
  this.pending.delete(id); clearTimeout(p.timer);
  if (err) return p.reject(err);
  r.entries = p.entries; r.references = p.references;
  p.resolve(r);
};
Conn.prototype._fail = function (err) {
  if (!err.transport) err.transport = true;
  if (!err.server) err.server = this.server.url;
  this.closed = true;
  const all = Array.from(this.pending.keys());
  all.forEach(function (id) { this._finish(id, err); }, this);
  try { this.sock.destroy(); } catch (e) { /* already gone */ }
};
Conn.prototype._request = function (op, controls, maxEntries) {
  const self = this;
  if (this.closed) return Promise.reject(new LdapError('connection is closed', { transport: true, code: 'CLOSED' }));
  const id = this.nextId++;
  if (this.nextId > 0x7fffffff) this.nextId = 1;
  return new Promise(function (resolve, reject) {
    const timer = setTimeout(function () {
      self._fail(new LdapError('LDAP operation timed out after ' + self.opts.timeoutMs + ' ms on ' + self.server.url, { transport: true, code: 'TIMEOUT' }));
    }, self.opts.timeoutMs);
    self.pending.set(id, { resolve: resolve, reject: reject, timer: timer, entries: [], references: [], maxEntries: maxEntries || 500000 });
    self.sock.write(message(id, op, controls));
  });
};
Conn.prototype.log = function (level, msg, meta) { if (typeof this.opts.log === 'function') { try { this.opts.log(level, msg, Object.assign({ server: this.server.url }, meta || {})); } catch (e) { /* logger must not break LDAP */ } } };
Conn.prototype.extended = function (oid, value) { return this._request(extendedRequest(oid, value)); };

/* Simple bind. Empty / missing password or DN → refused here and never sent (RFC 4513 unauthenticated bind). */
Conn.prototype.bind = function (dn, password) {
  if (typeof dn !== 'string' || !dn.trim()) return Promise.reject(new LdapError('bind refused: empty DN', { code: 'EMPTY_DN' }));
  if (typeof password !== 'string' || password.length === 0) return Promise.reject(new LdapError('bind refused: empty password (unauthenticated bind)', { code: 'EMPTY_PASSWORD' }));
  if (/^\s+$/.test(password)) return Promise.reject(new LdapError('bind refused: blank password', { code: 'EMPTY_PASSWORD' }));
  const self = this;
  return this._request(bindRequest(dn, password)).then(function (r) {
    self.log(r.code === 0 ? 'debug' : 'info', 'ldap bind', { result: r.code });
    if (r.code !== 0) throw resultError('bind', r);
    return { ok: true };
  });
};

/* search(base, {scope, filter, attributes, pageSize, sizeLimit, timeLimit, maxEntries}) → {entries, references, pages} */
Conn.prototype.search = function (base, o) {
  o = o || {};
  const self = this;
  const scope = typeof o.scope === 'number' ? o.scope : SCOPE[String(o.scope || 'sub').toLowerCase()];
  if (scope === undefined) return Promise.reject(new LdapError('invalid scope ' + o.scope));
  let filter;
  try { filter = typeof o.filter === 'object' && o.filter ? o.filter : parseFilter(o.filter || '(objectClass=*)'); } catch (e) { return Promise.reject(e); }
  const req = { scope: scope, deref: o.deref || 0, sizeLimit: o.sizeLimit || 0, timeLimit: o.timeLimit || 0, filter: filter, attributes: o.attributes || [] };
  const size = o.pageSize ? Math.min(MAX_PAGE, Math.max(1, Math.trunc(o.pageSize))) : 0;
  const max = o.maxEntries || 500000;
  const out = { entries: [], references: [], pages: 0 };
  function page(cookie) {
    return self._request(searchRequest(base, req), size ? [pagedControl(size, cookie)] : null, max - out.entries.length).then(function (r) {
      out.pages++;
      out.entries = out.entries.concat(r.entries); out.references = out.references.concat(r.references);
      if (r.code !== 0) throw resultError('search', r);
      if (!size) return out;
      const pc = (r.controls || []).filter(function (c) { return c.oid === OID.PAGED; })[0];
      if (!pc || !pc.value) return out;
      const v = mustTLV(pc.value, 0), k = children(pc.value, v);
      const next = k[1] ? readBuf(pc.value, k[1]) : Buffer.alloc(0);
      return next.length ? page(next) : out;
    });
  }
  return page(Buffer.alloc(0)).then(function (res) { self.log('debug', 'ldap search', { entries: res.entries.length, pages: res.pages }); return res; });
};
Conn.prototype.rootDSE = function (attributes) {
  return this.search('', { scope: 'base', filter: '(objectClass=*)', attributes: attributes || ['defaultNamingContext', 'dnsHostName', 'supportedControl', 'domainFunctionality', 'ldapServiceName', 'currentTime'] })
    .then(function (r) { return r.entries[0] || null; });
};
Conn.prototype.close = function () {
  if (this.closed) return;
  this.closed = true;
  const s = this.sock;
  try { s.write(message(this.nextId++, UNBIND)); s.end(); } catch (e) { /* ignore */ }
  const t = setTimeout(function () { try { s.destroy(); } catch (e) { /* ignore */ } }, 1000);
  if (t.unref) t.unref();
};
Conn.prototype.unbind = Conn.prototype.close;

/* ───────────── client: server list, TLS, failover ───────────── */
/* "ldaps://dc1.example.com:636" | { url, ip?, servername? }  →  { url, scheme, host, port, ip, servername } */
function parseServer(s) {
  const o = typeof s === 'string' ? { url: s } : Object.assign({}, s || {});
  const m = /^(ldaps?):\/\/(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9._-]+)(?::(\d{1,5}))?\/?$/.exec(String(o.url || '').trim());
  if (!m) throw new LdapError('invalid LDAP server URL "' + o.url + '" (use ldaps://dc.example.com:636 or ldap://dc.example.com:389 for StartTLS)');
  const scheme = m[1].toLowerCase(), host = m[2].replace(/^\[|\]$/g, '');
  if (o.ip && !net.isIP(String(o.ip))) throw new LdapError('invalid ip "' + o.ip + '" for ' + o.url);
  return { url: scheme + '://' + m[2] + ':' + (m[3] || (scheme === 'ldaps' ? 636 : 389)), scheme: scheme, host: host,
    port: Number(m[3] || (scheme === 'ldaps' ? 636 : 389)), ip: o.ip ? String(o.ip) : '', servername: o.servername ? String(o.servername) : host };
}

function createClient(o) {
  o = o || {};
  const servers = [].concat(o.servers || []).map(parseServer);
  if (!servers.length) throw new LdapError('no LDAP servers configured');
  let ca = o.ca;
  if (!ca && o.caFile) {
    try { ca = fs.readFileSync(o.caFile); } catch (e) { throw new LdapError('cannot read caFile ' + o.caFile + ': ' + e.code, { code: 'CA_FILE' }); }
  }
  if (!ca || !/-----BEGIN CERTIFICATE-----/.test(String(ca))) throw new LdapError('caFile must be a PEM (Base-64) certificate of the AD CS root CA', { code: 'CA_FILE' });
  const opts = { timeoutMs: Math.max(500, Number(o.timeoutMs) || 10000), log: o.log, maxMessageBytes: o.maxMessageBytes };
  const connectMs = Math.max(500, Number(o.connectTimeoutMs) || opts.timeoutMs);

  function log(level, msg, meta) { if (typeof o.log === 'function') { try { o.log(level, msg, meta || {}); } catch (e) { /* ignore */ } } }

  function connectTo(s) {
    return new Promise(function (resolve, reject) {
      const tlsOpts = { ca: ca, rejectUnauthorized: true, minVersion: 'TLSv1.2',
        checkServerIdentity: function (_h, cert) { return tls.checkServerIdentity(s.servername, cert); } };
      if (!net.isIP(s.servername)) tlsOpts.servername = s.servername;
      const dial = s.ip || s.host;
      let sock = null, done = false;
      const timer = setTimeout(function () { fail(new LdapError('connect timeout after ' + connectMs + ' ms', { code: 'TIMEOUT' })); }, connectMs);
      function fail(e) {
        if (done) return;
        done = true; clearTimeout(timer);
        try { if (sock) sock.destroy(); } catch (x) { /* ignore */ }
        const err = e instanceof LdapError ? e : new LdapError((e && e.message) || String(e), { code: e && e.code });
        err.transport = true; err.server = s.url;
        reject(err);
      }
      function secured(ts, firstId) {
        ts.once('secureConnect', function () {
          if (done) return;
          if (!ts.authorized) return fail(new LdapError('TLS certificate not trusted: ' + ts.authorizationError, { code: String(ts.authorizationError) }));
          done = true; clearTimeout(timer);
          ts.removeListener('error', fail);
          resolve(new Conn(ts, s, opts, firstId));
        });
        ts.once('error', fail);
      }
      if (s.scheme === 'ldaps') {
        sock = tls.connect(Object.assign({ host: dial, port: s.port }, tlsOpts));
        secured(sock, 1);
      } else {                                                         // ldap:// → StartTLS, never cleartext
        sock = net.connect({ host: dial, port: s.port });
        sock.once('error', fail);
        sock.once('connect', function () {
          const plain = new Conn(sock, s, opts, 1);
          plain.extended(OID.STARTTLS).then(function (r) {
            if (r.code !== 0) return fail(resultError('StartTLS', r));
            plain.detach(); sock.removeListener('error', fail);
            const ts = tls.connect(Object.assign({ socket: sock }, tlsOpts));
            secured(ts, plain.nextId);
          }, fail);
        });
      }
    });
  }

  /* connect() → first server that completes the TLS handshake */
  async function connect() {
    const errors = [];
    for (let i = 0; i < servers.length; i++) {
      try { const c = await connectTo(servers[i]); if (i > 0) log('warn', 'ldap failover', { server: servers[i].url, skipped: errors.length }); return c; } catch (e) {
        errors.push(servers[i].url + ': ' + e.message);
        log('warn', 'ldap server unavailable', { server: servers[i].url, err: e.message });
      }
    }
    throw new LdapError('no directory server reachable — ' + errors.join('; '), { transport: true, code: 'UNAVAILABLE', errors: errors });
  }

  /* run(fn): fn(conn) on the first usable server; transport failures move on to the next server. Always closes. */
  async function run(fn) {
    const errors = [];
    for (let i = 0; i < servers.length; i++) {
      let conn = null;
      try { conn = await connectTo(servers[i]); } catch (e) {
        errors.push(servers[i].url + ': ' + e.message); log('warn', 'ldap server unavailable', { server: servers[i].url, err: e.message }); continue;
      }
      try { return await fn(conn); } catch (e) {
        if (!e.transport) throw e;
        errors.push(servers[i].url + ': ' + e.message); log('warn', 'ldap server failed during operation', { server: servers[i].url, err: e.message });
      } finally { conn.close(); }
    }
    throw new LdapError('no directory server reachable — ' + errors.join('; '), { transport: true, code: 'UNAVAILABLE', errors: errors });
  }

  return { connect: connect, run: run, connectTo: connectTo, servers: servers };
}

/* ───────────── Active Directory helpers ───────────── */
const UAC = { SCRIPT: 0x1, ACCOUNTDISABLE: 0x2, LOCKOUT: 0x10, PASSWD_NOTREQD: 0x20, NORMAL_ACCOUNT: 0x200, DONT_EXPIRE_PASSWORD: 0x10000,
  SMARTCARD_REQUIRED: 0x40000, TRUSTED_FOR_DELEGATION: 0x80000, NOT_DELEGATED: 0x100000, DONT_REQ_PREAUTH: 0x400000, PASSWORD_EXPIRED: 0x800000 };
const FILETIME_EPOCH_MS = 11644473600000;
/* FILETIME (100 ns since 1601) → epoch ms; 0 / never (0x7fffffffffffffff) / garbage → 0 */
function fileTimeToMs(v) {
  const s = String(v == null ? '' : v).trim();
  if (!/^\d+$/.test(s) || s === '0' || s === '9223372036854775807') return 0;
  const ms = Number(s) / 1e4 - FILETIME_EPOCH_MS;
  return ms > 0 ? Math.round(ms) : 0;
}
/* lockoutDuration / maxPwdAge are negative 100 ns intervals; -9223372036854775808 = "until an admin unlocks" → Infinity */
function intervalToMs(v) {
  const s = String(v == null ? '' : v).trim();
  if (!/^-?\d+$/.test(s)) return null;
  if (s === '-9223372036854775808') return Infinity;
  return Math.abs(Number(s)) / 1e4;
}
/* "20240131120000.0Z" → epoch ms */
function generalizedTimeToMs(v) {
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/.exec(String(v || ''));
  return m ? Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]) : 0;
}
/* binary objectSid → "S-1-5-21-…" */
function sidToString(b) {
  if (!Buffer.isBuffer(b) || b.length < 8) return '';
  const n = b[1];
  if (b.length < 8 + 4 * n) return '';
  let auth = 0;
  for (let i = 2; i < 8; i++) auth = auth * 256 + b[i];
  let s = 'S-' + b[0] + '-' + auth;
  for (let i = 0; i < n; i++) s += '-' + b.readUInt32LE(8 + 4 * i);
  return s;
}
/* value of the first RDN ("CN=Smith\, John,OU=…" → "Smith, John") */
function firstRdnValue(dn) {
  const m = /^[^=]+=((?:\\.|[^,\\])*)/.exec(String(dn || ''));
  if (!m) return '';
  return m[1].replace(/\\([0-9a-fA-F]{2}|.)/g, function (_x, c) { return c.length === 2 ? String.fromCharCode(parseInt(c, 16)) : c; });
}
/* case-insensitive attribute access on a parsed entry */
function first(entry, name) { const v = entry && entry.attrs[String(name).toLowerCase()]; return v && v.length ? v[0] : ''; }
function all(entry, name) { return (entry && entry.attrs[String(name).toLowerCase()]) || []; }

const ad = { UAC: UAC, fileTimeToMs: fileTimeToMs, intervalToMs: intervalToMs, generalizedTimeToMs: generalizedTimeToMs, sidToString: sidToString,
  firstRdnValue: firstRdnValue, first: first, all: all, IN_CHAIN: OID.IN_CHAIN };

module.exports = {
  createClient: createClient, parseServer: parseServer, LdapError: LdapError, escapeFilter: escapeFilter, escapeDN: escapeDN,
  parseFilter: parseFilter, encodeFilter: encodeFilter, ad: ad, OID: OID, RESULT: RESULT, MAX_PAGE: MAX_PAGE,
  _ber: { tlv: tlv, berInt: berInt, berStr: berStr, readTLV: readTLV, children: children, readInt: readInt, readStr: readStr,
    bindRequest: bindRequest, searchRequest: searchRequest, message: message, parseMessage: parseMessage, parseEntry: parseEntry },
};
