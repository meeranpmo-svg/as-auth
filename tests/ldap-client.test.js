'use strict';
// LDAPv3/TLS client (as-auth-ad/ldap-client.js — identical copy ships in the SIEM as engine/ad/ldap-client.js) against an in-process fake
// AD over TLS with a throw-away CA. No real network: everything listens on 127.0.0.1.
const test = require('node:test');
const assert = require('node:assert/strict');
const L = require('../ldap-client');
const { makeCA, makeServerCert } = require('./helpers/x509');
const { startFakeLdap, deadPort, hangServer } = require('./helpers/fake-ldap');
const { buildDirectory, DN, PASSWORDS, BASE } = require('./helpers/ad-fixture');

const DC = 'asdc-hqa.asic-hq.com';
let ca, ca2, good, rogue, fx, srv, plain, logs;
const server = (port) => ({ url: `ldaps://${DC}:${port}`, ip: '127.0.0.1' });   // dial 127.0.0.1, verify the cert for the DC name
function client(servers, extra = {}) { return L.createClient(Object.assign({ servers, ca: ca.cert, timeoutMs: 3000, log: (lvl, msg, meta) => logs.push({ lvl, msg, meta }) }, extra)); }

test.before(async () => {
  ca = makeCA('Synthetic Asic Test CA');
  ca2 = makeCA('Synthetic Untrusted CA');
  good = makeServerCert(ca, { cn: DC, dns: [DC, 'localhost'], ip: ['127.0.0.1'] });
  rogue = makeServerCert(ca2, { cn: DC, dns: [DC, 'localhost'], ip: ['127.0.0.1'] });
  fx = buildDirectory({ bulk: 2500 });
  srv = await startFakeLdap({ key: good.key, cert: good.cert, dir: fx.dir, passwords: fx.passwords });
  plain = await startFakeLdap({ key: good.key, cert: good.cert, dir: fx.dir, passwords: fx.passwords, tls: false });
});
test.after(async () => { await srv.close(); await plain.close(); });
test.beforeEach(() => { logs = []; });

test('BER known answers: bind request, filters, escaping, AD value helpers', () => {
  assert.equal(L._ber.bindRequest('cn=a', 'b').toString('hex'), '600c0201030404636e3d61800162');
  assert.equal(L._ber.berInt(-1).toString('hex'), '0201ff');
  assert.equal(L._ber.berInt(128).toString('hex'), '02020080');
  assert.equal(L._ber.berInt(1000).toString('hex'), '020203e8');
  // (&(objectClass=user)(!(cn=*))(member:1.2.840.113556.1.4.1941:=CN=x))
  assert.equal(L.encodeFilter('(&(objectClass=user)(!(cn=*))(member:1.2.840.113556.1.4.1941:=CN=x))').toString('hex'),
    'a044' +                                                                           // and [0], 68 bytes
    'a313' + '040b' + Buffer.from('objectClass').toString('hex') + '0404' + Buffer.from('user').toString('hex') +   // equalityMatch [3]
    'a204' + '8702' + Buffer.from('cn').toString('hex') +                             // not [2] { present [7] }
    'a927' + '8117' + Buffer.from('1.2.840.113556.1.4.1941').toString('hex') +        // extensibleMatch [9] { matchingRule [1]
    '8206' + Buffer.from('member').toString('hex') + '8304' + Buffer.from('CN=x').toString('hex'));             //   type [2], matchValue [3] }
  const sub = L.parseFilter('(cn=ab*c\\2a*d)');
  assert.equal(sub.type, 'substr'); assert.equal(sub.initial.toString(), 'ab'); assert.equal(sub.any[0].toString(), 'c*'); assert.equal(sub.final.toString(), 'd');
  assert.equal(L.parseFilter('objectClass=*').type, 'present');
  assert.equal(L.parseFilter('(uac>=5)').type, 'ge');
  assert.throws(() => L.parseFilter('(cn=a)(cn=b)'), /trailing/);
  assert.throws(() => L.parseFilter('(cn=a*)(b)'), /trailing|invalid/);
  assert.throws(() => L.parseFilter('(cn=a\\zz)'), /bad escape/);
  assert.equal(L.escapeFilter('*)(uid=*'), '\\2a\\29\\28uid=\\2a');
  assert.equal(L.escapeFilter('a\\b\0'), 'a\\5cb\\00');
  assert.equal(L.escapeDN(' #a,b+c=d '), '\\ #a\\,b\\+c\\=d\\ ');
  assert.equal(L.ad.firstRdnValue('CN=Smith\\, John,OU=x'), 'Smith, John');
  assert.equal(L.ad.fileTimeToMs('9223372036854775807'), 0);
  assert.equal(L.ad.fileTimeToMs('0'), 0);
  assert.equal(L.ad.fileTimeToMs('133000000000000000'), Date.parse('2022-06-18T04:26:40Z'));
  assert.equal(L.ad.intervalToMs('-18000000000'), 1800000);
  assert.equal(L.ad.intervalToMs('-9223372036854775808'), Infinity);
  assert.equal(L.ad.sidToString(Buffer.from('010400000000000515000000dcf4dc3b833d2b46828ba628', 'hex')), 'S-1-5-21-1004336348-1177238915-682003330');
  assert.equal(L.ad.generalizedTimeToMs('20240131120000.0Z'), Date.UTC(2024, 0, 31, 12));
  assert.throws(() => L.parseServer('ldap//x'), /invalid LDAP server URL/);
  assert.deepEqual(L.parseServer('ldaps://dc.example.com').port, 636);
  assert.deepEqual(L.parseServer('ldap://dc.example.com').port, 389);
});

test('configuration guards: no servers, missing / non-PEM CA file', () => {
  assert.throws(() => L.createClient({ servers: [], ca: 'x' }), /no LDAP servers/);
  assert.throws(() => L.createClient({ servers: ['ldaps://a:636'], caFile: '/nonexistent/ca.pem' }), /cannot read caFile/);
  assert.throws(() => L.createClient({ servers: ['ldaps://a:636'], ca: 'not a pem' }), /PEM/);
});

test('empty / blank password is refused client-side and never reaches the server', async () => {
  const before = srv.binds.length;
  await client([server(srv.port)]).run(async (conn) => {
    await assert.rejects(conn.bind(DN.user('bob'), ''), (e) => e.code === 'EMPTY_PASSWORD');
    await assert.rejects(conn.bind(DN.user('bob'), undefined), (e) => e.code === 'EMPTY_PASSWORD');
    await assert.rejects(conn.bind(DN.user('bob'), '   '), (e) => e.code === 'EMPTY_PASSWORD');
    await assert.rejects(conn.bind('', 'x'), (e) => e.code === 'EMPTY_DN');
  });
  assert.equal(srv.binds.length, before, 'no bind request was sent');
  assert.ok(!srv.binds.some((b) => b.empty));
});

test('bind: success, wrong password → invalidCredentials 49 / data 52e; search before bind is refused', async () => {
  await client([server(srv.port)]).run(async (conn) => {
    await assert.rejects(conn.search(BASE, { filter: '(objectClass=user)' }), (e) => e.code === 1 && !e.transport);
    await assert.rejects(conn.bind(DN.user('bob'), 'wrong-password'), (e) => e.code === 49 && e.adCode === '52e' && !e.transport);
    assert.deepEqual(await conn.bind(DN.svc, PASSWORDS.svc), { ok: true });
  });
  assert.ok(!JSON.stringify(logs).includes(PASSWORDS.svc), 'password never logged');
  assert.ok(!JSON.stringify(logs).includes('wrong-password'));
});

test('paged search: 2,500+ users in 3 pages of 1000 (AD MaxPageSize); unpaged > 1000 → sizeLimitExceeded', async () => {
  const n0 = srv.requests.length;
  const r = await client([server(srv.port)]).run(async (conn) => {
    await conn.bind(DN.svc, PASSWORDS.svc);
    const paged = await conn.search(BASE, { filter: '(&(objectCategory=person)(objectClass=user)(sAMAccountName=u*))', attributes: ['sAMAccountName'], pageSize: 5000 });
    await assert.rejects(conn.search(BASE, { filter: '(&(objectCategory=person)(objectClass=user))', attributes: ['sAMAccountName'] }), (e) => e.code === 4);
    return paged;
  });
  assert.equal(r.entries.length, 2500);
  assert.equal(r.pages, 3);
  assert.equal(new Set(r.entries.map((e) => L.ad.first(e, 'samaccountname'))).size, 2500);
  assert.ok(r.references.length >= 1, 'continuation references are collected, not followed');
  const pages = srv.requests.slice(n0).filter((q) => q.op === 'search' && q.page);
  assert.deepEqual(pages.map((q) => q.page), [{ size: 1000, offset: 0 }, { size: 1000, offset: 1000 }, { size: 1000, offset: 2000 }]);
});

test('LDAP_MATCHING_RULE_IN_CHAIN: nested groups of a user, and transitive members of a group', async () => {
  await client([server(srv.port)]).run(async (conn) => {
    await conn.bind(DN.svc, PASSWORDS.svc);
    const g = await conn.search(BASE, { filter: `(&(objectClass=group)(member:${L.OID.IN_CHAIN}:=${L.escapeFilter(DN.user('dave'))}))`, attributes: ['cn'] });
    assert.deepEqual(g.entries.map((e) => e.dn).sort(), [DN.socAnalysts, DN.socL2].sort());
    const m = await conn.search(BASE, { filter: `(&(objectCategory=person)(memberOf:${L.OID.IN_CHAIN}:=${L.escapeFilter(DN.administrators)}))`, attributes: ['sAMAccountName'] });
    assert.deepEqual(m.entries.map((e) => L.ad.first(e, 'sAMAccountName')), ['alice']);    // alice ∈ IT-Admins ⊂ Domain Admins ⊂ Administrators
  });
});

test('filter injection: a typed "*)(uid=*" is escaped and matches nothing', async () => {
  const n0 = srv.requests.length;
  const r = await client([server(srv.port)]).run(async (conn) => {
    await conn.bind(DN.svc, PASSWORDS.svc);
    return conn.search(BASE, { filter: `(&(objectCategory=person)(objectClass=user)(sAMAccountName=${L.escapeFilter('*)(uid=*')}))`, attributes: ['sAMAccountName'] });
  });
  assert.equal(r.entries.length, 0);
  const q = srv.requests.slice(n0).find((x) => x.op === 'search');
  assert.deepEqual(q.filter.f[2], { t: 'eq', a: 'sAMAccountName', v: '*)(uid=*' }, 'sent as one literal equality value');
});

test('failover: first DC refuses connections, second answers', async () => {
  const dead = await deadPort();
  const r = await client([server(dead), server(srv.port)]).run(async (conn) => { await conn.bind(DN.svc, PASSWORDS.svc); return conn.server.url; });
  assert.equal(r, `ldaps://${DC}:${srv.port}`);
  assert.ok(logs.some((l) => l.msg === 'ldap server unavailable' && l.meta.server.endsWith(':' + dead)));
});

test('failover: first DC accepts TCP but never answers (per-operation timeout), second answers', async () => {
  const hang = await hangServer();
  try {
    const t0 = Date.now();
    const r = await client([server(hang.port), server(srv.port)], { timeoutMs: 700 }).run(async (conn) => { await conn.bind(DN.svc, PASSWORDS.svc); return conn.server.url; });
    assert.equal(r, `ldaps://${DC}:${srv.port}`);
    assert.ok(Date.now() - t0 < 5000);
  } finally { await hang.close(); }
});

test('all DCs down → UNAVAILABLE transport error listing every server', async () => {
  const d1 = await deadPort(); const d2 = await deadPort();
  await assert.rejects(client([server(d1), server(d2)]).run(async () => 1), (e) => e.code === 'UNAVAILABLE' && e.transport && e.errors.length === 2);
});

test('TLS: certificate from an untrusted CA is rejected before any LDAP traffic', async () => {
  const bad = await startFakeLdap({ key: rogue.key, cert: rogue.cert, dir: fx.dir, passwords: fx.passwords });
  try {
    await assert.rejects(client([server(bad.port)]).run(async (conn) => conn.bind(DN.svc, PASSWORDS.svc)), (e) => e.code === 'UNAVAILABLE' && /certificate|self.signed|verify/i.test(e.message));
    assert.equal(bad.binds.length, 0);
  } finally { await bad.close(); }
});

test('TLS: the certificate must name the DC (servername check even when dialling an IP)', async () => {
  const c = client([{ url: `ldaps://wrong-dc.asic-hq.com:${srv.port}`, ip: '127.0.0.1' }]);
  await assert.rejects(c.run(async (conn) => conn.bind(DN.svc, PASSWORDS.svc)), (e) => /altname|does not match|Hostname/i.test(e.message));
  const ok = await client([`ldaps://localhost:${srv.port}`]).run(async (conn) => conn.bind(DN.svc, PASSWORDS.svc));  // localhost is in the SAN
  assert.deepEqual(ok, { ok: true });
});

test('ldap:// on 389-style port always upgrades with StartTLS before binding (no cleartext mode)', async () => {
  const n0 = plain.requests.length;
  const r = await client([{ url: `ldap://${DC}:${plain.port}`, ip: '127.0.0.1' }]).run(async (conn) => {
    await conn.bind(DN.svc, PASSWORDS.svc);
    return conn.search(DN.user('alice'), { scope: 'base', attributes: ['department'] });
  });
  assert.equal(L.ad.first(r.entries[0], 'department'), 'Cyber Security');
  const ops = plain.requests.slice(n0).map((q) => q.op);
  assert.equal(ops[0], 'starttls');
  assert.ok(!ops.includes('cleartext-refused'));
});

test('result entries: case-insensitive attributes, raw buffers kept, rootDSE', async () => {
  await client([server(srv.port)]).run(async (conn) => {
    const root = await conn.rootDSE();
    assert.equal(L.ad.first(root, 'defaultNamingContext'), 'DC=asic-hq,DC=com');
    await conn.bind(DN.svc, PASSWORDS.svc);
    const r = await conn.search(DN.user('ivan'), { scope: 'base', attributes: ['memberOf', 'userAccountControl'] });
    assert.equal(L.ad.all(r.entries[0], 'MEMBEROF').length, 2);
    assert.ok(Buffer.isBuffer(r.entries[0].raw.useraccountcontrol[0]));
  });
});
