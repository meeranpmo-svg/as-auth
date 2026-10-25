'use strict';
// CLEARLY SYNTHETIC test directory modelled on the customer's AD layout (domain asic-hq.com, base DC=asic-hq,DC=com).
// Names/passwords below exist only in tests. buildDirectory({bulk}) → {dir, passwords, DN, NOW}
const { makeDirectory } = require('./fake-ldap');

const BASE = 'DC=asic-hq,DC=com';
const NOW = Date.UTC(2026, 9, 6, 9, 0, 0);
const DAY = 86400000;
const ft = (ms) => String((BigInt(Math.round(ms)) + 11644473600000n) * 10000n);       // epoch ms → FILETIME string
const DOMAIN_SID = 'S-1-5-21-1004336348-1177238915-682003330';
function sid(str) {                                                                     // "S-1-5-21-…" → binary objectSid
  const p = str.split('-').slice(1).map(Number); const subs = p.slice(2);
  const b = Buffer.alloc(8 + 4 * subs.length); b[0] = p[0]; b[1] = subs.length; b.writeUIntBE(p[1], 2, 6);
  subs.forEach((v, i) => b.writeUInt32LE(v, 8 + 4 * i)); return b;
}
const gt = (ms) => new Date(ms).toISOString().replace(/[-:T]/g, '').slice(0, 14) + '.0Z';

const PERSON = 'CN=Person,CN=Schema,CN=Configuration,' + BASE;
const GROUP = 'CN=Group,CN=Schema,CN=Configuration,' + BASE;
const DN = {
  svc: 'CN=svc-zyberon-ldap,OU=Service Accounts,' + BASE,
  socAdmins: 'CN=SOC-Admins,OU=Groups,' + BASE,
  socAnalysts: 'CN=SOC-Analysts,OU=Groups,' + BASE,
  socViewers: 'CN=SOC-Viewers,OU=Groups,' + BASE,
  socL2: 'CN=SOC-L2 (Nested),OU=Groups,' + BASE,
  domainAdmins: 'CN=Domain Admins,CN=Users,' + BASE,
  enterpriseAdmins: 'CN=Enterprise Admins,CN=Users,' + BASE,
  administrators: 'CN=Administrators,CN=Builtin,' + BASE,
  backupOps: 'CN=Backup Operators,CN=Builtin,' + BASE,
  itAdmins: 'CN=IT-Admins,OU=Groups,' + BASE,
  user: (sam) => `CN=${sam},OU=Staff,${BASE}`,
};
const PASSWORDS = {
  svc: 'Synthetic-Svc-Bind-9f3!x',
  user: 'Synthetic-User-Pass-1!',
};

function buildDirectory({ bulk = 0 } = {}) {
  const dir = makeDirectory();
  const passwords = {};
  dir.add(BASE, { objectClass: ['top', 'domain', 'domainDNS'], lockoutDuration: '-18000000000', name: 'asic-hq' });   // 30 min
  for (const ou of ['OU=Staff', 'OU=Groups', 'OU=Service Accounts', 'CN=Users', 'CN=Builtin']) dir.add(`${ou},${BASE}`, { objectClass: ['top', 'organizationalUnit'] });
  const group = (dn, sam, extra = {}) => dir.add(dn, Object.assign({ objectClass: ['top', 'group'], objectCategory: GROUP, sAMAccountName: sam, cn: sam }, extra));
  group(DN.socAdmins, 'SOC-Admins'); group(DN.socAnalysts, 'SOC-Analysts'); group(DN.socViewers, 'SOC-Viewers'); group(DN.socL2, 'SOC-L2 (Nested)');
  group(DN.domainAdmins, 'Domain Admins', { adminCount: '1', objectSid: sid(DOMAIN_SID + '-512') }); group(DN.enterpriseAdmins, 'Enterprise Admins', { adminCount: '1', objectSid: sid(DOMAIN_SID + '-519') });
  group(DN.administrators, 'Administrators', { adminCount: '1', objectSid: sid('S-1-5-32-544') }); group(DN.backupOps, 'Backup Operators', { adminCount: '1', objectSid: sid('S-1-5-32-551') });
  group(DN.itAdmins, 'IT-Admins');
  dir.addMember(DN.socAnalysts, DN.socL2);                       // nested: SOC-L2 ⊂ SOC-Analysts
  dir.addMember(DN.domainAdmins, DN.itAdmins);                   // nested: IT-Admins ⊂ Domain Admins
  dir.addMember(DN.administrators, DN.domainAdmins);             // as in real AD: Domain Admins ⊂ Administrators

  const user = (dn, sam, o = {}) => {
    const e = dir.add(dn, Object.assign({
      objectClass: ['top', 'person', 'organizationalPerson', 'user'], objectCategory: PERSON, sAMAccountName: sam,
      userPrincipalName: `${sam}@asic-hq.com`, displayName: o.displayName || `Synthetic ${sam}`, mail: `${sam}@asic-hq.com`,
      department: o.department || 'IT', title: o.title || 'Analyst', userAccountControl: String(o.uac || 512), accountExpires: o.accountExpires || '9223372036854775807',
      lockoutTime: o.lockoutTime || '0', lastLogonTimestamp: o.lastLogon === undefined ? ft(NOW - 2 * DAY) : o.lastLogon, pwdLastSet: ft(NOW - 30 * DAY),
      whenCreated: gt(o.created || NOW - 400 * DAY),
    }, o.attrs || {}));
    passwords[dn] = o.password || PASSWORDS.user;
    for (const g of o.groups || []) dir.addMember(g, dn);
    return e;
  };
  user(DN.svc, 'svc-zyberon-ldap', { password: PASSWORDS.svc, uac: 66048, title: 'Service account' });
  user(DN.user('alice'), 'alice', { groups: [DN.socAdmins, DN.itAdmins], title: 'SOC Manager', department: 'Cyber Security' });
  user(DN.user('bob'), 'bob', { groups: [DN.socAnalysts] });
  user(DN.user('carol'), 'carol', { groups: [DN.socViewers] });
  user(DN.user('dave'), 'dave', { groups: [DN.socL2] });                                          // operator via nesting
  user(DN.user('erin'), 'erin', { groups: [DN.socAdmins], uac: 514 });                            // disabled
  user(DN.user('frank'), 'frank', { groups: [DN.socViewers], accountExpires: ft(NOW - DAY) });    // expired yesterday
  user(DN.user('gina'), 'gina', {});                                                             // in no mapped group
  user(DN.user('henry'), 'henry', { groups: [DN.socViewers], lockoutTime: ft(Date.now() - 5 * 60000) }); // locked 5 min ago
  user(DN.user('ivan'), 'ivan', { groups: [DN.socViewers, DN.socAdmins] });                       // highest role wins
  user(DN.user('olga'), 'olga', { lastLogon: ft(NOW - 200 * DAY) });                              // dormant
  user(DN.user('svc-sql'), 'svc-sql', { title: 'Service account' });
  user(DN.user('bkp'), 'bkp', { groups: [DN.backupOps], attrs: { adminCount: '1' } });
  user(DN.user('pgadm'), 'pgadm', { attrs: { primaryGroupID: '512', objectSid: sid(DOMAIN_SID + '-4242') } });          // Domain Admins via primaryGroupID only
  // configuration partition: lets the sync read the NetBIOS name like on a real DC
  dir.add('CN=Configuration,' + BASE, { objectClass: ['top', 'configuration'] });
  dir.add('CN=Partitions,CN=Configuration,' + BASE, { objectClass: ['top', 'crossRefContainer'] });
  dir.add('CN=ASIC-HQ,CN=Partitions,CN=Configuration,' + BASE, { objectClass: ['top', 'crossRef'], nCName: BASE, nETBIOSName: 'ASIC-HQ', dnsRoot: 'asic-hq.com' });
  for (let i = 1; i <= bulk; i++) {
    const sam = 'u' + String(i).padStart(5, '0');
    user(DN.user(sam), sam, { department: i % 2 ? 'Claims' : 'Finance' });
  }
  return { dir, passwords, DN, NOW, BASE };
}

const ROOT_DSE = { defaultNamingContext: BASE, configurationNamingContext: 'CN=Configuration,' + BASE, dnsHostName: 'asdc-hqa.asic-hq.com' };

module.exports = { buildDirectory, DN, PASSWORDS, BASE, NOW, DAY, ft, sid, DOMAIN_SID, ROOT_DSE };
