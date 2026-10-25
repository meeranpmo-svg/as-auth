# Arabian Shield platform — Active Directory sign-in (LDAPS) setup

For Arabian Shield (ASIC-HQ) administrators. The SOC platform (`https://soc.der3.com`, server 10.100.12.134) can let staff
sign in with their **ASIC-HQ** domain account. The platform talks to the domain controllers over **LDAPS (TCP 636)** only,
with certificate verification always on, using a **read-only service account**. The AD password typed at sign-in is
checked by AD and is never stored or logged. Two-step verification (authenticator app, TOTP) stays mandatory.

| Item | Value used in this deployment |
|---|---|
| AD DNS domain / base DN | `asic-hq.com` / `DC=asic-hq,DC=com` |
| NetBIOS name | `ASIC-HQ` (accepted as `ASIC-HQ\user`; configurable list, matched case-insensitively) |
| UPN suffix | `asic-hq.com` (accepted as `user@asic-hq.com`) |
| Domain controller | `asdc-hqa.asic-hq.com` (192.168.12.52) → `ldaps://asdc-hqa.asic-hq.com:636` |
| Issuing CA | "Asic Microsoft CA" (root, CA server AS-CA01) → `/etc/ssl/asic-hq/asic-microsoft-ca.pem` |
| Service account | `svc-zyberon-ldap` (Domain Users only) |
| Role groups | `SOC-Admins` → admin, `SOC-Analysts` → operator, `SOC-Viewers` → viewer (names/DNs configurable) |

`soc.der3.com` is only the portal's web name — it has nothing to do with the AD domain.

---

## 1. Prerequisites in Active Directory (Windows side)

### 1.1 LDAPS on every DC that will be used

Each DC needs a server-authentication certificate from AD CS (the *Domain Controller Authentication* / *Kerberos
Authentication* template, normally auto-enrolled) whose subject or SAN contains the DC's DNS name. A DC with such a
certificate answers LDAPS on 636 automatically (restart the DC or run `ldp`-verified once after enrolment).

Test from any domain-joined Windows machine:

```powershell
Test-NetConnection asdc-hqa.asic-hq.com -Port 636          # TcpTestSucceeded : True
```

`ldp.exe` (RSAT): *Connection → Connect…* → Server `asdc-hqa.asic-hq.com`, Port `636`, tick **SSL** → the output must
show `Established connection to asdc-hqa.asic-hq.com` without certificate errors. Then *Connection → Bind…* → *Simple
bind* with `svc-zyberon-ldap@asic-hq.com` and its password → `Authenticated as: 'ASIC-HQ\svc-zyberon-ldap'`.

*(Already verified from 10.100.12.134 for asdc-hqa: ports 389/636/3268/3269 open, certificate `CN=asdc-hqa.asic-hq.com`
issued by "Asic Microsoft CA", chain OK.)* Repeat for every additional DC you list.

### 1.2 Export the AD CS root CA certificate (Base-64)

On AS-CA01 (or any machine that trusts it): `certlm.msc` → *Trusted Root Certification Authorities → Certificates* →
**Asic Microsoft CA** → *All Tasks → Export…* → **Base-64 encoded X.509 (.CER)** → `asic-microsoft-ca.cer`.
Command-line alternative on the CA: `certutil -ca.cert asic-root.der` then `certutil -encode asic-root.der asic-microsoft-ca.cer`.

Copy it to the platform server as `/etc/ssl/asic-hq/asic-microsoft-ca.pem` (a Base-64 .cer *is* a PEM file):

```bash
sudo install -d -m 755 /etc/ssl/asic-hq
sudo install -m 644 asic-microsoft-ca.cer /etc/ssl/asic-hq/asic-microsoft-ca.pem
openssl x509 -in /etc/ssl/asic-hq/asic-microsoft-ca.pem -noout -subject -enddate
openssl s_client -connect asdc-hqa.asic-hq.com:636 -servername asdc-hqa.asic-hq.com \
        -CAfile /etc/ssl/asic-hq/asic-microsoft-ca.pem -verify_return_error </dev/null | grep -E 'subject=|Verify return'
#  → "Verify return code: 0 (ok)"
```

*(Already in place on 10.100.12.134.)* If the root CA is renewed, replace the file — no restart needed.

### 1.3 Read-only service account `svc-zyberon-ldap`

Used only to look users up (bind DN). It needs **no rights beyond Domain Users** — the default "Authenticated Users"
read access to user and group objects is all it uses. Nothing is ever written to AD.

```powershell
# on a DC / RSAT, as a Domain Admin. Choose the OU that holds your service accounts.
$pw = Read-Host -AsSecureString "Password for svc-zyberon-ldap (24+ random characters)"
New-ADUser -Name "svc-zyberon-ldap" -SamAccountName "svc-zyberon-ldap" -UserPrincipalName "svc-zyberon-ldap@asic-hq.com" `
  -Path "OU=Service Accounts,DC=asic-hq,DC=com" -AccountPassword $pw -Enabled $true `
  -PasswordNeverExpires $true -CannotChangePassword $true `
  -Description "Zyberon SOC platform - read-only LDAPS lookups (soc.der3.com / 10.100.12.134)"
Set-ADAccountControl svc-zyberon-ldap -AccountNotDelegated $true
Get-ADUser svc-zyberon-ldap -Properties MemberOf | Select DistinguishedName, MemberOf     # MemberOf must be empty (Domain Users is the primary group)
```

* Deny interactive use with a GPO linked to all computers (*Computer Configuration → Policies → Windows Settings →
  Security Settings → Local Policies → User Rights Assignment*): **Deny log on locally** and **Deny log on through Remote
  Desktop Services** → add `ASIC-HQ\svc-zyberon-ldap`. Do **not** restrict it with "Log On To" workstations — that can
  break LDAP binds (error 531).
* Strong password (24+ random characters), kept in the password vault; on the platform it is stored only AES-256-GCM
  encrypted (section 3). Rotate it yearly: reset in AD, then re-run `--set-bind-password`.
* Put the **real DN** of the account into the config (`Get-ADUser svc-zyberon-ldap | Select DistinguishedName`). The
  default assumed below is `CN=svc-zyberon-ldap,OU=Service Accounts,DC=asic-hq,DC=com`.

### 1.4 Role groups

Membership decides the platform role; a user in several groups gets the **highest** role; nested groups count; a user
in none of them is refused ("not given access").

```powershell
$ou = "OU=Groups,DC=asic-hq,DC=com"      # any OU
New-ADGroup -Name "SOC-Admins"   -GroupScope Global -GroupCategory Security -Path $ou -Description "Zyberon SOC platform: admin"
New-ADGroup -Name "SOC-Analysts" -GroupScope Global -GroupCategory Security -Path $ou -Description "Zyberon SOC platform: operator"
New-ADGroup -Name "SOC-Viewers"  -GroupScope Global -GroupCategory Security -Path $ou -Description "Zyberon SOC platform: viewer"
Add-ADGroupMember SOC-Admins -Members jdoe
Get-ADGroup -Filter 'Name -like "SOC-*"' | Select Name, DistinguishedName     # copy these DNs into ldap.groupRoles
```

Keep SOC-Admins small. Membership changes apply at the user's next sign-in.

### 1.5 Firewall

Allow **10.100.12.134 → each DC, TCP 636** (LDAPS). TCP 3269 (Global Catalog over TLS) is optional and not used by
default. Nothing is needed in the other direction. *(Verified open for asdc-hqa.)*

---

## 2. Install the code on the platform server

Copy the `as-auth-ad` folder to the server and run, as root:

```bash
cd as-auth-ad
sudo ./install-ad.sh                     # finds the as-auth systemd unit, backs up, installs, restarts, checks GET /login = 200
```

It installs `as-auth.js`, `ldap-client.js` and `as-auth-ldap.js` into `/opt/arabianshield-auth/`, keeps a timestamped
backup of the previous files **and** of `/etc/arabianshield-auth.json` in `/opt/arabianshield-auth/backup-ad-<time>/`, and
rolls back automatically if the service does not come back. Running it again with the same files does nothing.
AD sign-in stays **off** after the install — the gate behaves exactly as before until section 3 is done.

---

## 3. Configure and switch on (exact commands, on the server as root)

```bash
cd /opt/arabianshield-auth
sudo /usr/bin/node as-auth-ldap.js --init                  # adds a DISABLED "ldap" block with the ASIC-HQ defaults
sudo nano /etc/arabianshield-auth.json                     # check ldap.bindDN and the three ldap.groupRoles DNs (1.3 / 1.4)
sudo /usr/bin/node as-auth-ldap.js --set-bind-password     # prompts (no echo), test-binds, stores it encrypted
sudo /usr/bin/node as-auth-ldap.js --check                 # DNS, TCP 636, TLS + certificate, service bind, base DN, group DNs
sudo /usr/bin/node as-auth-ldap.js --test-user 'ASIC-HQ\jdoe'   # prompts for jdoe's password: DN, flags, groups → role, verdict
sudo /usr/bin/node as-auth-ldap.js --enable                # AD sign-in on — no restart needed
```

`--test-user` performs one real bind as that user: a wrong password counts towards the AD lockout like any failed logon.
Turn it off again at any time with `--disable` (local accounts keep working throughout).

The block written by `--init` (all names are configurable):

```json
"ldap": {
  "enabled": false,
  "servers": ["ldaps://asdc-hqa.asic-hq.com:636"],
  "caFile": "/etc/ssl/asic-hq/asic-microsoft-ca.pem",
  "baseDN": "DC=asic-hq,DC=com",
  "bindDN": "CN=svc-zyberon-ldap,OU=Service Accounts,DC=asic-hq,DC=com",
  "bindPassword": "",
  "netbios": ["ASIC-HQ"],
  "upnSuffix": ["asic-hq.com"],
  "userAttr": "sAMAccountName",
  "groupRoles": {
    "CN=SOC-Admins,OU=Groups,DC=asic-hq,DC=com": "admin",
    "CN=SOC-Analysts,OU=Groups,DC=asic-hq,DC=com": "operator",
    "CN=SOC-Viewers,OU=Groups,DC=asic-hq,DC=com": "viewer"
  },
  "nested": true,
  "requireMfa": true,
  "timeoutMs": 8000,
  "hint": "Sign in with your ASIC-HQ account"
}
```

| key | meaning |
|---|---|
| `servers` | tried in order — list a second DC for failover. Always the DC's **DNS name** (the certificate is checked against it). Before the server uses AD DNS, add the address explicitly: `{"url": "ldaps://asdc-hqa.asic-hq.com:636", "ip": "192.168.12.52"}` — it dials the IP and still verifies the certificate for `asdc-hqa.asic-hq.com`. `ldap://host:389` is accepted only with StartTLS (always performed); there is no cleartext mode. |
| `caFile` | Base-64 PEM of the AD CS root (1.2). Verification cannot be switched off. |
| `bindPassword` | written by `--set-bind-password`, AES-256-GCM encrypted with the gate's own key; never shown by the admin API. |
| `netbios` / `upnSuffix` | the domain prefixes / suffixes accepted at the sign-in form (case-insensitive lists). A plain user name that is not a local account is also looked up in AD. |
| `groupRoles` | group DN → `admin` / `operator` / `viewer`. |
| `nested` | `true`: nested membership counts (one `LDAP_MATCHING_RULE_IN_CHAIN` query per sign-in). |
| `requireMfa` | `true`: every AD user enrols the authenticator app on first sign-in and uses it every time. |

---

## 4. How sign-in behaves

* The sign-in page shows "Sign in with your ASIC-HQ account". Users type `ASIC-HQ\jdoe`, `jdoe@asic-hq.com` or `jdoe`.
* Order of checks: service bind → find the user → refuse if **disabled**, **expired** or **locked out** in AD (no bind as
  the user is attempted) → bind as the user with the typed password → role from the groups → TOTP. An empty password is
  refused before anything is sent to AD (an empty LDAP "simple bind" would otherwise succeed anonymously).
* Wrong password, unknown user, disabled/expired/locked account all show the same "Incorrect username or password." —
  nobody can probe which accounts exist. The audit log has the real reason.
* After a successful AD sign-in the platform keeps a **shadow record** (`<user>@asic-hq.com`, source "ad", DN, role, no
  password) so sessions, TOTP enrolment, recovery codes, lockout and audit use the existing code. It appears in the
  user list of the platform's sign-in administration; an admin can disable it there (effective immediately) or reset its
  TOTP. Password and role cannot be set there — they come from AD.
* Removed from the SOC groups / disabled / expired in AD: the next sign-in attempt is refused **and** that account's
  open sessions end at once. Without a new attempt an existing session lives until it expires (12 h); disable the
  shadow account in the portal for an immediate cut-off.
* The portal locks an account for 15 minutes after 5 failures — keep the AD lockout threshold above 5 so the portal
  cannot be used to lock users out of Windows.
* Local accounts (and break-glass admins) keep working unchanged — keep at least one local admin with TOTP.
* Audit: `/var/log/arabianshield-auth.log`, JSON lines with `"method":"ad"` (failures: `reason` such as
  `AD rejected the password (data 52e)`, `account disabled in AD`, `not in any mapped AD group`); successful
  sign-ins `"method":"ad+totp"`. Passwords never appear there.

---

## 5. Troubleshooting

| symptom (`--check`, `--test-user`, audit log) | cause / fix |
|---|---|
| `TCP … ECONNREFUSED / timeout` | firewall 10.100.12.134 → DC TCP 636, or LDAPS not enabled on that DC (1.1) |
| `TLS certificate not trusted: UNABLE_TO_VERIFY_LEAF_SIGNATURE` / `SELF_SIGNED_CERT_IN_CHAIN` | `caFile` is not the root that issued the DC certificate — `--check` prints the issuer the DC presents |
| `ERR_TLS_CERT_ALTNAME_INVALID` / "does not match" | the URL uses an IP or another name — use the DC's DNS name (add `"ip"` if DNS is not available) |
| `service bind: invalidCredentials (49) … data 52e` | wrong service password → `--set-bind-password`; `data 533` disabled, `775` locked, `532` expired |
| user refused, audit `no such account` | wrong `baseDN`, or the user is outside it |
| user refused, audit `not in any mapped AD group` | add the user to SOC-Admins/Analysts/Viewers; check the DNs in `groupRoles` (`--check`) |
| 503 "directory cannot be reached" | no DC answered within `timeoutMs` — audit event `ad-error` has the details |

Rollback: `--disable` (instant), or restore the files from `/opt/arabianshield-auth/backup-ad-<time>/` and restart the
service.

---

## 6. Domain-controller logs for the SIEM (recommended alongside)

AD sign-in and the SIEM's AD identity sync tell the SOC **who** an account is; the DC Security logs tell it **what**
happened. Collect them with the Windows agent, source id **`win-dc`** — see `ash-siem/agents/windows/README.md`:

1. Section **"Install"**: on the SIEM `sudo ash-siem-token add win-dc --type windows` (if missing) and
   `sudo ash-siem-token show win-dc` for the deployment share; on every DC, elevated PowerShell:
   `.\install-agent.ps1 -CollectorUrl <the collector URL your other Windows agents use> -SourceId win-dc -TokenFile \\…\win-dc.token -SetLogSizes`
   (add `-Loop` on busy DCs).
2. Section **"Recommended Windows audit policy"**: apply it by GPO to the *Domain Controllers* OU. The ASH-AD rules and
   the existing authentication rules rely in particular on: *Credential Validation*, *Kerberos Authentication Service*,
   *Kerberos Service Ticket Operations*, *Logon*, *Account Lockout*, *User Account Management*, *Security Group
   Management* (4728/4732/4756 group changes) and *Directory Service Changes*; size the Security log ≥ 1 GB on DCs.
3. Section **"Sysmon"** (optional, recommended on DCs).
4. On the SIEM, switch on the AD identity sync (`ash-siem/install/AD-IDENTITY.md`): it adds department, title, privileged /
   disabled / dormant flags to every event of a domain account and enables rules ASH-AD-001…005. It can use the same
   read-only service account.

## Sessions and single sign-on re-check

Every session is also kept on the server (`/etc/arabianshield-auth.sessions.json`, chmod 600, override with `AS_AUTH_SESS`),
so it can end before its cookie does:

| Event | Effect |
|---|---|
| Sign-out | the session ends on the server; a copied cookie no longer works |
| Admin revoke | `GET /auth/admin/sessions` lists who is signed in (no tokens); `POST /auth/admin/sessions/revoke {"user": "..."}` or `{"id": "<8 chars>"}` ends them |
| Account disabled, deleted or password reset | that account's sessions end at once |
| Idle | no request for `idleMinutes` (default 60) ends the session |
| Admin | admin sessions last `adminHours` (default 8) instead of `hours` (12) |
| Single sign-on | every `ssoRecheckMinutes` (default 15) the gate asks the identity provider again (refresh-token grant). Disabled, deleted or revoked account, or role removed → the session ends at that check. Provider unreachable → tolerated for `ssoOutageMinutes` (60), then the session ends |
| 2FA grace | a session admitted during the enrolment grace window is read-only (viewer) until TOTP is set up |

The gate adds `offline_access` to the SSO scopes so the provider issues a refresh token (in Entra ID it is a default delegated
permission). If the provider issues none, an SSO session lasts `ssoNoRefreshMinutes` (60) and the user signs in again. Refresh
tokens are stored encrypted and never logged.

Settings: `POST /auth/admin/policy {"session": {"idleMinutes": 30, "adminHours": 8, "ssoRecheckMinutes": 15, "ssoOutageMinutes": 60, "ssoNoRefreshMinutes": 60}}`
(admin; each value is bounded and the change is audited). After the first install, sessions issued before it are not in the
table: everyone signs in once more.
