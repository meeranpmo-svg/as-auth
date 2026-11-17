#!/bin/bash
# setup-ad-signin.sh - switch on Active Directory (LDAPS) sign-in for the Arabian Shield platform, step by step.
#
#   sudo bash setup-ad-signin.sh            (on the platform server, from the folder holding the as-auth files)
#
# Walks through AD-SETUP.md sections 2 and 3, asking before every change:
#   1. installs as-auth.js / ldap-client.js / as-auth-ldap.js with install-ad.sh (backup + automatic rollback) when the
#      installed copies differ from these;
#   2. adds the (disabled) AD settings block once (--init);
#   3. asks for the service account DN and the three role-group DNs (Enter keeps what is there), backs the config up,
#      and who may sign in: only people an administrator adds in the user manager (recommended), or anyone in the groups;
#   4. runs --set-bind-password, --check, --test-user and, only when you say so, --enable.
# Passwords are never read by this script: as-auth-ldap.js asks for them itself, without echo, and stores the service
# password encrypted. Safe to run again: every step shows the current state and can be skipped.
# Undo: sudo node /opt/arabianshield-auth/as-auth-ldap.js --disable   (local accounts keep working throughout)
set -euo pipefail
umask 077

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="${AS_AUTH_DEST:-/opt/arabianshield-auth}"
CFG="${AS_AUTH_CFG:-/etc/arabianshield-auth.json}"
NODE="${NODE:-$(command -v node || echo /usr/bin/node)}"
FILES="as-auth.js ldap-client.js as-auth-ldap.js"
TOOL="$DEST/as-auth-ldap.js"

say() { printf '\n==> %s\n' "$*"; }
die() { printf '\nERROR: %s\n' "$*" >&2; exit 1; }
ask() { local a; flush; read -r -p "$1 [${2:-y}/$( [ "${2:-y}" = y ] && echo n || echo y )] " a || true; a="${a:-${2:-y}}"; [[ "$a" =~ ^[Yy] ]]; }
# drop keystrokes left over from the previous answer (a Windows terminal over SSH sends CR LF) before a prompt reads
flush() { local junk; while read -r -t 0.05 -n 256 junk 2>/dev/null; do :; done; }
tool() { flush; "$NODE" "$TOOL" "$@"; }

[ "$(id -u)" = 0 ] || die "run as root: sudo bash $0"
[ -x "$NODE" ] || die "node not found (set NODE=/path/to/node)"
[ -t 0 ] || die "run this in a terminal (ssh -t): it asks questions and the passwords are typed at hidden prompts"
for f in $FILES install-ad.sh; do [ -f "$HERE/$f" ] || die "$f is missing next to this script ($HERE)"; done
[ -f "$CFG" ] || die "$CFG not found - is the sign-in service (as-auth) installed on this server?"

# ---------------------------------------------------------------- 1. code
say "1/6  sign-in service files in $DEST"
diff=0; for f in $FILES; do cmp -s "$HERE/$f" "$DEST/$f" 2>/dev/null || { echo "    differs or missing: $f"; diff=1; }; done
if [ $diff = 0 ]; then echo "    up to date - nothing to install"
elif ask "    install them now (install-ad.sh backs up the current files and the config, and rolls back if the service does not come back)?"; then
  bash "$HERE/install-ad.sh" || die "install-ad.sh failed - it has put the previous files back. Its output above says why."
else die "stopped before installing - nothing changed"; fi

# ---------------------------------------------------------------- 2. settings block
say "2/6  AD settings block in $CFG"
if "$NODE" -e 'const c=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));process.exit(c.ldap?0:1)' "$CFG"; then
  echo "    present"
else
  tool --init
fi

# ---------------------------------------------------------------- 3. DNs
say "3/6  service account and role groups"
show() { "$NODE" -e '
  const l=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).ldap||{};
  console.log("    AD sign-in      : "+(l.enabled?"ON":"off"));
  console.log("    servers         : "+(l.servers||[]).map(s=>typeof s==="string"?s:s.url+(s.ip?" ("+s.ip+")":"")).join(", "));
  console.log("    service account : "+(l.bindDN||"(not set)")+"   password "+(l.bindPassword?"stored (encrypted)":"NOT set"));
  for (const [dn,r] of Object.entries(l.groupRoles||{})) console.log("    "+r.padEnd(8)+" group  : "+dn);' "$CFG"; }
# the service account's name, from the DN in the config (CN=<name>,...) - whichever account Arabian Shield uses (zmonitor.ad, ...)
svcname() { "$NODE" -e 'const l=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).ldap||{};const m=/^CN=([^,]+)/i.exec(l.bindDN||"");console.log(m?m[1]:"the service account")' "$CFG"; }
show
echo
if [ "$(svcname)" = svc-zyberon-ldap ]; then echo "    NOTE: the service account above is the built-in example. If yours is another account (e.g. zmonitor.ad), answer y below and enter its DN."; fi
echo "    On a DC (PowerShell) these give the exact values (use your service account's logon name):"
echo "      Get-ADUser zmonitor.ad | Select DistinguishedName"
echo "      Get-ADGroup -Filter 'Name -like \"SOC-*\"' | Select Name, DistinguishedName"
if ask "    change any of them?" "$( [ "$(svcname)" = svc-zyberon-ldap ] && echo y || echo n )"; then
  cur() { "$NODE" -e '
    const l=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).ldap||{}, w=process.argv[2];
    if (w==="bind") console.log(l.bindDN||""); else console.log(Object.keys(l.groupRoles||{}).find(k=>l.groupRoles[k]===w)||"");' "$CFG" "$1"; }
  okdn() { [[ "$1" =~ ^[Cc][Nn]=[^,]+(,[A-Za-z]+=[^,]+)*,[Dd][Cc]=[^,]+$ ]]; }
  readdn() { local c v; c="$(cur "$1")"
    while :; do flush; read -r -p "    $2 [Enter keeps: ${c:-none}]: " v || true; v="${v:-$c}"
      [ -n "$v" ] && okdn "$v" && { printf '%s' "$v"; return; }
      echo "      that is not a DN like CN=Name,OU=Groups,DC=asic-hq,DC=com - try again" >&2; done; }
  B="$(readdn bind 'service account DN')"; echo
  GA="$(readdn admin 'admin    group DN (e.g. SOC-Admins)')"; echo
  GO="$(readdn operator 'operator group DN (e.g. SOC-Analysts)')"; echo
  GV="$(readdn viewer 'viewer   group DN (e.g. SOC-Viewers)')"; echo
  BAK="$CFG.bak-$(date +%Y%m%d-%H%M%S)"; cp -a "$CFG" "$BAK"; echo "    backup: $BAK"
  ZB="$B" ZA="$GA" ZO="$GO" ZV="$GV" "$NODE" -e '
    const fs=require("fs"), f=process.argv[1], c=JSON.parse(fs.readFileSync(f,"utf8")), e=process.env;
    if (new Set([e.ZA,e.ZO,e.ZV].map(s=>s.toLowerCase())).size!==3) { console.error("    the three groups must be different - nothing changed"); process.exit(1); }
    c.ldap.bindDN=e.ZB; c.ldap.groupRoles={[e.ZA]:"admin",[e.ZO]:"operator",[e.ZV]:"viewer"};
    const st=fs.statSync(f), t=f+".tmp-"+process.pid;
    fs.writeFileSync(t, JSON.stringify(c,null,2)+"\n", {mode:st.mode&0o777}); fs.chownSync(t, st.uid, st.gid); fs.renameSync(t,f);' "$CFG" \
    || die "could not save - the config is unchanged (backup $BAK)"
  echo "    saved:"; show
fi

# ---------------------------------------------------------------- 3b. who may sign in
echo
ACC="$("$NODE" -e 'const l=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).ldap||{};console.log(l.access||"groups")' "$CFG")"
echo "    Who may sign in with AD now: $( [ "$ACC" = listed ] && echo 'ONLY people an administrator added in Identity & Sign-in -> Users' || echo 'anyone in the three SOC groups (account created at first sign-in)')"
if ask "    allow ONLY people an administrator adds in Identity & Sign-in -> Users (recommended)?" "$( [ "$ACC" = listed ] && echo y || echo y )"; then WANT=listed; else WANT=groups; fi
if [ "$WANT" != "$ACC" ]; then
  BAK="$CFG.bak-$(date +%Y%m%d-%H%M%S)"; cp -a "$CFG" "$BAK"; echo "    backup: $BAK"
  ZW="$WANT" "$NODE" -e '
    const fs=require("fs"), f=process.argv[1], c=JSON.parse(fs.readFileSync(f,"utf8")); c.ldap.access=process.env.ZW;
    const st=fs.statSync(f), t=f+".tmp-"+process.pid;
    fs.writeFileSync(t, JSON.stringify(c,null,2)+"\n", {mode:st.mode&0o777}); fs.chownSync(t, st.uid, st.gid); fs.renameSync(t,f);' "$CFG" || die "could not save (backup $BAK)"
  echo "    saved: $WANT"
fi
[ "$WANT" = listed ] && echo "    -> after switching on, add each person in Identity & Sign-in -> Users -> Add AD user (name + role). A local admin signs in first to do that."

# ---------------------------------------------------------------- 4. service password
say "4/6  service account password"
if ask "    type (or replace) the $(svcname) password now? It is tested against AD, then stored encrypted" \
     "$("$NODE" -e 'const l=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).ldap||{};console.log(l.bindPassword?"n":"y")' "$CFG")"; then
  tool --set-bind-password || die "the password was not stored (wrong password, or the DC cannot be reached - --check below shows which)"
fi

# ---------------------------------------------------------------- 5. check + test user
say "5/6  connection check (DNS, port 636, certificate, service account, base DN, groups)"
if ! tool --check; then die "the check found a problem (the [FAIL] lines above). Fix it and run this script again - AD sign-in is still off."; fi
echo
echo "    Now one real sign-in test with a person who is in one of the SOC groups."
echo "    (A wrong password counts towards that person's AD lockout, like any failed logon.)"
flush; read -r -p "    user to test, e.g. ASIC-HQ\\jdoe (Enter to skip): " TU || true
if [ -n "${TU:-}" ]; then
  [[ "$TU" =~ ^[A-Za-z0-9._@\\-]{1,120}$ ]] || die "that does not look like a user name"
  tool --test-user "$TU" || die "the test sign-in failed (the reason is above). AD sign-in is still off."
fi

# ---------------------------------------------------------------- 6. switch on
say "6/6  switch AD sign-in on"
if ask "    switch it on now? (takes effect at once; local accounts keep working; undo with: node $TOOL --disable)" n; then
  tool --enable
  echo; echo "    Done. Open https://soc.der3.com in a private window and sign in as ASIC-HQ\\<user> with the AD password."
  echo "    The first sign-in asks to set up the authenticator app. Sign-in log: /var/log/arabianshield-auth.log"
else
  echo "    left off. Run this script again, or: sudo node $TOOL --enable"
fi
