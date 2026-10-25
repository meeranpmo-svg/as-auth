#!/bin/bash
# install-ad.sh - add Active Directory (LDAPS) sign-in to the Arabian Shield sign-in gate (as-auth).
#
#   sudo ./install-ad.sh [--service NAME] [--dest DIR] [--port N] [--force]
#
# Copies as-auth.js + ldap-client.js + as-auth-ldap.js (from this directory) to /opt/arabianshield-auth/, restarts the
# as-auth service and checks that GET /login answers 200. Idempotent: identical files are left alone (no restart unless
# --force). Every run that changes something first backs up the current files AND /etc/arabianshield-auth.json to
# <dest>/backup-ad-<timestamp>/; if the restart or the health check fails the backup is restored and the service restarted.
# The config is NOT changed: AD sign-in stays off until an admin runs as-auth-ldap.js --init / --set-bind-password /
# --check / --enable (AD-SETUP.md). Until then the gate behaves exactly as before.
# The same files also carry the session hardening (server-side sessions, SSO re-check, idle timeout, shorter admin sessions):
# sessions issued before it have no server-side record, so after the first install everyone signs in once more.
set -euo pipefail
umask 022

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST=/opt/arabianshield-auth
CFG="${AS_AUTH_CFG:-/etc/arabianshield-auth.json}"
SERVICE="${AS_AUTH_SERVICE:-}"
PORT=""
FORCE=0
FILES="as-auth.js ldap-client.js as-auth-ldap.js"

say() { echo "==> $*"; }
warn() { echo "WARN: $*" >&2; }
die() { echo "ERROR: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --service) SERVICE="${2:-}"; shift 2 ;;
    --dest) DEST="${2:-}"; shift 2 ;;
    --port) PORT="${2:-}"; shift 2 ;;
    --force) FORCE=1; shift ;;
    -h|--help) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option $1 (see --help)" ;;
  esac
done

# ---------------------------------------------------------------- preflight
[ "$(id -u)" = 0 ] || die "run as root (sudo $0)"
for f in $FILES; do [ -f "$HERE/$f" ] || die "$HERE/$f missing - run from the unpacked as-auth-ad package"; done
[ -f "$DEST/as-auth.js" ] || die "$DEST/as-auth.js not found - is the sign-in gate installed here? (--dest DIR)"
[ -r "$CFG" ] || die "$CFG not readable"
command -v curl >/dev/null 2>&1 || die "curl is required for the health check"

if [ -z "$SERVICE" ]; then        # the unit whose ExecStart runs <dest>/as-auth.js
  for u in /etc/systemd/system/*.service /lib/systemd/system/*.service /usr/lib/systemd/system/*.service; do
    [ -f "$u" ] || continue
    if grep -qE "^ExecStart=.*$DEST/as-auth\.js" "$u"; then SERVICE="$(basename "$u" .service)"; break; fi
  done
fi
[ -n "$SERVICE" ] || die "could not find the systemd unit running $DEST/as-auth.js - pass --service NAME"
UNIT_TEXT="$(systemctl cat "$SERVICE" 2>/dev/null || true)"
[ -n "$UNIT_TEXT" ] || die "systemd unit $SERVICE not found"
NODE_BIN="$(printf '%s\n' "$UNIT_TEXT" | sed -n 's/^ExecStart=\([^ ]*node[^ ]*\) .*/\1/p' | head -n 1)"
NODE_BIN="${NODE_BIN:-$(command -v node || true)}"
[ -x "$NODE_BIN" ] || die "node binary not found (unit ExecStart / PATH)"
if [ -z "$PORT" ]; then PORT="$(printf '%s\n' "$UNIT_TEXT" | sed -n 's/.*AS_AUTH_PORT=\([0-9]\{2,5\}\).*/\1/p' | head -n 1)"; fi
PORT="${PORT:-9098}"
say "service $SERVICE · node $("$NODE_BIN" --version) ($NODE_BIN) · port $PORT · dest $DEST"

# syntax check with the SAME node the service uses (Node 12 on the old server: catches any post-ES2019 syntax)
for f in $FILES; do "$NODE_BIN" --check "$HERE/$f" || die "$f does not parse with $("$NODE_BIN" --version)"; done

health() {   # GET /login must answer 200 within ~20 s
  local i code
  for i in $(seq 1 20); do
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:$PORT/login" || true)"
    [ "$code" = 200 ] && return 0
    sleep 1
  done
  echo "last HTTP status: ${code:-none}" >&2
  return 1
}

# ---------------------------------------------------------------- idempotence
CHANGED=0
for f in $FILES; do cmp -s "$HERE/$f" "$DEST/$f" || CHANGED=1; done
if [ "$CHANGED" = 0 ] && [ "$FORCE" = 0 ]; then
  say "already installed (files identical) - nothing to do"
  if health; then say "health check OK (GET /login 200)"; exit 0; fi
  die "files are current but GET /login does not answer 200 - check: systemctl status $SERVICE"
fi

# ---------------------------------------------------------------- backup
TS="$(date +%Y%m%d-%H%M%S)"
BK="$DEST/backup-ad-$TS"
mkdir -p "$BK"; chmod 700 "$BK"
for f in $FILES; do if [ -f "$DEST/$f" ]; then cp -p "$DEST/$f" "$BK/$f"; else : > "$BK/$f.absent"; fi; done
cp -p "$CFG" "$BK/arabianshield-auth.json"; chmod 600 "$BK/arabianshield-auth.json"
say "backup: $BK"

rollback() {
  warn "rolling back to $BK"
  for f in $FILES; do
    if [ -f "$BK/$f" ]; then cp -p "$BK/$f" "$DEST/$f"; elif [ -f "$BK/$f.absent" ]; then rm -f "$DEST/$f"; fi
  done
  systemctl restart "$SERVICE" || true
  if health; then warn "rollback done - the previous version is running again"; else warn "rollback done but GET /login still fails - check: journalctl -u $SERVICE -n 50"; fi
  exit 1
}

# ---------------------------------------------------------------- install
OWNER="$(stat -c '%u:%g' "$DEST/as-auth.js")"
trap 'warn "install step failed"; rollback' ERR
for f in $FILES; do
  install -m 644 -o "${OWNER%%:*}" -g "${OWNER##*:}" "$HERE/$f" "$DEST/$f.new-ad"
  mv -f "$DEST/$f.new-ad" "$DEST/$f"
done
chmod 750 "$DEST/as-auth-ldap.js"
trap - ERR

say "restarting $SERVICE"
systemctl restart "$SERVICE" || rollback
if ! health; then warn "health check failed after restart"; journalctl -u "$SERVICE" -n 20 --no-pager 2>/dev/null || true; rollback; fi
say "health check OK (GET /login 200)"

cat <<EOF

AD sign-in code installed (still OFF until configured).  Backup: $BK
Next (as root, see AD-SETUP.md):
  $NODE_BIN $DEST/as-auth-ldap.js --init                 # adds a disabled ldap block with the ASIC-HQ defaults
  (edit $CFG: ldap.bindDN / ldap.groupRoles group DNs if they differ)
  $NODE_BIN $DEST/as-auth-ldap.js --set-bind-password
  $NODE_BIN $DEST/as-auth-ldap.js --check
  $NODE_BIN $DEST/as-auth-ldap.js --test-user 'ASIC-HQ\\someone'
  $NODE_BIN $DEST/as-auth-ldap.js --enable
Rollback at any time:  $NODE_BIN $DEST/as-auth-ldap.js --disable   (or copy the files back from $BK and restart $SERVICE)
EOF
