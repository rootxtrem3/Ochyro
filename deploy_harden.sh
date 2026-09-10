#!/usr/bin/env bash
# =============================================================================
#  deploy_harden.sh - push a hardener to a remote host and run it.
#
#  The target is REQUIRED as an argument; nothing is hardcoded.
#
#  Usage:
#    ./deploy_harden.sh user@host                 # deploy + run linux_harden.sh
#    ./deploy_harden.sh host                      # uses current user
#    ./deploy_harden.sh host -s ./linux_harden.sh
#    ./deploy_harden.sh host --dry-run            # preview on the remote
#    ./deploy_harden.sh host -u frost -p 22 -i ~/.ssh/id_ed25519
#    SSH_PASS='...' ./deploy_harden.sh frost@host
#    ./deploy_harden.sh -w winadmin@host          # Windows: runs windows_harden.ps1
#
#  Options:
#    -s <path>     script to deploy (default: script next to this helper)
#    -u <user>     override username
#    -p <port>     SSH port (default 22)
#    -i <keyfile>  SSH identity key
#    -P <pass>     password (prefer SSH_PASS env)
#    -w            Windows target: run via powershell.exe
#    -h --help     this help
#    -- <args>     extra args forwarded to the remote script
# =============================================================================

APP="deploy_harden.sh"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TARGET=""
SCRIPT=""
USERNAME=""
PORT=22
KEY=""
PASS="${SSH_PASS:-}"
WINDOWS=0
FWD=()
PRE=()

usage() { awk 'NR>1 && /^[^#]/ {exit} { sub(/^# ?/,""); print }' "$0"; }

die() { echo "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    -s) shift; SCRIPT="$1" ;;
    -u) shift; USERNAME="$1" ;;
    -p) shift; PORT="$1" ;;
    -i) shift; KEY="$1" ;;
    -P) shift; PASS="$1" ;;
    -w) WINDOWS=1 ;;
    -h|--help) usage; exit 0 ;;
    --) shift; FWD=("$@"); break ;;
    -*) case "$1" in
          --dry-run|--apply-all|--all|--wizard|--interactive)
            FWD+=("$1") ;;
          --module|--skip|--ssh-port|--password-min|--max-age|--min-age|--warn-age|--version)
            FWD+=("$1"); [ $# -gt 1 ] && { shift; FWD+=("$1"); } ;;
          *) die "unknown option: $1 (see --help)" ;;
        esac ;;
    *) TARGET="$1" ;;
  esac
  shift
done

[ -n "${TARGET}" ] || die "no target given. Usage: $APP <user@host> [options]"
[ -n "$SCRIPT" ] || SCRIPT="$DIR/linux_harden.sh"
[ "$WINDOWS" -eq 1 ] && [ -z "$SCRIPT" ] && SCRIPT="$DIR/windows_harden.ps1"
[ -f "$SCRIPT" ] || die "script not found: $SCRIPT"

# split user@host
if [[ "$TARGET" == *@* ]]; then
  USERNAME="${TARGET%%@*}"; TARGET="${TARGET#*@}"
fi
SSH_CMD=(ssh -p "$PORT" -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10)
[ -n "$KEY" ] && SSH_CMD+=(-i "$KEY")

# figure out auth
if [ -n "$PASS" ]; then
  command -v sshpass >/dev/null 2>&1 || die "password given but sshpass not installed"
  PRE=(sshpass -p "$PASS")
elif [ "$WINDOWS" -eq 0 ]; then
  if ! "${PRE[@]}" "${SSH_CMD[@]}" -o User="$USERNAME" "$TARGET" true 2>/dev/null; then
    if command -v sshpass >/dev/null 2>&1 && [ -n "${SSH_PASS:-}" ]; then
      PRE=(sshpass -p "$SSH_PASS")
    else
      echo "note: no SSH key configured for $TARGET; set SSH_PASS (or -P) for password auth." >&2
      die "cannot authenticate without a key (-i) or password (-P/SSH_PASS)"
    fi
  fi
fi

DST="$SCRIPT_NAME"
SCRIPT_NAME="$(basename "$SCRIPT")"
REMOTE="$(printf '%s' "$SCRIPT_NAME")"
TMP="/tmp/harden_${REMOTE}_$$"

echo "[*] target: ${USERNAME}@${TARGET}:${PORT} ($([ "$WINDOWS" -eq 1 ] && echo windows || echo linux))"
echo "[*] script: $SCRIPT"
echo "[*] uploading to $TARGET:$TMP ..."

"${PRE[@]}" "${SSH_CMD[@]}" -o User="$USERNAME" "$TARGET" "cat > '${TMP}'" < "$SCRIPT" \
  || die "upload failed"
echo "[+] uploaded"

echo "[*] executing remotely ..."
if [ "$WINDOWS" -eq 1 ]; then
  REMOTE_RUN="powershell.exe -ExecutionPolicy Bypass -File C:\\Windows\\Temp\\$SCRIPT_NAME"
  "${PRE[@]}" "${SSH_CMD[@]}" -o User="$USERNAME" "$TARGET" \
    "cp '$TMP' '/c/Windows/Temp/$SCRIPT_NAME' 2>/dev/null; $REMOTE_RUN ${FWD[*]}"
else
  "${PRE[@]}" "${SSH_CMD[@]}" -o User="$USERNAME" "$TARGET" \
    "sudo -n bash '$TMP' ${FWD[*]} 2>/dev/null || { echo; echo '[*] retrying with interactive sudo...'; sudo bash '$TMP' ${FWD[*]}; }"
fi

echo "[*] cleaning up"
"${PRE[@]}" "${SSH_CMD[@]}" -o User="$USERNAME" "$TARGET" "rm -f '$TMP'" 2>/dev/null
echo "[+] done"