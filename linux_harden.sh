#!/usr/bin/env bash
# =============================================================================
#  linux_harden.sh - Interactive Linux hardening (Debian/Ubuntu, systemd)
#
#  Modes:
#    ./linux_harden.sh                     interactive category menu
#    ./linux_harden.sh --wizard            guided walk-through, asks per measure
#    ./linux_harden.sh --apply-all         unattended: apply every measure
#    ./linux_harden.sh --module ssh,fw,..  run specific categories only
#    ./linux_harden.sh --dry-run           preview only - changes nothing
#
#  Options:
#    --ssh-port <n>      SSH port to keep open (default: discovered/22)
#    --password-min <n>  minimum password length (default 12)
#    --max-age <n>       maximum password age in days (default 90)
#    --min-age <n>       minimum password age in days (default 1)
#    --warn-age <n>      password expiry warning days (default 7)
#    --skip <cat>        skip a category (ssh,firewall,kernel,users,services,files,logging)
#    --help  --version
#
#  Safety:
#    * every modified file is backed up under ~/.harden-backups/<timestamp>/
#    * a rollback script is generated next to the backups
#    * sshd_config is validated (sshd -t) before the service is reloaded
#    * the nftables ruleset is saved and restored automatically on failure
#    * repeat runs are idempotent (already-applied measures are skipped)
# =============================================================================

APP="linux_harden.sh"
VERSION="1.0.0"

# ---- defaults & overridable state ------------------------------------------
BACKUP_ROOT="${HARDEN_BACKUP_ROOT:-${HOME:?}/.harden-backups}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="${BACKUP_ROOT}/${TIMESTAMP}"
ROLLBACK_SCRIPT="${BACKUP_DIR}/rollback_${TIMESTAMP}.sh"
LOG_FILE="${BACKUP_DIR}/harden_${TIMESTAMP}.log"
MANIFEST="${BACKUP_DIR}/manifest"

MODE="menu"                 # menu | wizard | apply | modules
DRY_RUN=0
INTERACTIVE=0

SSH_PORT=""
PW_MIN=12; PW_MAX=90; PW_MIN_AGE=1; PW_WARN=7

SELECTED=()
SKIP=()
ALL_MODULES=(ssh firewall kernel users services files logging)
NUM_PASS=0; NUM_APPLIED=0; NUM_SKIPPED=0

# ---- colors (only on a tty) ------------------------------------------------
if [ -t 1 ]; then
  CR=$'\e[31m'; CG=$'\e[32m'; CY=$'\e[33m'; CB=$'\e[34m'; CBB=$'\e[1m'; CN=$'\e[0m'
else
  CR=""; CG=""; CY=""; CB=""; CBB=""; CN=""
fi

# ---- output helpers ---------------------------------------------------------
say() { printf '%s\n' "$*"; }
info() { printf '%s\n' "${CB}[i]${CN} $*"; __log "   $*"; }
ok()   { printf '%s\n' "${CG}[+]${CN} $*"; __log "OK $*"; NUM_APPLIED=$((NUM_APPLIED+1)); }
skip() { printf '%s\n' "${CY}[-]${CN} $*"; __log "SKIP $*"; NUM_SKIPPED=$((NUM_SKIPPED+1)); }
warn() { printf '%s\n' "${CY}[!]${CN} $*"; __log "WARN $*"; }
err()  { printf '%s\n' "${CR}[-]${CN} $*" >&2; __log "ERR $*"; }
die()  { err "$*"; exit 1; }
banner_t() { printf '%s\n' "${CBB}$*${CN}"; }
__log() {
  [ -d "${LOG_FILE%/*}" ] || return 0
  { printf '%s %s\n' "$(date '+%H:%M:%S')" "$*"; } >> "$LOG_FILE" 2>/dev/null || true
}

# ----------------------------------------------------------------------------
#  Backup infrastructure
# ----------------------------------------------------------------------------
init_backup() {
  [ "$DRY_RUN" -eq 1 ] && return 0
  [ -d "$BACKUP_DIR" ] && return 0
  mkdir -p "$BACKUP_DIR" || die "cannot create backup dir: $BACKUP_DIR"
  : > "$MANIFEST"
  {
    printf '#!/usr/bin/env bash\n'
    printf '# Rollback for hardening run started %s\n' "$(date '+%Y-%m-%d %H:%M:%S')"
    printf '# Backups live in: %s\n\n' "$BACKUP_DIR"
    printf 'set -u\n'
    printf 'BD="%s"\n\n' "$BACKUP_DIR"
    printf 'restore() { local src="$BD/%s"; src="${src//#PATH#}"; true; }\n'
    printf 'rf() { local rel="$1"; local dst="$2"; [ -f "$BD/$rel" ] && { cp -a -- "$BD/$rel" "$dst" && echo "restored: $dst"; } || echo "!! no backup for $dst"; }\n'
    printf 'pkgs() { for p in "$@"; do [ -n "$p" ] && { apt-get purge -y --auto-remove "$p" >/dev/null 2>&1 && echo "removed pkg: $p"; }; done; }\n'
    printf '\n'
  } > "$ROLLBACK_SCRIPT"
  chmod +x "$ROLLBACK_SCRIPT"
  info "backup dir: $BACKUP_DIR"
}

backup_file() {
  local path="$1"
  [ "$DRY_RUN" -eq 1 ] && return 0
  [ -f "$path" ] || return 0
  local rel="${path#/}"
  local dest="${BACKUP_DIR}/${rel}"
  mkdir -p "$(dirname "$dest")"
  cp -a -- "$path" "$dest" || return 1
  printf '%s\n' "$path" >> "$MANIFEST" 2>/dev/null || true
  local rel_q="${rel//\\/}"; local dst_q="${path//\"/\\\"}"
  printf 'rf "%s" "%s"\n' "$rel_q" "$path" >> "$ROLLBACK_SCRIPT" 2>/dev/null || true
  return 0
}

backup_ruleset() {  # save current nftables ruleset for rollback
  [ "$DRY_RUN" -eq 1 ] && return 0
  init_backup
  if command -v nft >/dev/null 2>&1; then
    nft list ruleset > "$BACKUP_DIR/nft.ruleset.before" 2>/dev/null
    printf 'nft -f "%s/nft.ruleset.before" >/dev/null 2>&1 && echo "restored nftables ruleset"\n' "$BACKUP_DIR" >> "$ROLLBACK_SCRIPT"
    printf 'systemctl disable --now nftables.service >/dev/null 2>&1 || true\n' >> "$ROLLBACK_SCRIPT"
  fi
}

# ----------------------------------------------------------------------------
#  Generic primitives
# ----------------------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }
svc_active() { systemctl is-active --quiet "$1" 2>/dev/null; }
sys_get() { sysctl -n "$1" 2>/dev/null; }
is_root() { [ "$(id -u)" -eq 0 ]; }

confirm() {  # confirm <prompt> -> 0 yes / 1 no
  local prompt="$1"
  if [ "$DRY_RUN" -eq 1 ]; then return 0; fi   # dry-run: walk the apply path (write helpers only print)
  if [ "$INTERACTIVE" -eq 0 ]; then return 0; fi
  local ans
  while true; do
    read -r -p "${CY}?${CN} $prompt [y/N] " ans || return 1
    case "$ans" in y|Y|yes|YES|Yes) return 0 ;; n|N|no|NO|No|"") return 1 ;; *) say "         please answer y or n" ;; esac
  done
}

ask_value() {  # ask_value <prompt> <default> ; sets REPLY
  REPLY="$2"
  [ "$INTERACTIVE" -eq 1 ] || return 0
  local inp
  read -r -p "${CY}?${CN} $1 [$2]: " inp
  [ -n "$inp" ] && REPLY="$inp"
}

append_config() {  # append_config <file> <line...>
  local f="$1"; shift
  [ "$DRY_RUN" -eq 1 ] && { say "         ${CY}(dry) would append to $f: $*${CN}"; return 0; }
  init_backup; backup_file "$f"
  local changed=0
  for line in "$@"; do
    if grep -Fqs -- "$line" "$f" 2>/dev/null; then
      skip "already present: $line"
    else
      printf '%s\n' "$line" >> "$f"
      ok "appended: $line"
      changed=1
    fi
  done
  return "$changed"
}

write_config() {  # write_config <file> <content (one big string)>
  local f="$1"; local content="$2"
  [ "$DRY_RUN" -eq 1 ] && { say "         ${CY}(dry) would write $f${CN}"; return 0; }
  init_backup; backup_file "$f"
  printf '%s\n' "$content" > "$f"
  ok "wrote $f"
}

run_cmd() {  # run_cmd <cmd...>
  if [ "$DRY_RUN" -eq 1 ]; then say "         ${CY}(dry) would run: $*${CN}"; return 0; fi
  if "$@"; then __log "cmd ok: $*"; return 0; else err "command failed: $*"; return 1; fi
}

pkg_install() {  # pkg_install <pkg>
  local pkg="$1"
  if dpkg -s "$pkg" >/dev/null 2>&1; then ok "package already installed: $pkg"; return 0; fi
  [ "$DRY_RUN" -eq 1 ] && { say "         ${CY}(dry) would install: $pkg${CN}"; return 0; }
  init_backup
  info "installing $pkg ..."
  if DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$pkg" >/dev/null 2>&1; then
    ok "installed $pkg"
    printf 'pkgs "%s"\n' "$pkg" >> "$ROLLBACK_SCRIPT"
  else
    err "failed to install $pkg"
    return 1
  fi
}

svc_enable_now() {  # svc_enable_now <unit>
  local s="$1"
  if [ "$DRY_RUN" -eq 1 ]; then say "         ${CY}(dry) would enable+start $s${CN}"; return 0; fi
  if svc_active "$s" && systemctl is-enabled --quiet "$s" 2>/dev/null; then
    ok "$s already active + enabled"; return 0
  fi
  init_backup
  if systemctl enable --now "$s" >/dev/null 2>&1; then
    ok "enabled + started $s"
    printf 'systemctl disable --now %s >/dev/null 2>&1; echo "disabled service: %s"\n' "$s" "$s" >> "$ROLLBACK_SCRIPT"
  else
    err "could not enable/start $s"
  fi
}

svc_disable_now() {  # svc_disable_now <unit>
  local s="$1"
  if [ "$DRY_RUN" -eq 1 ]; then say "         ${CY}(dry) would stop+disable $s${CN}"; return 0; fi
  if ! systemctl is-active --quiet "$s" 2>/dev/null && ! systemctl is-enabled --quiet "$s" 2>/dev/null; then
    skip "$s already stopped + disabled"; return 0
  fi
  init_backup
  if systemctl disable --now "$s" >/dev/null 2>&1; then
    ok "stopped + disabled $s"
    printf 'systemctl enable --now %s >/dev/null 2>&1; echo "re-enabled service: %s"\n' "$s" "$s" >> "$ROLLBACK_SCRIPT"
  else
    err "could not stop/disable $s"
  fi
}

# mark planned action for apply-all (keeps summaries honest)
planned() { __log "PLAN $*"; }

# ----------------------------------------------------------------------------
#  Module: SSH
# ----------------------------------------------------------------------------
SSH_DROPIN="/etc/ssh/sshd_config.d/99-hardening.conf"
ISSUE_NET="/etc/issue.net"

check_keys() {
  local u; local kf
  for u in $(awk -F: '$3>=1000 || $1=="root"{print $1":"$6}' /etc/passwd); do
    kf="${u#*:}/.ssh/authorized_keys"; [ "${u%%:*}" = "root" ] && kf="/root/.ssh/authorized_keys"
    [ -s "$kf" ] && { echo 1; return; }
  done
  echo 0
}

module_ssh() {
  banner_t "  ── SSH Server Hardening ──"
  have sshd || { warn "openssh-server not installed; skipping SSH module"; return 0; }
  local T; T="$(sshd -T 2>/dev/null)"
  Tv() { printf '%s\n' "$T" | awk -v k="$1" 'tolower($1)==tolower(k){print $2}' | head -n1; }
  local port; port="$(Tv Port)"; [ -z "$port" ] && port=22
  [ -n "$SSH_PORT" ] && port="$SSH_PORT"
  [ "$INTERACTIVE" -eq 1 ] && ask_value "SSH port to keep open" "$port" && port="$REPLY"
  SSH_PORT="$port"

  mkdir -p /etc/ssh/sshd_config.d 2>/dev/null || true

  # --- password authentication (interacts with key presence) ---
  local pa; pa="$(Tv PasswordAuthentication)"; [ -z "$pa" ] && pa="yes"
  if [ "$pa" != "no" ]; then
    planned "disable SSH password authentication"
    if [ "$(check_keys)" = "1" ]; then
      if confirm "Disable SSH password authentication (key-based access only)?"; then
        append_config "$SSH_DROPIN" "PasswordAuthentication no" "KbdInteractiveAuthentication no"
      else skip "SSH password authentication left enabled"; fi
    else
      warn "No SSH key detected for login accounts."
      if [ "$INTERACTIVE" -eq 1 ]; then
        if confirm "Proceed anyway? This may LOCK you out of SSH."; then
          append_config "$SSH_DROPIN" "PasswordAuthentication no" "KbdInteractiveAuthentication no"
        else skip "SSH password authentication left enabled"; fi
      else
        err "apply-all: refusing to disable password auth (no keys). Use --ssh-port & set up keys first."
        skip "SSH password authentication (safety block)"
      fi
    fi
  else
    ok "SSH password authentication already disabled"
  fi

  # --- PermitRootLogin ---
  local prl; prl="$(Tv PermitRootLogin)"
  if [ "$prl" = "no" ] || [ "$prl" = "prohibit-password" ]; then
    ok "PermitRootLogin already restricted ($prl)"
  else
    if confirm "Disable root SSH login?"; then append_config "$SSH_DROPIN" "PermitRootLogin no"; else skip "root SSH login"; fi
  fi

  # --- the safe-by-default set (grouped into one confirmation) ---
  local apply
  apply="MaxAuthTries 3|X11Forwarding no|AllowAgentForwarding no|MaxSessions 4|MaxStartups 10:30:60|ClientAliveInterval 300|ClientAliveCountMax 2|LoginGraceTime 30"
  if confirm "Apply recommended SSH defaults (tries/forwarding/alive/grace)? [$apply]"; then
    append_config "$SSH_DROPIN" \
      "MaxAuthTries 3" "X11Forwarding no" "AllowAgentForwarding no" \
      "MaxSessions 4" "MaxStartups 10:30:60" "ClientAliveInterval 300" \
      "ClientAliveCountMax 2" "LoginGraceTime 30"
  else
    skip "recommended SSH defaults"
  fi

  # --- user-impacting forwardings ask individually ---
  local tf; tf="$(Tv AllowTcpForwarding)"
  if [ "$tf" = "no" ]; then
    ok "AllowTcpForwarding already disabled"
  elif confirm "Disable TCP forwarding? (blocks SSH tunnels/port-forwards)"; then
    append_config "$SSH_DROPIN" "AllowTcpForwarding no"
  else skip "TCP forwarding"; fi

  # --- banner ---
  local bn; bn="$(Tv Banner)"
  if [ -n "$bn" ] && [ -f "$bn" ]; then
    ok "SSH banner already configured"
  elif confirm "Install a legal SSH login banner (/etc/issue.net)?"; then
    [ "$DRY_RUN" -eq 1 ] || { [ -f "$ISSUE_NET" ] || backup_file "$ISSUE_NET"; }
    if [ "$DRY_RUN" -eq 1 ]; then
      say "         ${CY}(dry) would create $ISSUE_NET${CN}"
    else
      { printf '%s\n' "####################################################################"
        printf '#  Authorized access only. All activity is monitored and logged.        #\n'
        printf '#  Unauthorized access is prohibited and will be prosecuted.            #\n'
        printf '####################################################################\n'; } > "$ISSUE_NET"
      ok "wrote $ISSUE_NET"
    fi
    append_config "$SSH_DROPIN" "Banner $ISSUE_NET"
  else
    skip "SSH banner"
  fi

  # --- validate + reload ---
  [ "$DRY_RUN" -eq 1 ] && return 0
  if [ -f "$SSH_DROPIN" ] && grep -vE '^\s*#|^\s*$' "$SSH_DROPIN" | grep -q .; then
    if sshd -t 2>/dev/null; then
      if systemctl reload ssh >/dev/null 2>&1 || systemctl reload sshd >/dev/null 2>&1 || systemctl try-reload-or-restart ssh >/dev/null 2>&1; then
        ok "sshd config validated + service reloaded"
      else
        warn "sshd reload failed (restart manually: systemctl restart ssh)"
      fi
    else
      err "sshd config INVALID - reverting change"
      local rel="${SSH_DROPIN#/}"; [ -f "$BACKUP_DIR/$rel" ] && cp -a -- "$BACKUP_DIR/$rel" "$SSH_DROPIN"
      rm -f "$SSH_DROPIN"
    fi
  else
    info "no SSH hardening changes to apply"
  fi
}

# ----------------------------------------------------------------------------
#  Module: Firewall (nftables)
# ----------------------------------------------------------------------------
module_firewall() {
  banner_t "  ── Firewall (nftables) ──"
  local fw_tool="nft"
  have nft || { warn "nftables not installed"; if confirm "Install nftables and continue?"; then pkg_install nftables; else return 0; fi; }

  # is a hardening ruleset already active?
  local cur_pol; cur_pol="$(nft list chain inet filter input 2>/dev/null | awk '$1=="policy"{print $2}')"
  if [ "$cur_pol" = "drop" ] && [ "$DRY_RUN" -eq 0 ] && ! confirm "Firewall already enforces DROP. Flush and rewrite anyway?"; then
    ok "existing DROP policy detected - leaving ruleset untouched"
    return 0
  fi
  backup_ruleset

  # parameters
  local port="${SSH_PORT:-22}"
  if [ "$INTERACTIVE" -eq 1 ] && [ -z "$SSH_PORT" ]; then
    ask_value "SSH port to keep open" "$port"; port="$REPLY"
  fi

  local has_tailscale=0; ip link show tailscale0 >/dev/null 2>&1 && has_tailscale=1
  local has_docker=0; have docker && docker info >/dev/null 2>&1 && has_docker=1
  local allow_http=0
  if pgrep -x apache2 >/dev/null 2>&1 || pgrep -x nginx >/dev/null 2>&1 || pgrep -x caddy >/dev/null 2>&1; then allow_http=1; fi

  if confirm "Allow inbound HTTP/HTTPS (80/443)? $([ "$allow_http" -eq 1 ] && echo '(web server detected)')"; then allow_http=1; else allow_http=0; fi

  local block_samba=0
  if ss -tlnH 2>/dev/null | grep -qE ':(139|445)\b'; then
    if confirm "SMB (139/445) is listening. Block it from the network?"; then block_samba=1; fi
  fi

  local log_drops=1
  confirm "Log dropped packets (rate-limited)?" && log_drops=1 || log_drops=0

  local fwd_policy="drop"; [ "$has_docker" -eq 1 ] && fwd_policy="accept"
  [ "$has_docker" -eq 1 ] && warn "Docker detected - FORWARD chain left ACCEPT to avoid breaking containers."

  local rules="# Hardening ruleset generated by $APP $(date '+%F %T')
flush ruleset

table inet filter {
  chain input {
    type filter hook input priority filter; policy drop;

    iifname \"lo\" accept
    ct state established,related accept
    ct state invalid drop
    ip protocol icmp icmp type { echo-request, echo-reply, destination-unreachable, time-exceeded } limit rate 10/second accept
    ip6 nexthdr ipv6-icmp icmpv6 type { echo-request, echo-reply, destination-unreachable, time-exceeded, router-advertisement, neighbour-solicitation, neighbour-advertisement } limit rate 10/second accept
    tcp dport $port accept
"
  [ "$allow_http" -eq 1 ] && rules+="    tcp dport { 80, 443 } accept
"
  [ "$has_tailscale" -eq 1 ] && rules+="    iifname \"tailscale0\" accept
    udp dport 41641 accept
"
  [ "$has_docker" -eq 1 ] && rules+="    iifname \"docker0\" accept
"
  [ "$block_samba" -eq 1 ] && rules+="    iifname != \"lo\" tcp dport { 139, 445 } drop
"
  [ "$log_drops" -eq 1 ] && rules+="    counter log prefix \"ipt-drop: \" limit rate 5/minute
"
  rules+="  }

  chain output {
    type filter hook output priority filter; policy accept;
  }

  chain forward {
    type filter hook forward priority filter; policy $fwd_policy;
"
  [ "$has_docker" -eq 1 ] && rules+="    ct state established,related accept
    iifname \"docker0\" accept
    oifname \"docker0\" accept
"
  [ "$log_drops" -eq 1 ] && rules+="    counter log prefix \"fwd-drop: \" limit rate 5/minute
"
  rules+="  }
}
"

  if [ "$DRY_RUN" -eq 1 ]; then
    say "         ${CY}(dry) proposed ruleset for /etc/nftables.conf:${CN}"
    say "$rules"
    return 0
  fi

  write_config /etc/nftables.conf "$rules"
  if nft -c -f /etc/nftables.conf 2>/dev/null; then
    if nft -f /etc/nftables.conf; then
      ok "ruleset applied (INPUT policy drop, port $port open)"
    else
      err "nft apply failed - restoring previous ruleset"
      [ -f "$BACKUP_DIR/nft.ruleset.before" ] && nft -f "$BACKUP_DIR/nft.ruleset.before"
      return 1
    fi
    svc_enable_now nftables
    warn "KEEP THIS SESSION OPEN. Verify SSH connectivity to port ${port}; recovery:"
    warn "  sudo nft -f ${BACKUP_DIR}/nft.ruleset.before"
  else
    err "ruleset failed validation (nft -c) - no change applied"
  fi
}

# ----------------------------------------------------------------------------
#  Module: Kernel / Sysctl
# ----------------------------------------------------------------------------
module_kernel() {
  banner_t "  ── Kernel & Sysctl Hardening ──"
  local f="/etc/sysctl.d/99-hardening.conf"
  local bpf_choice="0"
  if [ "$(sys_get kernel.unprivileged_bpf_disabled)" = "2" ]; then
    if confirm "Set kernel.unprivileged_bpf_disabled=1? (may affect sandboxing features)"; then bpf_choice="1"; fi
  fi

  local cfg=""
  cfg+="net.ipv4.conf.all.send_redirects = 0
"
  cfg+="net.ipv4.conf.default.send_redirects = 0
"
  cfg+="net.ipv4.conf.all.accept_redirects = 0
"
  cfg+="net.ipv4.conf.default.accept_redirects = 0
"
  cfg+="net.ipv6.conf.all.accept_redirects = 0
"
  cfg+="net.ipv6.conf.default.accept_redirects = 0
"
  cfg+="net.ipv6.conf.all.accept_source_route = 0
"
  cfg+="net.ipv6.conf.default.accept_source_route = 0
"
  cfg+="net.ipv4.conf.all.log_martians = 1
"
  cfg+="net.ipv4.conf.default.log_martians = 1
"
  cfg+="net.ipv4.conf.all.rp_filter = 1
"
  cfg+="net.ipv4.conf.default.rp_filter = 1
"
  cfg+="net.ipv6.conf.all.accept_ra = 0
"
  cfg+="kernel.kptr_restrict = 2
"
  cfg+="kernel.dmesg_restrict = 1
"
  cfg+="kernel.yama.ptrace_scope = 1
"
  cfg+="fs.suid_dumpable = 0
"
  cfg+="fs.protected_symlinks = 1
"
  cfg+="fs.protected_hardlinks = 1
"
  cfg+="kernel.unprivileged_bpf_disabled = $bpf_choice
"

  if [ "$DRY_RUN" -eq 1 ]; then
    say "         ${CY}(dry) proposed $f:${CN}"
    say "$cfg"
    return 0
  fi
  init_backup; backup_file "$f"
  local pre=""; [ -f "$f" ] && pre="$(cat "$f")"
  write_config "$f" "$pre
$cfg"
  if sysctl --system >/dev/null 2>&1; then
    ok "sysctl applied at runtime"
  else
    warn "sysctl --system had warnings (check new kernel perms)"
  fi
  # verify a couple
  [ "$(sys_get kernel.kptr_restrict)" = "2" ] && ok "kptr_restrict=2 confirmed" || warn "kptr_restrict not applied"
  [ "$(sys_get net.ipv4.conf.all.log_martians)" = "1" ] && ok "log_martians=1 confirmed" || warn "log_martians not applied"
}

# ----------------------------------------------------------------------------
#  Module: Users & Password policy
# ----------------------------------------------------------------------------
login_defs_set() {  # login_defs_set <KEY> <value>
  local k="$1" v="$2" f=/etc/login.defs
  [ "$DRY_RUN" -eq 1 ] && { say "         ${CY}(dry) would set $k=$v in $f${CN}"; return 0; }
  init_backup; backup_file "$f"
  if grep -E "^[[:space:]]*$k[[:space:]]" "$f" >/dev/null 2>&1; then
    sed -i -E "s/^([[:space:]]*${k}[[:space:]]+).*/\1$v/" "$f"
    ok "set $k = $v"
  else
    printf '%s\t%s\n' "$k" "$v" >> "$f"
    ok "appended $k = $v"
  fi
}

pam_insert_before() {  # pam_insert_before <file> <pattern> <line to insert>
  local f="$1" pat="$2" ins="$3"
  [ -f "$f" ] || { warn "pam file missing: $f"; return 1; }
  if grep -Fqs -- "$ins" "$f"; then skip "already present in $f: $ins"; return 0; fi
  cmp="$(grep -Ec "$pat" "$f")"
  [ "$cmp" -eq 0 ] && { warn "pattern not found in $f ($pat); skipping pwquality"; return 1; }
  [ "$DRY_RUN" -eq 1 ] && { say "         ${CY}(dry) would insert in $f: $ins${CN}"; return 0; }
  init_backup; backup_file "$f"
  awk -v pat="$pat" -v ins="$ins" 'BEGIN{done=0} { if ($0 ~ pat && !done) { print ins; done=1 } print }' "$f" > "${f}.new" \
    && mv "${f}.new" "$f" && ok "inserted in $f: $ins"
}

pam_insert_after() {  # pam_insert_after <file> <pattern> <line to insert>
  local f="$1" pat="$2" ins="$3"
  [ -f "$f" ] || { warn "pam file missing: $f"; return 1; }
  if grep -Fqs -- "$ins" "$f"; then skip "already present in $f: $ins"; return 0; fi
  [ "$(grep -Ec "$pat" "$f")" -eq 0 ] && { warn "pattern not found in $f ($pat)"; return 1; }
  [ "$DRY_RUN" -eq 1 ] && { say "         ${CY}(dry) would insert in $f: $ins${CN}"; return 0; }
  init_backup; backup_file "$f"
  awk -v pat="$pat" -v ins="$ins" 'BEGIN{done=0} { print; if ($0 ~ pat && !done) { print ins; done=1 } }' "$f" > "${f}.new" \
    && mv "${f}.new" "$f" && ok "inserted in $f: $ins"
}

module_users() {
  banner_t "  ── User & Password Policy ──"
  [ -f /etc/login.defs ] || { warn "login.defs missing; skipping user module"; return 0; }

  local v
  v="$(grep -E '^PASS_MAX_DAYS' /etc/login.defs 2>/dev/null | awk '{print $2}')"
  [ "$v" = "$PW_MAX" ] && ok "PASS_MAX_DAYS already $PW_MAX" || { planned "PASS_MAX_DAYS=$PW_MAX"; confirm "Enforce max password age of $PW_MAX days?" && login_defs_set PASS_MAX_DAYS "$PW_MAX"; }

  v="$(grep -E '^PASS_MIN_DAYS' /etc/login.defs 2>/dev/null | awk '{print $2}')"
  [ "$v" = "$PW_MIN_AGE" ] && ok "PASS_MIN_DAYS already $PW_MIN_AGE" || { planned "PASS_MIN_DAYS=$PW_MIN_AGE"; confirm "Enforce min password age of $PW_MIN_AGE day(s)?" && login_defs_set PASS_MIN_DAYS "$PW_MIN_AGE"; }

  v="$(grep -E '^PASS_MIN_LEN' /etc/login.defs 2>/dev/null | awk '{print $2}')"
  [ "$v" = "$PW_MIN" ] && ok "PASS_MIN_LEN already $PW_MIN" || { planned "PASS_MIN_LEN=$PW_MIN"; confirm "Enforce minimum password length of $PW_MIN?" && login_defs_set PASS_MIN_LEN "$PW_MIN"; }

  v="$(grep -E '^PASS_WARN_AGE' /etc/login.defs 2>/dev/null | awk '{print $2}')"
  [ "$v" = "$PW_WARN" ] && ok "PASS_WARN_AGE already $PW_WARN" || { planned "PASS_WARN_AGE=$PW_WARN"; confirm "Warn users $PW_WARN days before expiry?" && login_defs_set PASS_WARN_AGE "$PW_WARN"; }

  # PAM: pwquality
  if [ -f /etc/pam.d/common-password ]; then
    if grep -qs pam_pwquality /etc/pam.d/common-password; then
      ok "pam_pwquality already enabled"
    elif confirm "Add password complexity checks (pam_pwquality, minlen=$PW_MIN)?"; then
      pam_insert_before /etc/pam.d/common-password 'pam_unix.so' "password	requisite	pam_pwquality.so retry=3 minlen=$PW_MIN"
    else
      skip "password complexity"
    fi
  fi

  # PAM: faillock (lockout)
  if grep -rqs pam_faillock /etc/pam.d/ 2>/dev/null; then
    ok "pam_faillock already enabled"
  elif confirm "Enable account lockout after failed logins (pam_faillock)?"; then
    if [ -f /etc/pam.d/common-auth ]; then
      pam_insert_before /etc/pam.d/common-auth 'pam_unix.so' "auth	required	pam_faillock.so preauth"
      pam_insert_after  /etc/pam.d/common-auth 'pam_deny.so' "auth	required	pam_faillock.so authfail"
      pam_insert_after  /etc/pam.d/common-auth 'pam_faillock.so authfail' "auth	required	pam_faillock.so authsucc"
    else
      warn "common-auth not found; faillock skipped"
    fi
    [ -f /etc/pam.d/common-account ] && pam_insert_before /etc/pam.d/common-account 'pam_unix.so' "account	required	pam_faillock.so"
  else
    skip "account lockout"
  fi

  # sudoers hardening
  if [ -d /etc/sudoers.d ]; then
    local sd="/etc/sudoers.d/99-hardening"
    local want_present=1
    if grep -qs 'use_pty' "$sd" 2>/dev/null && grep -qs 'logfile' "$sd" 2>/dev/null && grep -qs 'timestamp_timeout=5' "$sd" 2>/dev/null; then
      ok "sudoers hardening already present in $sd"
    else
      planned "sudoers: use_pty, logfile, timeout=5"
      if confirm "Harden sudoers (require pty, log commands, 5 min timeout)?"; then
        cfg="# Generated by $APP $(date '+%F %T')
Defaults	env_reset
Defaults	use_pty
Defaults	logfile=\"/var/log/sudo.log\"
Defaults	timestamp_timeout=5
"
        if [ "$DRY_RUN" -eq 1 ]; then say "         ${CY}(dry) would write $sd${CN}"; else
          init_backup; backup_file "$sd"
          printf '%s\n' "$cfg" > "$sd"
          chmod 440 "$sd"
          if visudo -c -f "$sd" >/dev/null 2>&1; then
            ok "sudoers drop-in installed + validated"
          else
            err "sudoers validation FAILED - removing drop-in"
            rm -f "$sd"
          fi
        fi
      else
        skip "sudoers hardening"
      fi
    fi
  fi

  # umask
  v="$(grep -E '^UMASK' /etc/login.defs 2>/dev/null | awk '{print $2}')"
  if [ "$v" = "027" ] || [ "$v" = "077" ]; then
    ok "UMASK already $v"
  elif confirm "Set default umask to 027 (stricter file permissions)?"; then
    login_defs_set UMASK "027"
  else
    skip "umask"
  fi

  # root lock
  local rpw="$(awk -F: '$1=="root"{print $2}' /etc/shadow 2>/dev/null)"
  if [ "$rpw" = "*" ] || [ "$rpw" = "!" ]; then
    ok "root account already locked"
  elif [ "$DRY_RUN" -eq 1 ]; then
    say "         ${CY}(dry) would lock root password (sudo still works)${CN}"
  elif [ "$INTERACTIVE" -eq 1 ]; then
    if confirm "Lock the root account password? (sudo users keep working)"; then
      passwd -l root >/dev/null 2>&1 && ok "root account locked" || err "failed to lock root"
      printf 'passwd -u root >/dev/null 2>&1 && echo "unlocked root"\n' >> "$ROLLBACK_SCRIPT"
    else skip "root lock"; fi
  else
    warn "apply-all: skipping root lock (destructive); run interactively to approve"
    skip "root lock (require interactive)"
  fi
}

# ----------------------------------------------------------------------------
#  Module: Services & Packages
# ----------------------------------------------------------------------------
module_services() {
  banner_t "  ── Services & Packages ──"
  have apt-get || { warn "apt-get not found; skipping services module"; return 0; }

  # repositories refresh may be needed; do a quiet update if stale
  [ "$DRY_RUN" -eq 0 ] && apt-get update -qq >/dev/null 2>&1 &

  local pkgs=(unattended-upgrades fail2ban auditd rsyslog)
  local install_all=0; local some=()
  if [ "$INTERACTIVE" -eq 1 ]; then
    for p in "${pkgs[@]}"; do
      if dpkg -s "$p" >/dev/null 2>&1; then some+=("$p"); fi
    done
    local missing=(); for p in "${pkgs[@]}"; do dpkg -s "$p" >/dev/null 2>&1 || missing+=("$p"); done
    if [ "${#missing[@]}" -gt 0 ]; then
      if confirm "Install missing hardening packages: ${missing[*]} ?"; then install_all=1; fi
    else
      info "all hardening packages already installed"
    fi
  else
    install_all=1
  fi

  if [ "$install_all" -eq 1 ]; then
    for p in "${pkgs[@]}"; do
      if dpkg -s "$p" >/dev/null 2>&1; then ok "$p present"; else pkg_install "$p"; fi
    done
  fi

  # unattended-upgrades config
  if [ -f /etc/apt/apt.conf.d/20auto-upgrades ]; then
    c="$(grep -h 'Unattended-Upgrade' /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null | awk '{print $2}' | tr -d ';"')"
    if [ "$c" = "1" ]; then ok "auto-upgrades already configured"; else
      confirm "Enable automatic security updates (apt periodic)?" && {
        cfg='APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
'
        if [ "$DRY_RUN" -eq 1 ]; then say "         ${CY}(dry) would write /etc/apt/apt.conf.d/20auto-upgrades${CN}"; else
          write_config /etc/apt/apt.conf.d/20auto-upgrades "$cfg"
        fi
      }
    fi
  else
    confirm "Enable automatic security updates (apt periodic)?" && {
      cfg='APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
'
      if [ "$DRY_RUN" -eq 1 ]; then say "         ${CY}(dry) would write /etc/apt/apt.conf.d/20auto-upgrades${CN}"; else
        write_config /etc/apt/apt.conf.d/20auto-upgrades "$cfg"
      fi
    }
  fi

  # enable the key services
  for s in auditd fail2ban unattended-upgrades rsyslog; do
    systemctl list-unit-files 2>/dev/null | grep -q "^$s\." && svc_enable_now "$s"
  done

  # fail2ban sshd jail
  if dpkg -s fail2ban >/dev/null 2>&1; then
    if [ -f /etc/fail2ban/jail.d/sshd.local ]; then
      ok "fail2ban sshd jail present"
    elif confirm "Protect SSH with a fail2ban jail (5 tries / 10 min)?"; then
      cfg='[sshd]
enabled = true
backend = systemd
maxretry = 5
findtime = 10m
bantime = 10m
ignoreip = 127.0.0.1/8 ::1
'
      if [ "$DRY_RUN" -eq 1 ]; then say "         ${CY}(dry) would create /etc/fail2ban/jail.d/sshd.local${CN}"; else
        write_config /etc/fail2ban/jail.d/sshd.local "$cfg"
        systemctl restart fail2ban >/dev/null 2>&1 && ok "fail2ban restarted" || err "fail2ban restart failed"
      fi
    else
      skip "fail2ban sshd jail"
    fi
  fi

  # optionally disable noisy/unneeded services that are actually running
  local candidates=(smbd nmbd winbind cups avahi-daemon bluetooth)
  local running=()
  for s in "${candidates[@]}"; do systemctl is-active --quiet "$s" 2>/dev/null && running+=("$s"); done
  if [ "${#running[@]}" -gt 0 ]; then
    if confirm "Stop and disable running service(s): ${running[*]} ?"; then
      for s in "${running[@]}"; do svc_disable_now "$s"; done
    else
      skip "services left running: ${running[*]}"
    fi
  else
    info "no disable-worthy services currently running"
  fi
}

# ----------------------------------------------------------------------------
#  Module: File permissions
# ----------------------------------------------------------------------------
module_files() {
  banner_t "  ── File Permissions ──"
  # cron
  local fixed=0
  for f in /etc/crontab /etc/anacrontab; do
    [ -f "$f" ] || continue
    [ "$(stat -c '%a' "$f")" = "644" ] || [ "$(stat -c '%a' "$f")" = "600" ] && continue
    planned "chmod 600 $f"
    if confirm "Tighten $f to 0600?"; then
      [ "$DRY_RUN" -eq 1 ] && { say "         ${CY}(dry) chmod 600 $f${CN}"; continue; }
      init_backup; backup_file "$f"
      chmod 600 "$f" && ok "chmod 600 $f"; fixed=1
    fi
  done
  for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    [ -d "$d" ] || continue
    a="$(stat -c '%a' "$d")"
    [ "$a" = "700" ] || [ "$a" = "600" ] && continue
    planned "chmod 700 $d"
    if confirm "Tighten $d to 0700?"; then
      [ "$DRY_RUN" -eq 1 ] && { say "         ${CY}(dry) chmod 700 $d${CN}"; continue; }
      init_backup; backup_file "$d"
      chmod 700 "$d" && ok "chmod 700 $d"; fixed=1
    fi
  done
  [ "$fixed" -eq 0 ] && [ "$DRY_RUN" -eq 0 ] && info "cron permissions already sane"

  # SUID report (informational)
  local suid_count; suid_count="$(find / -xdev -type f -perm -4000 2>/dev/null | wc -l)"
  info "SUID binaries found: $suid_count"
  [ "$suid_count" -gt 0 ] && [ "$INTERACTIVE" -eq 1 ] && {
    find / -xdev -type f -perm -4000 -printf '    %m %u %p\n' 2>/dev/null | sort
  }

  # world-writable audit (ask before touching)
  local ww filesonly; ww="$(find / -xdev -type d -perm -0002 -print 2>/dev/null)"
  filesonly="$(find / -xdev -type f -perm -0002 2>/dev/null | wc -l)"
  info "world-writable regular files: $filesonly"
  ww="$(printf '%s\n' "$ww" | grep -vE '^/(proc|sys|run|dev|tmp)$|^/tmp$' | wc -l)"
  info "world-writable directories (no sticky bit): $ww"
  if [ "$ww" -gt 0 ] || [ "$filesonly" -gt 0 ]; then
    if [ "$INTERACTIVE" -eq 1 ] && confirm "Review world-writable paths now? (listing only, no changes)"; then
      find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null | grep -vE '^/(proc|sys|run|dev)' | head -n 40
      find / -xdev -type f -perm -0002 2>/dev/null | grep -vE '^/(proc|sys|run|dev)' | head -n 40
    else
      info "world-writable paths NOT modified (review manually)"
    fi
  fi
}

# ----------------------------------------------------------------------------
#  Module: Logging & Audit
# ----------------------------------------------------------------------------
module_logging() {
  banner_t "  ── Logging & Audit ──"
  [ "$DRY_RUN" -eq 0 ] && {
    [ -d /etc/logrotate.d ] || { have apt-get && { pkg_install logrotate; }; }
  }

  # journal persistence
  [ -d /var/log/journal ] || {
    planned "persistent journal storage"
    if [ "$DRY_RUN" -eq 1 ]; then say "         ${CY}(dry) mkdir /var/log/journal${CN}"; else
      mkdir -p /var/log/journal
      systemctl kill -s SIGUSR1 systemd-journald >/dev/null 2>&1
      ok "journal storage made persistent"
    fi
  }

  # rsyslog + auth log
  if command -v rsyslogd >/dev/null 2>&1 || dpkg -s rsyslog >/dev/null 2>&1; then
    svc_enable_now rsyslog
    [ -e /var/log/auth.log ] || [ "$DRY_RUN" -eq 1 ] || { : > /var/log/auth.log && ok "created /var/log/auth.log"; }
  fi

  # remote syslog (optional, prompt)
  if confirm "Forward logs to a remote syslog server? (skip if no)"; then
    ask_value "Remote syslog server (host or host:port)" ""
    if [ -n "$REPLY" ]; then
      if [ "$DRY_RUN" -eq 1 ]; then
        say "         ${CY}(dry) would write /etc/rsyslog.d/99-remote.conf: *.* @@$REPLY${CN}"
      else
        write_config /etc/rsyslog.d/99-remote.conf "*.*\t@@$REPLY"
        systemctl restart rsyslog >/dev/null 2>&1 && ok "rsyslog restarted" || warn "rsyslog restart failed"
      fi
    else skip "remote syslog (none given)"; fi
  fi

  # auditd rules
  if dpkg -s auditd >/dev/null 2>&1 || command -v auditctl >/dev/null 2>&1; then
    svc_enable_now auditd
    local rulef="/etc/audit/rules.d/99-hardening.rules"
    if [ -f "$rulef" ] && [ -s "$rulef" ]; then
      ok "audit rules already present"
    elif confirm "Monitor critical files with auditd (passwd/shadow/sudoers/sshd_config)?"; then
      cfg='-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/issue.net -p wa -k systemd
'
      if [ "$DRY_RUN" -eq 1 ]; then say "         ${CY}(dry) would write $rulef${CN}"; else
        write_config "$rulef" "$cfg"
        augenrules --load >/dev/null 2>&1 && { auditctl -R "$rulef" >/dev/null 2>&1; ok "audit rules loaded"; } || err "failed to load audit rules"
      fi
    else
      skip "audit rules"
    fi
  else
    warn "auditd not installed"
  fi

  # logrotate compression
  if [ -f /etc/logrotate.conf ]; then
    if grep -E '^\s*compress' /etc/logrotate.conf >/dev/null 2>&1; then
      ok "logrotate compression already on"
    elif confirm "Enable logrotate compression?"; then
      append_config /etc/logrotate.conf "compress"
    else skip "logrotate compression"; fi
  fi
}

# ----------------------------------------------------------------------------
#  Menu / wizard / apply-all
# ----------------------------------------------------------------------------
menu() {
  while true; do
    printf '\n%72s\n' "" | tr ' ' '-'
    banner_t "  Hardening categories"
    printf '   1) SSH               5) Services & Packages\n'
    printf '   2) Firewall          6) File permissions\n'
    printf '   3) Kernel/Sysctl     7) Logging & Audit\n'
    printf '   4) Users/Passwords\n\n'
    printf '   a) Apply ALL         d) Dry-run preview all\n'
    printf '   q) Quit\n\n'
    printf '  %spaths%s:   backups → %s\n' "$CB" "$CN" "$BACKUP_ROOT"
    printf '  %srollback%s: %s\n' "$CB" "$CN" "$ROLLBACK_SCRIPT"
    printf '  %sstatus%s:   %d applied, %d skipped, %d passed\n' "$CB" "$CN" "$NUM_APPLIED" "$NUM_SKIPPED" "$NUM_PASS"
    local sel
    read -r -p "${CY}?${CN} Select (comma list, e.g. 1,3,4): " sel
    case "$sel" in
      q|Q|quit|exit) break ;;
      a|A|all) for m in "${ALL_MODULES[@]}"; do run_module "$m"; done ;;
      d|D) DRY_RUN=1; for m in "${ALL_MODULES[@]}"; do run_module "$m"; done; DRY_RUN=0 ;;
      *)
        IFS=',' read -ra picks <<< "$sel"
        for p in "${picks[@]}"; do
          case "$p" in
            1) run_module ssh ;; 2) run_module firewall ;; 3) run_module kernel ;;
            4) run_module users ;; 5) run_module services ;; 6) run_module files ;;
            7) run_module logging ;;
            *) warn "unknown selection: $p" ;;
          esac
        done
        ;;
    esac
  done
}

run_module() {  # run_module <name>
  case "$1" in
    ssh|firewall|kernel|users|services|files|logging) ;;
    *) err "unknown module: $1"; return 1 ;;
  esac
  local s
  for s in "${SKIP[@]}"; do [ "$s" = "$1" ] && { info "skipped module $1 (--skip)"; return 0; }; done
  case "$1" in
    ssh) module_ssh ;;
    firewall) module_firewall ;;
    kernel) module_kernel ;;
    users) module_users ;;
    services) module_services ;;
    files) module_files ;;
    logging) module_logging ;;
  esac
}

summary() {
  printf '\n%72s\n' "" | tr ' ' '-'
  banner_t "  Run summary"
  printf '  measures applied : %s%d%s\n' "$CG" "$NUM_APPLIED" "$CN"
  printf '  measures skipped : %s%d%s\n' "$CY" "$NUM_SKIPPED" "$CN"
  [ "$DRY_RUN" -eq 1 ] && printf '  %smode%s           : %sDRY-RUN (nothing written)%s\n' "$CY" "$CN" "$CY" "$CN"
  if [ -d "$BACKUP_DIR" ]; then
    printf '  backups          : %s\n' "$BACKUP_DIR"
    printf '  rollback script  : %s\n' "$ROLLBACK_SCRIPT"
  else
    [ "$DRY_RUN" -eq 0 ] && printf '  %s%s%s\n' "$CR" "  no changes were made this run." "$CN"
  fi
}

usage() {
  sed -n '1,32p' "$0" | sed 's/^# \{0,1\}//'
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --wizard) MODE="wizard" ;;
      --apply-all|--all) MODE="apply"; INTERACTIVE=0 ;;
      --module|-m) MODE="modules"; shift; IFS=',' read -ra SELECTED <<< "$1" ;;
      --dry-run) DRY_RUN=1; MODE="apply"; INTERACTIVE=0 ;;
      --skip) shift; IFS=',' read -ra SKIP <<< "$1" ;;
      --ssh-port) shift; SSH_PORT="$1" ;;
      --password-min) shift; PW_MIN="$1" ;;
      --max-age) shift; PW_MAX="$1" ;;
      --min-age) shift; PW_MIN_AGE="$1" ;;
      --warn-age) shift; PW_WARN="$1" ;;
      --interactive) INTERACTIVE=1 ;;
      --version|-v) say "$APP $VERSION"; exit 0 ;;
      --help|-h) usage; exit 0 ;;
      *) err "unknown option: $1 (see --help)"; exit 64 ;;
    esac
    shift
  done
  [ "$MODE" = "modules" ] && [ ${#SELECTED[@]} -eq 0 ] && MODE="menu"
}

require_root() {
  [ "$DRY_RUN" -eq 1 ] && return 0
  [ -n "${HARDEN_ALLOW_NONROOT:-}" ] && { warn "running WITHOUT root privileges (HARDEN_ALLOW_NONROOT set)"; return 0; }
  if ! is_root; then
    if have sudo; then
      warn "not running as root - elevating via sudo"
      exec sudo env HARDEN_BACKUP_ROOT="$BACKUP_ROOT" "$0" "$@"
    else
      die "must run as root (or with sudo)"
    fi
  fi
}

main() {
  parse_args "$@"
  require_root "$@"
  banner_t "$APP v$VERSION — interactive Linux hardening"
  say "  backups:      $BACKUP_ROOT"
  say "  dry run:      $([ "$DRY_RUN" -eq 1 ] && echo yes || echo no)"
  [ "$DRY_RUN" -eq 0 ] && mkdir -p "$BACKUP_ROOT" 2>/dev/null || true

  case "$MODE" in
    apply)
      for m in "${ALL_MODULES[@]}"; do run_module "$m"; done
      ;;
    wizard)
      INTERACTIVE=1
      for m in "${ALL_MODULES[@]}"; do
        if confirm "Run the $m module now?"; then run_module "$m"; else info "skipped $m"; fi
      done
      ;;
    modules)
      INTERACTIVE=1
      for m in "${SELECTED[@]}"; do run_module "$m"; done
      ;;
    menu|*)
      INTERACTIVE=1
      menu
      ;;
  esac
  summary
}
main "$@"