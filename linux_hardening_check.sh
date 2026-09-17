#!/usr/bin/env bash
# =============================================================================
#  linux_hardening_check.sh
#  Security posture scanner (read-only) for Debian/Ubuntu + systemd.
#  No changes are made to the system.
#
#  Usage:
#    bash linux_hardening_check.sh                    all categories
#    bash linux_hardening_check.sh -m ssh,firewall    specific categories
#    bash linux_hardening_check.sh -s HIGH            only HIGH/CRITICAL
#    bash linux_hardening_check.sh -j                 JSON report to stdout
#    bash linux_hardening_check.sh -o report.json     write JSON report to file
#    bash linux_hardening_check.sh -q                 quiet (suppress banner)
#    bash linux_hardening_check.sh -h                 help
#
#  Categories: ssh | firewall | kernel | users | services | files | logging
#
#  Exit codes: 0 = no findings, 1 = MEDIUM+, 2 = HIGH+, 3 = CRITICAL present
# =============================================================================

CATS="ssh firewall kernel users services files logging"
SSH_CONFIG="/etc/ssh/sshd_config"

PASS=0; FAIL=0; SSCORE=0; TOTAL=0
JSON_MODE=0; QUIET=0; OUTFILE=""; SEV_FILTER=""; SELECTED=(); EXIT=0
ROWS=(); declare -A FIX
START=$(date +%s)

# severity pass/fail tally (for summary)
S_CR_P=0; S_CR_T=0; S_HI_P=0; S_HI_T=0; S_ME_P=0; S_ME_T=0; S_LO_P=0; S_LO_T=0

# ---- argument parsing -------------------------------------------------------
usage() { sed -n '1,14p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    -m|--modules) IFS=',' read -ra SELECTED <<< "$2"; shift 2 ;;
    -s|--severity) SEV_FILTER="${2^^}"; shift 2 ;;
    -j|--json) JSON_MODE=1; shift ;;
    -o|--outfile) OUTFILE="$2"; shift 2 ;;
    -q|--quiet) QUIET=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 64 ;;
  esac
done

# ---- colors ----------------------------------------------------------------
if [ -t 1 ]; then
  R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[34m'; N=$'\e[0m'; BD=$'\e[1m'
else
  R=""; G=""; Y=""; B=""; N=""; BD=""
fi

# ---- output helpers ---------------------------------------------------------
J_RESULT='{"category":"%s","id":%s,"severity":"%s","name":"%s","expected":"%s","actual":"%s","status":"%s","fix":"%s"}'

jesc() { printf '%s' "${1:-}" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr '\n' ' '; }

_sev_tally() {  # tally severity pass/fail counters
  case "$1" in
    CRITICAL) S_CR_T=$((S_CR_T+1)); [ "$2" = "PASS" ] && S_CR_P=$((S_CR_P+1)) ;;
    HIGH)     S_HI_T=$((S_HI_T+1)); [ "$2" = "PASS" ] && S_HI_P=$((S_HI_P+1)) ;;
    MEDIUM)   S_ME_T=$((S_ME_T+1)); [ "$2" = "PASS" ] && S_ME_P=$((S_ME_P+1)) ;;
    LOW|INFO) S_LO_T=$((S_LO_T+1)); [ "$2" = "PASS" ] && S_LO_P=$((S_LO_P+1)) ;;
  esac
}

_sev_reported() {  # severity filters
  case "${SEV_FILTER}" in
    "") return 0 ;;
    CRITICAL) [ "$1" = "CRITICAL" ] && return 0 ;;
    HIGH) case "$1" in CRITICAL|HIGH) return 0 ;; esac ;;
    MEDIUM) case "$1" in CRITICAL|HIGH|MEDIUM) return 0 ;; esac ;;
  esac
  return 1
}

emit() {  # emit <cat> <id> <sev> <name> <expected> <actual> <status>
  local st="$7" fix jfix jrow
  fix="${FIX[$4]:-}"
  jfix="$(jesc "$fix")"
  jrow="$(printf "$J_RESULT" "$1" "$2" "$3" "$(jesc "$4")" "$(jesc "$5")" "$(jesc "$6")" "$st" "$jfix")"
  ROWS+=("${1}"$'\t'"${jrow}")
  TOTAL=$((TOTAL+1))
  _sev_tally "$3" "$st"
  [ "$st" = "PASS" ] && PASS=$((PASS+1)) || FAIL=$((FAIL+1))

  if [ "$JSON_MODE" -eq 1 ]; then
    return 0
  fi
  _sev_reported "$3" || return 0
  if [ "$st" = "PASS" ]; then
    printf '  %sPASS %s%s  %s\n' "$G" "[$3]" "$N" "$4"
  else
    printf '  %sFAIL %s%s  %s\n' "$R" "[$3]" "$N" "$4"
    printf '  %sExpected: %s%s\n' "$BD" "$5" "$N"
    printf '  %sActual:   %s%s\n' "$BD" "$6" "$N"
    [ -n "$fix" ] && printf '  %sFix:     %s%s\n' "$G" "$fix" "$N"
  fi
  return 0
}

section() {  # section <cat> <label>
  [ "$JSON_MODE" -eq 1 ] && return 0
  printf '\n%s[%s-] %s%s\n' "$BD" "${1^^}" "$2" "$N"
  printf '%s─%s\n' "$BD" "$N"
}
section_end() {  # section_end <count>
  [ "$JSON_MODE" -eq 1 ] && return 0
  printf '%s└─── %s checks%s\n' "$BD" "$1" "$N"
}

# ---- environment helpers ---------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }
svc_active() { systemctl is-active --quiet "$1" 2>/dev/null; }
sshd_T() { if have sshd; then sshd -T 2>/dev/null; fi; }

# ---- suggested fixes (v2.0) ------------------------------------------------
# keyed by exact check name as passed to emit()
FIX["PasswordAuthentication disabled"]="Append 'PasswordAuthentication no' to /etc/ssh/sshd_config, validate with sshd -t, then reload ssh (systemctl reload ssh)."
FIX["PermitRootLogin disabled"]="Set 'PermitRootLogin prohibit-password' or 'no' in /etc/ssh/sshd_config."
FIX["PermitEmptyPasswords disabled"]="Ensure 'PermitEmptyPasswords no' is set in /etc/ssh/sshd_config."
FIX["X11Forwarding disabled"]="Set 'X11Forwarding no' in /etc/ssh/sshd_config."
FIX["MaxAuthTries <= 4"]="Set 'MaxAuthTries 4' (or lower) in /etc/ssh/sshd_config."
FIX["ClientAliveInterval 300-600"]="Set 'ClientAliveInterval 300' in /etc/ssh/sshd_config."
FIX["ClientAliveCountMax <= 3"]="Set 'ClientAliveCountMax 3' (or lower) in /etc/ssh/sshd_config."
FIX["LoginGraceTime <= 60"]="Set 'LoginGraceTime 60' (or lower) in /etc/ssh/sshd_config."
FIX["AllowTcpForwarding disabled"]="Set 'AllowTcpForwarding no' in /etc/ssh/sshd_config."
FIX["AllowAgentForwarding disabled"]="Set 'AllowAgentForwarding no' in /etc/ssh/sshd_config."
FIX["MaxSessions <= 4"]="Set 'MaxSessions 4' or lower in /etc/ssh/sshd_config."
FIX["MaxStartups configured"]="Set 'MaxStartups 10:30:60' in /etc/ssh/sshd_config."
FIX["Login banner configured"]="Create a banner file (e.g. /etc/issue.net) and set 'Banner /etc/issue.net' in sshd_config."
FIX["No weak ciphers"]="Restrict ciphers to aes256-gcm@openssh.com,aes128-gcm@openssh.com,chacha20-poly1305@openssh.com in sshd_config."
FIX["No weak MACs"]="Restrict MACs to hmac-sha2-256,hmac-sha2-512 in /etc/ssh/sshd_config."
FIX["No weak key exchange"]="Restrict KexAlgorithms to curve25519-sha256,diffie-hellman-group16-sha512 in sshd_config."
FIX["SSH host key permissions <= 600"]="Run: chmod 600 /etc/ssh/ssh_host_*_key"
FIX["ED25519 host key present"]="Generate an ed25519 host key: ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N '' ; systemctl restart ssh"

FIX["INPUT chain policy is DROP"]="Set the default input policy to DROP (nftables: 'policy drop' on the input chain; iptables: iptables -P INPUT DROP)."
FIX["OUTPUT chain policy configured"]="Explicitly set an output policy (nftables 'policy drop'; iptables -P OUTPUT DROP) instead of the implicit ACCEPT."
FIX["ESTABLISHED/RELATED accepted"]="Add a rule accepting established/related traffic, e.g. nft 'ct state established,related accept' or iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT."
FIX["SSH not open to 0.0.0.0/0"]="Restrict SSH to trusted source networks (-s <cidr>) in your firewall accept rule instead of allowing from any."
FIX["ICMP rate limiting"]="Add an ICMP rate limit, e.g. nft 'icmp type echo-request limit rate 5/second accept'."
FIX["Drop logging configured"]="Add a logging rule for dropped traffic (nft 'log prefix \"dropped: \"' or iptables -A INPUT -j LOG) for forensic visibility."
FIX["FORWARD chain policy is DROP"]="Set the forward policy to DROP (iptables -P FORWARD DROP / nftables 'policy drop')."
FIX["Minimal wildcard listeners"]="Bind services to specific interfaces/addresses; replace 0.0.0.0: and ::: listeners where possible."
FIX["SMB not exposed on 0.0.0.0"]="Stop and disable Samba (systemctl --now disable smbd nmbd) or restrict it to the local subnet."
FIX["Ports inventory"]="Review the listening ports and close or firewall any service that is not required."

FIX["ASLR enabled (2)"]="Set 'kernel.randomize_va_space = 2' in /etc/sysctl.d/ (e.g. 99-security.conf) and run sysctl -p."
FIX["IP forwarding disabled"]="Set 'net.ipv4.ip_forward = 0' in /etc/sysctl.d/ unless routing is required."
FIX["IPv4 source routing disabled"]="Set 'net.ipv4.conf.all.accept_source_route = 0' and 'net.ipv4.conf.default.accept_source_route = 0'."
FIX["IPv4 ICMP redirects disabled"]="Set 'net.ipv4.conf.all.accept_redirects = 0' and the default interface value."
FIX["IPv4 send redirects disabled"]="Set 'net.ipv4.conf.all.send_redirects = 0'."
FIX["TCP SYN cookies enabled"]="Set 'net.ipv4.tcp_syncookies = 1'."
FIX["ICMP broadcast echo ignored"]="Set 'net.ipv4.icmp_echo_ignore_broadcasts = 1'."
FIX["Bogus ICMP responses ignored"]="Set 'net.ipv4.icmp_ignore_bogus_error_responses = 1'."
FIX["Martian logging enabled"]="Set 'net.ipv4.conf.all.log_martians = 1'."
FIX["IPv6 redirects disabled"]="Set 'net.ipv6.conf.all.accept_redirects = 0' and the default value."
FIX["IPv6 source routing disabled"]="Set 'net.ipv6.conf.all.accept_source_route = 0'."
FIX["IPv6 router advertisements off"]="Set 'net.ipv6.conf.all.accept_ra = 0' where IPv6 routing is not required."
FIX["Reverse path filtering on"]="Set 'net.ipv4.conf.all.rp_filter = 1'."
FIX["dmesg restricted"]="Set 'kernel.dmesg_restrict = 1'."
FIX["Kernel pointers hidden"]="Set 'kernel.kptr_restrict = 2' (or 1)."
FIX["Yama ptrace scope >= 1"]="Set 'kernel.yama.ptrace_scope = 1'."
FIX["SUID core dumps disabled"]="Set 'fs.suid_dumpable = 0'."
FIX["Unprivileged BPF disabled"]="Set 'kernel.unprivileged_bpf_disabled = 1'."
FIX["NX/Execute Shield"]="Ensure the CPU supports NX (nx flag in /proc/cpuinfo) and that no conflicting legacy exec-shield settings disable it."
FIX["KASLR not disabled"]="Remove 'nokaslr' from the kernel cmdline unless it is intentional."

FIX["Root account locked/no password"]="Lock the root account: passwd -l root (root login only via su/sudo)."
FIX["Only root has UID 0"]="Review UID-0 accounts in /etc/passwd and rename/remove any account other than root (usermod -u)."
FIX["Password max age <= 90 days"]="Set 'PASS_MAX_DAYS 90' in /etc/login.defs."
FIX["Password min age >= 1"]="Set 'PASS_MIN_DAYS 1' in /etc/login.defs."
FIX["Password min length >= 12"]="Set 'PASS_MIN_LEN 12' in /etc/login.defs and 'minlen=12' in pam_pwquality."
FIX["Password warning >= 7 days"]="Set 'PASS_WARN_AGE 7' in /etc/login.defs."
FIX["No empty passwords"]="Lock accounts with empty passwords: passwd -l <user>."
FIX["No NOPASSWD sudo"]="Remove NOPASSWD entries from /etc/sudoers and /etc/sudoers.d/."
FIX["Sudo use_pty enabled"]="Add 'Defaults use_pty' to a file under /etc/sudoers.d/."
FIX["Sudo logging"]="Add 'Defaults logfile=/var/log/sudo.log' and optionally log_input/log_output under /etc/sudoers.d/."
FIX["Sudo timeout <= 5 min"]="Set 'Defaults timestamp_timeout=5' in a sudoers file."
FIX["Account lockout configured"]="Enable account lockout in PAM (pam_faillock or pam_tally2) in the auth stack."
FIX["Password complexity module"]="Install libpam-pwquality (apt install libpam-pwquality) and add pam_pwquality to the password PAM stack."
FIX["Umask 027 or stricter"]="Set 'UMASK 027' in /etc/login.defs."
FIX["Home dirs not world-readable"]="Remove group/other read/execute bits on user home directories: chmod o-rx /home/<user>."
FIX[".ssh dirs are 700"]="Set strict permissions on .ssh directories: chmod 700 /home/<user>/.ssh"
FIX["authorized_keys are 600"]="Set strict permissions on authorized_keys: chmod 600 /home/<user>/.ssh/authorized_keys"
FIX["No .rhosts files"]="Remove legacy ~/.rhosts and ~/.shosts trust files."

FIX["Unattended upgrades active"]="Install and enable unattended-upgrades: apt install unattended-upgrades && systemctl enable --now unattended-upgrades."
FIX["Auto-update configured"]="Set 'APT::Periodic::Unattended-Upgrade \"1\"' in /etc/apt/apt.conf.d/20auto-upgrades."
FIX["Fail2ban active"]="Install and start fail2ban: apt install fail2ban && systemctl enable --now fail2ban."
FIX["Auditd active"]="Install and start auditd: apt install auditd && systemctl enable --now auditd."
FIX["Rsyslog active"]="Install and start rsyslog: apt install rsyslog && systemctl enable --now rsyslog."
FIX["MAC framework active"]="Install AppArmor (apt install apparmor apparmor-utils) and enable it on the kernel cmdline (apparmor=1 security=apparmor)."
FIX["Docker socket perms"]="Make the Docker socket root:docker owned: chown root:docker /var/run/docker.sock && chmod 660 /var/run/docker.sock."
FIX["Docker daemon not on 0.0.0.0:2375"]="Do not expose the Docker daemon over TCP; remove '-H tcp://0.0.0.0:2375' from the daemon config."
FIX["NTP sync active"]="enable the time sync: systemctl enable --now systemd-timesyncd (or install chrony/ntp)."
FIX["No failed services"]="Inspect and fix failed units: systemctl --failed and journalctl -u <unit>."
FIX["No pending security updates"]="Apply available updates: apt upgrade (and enable unattended-upgrades for auto patching)."
FIX["No reboot required"]="Reboot the host to activate pending kernel and library updates."

FIX["/tmp nosuid"]="Add 'nosuid' to the /tmp entry in /etc/fstab."
FIX["/tmp nodev"]="Add 'nodev' to the /tmp entry in /etc/fstab."
FIX["No unexpected SUID binaries"]="Audit SUID binaries (find / -perm -4000) and remove unexpected setuid bits: chmod u-s <path>."
FIX["No world-writable files"]="Restrict permissions on world-writable files: chmod o-w <path>."
FIX["No world-writable dirs"]="Remove write bits or set the sticky bit on world-writable directories: chomd o-w <dir> / chmod +t <dir>."
FIX["Critical file perms correct"]="Fix permissions: chmod 644 /etc/passwd; 640 or 600 for /etc/shadow /etc/gshadow; 440/400/600 for /etc/sudoers /etc/crontab."
FIX["No unowned files"]="Assign missing ownership: chown <user>:<group> <path> (find / -xdev -nouser -o -nogroup)."

FIX["Rsyslog active"]="Install and start rsyslog: apt install rsyslog && systemctl enable --now rsyslog."
FIX["Journal storage"]="Enable persistent journal: mkdir -p /var/log/journal && systemd-tmpfiles --create --prefix /var/log/journal."
FIX["Auditd active"]="Install and start auditd: apt install auditd && systemctl enable --now auditd."
FIX["Audit rules loaded"]="Load audit rules from /etc/audit/rules.d/ (see linux_harden.sh --module logging) and restart auditd."
FIX["Audit backlog configured"]="Set 'kernel.auditd_backlog_limit = 8192' in sysctl and raise the audit daemon backlog."
FIX["Critical files audited"]="Add watch rules, e.g. -w /etc/passwd -p wa, -w /etc/shadow -p wa, -w /etc/sudoers -p wa in /etc/audit/rules.d/."
FIX["Logrotate configured"]="Install logrotate (apt install logrotate) and verify /etc/logrotate.conf and /etc/logrotate.d/."
FIX["Logrotate compression"]="Add 'compress' to /etc/logrotate.conf to gzip rotated logs."
FIX["Log retention >= 4"]="Increase rotation count, e.g. 'rotate 4' in /etc/logrotate.conf."
FIX["Remote syslog"]="Configure a remote syslog sink in /etc/rsyslog.conf, e.g. '*.* @@logserver.example.com:514'."
FIX["Auth log exists"]="Ensure rsyslog writes the auth log: 'auth,authpriv.*  /var/log/auth.log' in /etc/rsyslog.d/."

# =============================================================================
#  SSH
# =============================================================================
check_ssh() {
  local T; T="$(sshd_T)"
  local n=0
  section ssh "SSH Configuration"
  local v

  v="$(printf '%s\n' "$T" | awk '$1=="passwordauthentication"{print $2}')"
  emit ssh 1 CRITICAL "PasswordAuthentication disabled" "no" "${v:-unset}" \
       "$([ "$v" = "no" ] || [ "$v" = "NO" ] && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(printf '%s\n' "$T" | awk '$1=="permitrootlogin"{print $2}')"
  [ -z "$v" ] && v="yes"
  emit ssh 2 CRITICAL "PermitRootLogin disabled" "no" "$v" \
       "$([ "$v" = "no" ] || [ "$v" = "prohibit-password" ] && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(printf '%s\n' "$T" | awk '$1=="permitemptypasswords"{print $2}')"
  emit ssh 3 HIGH "PermitEmptyPasswords disabled" "no" "${v:-unset}" \
       "$([ "$v" = "no" ] && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(printf '%s\n' "$T" | awk '$1=="x11forwarding"{print $2}')"
  emit ssh 4 MEDIUM "X11Forwarding disabled" "no" "${v:-unset}" \
       "$([ "$v" = "no" ] && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(printf '%s\n' "$T" | awk '$1=="maxauthtries"{print $2}')"
  emit ssh 5 HIGH "MaxAuthTries <= 4" "<= 4" "${v:-unset}" \
       "$([ -n "$v" ] && [ "$v" -le 4 ] 2>/dev/null && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(printf '%s\n' "$T" | awk '$1=="clientaliveinterval"{print $2}')"
  emit ssh 6 MEDIUM "ClientAliveInterval 300-600" "300-600" "${v:-unset}" \
       "$([ -n "$v" ] && [ "$v" -ge 300 ] 2>/dev/null && [ "$v" -le 600 ] 2>/dev/null && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(printf '%s\n' "$T" | awk '$1=="clientalivecountmax"{print $2}')"
  emit ssh 7 MEDIUM "ClientAliveCountMax <= 3" "<= 3" "${v:-unset}" \
       "$([ -n "$v" ] && [ "$v" -le 3 ] 2>/dev/null && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(printf '%s\n' "$T" | awk '$1=="logingracetime"{print $2}')"
  emit ssh 8 MEDIUM "LoginGraceTime <= 60" "<= 60" "${v:-unset}" \
       "$([ -n "$v" ] && [ "$v" -le 60 ] 2>/dev/null && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(printf '%s\n' "$T" | awk '$1=="allowtcpforwarding"{print $2}')"
  emit ssh 9 MEDIUM "AllowTcpForwarding disabled" "no" "${v:-unset}" \
       "$([ "$v" = "no" ] && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(printf '%s\n' "$T" | awk '$1=="allowagentforwarding"{print $2}')"
  emit ssh 10 LOW "AllowAgentForwarding disabled" "no" "${v:-unset}" \
       "$([ "$v" = "no" ] && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(printf '%s\n' "$T" | awk '$1=="maxsessions"{print $2}')"
  emit ssh 11 LOW "MaxSessions <= 4" "<= 4" "${v:-unset}" \
       "$([ -n "$v" ] && [ "$v" -le 4 ] 2>/dev/null && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(printf '%s\n' "$T" | awk '$1=="maxstartups"{print $2}')"
  emit ssh 12 MEDIUM "MaxStartups configured" "10:30:60" "${v:-unset}" \
       "$([ -n "$v" ] && [ "$v" != "10:30:100" ] && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(printf '%s\n' "$T" | awk '$1=="banner"{print $2}')"
  emit ssh 13 LOW "Login banner configured" "/etc/issue.net" "${v:-none}" \
       "$([ -n "$v" ] && [ -f "$v" ] && echo PASS || echo FAIL)"; n=$((n+1))

  # weak ciphers / MACs / KEX
  local ciphers macs kex
  ciphers="$(printf '%s\n' "$T" | awk '$1=="ciphers"{print $2}')"
  macs="$(printf '%s\n' "$T" | awk '$1=="macs"{print $2}')"
  kex="$(printf '%s\n' "$T" | awk '$1=="kexalgorithms"{print $2}')"

  case "$ciphers" in
    *aes128-cbc*|*aes256-cbc*|*3des-cbc*|*blowfish-cbc*|*arcfour*|*cast128-cbc*)
      emit ssh 14 INFO "No weak ciphers" "cbc/legacy absent" "weak cipher(s) present" "FAIL" ;;
    *) emit ssh 14 INFO "No weak ciphers" "cbc/legacy absent" "${ciphers:-unset}" "PASS" ;;
  esac; n=$((n+1))

  case "$macs" in
    *md5*|*hmac-sha1*|*umac-64*|*ripemd160*)
      emit ssh 15 INFO "No weak MACs" "md5/sha1 absent" "weak MAC(s) present" "FAIL" ;;
    *) emit ssh 15 INFO "No weak MACs" "md5/sha1 absent" "${macs:-unset}" "PASS" ;;
  esac; n=$((n+1))

  case "$kex" in
    *diffie-hellman-group1*|*diffie-hellman-group14-sha1*|*diffie-hellman-group-exchange-sha1*)
      emit ssh 16 INFO "No weak key exchange" "sha1 kex absent" "weak kex present" "FAIL" ;;
    *) emit ssh 16 INFO "No weak key exchange" "sha1 kex absent" "${kex:-unset}" "PASS" ;;
  esac; n=$((n+1))

  # host key permissions
  local hkbad=0; local kf; local hkperm=""
  for kf in /etc/ssh/ssh_host_*_key; do
    [ -e "$kf" ] || continue
    p="$(stat -c '%a' "$kf" 2>/dev/null)"
    hkperm="$p"
    case "$p" in 600|400|440|000) ;; *) hkbad=1 ;; esac
  done
  emit ssh 17 HIGH "SSH host key permissions <= 600" "600/400/440/000" "${hkperm:-none}" \
       "$([ "$hkbad" -eq 0 ] && echo PASS || echo FAIL)"; n=$((n+1))

  emit ssh 18 MEDIUM "ED25519 host key present" "present" "$([ -f /etc/ssh/ssh_host_ed25519_key ] && echo present || echo absent)" \
       "$([ -f /etc/ssh/ssh_host_ed25519_key ] && echo PASS || echo FAIL)"; n=$((n+1))

  section_end "$n"
}

# =============================================================================
#  Firewall
# =============================================================================
check_firewall() {
  local n=0
  section firewall "Firewall & Network"
  local nft=""; have nft && nft="$(nft list ruleset 2>/dev/null)"
  local ipt=""; have iptables && ipt="$(iptables -S 2>/dev/null)"
  local fw="no firewall"
  [ -n "$nft" ] && fw="nftables"
  [ -n "$ipt" ] && [ -z "$nft" ] && fw="iptables"

  local v
  v="no firewall"
  if [ -n "$ipt" ]; then v="$(printf '%s\n' "$ipt" | awk '$1=="-P" && $2=="INPUT"{print $3}')"; fi
  if [ -n "$nft" ]; then v="$(printf '%s\n' "$nft" | awk '$1=="policy"{print $2}' | head -n1)"; fi
  emit firewall 1 CRITICAL "INPUT chain policy is DROP" "DROP" "$v" \
       "$([ "$v" = "DROP" ] || [ "$v" = "drop" ] && echo PASS || echo FAIL)"; n=$((n+1))

  v="no firewall"
  if [ -n "$ipt" ]; then v="$(printf '%s\n' "$ipt" | awk '$1=="-P" && $2=="OUTPUT"{print $3}')"; fi
  emit firewall 2 MEDIUM "OUTPUT chain policy configured" "DROP/REJECT" "$v" \
       "$([ "$v" = "DROP" ] && echo PASS || echo FAIL)"; n=$((n+1))

  # ESTABLISHED/RELATED
  local est=0
  if [ -n "$nft" ] && printf '%s\n' "$nft" | grep -qE "estab.*related|ct state established"; then est=1; fi
  if [ -n "$ipt" ] && printf '%s\n' "$ipt" | grep -q -- "-m conntrack --ctstate ESTABLISHED,RELATED"; then est=1; fi
  emit firewall 3 HIGH "ESTABLISHED/RELATED accepted" "yes" "$([ "$est" -eq 1 ] && echo yes || echo no)" \
       "$([ "$est" -eq 1 ] && echo PASS || echo FAIL)"; n=$((n+1))

  # SSH restricted
  local ssh_open=0
  if [ -n "$nft" ] && printf '%s\n' "$nft" | grep -qE "tcp dport (22|sshd).*accept"; then ssh_open=1; fi
  if [ -n "$ipt" ] && printf '%s\n' "$ipt" | grep -qE -- "-p tcp --dport (22|sshd).*-j ACCEPT( -s 0.0.0.0)?"; then ssh_open=1; fi
  emit firewall 4 HIGH "SSH not open to 0.0.0.0/0" "restricted" "$([ "$ssh_open" -eq 1 ] && echo anywhere || echo restricted/none)" \
       "$([ "$ssh_open" -eq 0 ] && echo PASS || echo FAIL)"; n=$((n+1))

  local icmp_lim=0
  if [ -n "$nft" ] && printf '%s\n' "$nft" | grep -q "limit rate"; then icmp_lim=1; fi
  emit firewall 5 MEDIUM "ICMP rate limiting" "limited" "$([ "$icmp_lim" -eq 1 ] && echo limited || echo not\ limited)" \
       "$([ "$icmp_lim" -eq 1 ] && echo PASS || echo FAIL)"; n=$((n+1))

  local drop_log=0
  if [ -n "$nft" ] && printf '%s\n' "$nft" | grep -q "log prefix"; then drop_log=1; fi
  if [ -n "$ipt" ] && printf '%s\n' "$ipt" | grep -q "\-j LOG"; then drop_log=1; fi
  emit firewall 6 MEDIUM "Drop logging configured" "LOG target" "$([ "$drop_log" -eq 1 ] && echo configured || echo not\ configured)" \
       "$([ "$drop_log" -eq 1 ] && echo PASS || echo FAIL)"; n=$((n+1))

  v="unknown"
  if [ -n "$ipt" ]; then v="$(printf '%s\n' "$ipt" | awk '$1=="-P" && $2=="FORWARD"{print $3}')"; fi
  emit firewall 7 MEDIUM "FORWARD chain policy is DROP" "DROP" "$v" \
       "$([ "$v" = "DROP" ] && echo PASS || echo FAIL)"; n=$((n+1))

  local wl=0
  if have ss; then
    wl="$(ss -tlnH 2>/dev/null | awk '$4 ~ /\*:|0\.0\.0\.0:|:::/' | wc -l)"
  elif have netstat; then
    wl="$(netstat -tln 2>/dev/null | awk '$4 ~ /\*:|0\.0\.0\.0:|:::/' | wc -l)"
  fi
  emit firewall 8 HIGH "Minimal wildcard listeners" "<= 3" "$wl found" \
       "$([ -n "$wl" ] && [ "$wl" -le 3 ] 2>/dev/null && echo PASS || echo FAIL)"; n=$((n+1))

  local smb=0
  if have ss; then
    smb="$(ss -tlnH 2>/dev/null | awk '$4 ~ /:(139|445)$/' | wc -l)"
  fi
  emit firewall 9 CRITICAL "SMB not exposed on 0.0.0.0" "not exposed" "$smb listeners" \
       "$([ -n "$smb" ] && [ "$smb" -eq 0 ] 2>/dev/null && echo PASS || echo FAIL)"; n=$((n+1))

  local inv=""
  if have ss; then inv="$(ss -tln 2>/dev/null | awk 'NR>1 {gsub(/:.*/,"",$4); printf "%s ", $4}')"; fi
  emit firewall 10 INFO "Ports inventory" "-" "$([ -n "$inv" ] && echo "$inv" || echo none)" "PASS"; n=$((n+1))

  section_end "$n"
}

# =============================================================================
#  Kernel / Sysctl
# =============================================================================
check_kernel() {
  local n=0
  section kernel "Kernel & Sysctl"
  local v
  sys_get() { sysctl -n "$1" 2>/dev/null; }

  v="$(sys_get kernel.randomize_va_space)"
  emit kernel 1 CRITICAL "ASLR enabled (2)" "2" "$v" \
       "$([ -n "$v" ] && [ "$v" -ge 2 ] 2>/dev/null && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(sys_get net.ipv4.ip_forward)"
  emit kernel 2 MEDIUM "IP forwarding disabled" "0" "$v" \
       "$([ "$v" = "0" ] && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(sys_get net.ipv4.conf.all.accept_source_route)"
  emit kernel 3 HIGH "IPv4 source routing disabled" "0" "$v" \
       "$([ "$v" = "0" ] && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(sys_get net.ipv4.conf.all.accept_redirects)"
  emit kernel 4 HIGH "IPv4 ICMP redirects disabled" "0" "$v" \
       "$([ "$v" = "0" ] && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(sys_get net.ipv4.conf.all.send_redirects)"
  emit kernel 5 HIGH "IPv4 send redirects disabled" "0" "$v" \
       "$([ "$v" = "0" ] && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(sys_get net.ipv4.tcp_syncookies)"
  emit kernel 6 HIGH "TCP SYN cookies enabled" "1" "$v" \
       "$([ "$v" = "1" ] && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(sys_get net.ipv4.icmp_echo_ignore_broadcasts)"
  emit kernel 7 MEDIUM "ICMP broadcast echo ignored" "1" "$v" \
       "$([ "$v" = "1" ] && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(sys_get net.ipv4.icmp_ignore_bogus_error_responses)"
  emit kernel 8 MEDIUM "Bogus ICMP responses ignored" "1" "$v" \
       "$([ "$v" = "1" ] && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(sys_get net.ipv4.conf.all.log_martians)"
  emit kernel 9 HIGH "Martian logging enabled" "1" "$v" \
       "$([ "$v" = "1" ] && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(sys_get net.ipv6.conf.all.accept_redirects)"
  emit kernel 10 HIGH "IPv6 redirects disabled" "0" "$v" \
       "$([ "$v" = "0" ] && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(sys_get net.ipv6.conf.all.accept_source_route)"
  emit kernel 11 HIGH "IPv6 source routing disabled" "0" "$v" \
       "$([ "$v" = "0" ] && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(sys_get net.ipv6.conf.all.accept_ra)"
  emit kernel 12 MEDIUM "IPv6 router advertisements off" "0" "$v" \
       "$([ "$v" = "0" ] && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(sys_get net.ipv4.conf.all.rp_filter)"
  emit kernel 13 HIGH "Reverse path filtering on" "1 or 2" "$v" \
       "$([ -n "$v" ] && [ "$v" -ge 1 ] 2>/dev/null && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(sys_get kernel.dmesg_restrict)"
  emit kernel 14 MEDIUM "dmesg restricted" "1" "$v" \
       "$([ "$v" = "1" ] && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(sys_get kernel.kptr_restrict)"
  emit kernel 15 MEDIUM "Kernel pointers hidden" "1 or 2" "$v" \
       "$([ -n "$v" ] && [ "$v" -ge 1 ] 2>/dev/null && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(sys_get kernel.yama.ptrace_scope)"
  emit kernel 16 MEDIUM "Yama ptrace scope >= 1" ">= 1" "$v" \
       "$([ -n "$v" ] && [ "$v" -ge 1 ] 2>/dev/null && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(sys_get fs.suid_dumpable)"
  emit kernel 17 HIGH "SUID core dumps disabled" "0" "$v" \
       "$([ "$v" = "0" ] && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(sys_get kernel.unprivileged_bpf_disabled)"
  [ -z "$v" ] && v="n/a"
  emit kernel 18 MEDIUM "Unprivileged BPF disabled" "1" "$v" \
       "$([ "$v" = "1" ] && echo PASS || echo FAIL)"; n=$((n+1))

  # NX / execute-shield
  local nx="unknown"
  grep -qw nx /proc/cpuinfo 2>/dev/null && nx="enabled"
  emit kernel 19 HIGH "NX/Execute Shield" "enabled" "dmesg=$([ -r /proc/sys/kernel/dmesg_restrict ] && echo "$(sysctl -n kernel.dmesg_restrict)" || echo 0) exec-shield=$nx" \
       "$([ "$nx" = "enabled" ] && echo PASS || echo FAIL)"; n=$((n+1))

  # KASLR
  local kaslr="not disabled"; grep -qw nokaslr /proc/cmdline 2>/dev/null && kaslr="disabled on cmdline"
  emit kernel 20 HIGH "KASLR not disabled" "enabled" "$kaslr" \
       "$([ "$kaslr" = "not disabled" ] && echo PASS || echo FAIL)"; n=$((n+1))

  section_end "$n"
}

# =============================================================================
#  Users & Authentication
# =============================================================================
check_users() {
  local n=0
  section users "User & Authentication"
  local v

  # root account state
  local rootpw="no account"; local rf="$(awk -F: '$1=="root"{print $2}' /etc/shadow 2>/dev/null)"
  case "$rf" in
    "*"|"!"|"!*"|"!!"|"*!") rootpw="locked" ;;
    "") rootpw="no password" ;;
    *)  rootpw="has password" ;;
  esac
  emit users 1 HIGH "Root account locked/no password" "locked" "$rootpw" \
       "$([ "$rootpw" = "locked" ] && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(awk -F: '$3==0{print $1}' /etc/passwd | wc -l)"
  emit users 2 CRITICAL "Only root has UID 0" "root only" "$v user(s)" \
       "$([ "$v" -eq 1 ] 2>/dev/null && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(grep -E "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}')"
  emit users 3 HIGH "Password max age <= 90 days" "<= 90" "$v" \
       "$([ -n "$v" ] && [ "$v" -le 90 ] 2>/dev/null && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(grep -E "^PASS_MIN_DAYS" /etc/login.defs | awk '{print $2}')"
  emit users 4 MEDIUM "Password min age >= 1" ">= 1" "$v" \
       "$([ -n "$v" ] && [ "$v" -ge 1 ] 2>/dev/null && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(grep -E "^PASS_MIN_LEN" /etc/login.defs | awk '{print $2}')"
  emit users 5 HIGH "Password min length >= 12" ">= 12" "$v" \
       "$([ -n "$v" ] && [ "$v" -ge 12 ] 2>/dev/null && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(grep -E "^PASS_WARN_AGE" /etc/login.defs | awk '{print $2}')"
  emit users 6 MEDIUM "Password warning >= 7 days" ">= 7" "$v" \
       "$([ -n "$v" ] && [ "$v" -ge 7 ] 2>/dev/null && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(awk -F: '($2==""){print $1}' /etc/shadow | wc -l)"
  emit users 7 CRITICAL "No empty passwords" "0" "$v user(s)" \
       "$([ "$v" -eq 0 ] 2>/dev/null && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(grep -rE "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | wc -l)"
  emit users 8 HIGH "No NOPASSWD sudo" "none" "$v match(es)" \
       "$([ "$v" -eq 0 ] 2>/dev/null && echo PASS || echo FAIL)"; n=$((n+1))

  v="no"; grep -rqsE "^\s*Defaults.*use_pty" /etc/sudoers /etc/sudoers.d/ 2>/dev/null && v="yes"
  emit users 9 MEDIUM "Sudo use_pty enabled" "Defaults use_pty" "$([ "$v" = "yes" ] && echo enabled || echo no)" \
       "$([ "$v" = "yes" ] && echo PASS || echo FAIL)"; n=$((n+1))

  v="no"; grep -rqsE "^\s*Defaults.*logfile|^\s*Defaults.*log_input|^\s*Defaults.*log_output" /etc/sudoers /etc/sudoers.d/ 2>/dev/null && v="yes"
  emit users 10 MEDIUM "Sudo logging" "logfile configured" "$([ "$v" = "yes" ] && echo enabled || echo no)" \
       "$([ "$v" = "yes" ] && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(grep -rhE "^\s*Defaults.*timestamp_timeout" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -oE "[0-9]+" | head -n1)"
  [ -z "$v" ] && v=15
  emit users 11 MEDIUM "Sudo timeout <= 5 min" "<= 5" "$v" \
       "$([ "$v" -le 5 ] 2>/dev/null && echo PASS || echo FAIL)"; n=$((n+1))

  v="no"; grep -rqs "pam_faillock\|pam_tally2" /etc/pam.d/ 2>/dev/null && v="yes"
  emit users 12 HIGH "Account lockout configured" "pam_faillock/tally2" "$([ "$v" = "yes" ] && echo configured || echo no)" \
       "$([ "$v" = "yes" ] && echo PASS || echo FAIL)"; n=$((n+1))

  v="no"; grep -rqs "pam_pwquality\|pam_cracklib" /etc/pam.d/ 2>/dev/null && v="yes"
  emit users 13 HIGH "Password complexity module" "pam_pwquality/cracklib" "$([ "$v" = "yes" ] && echo configured || echo no)" \
       "$([ "$v" = "yes" ] && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(grep -E "^UMASK" /etc/login.defs | awk '{print $2}')"
  emit users 14 MEDIUM "Umask 027 or stricter" "027/077" "$v" \
       "$([ "$v" = "027" ] || [ "$v" = "077" ] && echo PASS || echo FAIL)"; n=$((n+1))

  # home dirs
  local homes_bad=0; local p
  while IFS=: read -r u h; do
    [ -d "$h" ] || continue
    p="$(stat -c '%a' "$h" 2>/dev/null)"
    [ -n "$p" ] && [ $(( ${p: -1} & 2 )) -ne 0 ] && homes_bad=$((homes_bad+1))
  done < <(awk -F: '($3>=1000){print $1":"$6}' /etc/passwd)
  emit users 15 HIGH "Home dirs not world-readable" "o-rx" "${homes_bad} bad" \
       "$([ "$homes_bad" -eq 0 ] && echo PASS || echo FAIL)"; n=$((n+1))

  # .ssh perms
  local ssh_bad=0
  while IFS=: read -r u h; do
    [ -d "$h/.ssh" ] || continue
    p="$(stat -c '%a' "$h/.ssh" 2>/dev/null)"
    [ -n "$p" ] && [ "$p" != "700" ] && [ "$p" != "600" ] && ssh_bad=$((ssh_bad+1))
  done < <(awk -F: '($3>=1000){print $1":"$6}' /etc/passwd)
  emit users 16 HIGH ".ssh dirs are 700" "700" "$ssh_bad bad" \
       "$([ "$ssh_bad" -eq 0 ] && echo PASS || echo FAIL)"; n=$((n+1))

  # authorized_keys perms
  local ak_bad=0
  while IFS=: read -r u h; do
    [ -f "$h/.ssh/authorized_keys" ] || continue
    p="$(stat -c '%a' "$h/.ssh/authorized_keys" 2>/dev/null)"
    [ -n "$p" ] && [ "$p" != "600" ] && [ "$p" != "400" ] && ak_bad=$((ak_bad+1))
  done < <(awk -F: '($3>=1000){print $1":"$6}' /etc/passwd)
  emit users 17 HIGH "authorized_keys are 600" "600" "$ak_bad bad" \
       "$([ "$ak_bad" -eq 0 ] && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(find /home -name .rhosts -o -name .shosts 2>/dev/null | wc -l)"
  emit users 18 HIGH "No .rhosts files" "none" "$v found" \
       "$([ "$v" -eq 0 ] 2>/dev/null && echo PASS || echo FAIL)"; n=$((n+1))

  section_end "$n"
}

# =============================================================================
#  Services & Packages
# =============================================================================
check_services() {
  local n=0
  section services "Services & Packages"
  local v

  v="inactive"; svc_active unattended-upgrades && v="active"
  emit services 1 HIGH "Unattended upgrades active" "active" "$v" \
       "$([ "$v" = "active" ] && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(grep -h "Unattended-Upgrade" /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null | awk '{print $2}' | tr -d ';"')"
  emit services 2 HIGH "Auto-update configured" "\"1\"" "${v:-not configured}" \
       "$([ "$v" = "1" ] && echo PASS || echo FAIL)"; n=$((n+1))

  v="inactive"; svc_active fail2ban && v="active"
  emit services 3 CRITICAL "Fail2ban active" "active" "$v" \
       "$([ "$v" = "active" ] && echo PASS || echo FAIL)"; n=$((n+1))

  v="inactive"; svc_active auditd && v="active"
  emit services 4 HIGH "Auditd active" "active" "$v" \
       "$([ "$v" = "active" ] && echo PASS || echo FAIL)"; n=$((n+1))

  v="inactive"; svc_active rsyslog && v="active"
  emit services 5 HIGH "Rsyslog active" "active" "$v" \
       "$([ "$v" = "active" ] && echo PASS || echo FAIL)"; n=$((n+1))

  v="inactive"; svc_active apparmor && v="active"; [ -d /sys/kernel/security/apparmor ] && v="active"
  emit services 6 HIGH "MAC framework active" "active" "$v" \
       "$([ "$v" = "active" ] && echo PASS || echo FAIL)"; n=$((n+1))

  v="not installed"
  if [ -e /var/run/docker.sock ]; then
    v="$(stat -c '%a' /var/run/docker.sock 2>/dev/null)"
    [ "$v" = "660" ] && v="root:docker 660"
  fi
  emit services 7 HIGH "Docker socket perms" "root:docker 660" "$v" \
       "$([ "${v%% *}" = "root:docker" ] && echo PASS || echo FAIL)"; n=$((n+1))

  v="not exposed"; ss -tlnH 2>/dev/null | grep -q "0.0.0.0:2375" && v="0.0.0.0:2375"
  emit services 8 CRITICAL "Docker daemon not on 0.0.0.0:2375" "not exposed" "$v" \
       "$([ "$v" = "not exposed" ] && echo PASS || echo FAIL)"; n=$((n+1))

  v="no"
  if svc_active systemd-timesyncd || svc_active chrony || svc_active ntp || svc_active ntpd; then v="active"; fi
  emit services 9 MEDIUM "NTP sync active" "active" "$v" \
       "$([ "$v" = "active" ] && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(systemctl --failed --no-legend 2>/dev/null | wc -l)"
  emit services 10 MEDIUM "No failed services" "0" "$v unit(s)" \
       "$([ "$v" -eq 0 ] 2>/dev/null && echo PASS || echo FAIL)"; n=$((n+1))

  local sec=0
  if have apt-get && [ -d /var/lib/apt/lists ]; then
    sec="$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst')"
  fi
  emit services 11 HIGH "No pending security updates" "none" "$sec pending" \
       "$([ "$sec" -eq 0 ] 2>/dev/null && echo PASS || echo FAIL)"; n=$((n+1))

  v="no"; [ -f /run/reboot-required ] || [ -f /var/run/reboot-required ] && v="yes"
  emit services 12 HIGH "No reboot required" "not required" "$v" \
       "$([ "$v" = "no" ] && echo PASS || echo FAIL)"; n=$((n+1))

  section_end "$n"
}

# =============================================================================
#  File permissions
# =============================================================================
check_files() {
  local n=0
  section files "File Permissions"
  local v

  v="$(findmnt -no OPTIONS /tmp 2>/dev/null)"
  [ -z "$v" ] && v="$(awk '$2=="/tmp"{print $4}' /proc/mounts)"
  emit files 1 HIGH "/tmp nosuid" "nosuid" "${v:-not mounted}" \
       "$(printf '%s' "$v" | grep -q nosuid && echo PASS || echo FAIL)"; n=$((n+1))

  emit files 2 HIGH "/tmp nodev" "nodev" "${v:-not mounted}" \
       "$(printf '%s' "$v" | grep -q nodev && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(find / -xdev -type f -perm -4000 2>/dev/null | wc -l)"
  emit files 3 HIGH "No unexpected SUID binaries" "baseline" "$v found" \
       "$([ "$v" -le 30 ] 2>/dev/null && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(find / -xdev -type f -perm -0002 2>/dev/null | wc -l)"
  emit files 4 HIGH "No world-writable files" "0" "$v found" \
       "$([ "$v" -eq 0 ] 2>/dev/null && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null | wc -l)"
  emit files 5 MEDIUM "No world-writable dirs" "0" "$v found" \
       "$([ "$v" -eq 0 ] 2>/dev/null && echo PASS || echo FAIL)"; n=$((n+1))

  local crit=0
  for f in /etc/passwd /etc/shadow /etc/gshadow /etc/sudoers /etc/crontab; do
    [ -e "$f" ] || continue
    p="$(stat -c '%a' "$f" 2>/dev/null)"
    case "$f" in
      /etc/passwd) [ "$p" = "644" ] || crit=1 ;;
      /etc/shadow|/etc/gshadow) case "$p" in 640|600|000|400) ;; *) crit=1 ;; esac ;;
      *) case "$p" in 440|400|600) ;; *) crit=1 ;; esac ;;
    esac
  done
  emit files 6 HIGH "Critical file perms correct" "standard" "$crit bad" \
       "$([ "$crit" -eq 0 ] && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(find / -xdev \( -nouser -o -nogroup \) 2>/dev/null | wc -l)"
  emit files 7 MEDIUM "No unowned files" "0" "$v found" \
       "$([ "$v" -eq 0 ] 2>/dev/null && echo PASS || echo FAIL)"; n=$((n+1))

  section_end "$n"
}

# =============================================================================
#  Logging & Audit
# =============================================================================
check_logging() {
  local n=0
  section logging "Logging & Audit"
  local v

  v="inactive"; svc_active rsyslog && v="active"
  emit logging 1 HIGH "Rsyslog active" "active" "$v" \
       "$([ "$v" = "active" ] && echo PASS || echo FAIL)"; n=$((n+1))

  v="volatile"; [ -d /var/log/journal ] && v="persistent"
  emit logging 2 MEDIUM "Journal storage" "persistent" "$v" \
       "$([ "$v" = "persistent" ] && echo PASS || echo FAIL)"; n=$((n+1))

  v="inactive"; svc_active auditd && v="active"
  emit logging 3 HIGH "Auditd active" "active" "$v" \
       "$([ "$v" = "active" ] && echo PASS || echo FAIL)"; n=$((n+1))

  v=0; have auditctl && v="$(auditctl -l 2>/dev/null | wc -l)"
  emit logging 4 HIGH "Audit rules loaded" ">= 1 rule" "$v rules" \
       "$([ "${v:-0}" -ge 1 ] 2>/dev/null && echo PASS || echo FAIL)"; n=$((n+1))

  v="not found"; v="$(sysctl -n kernel.auditd_backlog_limit 2>/dev/null)"
  [ -z "$v" ] && v="not found"
  emit logging 5 MEDIUM "Audit backlog configured" "set" "$v" \
       "$([ "$v" != "not found" ] && echo PASS || echo FAIL)"; n=$((n+1))

  local mon=0
  if have auditctl; then
    mon="$(auditctl -l 2>/dev/null | grep -cE 'passwd|shadow|sudoers|sshd_config')"
  else
    mon="$(grep -rE '/etc/(passwd|shadow|sudoers)' /etc/audit/rules.d/ 2>/dev/null | wc -l)"
  fi
  emit logging 6 HIGH "Critical files audited" ">= 2 files" "$mon monitored" \
       "$([ "${mon:-0}" -ge 2 ] 2>/dev/null && echo PASS || echo FAIL)"; n=$((n+1))

  v="no"; [ -d /etc/logrotate.d ] && v="configured"
  emit logging 7 MEDIUM "Logrotate configured" "yes" "$v" \
       "$([ "$v" = "configured" ] && echo PASS || echo FAIL)"; n=$((n+1))

  v="disabled"; grep -qsE "^\s*compress" /etc/logrotate.conf /etc/logrotate.d/* 2>/dev/null && v="enabled"; true
  emit logging 8 LOW "Logrotate compression" "compress" "$v" \
       "$([ "$v" = "enabled" ] && echo PASS || echo FAIL)"; n=$((n+1))

  v="$(grep -E "^\s*rotate" /etc/logrotate.conf 2>/dev/null | awk '{print $2}')"
  emit logging 9 LOW "Log retention >= 4" ">= 4" "${v:-unknown}" \
       "$([ -n "$v" ] && [ "$v" -ge 4 ] 2>/dev/null && echo PASS || echo FAIL)"; n=$((n+1))

  v="no"; grep -rhqE "@(host|server)" /etc/rsyslog.d/ /etc/rsyslog.conf 2>/dev/null && v="configured"
  emit logging 10 MEDIUM "Remote syslog" "@server configured" "$v" \
       "$([ "$v" = "configured" ] && echo PASS || echo FAIL)"; n=$((n+1))

  v="missing"
  [ -e /var/log/auth.log ] || [ -e /var/log/secure ] && v="exists"
  emit logging 11 HIGH "Auth log exists" "auth.log/secure" "$v" \
       "$([ "$v" = "exists" ] && echo PASS || echo FAIL)"; n=$((n+1))

  section_end "$n"
}

# =============================================================================
#  Runner / summary
# =============================================================================
banner() {
  [ "$JSON_MODE" -eq 1 ] || [ "$QUIET" -eq 1 ] && return 0
  printf '%s\n' "$BD==============================================================$N"
  printf '%s\n' "$BD          Linux Hardening Assessment Tool (Bash)$N"
  printf '%s\n' "$BD          Security Posture Scanner v2.0$N"
  printf '%s\n' "$BD==============================================================$N"
  printf '  Target: %s\n  Time:   %s\n' "$(hostname 2>/dev/null || echo unknown)" "$(date '+%Y-%m-%d %H:%M:%S')"
}

run_cats() {
  local cat
  for cat in "${SELECTED[@]}"; do
    case "$cat" in
      ssh) check_ssh ;;
      firewall) check_firewall ;;
      kernel) check_kernel ;;
      users) check_users ;;
      services) check_services ;;
      files) check_files ;;
      logging) check_logging ;;
      *) echo "unknown category: $cat" >&2 ;;
    esac
  done
}

sev_bar() {  # sev_bar <pass> <total>
  local p="$1" t="$2"; [ "$t" -eq 0 ] && { printf '  '; return; }
  local filled=$(( p * 10 / t )); [ "$filled" -lt 1 ] && [ "$p" -gt 0 ] && filled=1
  printf '%s' "$BD"
  printf '█%.0s' $(seq 1 "$filled" 2>/dev/null)
  printf '░%.0s' $(seq 1 $((10 - filled)) 2>/dev/null)
  printf '%s  %d/%d passed\n' "$N" "$p" "$t"
}

grade_of() {  # grade_of <score>
  local s="$1"
  if   [ "$s" -ge 90 ]; then echo "A"
  elif [ "$s" -ge 75 ]; then echo "B"
  elif [ "$s" -ge 60 ]; then echo "C"
  elif [ "$s" -ge 50 ]; then echo "D"
  else echo "F"; fi
}

report_doc() {  # assemble the full JSON report (v2.0)
  local cat= r= arr= line= bycat=""
  for cat in ssh firewall kernel users services files logging; do
    arr="["
    for r in "${ROWS[@]}"; do
      [ "${r%$'\t'*}" = "$cat" ] && arr+="${r#*$'\t'},"
    done
    arr="${arr%,}]"
    [ -n "$bycat" ] && bycat+=","
    bycat+="$(printf '\n    "%s": %s' "$cat" "$arr")"
  done
  cat <<EOF
{
  "tool": "linux_hardening_check.sh",
  "version": "2.0",
  "hostname": "$(hostname 2>/dev/null || echo unknown)",
  "timestamp": "$(date -Iseconds)",
  "elapsed_seconds": $(( $(date +%s) - START )),
  "score": $SSCORE,
  "grade": "$(grade_of "$SSCORE")",
  "total": $TOTAL,
  "passed": $PASS,
  "failed": $FAIL,
  "by_severity": {
    "CRITICAL": { "passed": $S_CR_P, "total": $S_CR_T },
    "HIGH":     { "passed": $S_HI_P, "total": $S_HI_T },
    "MEDIUM":   { "passed": $S_ME_P, "total": $S_ME_T },
    "LOW":      { "passed": $S_LO_P, "total": $S_LO_T }
  },
  "categories": {$bycat
  }
}
EOF
}

summary() {
  local score=0
  if [ "$TOTAL" -gt 0 ]; then
    score=$((PASS*100/TOTAL))
    local rem=$((PASS*100 % TOTAL)); [ "$rem" -ge 5 ] && score=$((score+1))
  fi
  SSCORE=$score

  if [ -n "$OUTFILE" ]; then
    report_doc > "$OUTFILE"
    printf 'Report written: %s\n' "$OUTFILE"
  fi
  if [ "$JSON_MODE" -eq 1 ]; then
    report_doc
    return 0
  fi

  local grade="F"
  [ "$score" -ge 90 ] && grade="A"
  [ "$score" -ge 75 ] && grade="B"
  [ "$score" -ge 60 ] && grade="C"
  [ "$score" -ge 50 ] && grade="D"
  local col="$R"; [ "$score" -ge 60 ] && col="$Y"; [ "$score" -ge 90 ] && col="$G"

  printf '\n%s\n' "$BD==============================================================$N"
  printf '%s\n' "$BD                    ASSESSMENT SUMMARY$N"
  printf '%s\n' "$BD==============================================================$N"
  printf '  %sOverall Score:  %s%d/100  [%s]%s\n' "$BD" "$col" "$score" "$grade" "$N"
  printf '\n  Results:  %d passed | %d failed | %d total\n\n' "$PASS" "$FAIL" "$TOTAL"

  printf '  By Severity:\n'
  printf '    CRITICAL  '; sev_bar "$S_CR_P" "$S_CR_T"
  printf '    HIGH      '; sev_bar "$S_HI_P" "$S_HI_T"
  printf '    MEDIUM    '; sev_bar "$S_ME_P" "$S_ME_T"
  printf '    LOW       '; sev_bar "$S_LO_P" "$S_LO_T"

  EXIT=0
  [ -n "$SEV_FILTER" ] && return 0
  if [ "$S_CR_P" -lt "$S_CR_T" ]; then EXIT=3
  elif [ "$S_HI_P" -lt "$S_HI_T" ]; then EXIT=2
  elif [ "$S_ME_P" -lt "$S_ME_T" ]; then EXIT=1
  fi
}

# ---- main -------------------------------------------------------------------
banner
[ ${#SELECTED[@]} -eq 0 ] && SELECTED=(ssh firewall kernel users services files logging)
run_cats
summary
exit "$EXIT"