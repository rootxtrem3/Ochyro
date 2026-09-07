# hardening-tools

Security posture scanners and interactive hardening scripts for Linux and Windows.

## Scanners (read-only)

| Tool | Platform | Description |
|------|----------|-------------|
| `linux_hardening_check.sh` | Linux (Debian/Ubuntu, systemd) | ~96 read-only security checks, score `/100` |
| `windows_hardening_check.ps1` | Windows (PowerShell) | ~67 read-only security checks, score `/100` |

## Hardening scripts (interactive, backups + rollback)

| Tool | Platform | Description |
|------|----------|-------------|
| `linux_harden.sh` | Linux | Menu/wizard/`--apply-all`, timestamped backups, auto rollback |
| `windows_harden.ps1` | Windows | Menu/wizard/`--apply-all`, timestamped backups, auto rollback |
| `deploy_harden.sh` | Linux | Deploy a hardener to a remote host (target passed as argument) |

## Usage

### Scanners

```bash
# Linux scanner
bash linux_hardening_check.sh              # all categories
bash linux_hardening_check.sh -m ssh,fw    # specific categories
bash linux_hardening_check.sh -j           # JSON output

# Windows scanner (PowerShell 5.1+)
powershell -ExecutionPolicy Bypass -File windows_hardening_check.ps1
```

### Hardening

```bash
# Interactive menu (run as root / admin)
bash linux_harden.sh

# Guided, apply everything unattended
bash linux_harden.sh --apply-all

# Preview what would change (no writes)
bash linux_harden.sh --dry-run
```

Every change is recorded; a rollback script is generated alongside the
timestamped backups under `~/.harden-backups/`.

## Design principles

- Read-only scanners never modify the system.
- No target addresses, credentials, or environment-specific values are
  hardcoded; anything host-specific is discovered or prompted.
- Configuration files are backed up before modification.
- Scripts are idempotent (safe to re-run).