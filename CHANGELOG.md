# Ochyro - Changelog

All notable changes to this project. Dates follow the commit history.

## [1.0.0] - 2026-09-07 .. 2026-09-11

### 2026-09-07
- Add `linux_hardening_check.sh` - ~96-check read-only Linux security scanner with `/100` score, severity filter and JSON output.
- Add `windows_hardening_check.ps1` - ~67-check read-only Windows security scanner (firewall, users, services, registry, smb, audit, defender).

### 2026-09-08
- Add `linux_harden.sh` - interactive Linux hardener with menu/wizard/`--apply-all`/`--dry-run`, timestamped backups and auto-generated rollback. Safeguards: `sshd -t` validation, nftables auto-restore, SSH key check before disabling password auth.

### 2026-09-09
- Add `windows_harden.ps1` - interactive Windows hardener (admin required) with backup/rollback via `reg export` and file copy. Modules: firewall, accounts, registry, defender, services, audit.

### 2026-09-10
- Add `deploy_harden.sh` - remote deploy helper; target/user/port/password supplied at runtime, never hardcoded.
- Document full usage in `README.md`.

### 2026-09-11
- Add changelog; final polish pass.