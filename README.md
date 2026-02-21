# Ebooks Library - Django Backend Foundation

Implements SYSTEM 1-9 with authentication, content management, secure delivery, discovery, and operations security.

## SYSTEM 9: Security, Monitoring & Automation
- HTTPS-first hardening in settings:
  - secure cookies
  - SSL redirect
  - HSTS enabled
  - proxy SSL header support
- Expanded rate-limiting coverage and security event logging for:
  - login failures / lockouts
  - code entry abuse
  - review abuse
  - password reset abuse
- Security and monitoring models:
  - `SecurityEventLog`
  - `SystemErrorLog`
  - `BackupRecord`
  - `SystemSetting` (maintenance + notifications + controls)
- Admin command-center APIs:
  - dashboard overview + charts payload
  - maintenance mode toggles (downloads/code entry switches)
  - manual backup trigger
  - cleanup run (expired codes + old logs retention)
  - CSV exports (downloads, code usage, security activity)
- Maintenance mode behavior:
  - blocks code entry/download flows for non-admin users when enabled
  - keeps admin access functional
  - logs maintenance actions
- Cleanup automation endpoint supports pruning old logs (`LOG_RETENTION_DAYS` default).

## SYSTEM 9 Endpoints
- `GET /ebooks/admin/dashboard/`
- `POST /ebooks/admin/maintenance/`
- `POST /ebooks/admin/backups/trigger/`
- `POST /ebooks/admin/cleanup/run/`
- `GET /ebooks/admin/exports/?type=downloads|code_usage|security`

## Notes
- Runtime Django checks require `django` package installed in this environment.
