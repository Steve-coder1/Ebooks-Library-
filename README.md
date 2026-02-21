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


## Local Development (Android / Pydroid)
If you run with `python manage.py runserver` on Android and see browser errors like `ERR_SSL_PROTOCOL_ERROR` or Django logs saying:
- `You're accessing the development server over HTTPS, but it only supports HTTP.`

this is usually browser-side HTTPS auto-upgrade (HSTS / Always use secure connections), not a Django crash.

Recommended local setup:
- Keep HTTPS forcing disabled (default in this repo).
- Run: `python manage.py runserver 127.0.0.1:8000`
- Open exactly: `http://127.0.0.1:8000` (not `https://`, and avoid `localhost` if your browser upgrades it).
- If your browser still upgrades, use an incognito/private tab or clear HSTS/secure-site state for localhost.

Explicit HTTPS opt-in knobs:
- `DJANGO_FORCE_HTTPS=1` enables secure cookies + SSL redirect + HSTS.
- In `DEBUG=True`, also set `DJANGO_FORCE_HTTPS_IN_DEBUG=1` to prevent accidental HTTPS forcing in local dev.
