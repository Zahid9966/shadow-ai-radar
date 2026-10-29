# Security Notes for Shadow-AI Radar itself

A tool that reads employee prompts is itself a high-value target. This documents what is defended, and what is not.

## Implemented (each has a test in `tests/test_security.py` / `test_phase3.py`)
| Threat | Control |
|---|---|
| Crafted prompt stalls ingestion (ReDoS) | Linear card matcher, bounded regex quantifiers, 4 KB scan windows; adversarial 200 KB inputs finish in ~1 s (found and fixed during hardening: one input used to hang for minutes) |
| Secrets/PII persisted | Redact-before-store; only ≤160-char redacted snippets reach disk |
| Unauthorised dashboard access | Localhost bind, named users with analyst/viewer roles, constant-time token compare, HttpOnly SameSite cookie, per-client lockout (5 failures → 60 s) |
| CSRF / DNS rebinding | Host and Origin allow-list, CSP, `Cache-Control: no-store` |
| Insider changes or hides actions | Hash-chained audit log of views, API reads, status changes, denied writes, auth failures, exports, purges, backups, restores, identity loads |
| Other local users reading data | `umask 077`: `out/` is 0700, every file 0600 |
| Backup theft | `radar backup` → AES-256-CBC + PBKDF2 (600k) via system OpenSSL; passphrase via env, never argv |
| Corrupt or tampered restore | Restore verifies SQLite integrity and the audit chain before installing, refuses to overwrite without `--force` |

## Added in the compliance pass
Secure-by-default dashboard (refuses to start without users, tokens ≥ 16 chars), pseudonymization, DSR export/erase, automatic 90-day retention,
off-box audit anchors, log-injection sanitising, blocklist hostname validation, `doctor` and `evidence`. See `docs/COMPLIANCE.md`.

## Deployment requirements
- **Encrypt the host disk.** The live database is not encrypted by the tool (the standard library has no vetted cipher); backups are encrypted.
- **Anchor the audit chain externally.** The chain is tamper-evident: run `radar audit verify` on a schedule, store the printed head hash elsewhere, and check later with `--head`.
- **Serve the dashboard on localhost only.** Token logins over plain HTTP suit a single machine; for network access put it behind TLS and SSO.
- **Backups** use AES-CBC through `openssl enc`, with SQLite-integrity and audit-chain checks on restore.
- **Login lockout** is per-IP and in-memory; behind a reverse proxy, enforce rate limits at the proxy.
- **Independent review:** commission a penetration test before production use.
- **Card detection** matches numbers within a single digit run (spaces and dashes allowed).

## Operating checklist
1. Encrypt the disk. 2. Set `RADAR_USERS` with long random tokens (≥ 16 chars recommended). 3. Cron `radar backup` and `radar audit verify`, saving the head hash off-box. 4. Review `radar audit show` weekly. 5. Run `radar purge` on your retention schedule.
