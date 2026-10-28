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

## Known limits (be honest with your auditors)
- **The live database is not encrypted.** Python's stdlib has no vetted cipher and hand-rolled crypto would be a vulnerability. Use full-disk/LUKS encryption on the host. Only *backups* are encrypted.
- **Audit chain is tamper-evident, not tamper-proof.** Anyone who can rewrite the whole DB can rebuild the chain. Anchor the head hash externally: run `radar audit verify` on a schedule and store the printed head elsewhere; later check with `--head`.
- **Tokens are shared secrets over plain HTTP on localhost.** Fine for one machine; not acceptable across a network (needs TLS and SSO).
- **Backup cipher mode is unauthenticated (CBC).** Mitigated by integrity and audit-chain checks on restore, but GCM would be better than `openssl enc` allows.
- **Lockout is in-memory** and resets on restart; per-IP, which is meaningless behind a proxy.
- **No third-party security review or penetration test has been done.** Treat this as hardened prototype code until one is.
- **Credit-card detection** finds numbers in one digit run (spaces/dashes allowed). A card followed immediately by other digits in the same run can be missed.

## Operating checklist
1. Encrypt the disk. 2. Set `RADAR_USERS` with long random tokens (≥ 16 chars recommended). 3. Cron `radar backup` and `radar audit verify`, saving the head hash off-box. 4. Review `radar audit show` weekly. 5. Run `radar purge` on your retention schedule.
