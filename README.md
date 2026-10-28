# Shadow-AI Radar

[![tests](https://github.com/Zahid9966/shadow-ai-radar/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Zahid9966/shadow-ai-radar/actions/workflows/ci.yml)

Employees paste code, customer data and credentials into consumer AI tools the company never vetted.
Shadow-AI Radar reads egress-proxy logs and answers: **who uses which AI tools, how risky is it, and what leaked?**

| Discipline | Where |
|---|---|
| Data engineering | `pipeline.py`: bronze → silver → gold medallion on SQLite, schema/timestamp/dedupe data-quality rejects, idempotent rebuild |
| Cybersecurity | `detectors.py`: secrets, SSN, Luhn-validated cards, entropy tokens; redact-before-store; `catalog.py`: policy status + discovery of unknown AI tools |
| Data analysis | `analytics.py`: robust median/MAD volume anomalies vs department peers, adoption tracking, risk scoring by service × data sensitivity |
| AI engineering | `model.py`: prompt-sensitivity classifier (public/internal/confidential/source_code), feeds risk score |

## Run
```bash
python3 -m radar run --rebuild        # demo: generate, ingest, detect, report
python3 -m radar serve --allow-open    # demo only; real use needs RADAR_USERS (serve refuses otherwise)
python3 -m radar alerts --status open # list; `ack <id> resolved --note ...` to close
python3 -m radar triage <id>          # summary + next steps (offline by default; optional AI summary: see docs/PRIVACY.md)
python3 -m radar export               # out/blocklist.txt (proxy) + out/siem_alerts.jsonl
python3 -m radar watch --interval 30  # continuous ingest+detect
python3 -m radar --policy config/policy.json run   # tune catalog/thresholds without code changes
```
```bash
python3 -m radar convert squid access.log out/proxy.jsonl --identity hr.csv   # or: convert csv export.csv ...
python3 -m radar identity hr.csv        # managers appear on alerts
python3 -m radar label -n 50            # label least-confident prompts (active learning)
python3 -m radar eval                   # classifier precision/recall on eval/test.jsonl
python3 -m radar train labels.jsonl --save out/model.json && python3 -m radar --model out/model.json run
python3 -m radar purge --before 2026-07-01
RADAR_ANALYST_TOKEN=... RADAR_VIEWER_TOKEN=... python3 -m radar serve   # then open /?token=...
```
```bash
RADAR_USERS="alice=analyst:<long-token>;bob=viewer:<long-token>" python3 -m radar serve   # named, audited users
python3 -m radar audit show            # who did what;  `audit verify` checks the hash chain
RADAR_BACKUP_PASSPHRASE=... python3 -m radar backup --to out/radar.bak.enc   # `restore` verifies before installing
```
```bash
RADAR_PSEUDO_KEY=<24+ chars> python3 -m radar --logs out/proxy.jsonl run   # store pseudonyms, not names
python3 -m radar dsr export alice     # data-subject access;  `dsr erase alice --yes` after DPO approval
python3 -m radar doctor               # security/privacy posture (PASS/WARN/FAIL)
python3 -m radar audit anchor         # then copy out/audit_anchors.txt off-box;  `audit verify --against` later
python3 -m radar evidence             # auditor-ready snapshot in out/evidence/<date>/
```
```bash
python3 -m radar training start && python3 -m radar training score   # analyst practice with a hidden answer key
python3 -m radar export-csv                    # alerts.csv + audit_log.csv for auditors
python3 -m radar watch --notify                # desktop/terminal popup for new critical/high alerts
python3 -m radar schedule --env-file ~/.config/radar.env   # writes systemd units + cron lines to out/schedule/ (installs nothing)
```
Overview of the whole project: [docs/PROJECT_SUMMARY.md](docs/PROJECT_SUMMARY.md) (also as PDF and Word; rebuild with `python3 tools/build_docs.py`). Plan and status: [ROADMAP.md](ROADMAP.md). Tool security and limits: [docs/SECURITY.md](docs/SECURITY.md). Compliance mapping and gaps: [docs/COMPLIANCE.md](docs/COMPLIANCE.md). Governance: [docs/PRIVACY.md](docs/PRIVACY.md). Pilot plan: [docs/PILOT.md](docs/PILOT.md).

Original quick start:
```bash
python3 -m radar            # synthetic demo -> out/report.html
python3 -m radar --logs my.jsonl
python3 -m unittest discover tests
```
Zero dependencies (Python 3.10+ stdlib only).

## Scaling (local)
Measured on 8 cores: ~19k events/s, 255k events in ~13 s, analysis in <1 s. Re-runs are free: ingest is incremental
(byte-offset checkpoint) and crash-safe (one transaction per 5k-line chunk). `python3 bench/bench.py 1500` reproduces this.
- `enrich_chunk()` is a pure function and the unit of parallelism (process pool).
- Local ceiling: one SQLite writer (~19k ev/s; comfortable into the tens of millions of rows). `radar purge` keeps the DB small.
- `--rebuild` reprocesses from scratch, `--workers N` caps CPU use.

## Log format (JSONL, one event per line)
`event_id, ts (ISO), user, dept, host, bytes_out, bytes_in, prompt (optional; from TLS-inspecting proxy or browser extension)`

## Importing historical logs
Retention (default 90 days) runs on every `--logs` run and will expire old events immediately. For a one-off historical
analysis copy `config/policy.json`, set `"retention_days": 0`, and pass `--policy`. Squid native logs carry no request size, so
upload-volume alerts are blind unless you add `%>st` to the Squid `logformat`; shadow-AI discovery by domain still works.

## Honest limitations
- Demo data is synthetic with planted incidents. The classifier is bootstrapped on templated text; it scores 80% on a fresh synthetic held-out set but only **62% on 40 real WildChat prompts (worse than guessing "public")**, so it is advisory and down-weighted to 35% in risk scores until you train your own (`docs/REAL_DATA_TEST.md`). Secret/PII regex detection does not depend on it. Train on labelled, consented prompts (`radar train`) and re-measure (`radar eval`) before relying on it.
- Content inspection needs legal/HR sign-off (works council, privacy law). Redaction-before-storage is built in for that reason.
- Naive Bayes is a deliberately swappable baseline; replace `model.py` with an embedding or LLM classifier behind the same `predict()` interface.

## License
MIT, see [LICENSE](LICENSE). This is a prototype that has not been validated on real corporate traffic or independently security-reviewed: read [docs/SECURITY.md](docs/SECURITY.md) and [ROADMAP.md](ROADMAP.md) before relying on it.
