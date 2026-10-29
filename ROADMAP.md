# Shadow-AI Radar: Features & Roadmap

Goal: a tool a security/GRC team can run daily to see, triage and act on unsanctioned AI usage and data leakage.
Scope: local only. Everything runs on one machine with the Python standard library; no cloud components.

## Capabilities

### Detection core
Ingest → clean → enrich → detect → HTML report. Parallel, incremental and crash-safe (~20k events/s). Five alert types: `SECRET_LEAK`, `PII_LEAK`, `EXFIL_VOLUME`, `SHADOW_ADOPTION`, `OFF_HOURS`.

### Operations
| Area | What it provides |
|---|---|
| Policy as config | `config/policy.json`: tool catalog, status weights, thresholds; `--policy` overrides apply in worker processes too |
| Alert lifecycle | Stable IDs; open / ack / resolved / false positive; notes; reopen on recurrence |
| Enforcement export | Proxy blocklist (sanctioned tools excluded) and SIEM-ready JSONL |
| Dashboard | `radar serve`: localhost-only, analyst/viewer roles, triage actions, `/api/alerts`, Host/Origin checks |
| Watch mode | `radar watch` picks up appended log lines each cycle; `--notify` for desktop notifications |
| AI triage | `radar triage ID`: optional AI summary when an API key is configured, deterministic offline fallback; only redacted evidence is sent |
| Risk profiles | Per-user risk table; week-over-week trends normalised per active day |
| Scheduling | `radar schedule` generates hardened systemd units, cron lines and an env template (generates only; you install) |
| Audit exports | `radar export-csv` → `alerts.csv` + `audit_log.csv` (with hashes; formula-injection safe) |
| Analyst training | `radar training start\|score`: eight hidden cases scored with explanations revealed after you decide |

### Data & model
- Log adapters to a common schema: `radar convert squid|csv` (column aliases cover common Zscaler / Palo Alto-style exports). Squid's native format has no request size, so add `%>st` to the `logformat` to enable upload-volume alerts.
- HR/IdP join: `radar identity hr.csv` adds managers to alerts.
- Classifier loop: `radar label` (active learning, least-confident first, redacted snippets) → `radar train labels.jsonl` → `radar eval` against held-out sets in `eval/`.
- Retention: `radar purge --before DATE`; 90-day retention on by default.

### Security & privacy
- Named users (`RADAR_USERS`), login lockout, owner-only file permissions, hash-chained audit log (`radar audit show|verify`, off-box anchors), encrypted backup/restore, log-injection sanitising.
- Secure by default: `serve` refuses to start without named users (`--allow-open` for demos); tokens ≥ 16 characters.
- Privacy by design: redact-before-store, optional keyed pseudonymization (`RADAR_PSEUDO_KEY`) with audited `reveal`, data-subject export/erase (`radar dsr`).
- `radar doctor` (posture check) and `radar evidence` (dated auditor folder with a code-integrity manifest).
- Documents: `docs/SECURITY.md` (threat model), `docs/PRIVACY.md` (DPIA-style template), `docs/COMPLIANCE.md` (GDPR / SOC 2 / ISO 27001 control mapping, Art. 30 record, incident runbook), `docs/PILOT.md` (four-week shadow-mode runbook).

### Tooling
`tools/build_docs.py` rebuilds the PDF (headless Chrome/Chromium) and Word (`.docx`, written directly with the standard library) versions of any Markdown file, and verifies the Word output against the source.

## Roadmap
1. **Pilot** on one department's real proxy logs in shadow mode (`docs/PILOT.md`).
2. **Classifier** trained on ~500 labelled prompts; target ≥ 90% accuracy and ≥ 90% confidential recall on a held-out set.
3. **Privacy sign-off:** complete `docs/PRIVACY.md`, establish lawful basis, notify employees.
4. **Hardening for network deployment:** TLS termination and SSO, encrypted live database, independent penetration test.
5. **Integrations:** native connectors for additional proxy and CASB log formats; per-user timezone handling for the off-hours detector.
6. **Production scheduling:** install and monitor the generated units; store audit anchors off-box.

## Design principles
- Prompt inspection is legally sensitive: redact-before-store stays non-negotiable.
- Regex detectors (secrets, PII) are the primary signal; the classifier is advisory until trained on real labels.
- Alert fatigue is a first-class concern: lifecycle, de-duplication and tunable thresholds.
