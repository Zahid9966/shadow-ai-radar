# Shadow-AI Radar: Roadmap & Build Plan

Goal: a tool a security/GRC team can run daily to see, triage and *act on* unsanctioned AI usage and data leakage.
Scope: **local only**. Everything runs on one machine with the Python standard library; no cloud components.

## Phase 1: Detection core  ✅ done
Ingest → clean → enrich → detect → HTML report. Parallel, incremental, crash-safe (~20k events/s). Synthetic data with planted incidents; tests prove recall and zero false positives on them.

## Phase 2: Operable product (local)  ✅ done (13 tests green)
A detector nobody can triage or tune is a toy. This phase makes it something a team can work from.

| # | Deliverable | Why a company needs it | Done when |
|---|---|---|---|
| 2.1 | **Policy as config** (`config/policy.json`): catalog, status weights, thresholds | Security tunes rules without editing code | `--policy` overrides apply in workers too; test proves it |
| 2.2 | **Alert lifecycle**: stable IDs, open/ack/resolved/false_positive, notes, reopen on recurrence | Alerts must be owned and closed, with an audit trail | status survives re-runs; resolved alert reopens if it recurs |
| 2.3 | **Enforcement export**: proxy blocklist + SIEM JSONL | Detection is only valuable if it feeds blocking and the SIEM | files generated; blocklist excludes sanctioned tools |
| 2.4 | **Live dashboard** (`radar serve`): localhost-only, triage buttons, `/api/alerts` | Day-to-day working surface | ack from the browser persists; rejects foreign Host/Origin |
| 2.5 | **Watch mode** (`radar watch`) | Near-real-time instead of manual runs | picks up appended log lines each cycle |
| 2.6 | **AI triage summaries** (`radar triage ID`): Claude if `ANTHROPIC_API_KEY` set, deterministic fallback otherwise; only redacted evidence is sent | Cuts analyst time per alert | works offline; never sends raw secrets |
| 2.7 | **Per-user risk profile** | Targeted coaching rather than blanket blocking | top-risk users table in report |

Exit criteria: all tests green, a full demo walk-through (run → triage → export) works from the CLI.

## Phase 3: Hardening (local)  ✅ done (20 tests green)
| # | Deliverable | Status / evidence |
|---|---|---|
| 3.1 | Log adapters → common schema: `radar convert squid\|csv` (column aliases cover common Zscaler/Palo Alto-style exports) | done; Squid native has no request size, so volume-exfil is blind there unless `%>st` is added to the logformat |
| 3.2 | Measured classifier: `radar eval`, held-out sets in `eval/` | **80% accuracy on a fresh 40-prompt test set; confidential recall only 50%**. Dev set (tuned against) scores 97%, so ignore it |
| 3.3 | Train on real labels: `radar train labels.jsonl` → `--model` | done; save/load round-trip tested |
| 3.4 | HR/IdP join: `radar identity hr.csv`; managers on alerts | done |
| 3.5 | Retention: `radar purge --before DATE` (alerts kept as audit trail) | done |
| 3.6 | Dashboard auth: analyst/viewer tokens (`RADAR_ANALYST_TOKEN`, `RADAR_VIEWER_TOKEN`) | done; viewers are read-only |
| 3.7 | Privacy pack: `docs/PRIVACY.md` (DPIA-style template) | done; needs Legal/HR to complete |

**Gate before any real pilot:** collect ≥500 labelled real prompts (with consent/approval), retrain, and get confidential recall ≥ 0.9 on a held-out set. Until then the regex detectors (secrets/PII) are the reliable signal and the classifier is advisory.

## Phase 3.5: Pilot readiness  ✅ tooling done (21 tests green); the pilot itself needs real data
- `radar label` active-learning labeller (least-confident first, works on redacted snippets) → `radar train` → `radar eval` closes the loop to the 500-label gate.
- `docs/PILOT.md`: 4-week shadow-mode runbook with go/no-go metrics.
- Packaging: `pyproject.toml` installs a `radar` console script.
- Fixed: bare-`Z` timestamps rejected on Python 3.10.

**Blocked on you:** real proxy logs, HR export, Legal/HR sign-off. Everything else for a pilot is in place.

## Phase 4: Security hardening of the tool itself  ✅ done (31 tests green)
- **Found and fixed a real DoS:** a ~10 KB crafted prompt could hang the credit-card detector for minutes. Now linear and windowed; adversarial tests guard it.
- Hash-chained audit log + `radar audit show|verify [--head]`; named users (`RADAR_USERS`) so every action is attributed.
- Login lockout, owner-only file permissions (`umask 077`), encrypted backup/restore (`radar backup|restore`).
- Threat model and honest limits: `docs/SECURITY.md`. Biggest remaining gaps: live DB not encrypted (use disk encryption), no external pen test, no TLS/SSO.

## Phase 4.5: Secure by default & compliance support  ✅ done (44 tests green)
- Secure defaults: `serve` refuses to start without named users (`--allow-open` for demos); tokens ≥ 16 chars; 90-day retention on by default.
- Privacy by design: optional keyed pseudonymization of user IDs (`RADAR_PSEUDO_KEY`), audited `reveal`, no email stored when pseudonymizing.
- Data-subject rights: `radar dsr export|erase`; audit entries reference subjects by one-way hash only.
- Audit: off-box anchors (`audit anchor`, `verify --against`), log-injection sanitising; blocklist hostname validation; extra security headers.
- `radar doctor` (posture, never claims what it can't verify) and `radar evidence` (dated auditor folder with code-integrity manifest).
- `docs/COMPLIANCE.md`: GDPR / SOC 2 / ISO 27001 mapping, **gap list the org must close**, Art. 30 record, incident runbook, audit cadence.

**Compliance status, stated plainly:** supports compliance; is not itself compliant or certified. Blocking items before any real-data pilot: signed DPIA, lawful basis + employee notice, disk encryption, and an independent pen test.

## Phase 4.7: Real-data test (WildChat, 406 real prompts)  ✅ done (72 tests green)
Found and fixed: 100% of critical alerts were false positives (URL slugs flagged as secrets), Squid user misattribution, and an unreliable classifier now down-weighted. Details and what the data could NOT show: `docs/REAL_DATA_TEST.md`.

## Phase 4.8: Test-suite stability  ✅ done (73 tests green)
A stress loop (6 test modules in parallel, repeated) found two real problems:
- **ReDoS regression I had introduced:** the URL-masking regex from the WildChat fix had an unbounded scheme, making a crafted 200 KB prompt cost 6-9 s CPU. Fixed (bounded scheme + substring guards that skip regexes that cannot match). The old wall-clock test was replaced by a CPU-time test calibrated against harmless text (fixed code ~3x, old bug 20-30x; verified by swapping the old regex back in).
- **Test temp-dir leak:** tests left ~150-200 MB per full run in a RAM-backed `/tmp` and eventually filled it. `tests/_cleanup.py` now removes them at exit (measured growth: 0 MB).
Verified after the fixes: full suite 73/73; `test_security` 8/8 under parallel CPU load; the other five modules 15/15. One unexplained failure earlier (output not captured) is very likely the same timing test, but that was never directly confirmed.

## Phase 5: Local polish  ✅ done (62 tests green)
| Item | Delivered |
|---|---|
| Trend charts | Week-over-week table + bars in the report; risk normalised **per active day** so partial weeks don't mislead |
| CSV for audits | `radar export-csv` → `alerts.csv` + `audit_log.csv` (with hashes); formula-injection safe |
| Scheduling | `radar schedule` generates hardened systemd units (watch + weekly anchor/verify/backup/evidence/doctor), cron lines, env template. **Generates only; you install** |
| Notifications | `watch --notify`: desktop via `notify-send` (argument list, no shell), terminal fallback, once per alert, `notifications.log` evidence |
| New detector | `OFF_HOURS`: activity at hours rare for *that user's own history*; correlated into an existing alert for the same user/day instead of double-alerting |
| Analyst training | `radar training start|score`: 8 hidden cases (6 incidents, 2 realistic false positives, 1 decoy), scored with explanations revealed only after you decide |

Known limits: off-hours uses the timestamps as logged (no per-user timezone); needs ≥ 20 prior AI requests per user; trend needs several weeks of data to mean much; notifications need a desktop session (`notify-send`); the schedule units are validated with `systemd-analyze` but have not been run as a live service.

## Phase 5.1: Document tooling  ✅ done (87 tests green)
`tools/build_docs.py` rebuilds the PDF (headless Chrome/Chromium) and Word (`.docx`, written directly, stdlib only) versions of any Markdown file, including `docs/PROJECT_SUMMARY.md`. The Word output is verified after every build with an exact alphanumeric comparison against the source, so lost, duplicated or reordered content fails the build. Limits: the `.docx` has never been opened in Word or LibreOffice (neither is installed here), so appearance is unchecked; the Markdown subset is the one this project uses.

## Risks
- Prompt inspection is legally sensitive → redact-before-store stays non-negotiable; get HR/legal sign-off before Phase 3 pilots.
- Classifier trained on synthetic text → do not claim real-world accuracy until Phase 3 measurement.
- Alert fatigue → lifecycle + dedupe + tunable thresholds are in Phase 2 for this reason.
