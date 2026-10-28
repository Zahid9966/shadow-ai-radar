# Compliance Support Guide

**What this is:** a map from Shadow-AI Radar's features to common frameworks, plus the evidence it can produce.
**What this is not:** a certification, a legal opinion, or proof that your organisation is compliant. Compliance is a property of
your organisation's processes, contracts and people; software only supports it. Have your DPO/counsel and auditor confirm every row.
Run `radar doctor` for live posture and `radar evidence` for a dated evidence folder.

## 1. Control mapping (what the tool provides)
| Requirement | GDPR | SOC 2 (TSC) | ISO/IEC 27001:2022 Annex A | Feature · evidence |
|---|---|---|---|---|
| Data minimisation | Art. 5(1)(c) | P3.1 | 5.34 | Redact-before-store; only ≤160-char redacted snippets; no email stored when pseudonymizing · `tests/test_compliance.py` |
| Privacy by design / pseudonymization | Art. 25, 32(1)(a) | P3, CC6.1 | 8.11 | `RADAR_PSEUDO_KEY` keyed-HMAC user IDs; audited `reveal` · `Pseudonymization` tests |
| Storage limitation | Art. 5(1)(e) | P4.2, C1.2 | 8.10 | `retention_days` (default 90) enforced every `run`/`watch` cycle; `purge` · `Retention` tests |
| Access request / portability | Art. 15, 20 | P5.1 | 5.34 | `radar dsr export <user>` → JSON |
| Erasure | Art. 17 | P4.3, C1.2 | 8.10 | `radar dsr erase <user> --yes` (events, identity, aggregates; alerts detached) |
| Logical access control | Art. 32 | CC6.1–6.3 | 5.15, 5.18, 8.2, 8.3 | Named users, analyst/viewer roles, ≥16-char tokens, constant-time compare, lockout, refuses to start unauthenticated |
| Logging & monitoring | Art. 5(2), 32 | CC7.2 | 8.15, 8.16 | Hash-chained audit log: views, changes, denied writes, auth failures, exports, purges, DSRs |
| Log integrity | Art. 32 | CC7.2, CC4.1 | 8.15 | `audit verify`, off-box `audit anchor`, `--against` |
| Confidentiality of data | Art. 32 | C1.1, CC6.7 | 8.24, 5.14 | `umask 077`, 0700/0600 files, AES-256 encrypted backups (OpenSSL) |
| Secure development | Art. 25 | CC8.1 | 8.25–8.28 | Parameterized SQL (enforced by test), output escaping, CSP/frame/referrer headers, ReDoS-bounded parsing, zero third-party dependencies, code integrity manifest |
| Backup & recovery | Art. 32(1)(c) | A1.2, A1.3 | 8.13 | `backup`/`restore` with integrity + audit-chain verification |
| Data-loss prevention (the product itself) | Art. 32 | CC6.7 | 8.12 | Secrets/PII detection in AI prompts, blocklist + SIEM export |
| Auditor-friendly exports | Art. 5(2) | CC4.1 | 8.15 | `export-csv` (hashes included so the chain can be re-verified outside the tool; formula-injection safe) |
| Scheduled integrity checks | Art. 32(1)(d) | CC4.1, CC7.2 | 8.15, 8.16 | `schedule` → weekly anchor, verify, backup, evidence, doctor |
| Records of processing | Art. 30 | P1.1 | 5.34 | Template §3 below |
| DPIA | Art. 35 | P-series | 5.34 | `docs/PRIVACY.md` (to be completed) |

## 2. Gaps you must close yourself (the tool cannot)
| Gap | Why it matters | Owner |
|---|---|---|
| **Lawful basis + employee notice** for inspecting prompt content | Core GDPR requirement; works-council consent in some countries (e.g. DE, FR, NL) | Legal/HR |
| **Complete & sign** `docs/PRIVACY.md` (DPIA) | Art. 35 likely applies: systematic monitoring of employees | DPO |
| **Disk encryption** on the host | Live DB is not encrypted by the tool | IT |
| **TLS + SSO** if ever exposed beyond localhost | Plain-HTTP tokens | IT/Security |
| **Independent penetration test** | Required by most SOC 2/ISO audit programmes | Security |
| **Vendor DPA** for optional Claude triage (`ANTHROPIC_API_KEY`) | Redacted evidence leaves the machine; third-country transfer | Legal |
| **Access reviews, change management, training, BCP** | SOC 2/ISO are process audits, not just tooling | Org |
| **Retention in alerts** | Alerts keep a pseudonymous security record after erasure; confirm it is justified | DPO |
| Re-identification risk | Pseudonymized ≠ anonymous; dept + timing can identify people | DPO |

## 3. Record of processing (Art. 30) template
| Field | Entry |
|---|---|
| Controller / contact | _[company, DPO]_ |
| Purpose | Prevent leakage of confidential data and credentials to unapproved AI services |
| Data subjects | Employees and contractors using the corporate network |
| Data categories | Pseudonymous user ID, department, manager, destination host, timestamps, byte counts, redacted prompt snippets (≤160 chars) |
| Recipients | Security team (analyst role), GRC (viewer role); optional AI-triage provider (redacted evidence only) |
| Transfers | None by default; see Claude triage row above |
| Retention | `retention_days` (default 90) for events; alerts per policy _[set]_ |
| Security measures | See §1 |

## 4. Incident response for the tool itself
1. **Suspected token leak:** remove/replace the user in `RADAR_USERS`, restart `serve`; run `radar audit show -n 200` for that actor.
2. **Audit chain failure** (`doctor` FAIL or `audit verify` FAILED): stop `serve`, snapshot the host, compare against the latest off-box anchor (`audit verify --against`), restore from the newest encrypted backup (`restore` verifies before installing).
3. **Personal-data breach involving `out/`:** assess within the hour, notify the DPO; GDPR Art. 33 gives 72 h to notify the authority if risk to individuals. Pseudonymization + redaction reduce impact; record that in the assessment.
4. **Data subject request:** `dsr export` → DPO review → deliver; erasure only after DPO approval (`--yes`).

## 5. Audit cadence (suggested)
| Frequency | Action |
|---|---|
| Daily | Triage alerts |
| Weekly | `audit anchor` (store off-box), `audit verify --against`, `doctor`, encrypted `backup` |
| Monthly | Review `audit show` for denied writes / auth failures; review user list |
| Quarterly | `evidence` snapshot to the compliance folder; access review; restore test |
| Yearly | Re-run DPIA; pen test; review retention |
