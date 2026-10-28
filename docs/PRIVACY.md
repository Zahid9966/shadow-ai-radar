# Privacy & Governance Pack (template, not legal advice)

Complete and get sign-off from Legal/DPO, HR and (where applicable) the works council **before** enabling prompt-content inspection.

## 1. Purpose & lawful basis
- Purpose: protect company confidential data, credentials and regulated personal data from leaking to unvetted AI services.
- Lawful basis / justification: _[legitimate interest assessment, or local equivalent: fill in]_.
- Out of scope by design: performance management, profiling of individuals for HR decisions.

## 2. Data inventory (what Radar touches)
| Data | Source | Stored? | Retention |
|---|---|---|---|
| Request metadata (user, host, bytes, time) | Proxy | Yes (`silver_events`) | `radar purge --before <date>`; suggest 90 days |
| Prompt text | Proxy / browser agent (optional) | **No**: scanned in memory, only a redacted ≤160-char snippet stored | same |
| Detected secrets / PII values | Prompt text | **No**: replaced by `[TYPE]` tokens before storage | n/a |
| Alerts, status, notes | Radar | Yes (audit trail) | _[set per policy]_ |
| Manager / department | HR export | Yes (`identity`) | refresh on each load |

## 3. Controls implemented
- Redact-before-store (secrets, SSN, cards); verified by test.
- Dashboard bound to 127.0.0.1, Host/Origin checks, named analyst/viewer users, lockout, and a tamper-evident audit log of who viewed or changed what (see `docs/SECURITY.md`).
- AI triage sends **only redacted evidence**, only when `ANTHROPIC_API_KEY` is set (opt-in). Review the vendor DPA first.
- Retention purge command; policy thresholds in version-controlled config.

## 4. Controls to add before wider rollout
- Encrypt the disk holding `radar.db` (the live DB is not encrypted by the tool); keep the dashboard on localhost; anchor audit head hashes off-box.
- Documented data-subject request process (access/erasure by `user`).
- Employee notice: update the acceptable-use / AI policy and tell staff what is monitored.

## 5. Risk assessment (fill in)
| Risk | Likelihood | Impact | Mitigation | Owner |
|---|---|---|---|---|
| Over-collection of prompt content | | | Sampling, redaction, retention | |
| Misuse for individual surveillance | | | Access roles, coaching-first workflow | |
| False positives harming an employee | | | Human triage, `false_positive` status | |
| Classifier bias / low recall | | | Measured eval (`radar eval`), regex detectors independent of ML | |

## 6. Sign-off
Legal/DPO: ____  HR: ____  Security: ____  Date: ____
