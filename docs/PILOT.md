# Pilot Runbook (shadow mode, one department, 4 weeks)

**Prerequisite:** `docs/PRIVACY.md` signed off by Legal/DPO and HR.

## Week 0: Setup (≈1 day)
1. Export 2+ weeks of proxy logs for ONE department (Squid/Zscaler/CSV) plus an HR file `user,dept,manager,email[,ip]`.
2. `radar convert squid|csv <export> out/proxy.jsonl --identity hr.csv`
3. Edit `config/policy.json`: set your real sanctioned tools. Check `convert` warnings: if Squid, add `%>st` to the logformat or volume alerts stay blind.
4. `radar --policy config/policy.json run --rebuild && radar identity hr.csv`
5. Start the dashboard with tokens: analyst = security lead, viewer = CISO/GRC.

## Week 1-2: Label & measure
1. `radar label -n 50` daily (≈10 min). Target ≥500 labels; the tool shows the least-confident prompts first.
2. Hold out 100 labels as a test set (move them to `eval/pilot_test.jsonl`), train on the rest:
   `radar train out/labels.jsonl --save out/model.json`, then `radar --model out/model.json eval --data eval/pilot_test.jsonl`.
3. **Gate:** confidential recall ≥ 0.90 and overall accuracy ≥ 0.90 on the held-out set. If not, keep labelling; do not enable classifier-driven alerts.

## Week 2-4: Shadow mode
- Alerts go to security only. Nobody is contacted about an alert during week 2.
- Daily: triage every alert in the dashboard. Mark wrong ones `false_positive` with a note saying why.
- Weekly review (30 min): false-positive rate per alert type, tune `volume_z`, `adoption_users`, catalog entries.

## Success criteria (decide before starting, record here)
| Metric | Target | Actual |
|---|---|---|
| Secret/PII alert precision (confirmed / total) | ≥ 0.8 | |
| Analyst time per alert | ≤ 5 min | |
| Unknown AI tools discovered and reviewed | ≥ 1 | |
| Employee complaints / privacy escalations | 0 | |

## Exit
Go: expand to the next department. No-go: document why; run `radar purge --before <today>`.
