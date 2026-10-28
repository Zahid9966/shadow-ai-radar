# Real-data test: WildChat sample (2026-10-27)

**Data:** 406 real user prompts (200 conversations, 142 anonymised users, Apr–Sep 2023) from the public
[allenai/WildChat-1M](https://huggingface.co/datasets/allenai/WildChat-1M) preview API (~2.3 MB). English 56%, Chinese 21%, Russian, French, Spanish, Japanese.
Raw data was kept outside this project (no prompt text is stored here); check the dataset card's licence before any reuse.
**Method:** wrapped each prompt as a `chatgpt.com` proxy event and ran the real pipeline (`ingest → detect`), then manually reviewed every finding.

## What the dataset can and cannot tell us
- It is **pre-anonymised**: independent regexes found 0 emails, 0 phones, 0 SSNs, 0 API-key keywords. So this test measures **false positives and robustness**, and says **nothing about PII/secret recall**. Recall is still only verified on synthetic plants.
- It is consumer traffic (homework, games, translation), not corporate. It over-represents benign content.

## Results
| Check | Before | After fixes |
|---|---|---|
| Crashes / rejected lines | 0 / 0 | 0 / 0 |
| Scan time (median / worst, longest prompt 14,682 chars) | 0.06 ms / 12 ms | 0.09 ms / 17 ms |
| False **critical** SECRET_LEAK alerts | **2** (7 hits in 3 prompts: URL slugs, Medium and Twitter links) | **0** |
| Prompts flagged (all false) | 3 / 406 (0.7%) | 0 / 406 |
| Classifier accuracy vs my labels (n=40 English, single annotator) | **62%** (an "always public" guess scores 80%) | unchanged: not retrained |

## Bugs the real data exposed (all fixed, with regression tests)
1. Entropy detector treated long URL paths as secrets → URLs are now excluded from the entropy scan; added `url_credentials` and context-aware `secret_assignment` rules so secrets *inside* URLs/assignments are still caught; random tokens must mix upper+lower+digits.
2. Squid converter misattributed users when the URL contained spaces; error lines became junk events (see earlier fix).
3. Bootstrap classifier is unreliable on natural language: misses plain-English code requests ("write me an android app"), and labels harmless prompts `internal`/`confidential` at 0.8–1.0 confidence. **Mitigation:** its contribution to risk is now capped at 35% until you load a model you trained (`radar train` + `--model`). It never raised alerts; it only inflated risk scores.

## Not covered / next
- Detector **recall** on real secrets/PII (needs un-redacted corporate samples; get approval).
- Non-English prompts (21% Chinese here) are not meaningfully classified by the English bag-of-words model.
- Classifier labels were mine, n=40: indicative only. Real validation needs ≥500 labelled corporate prompts (`docs/PILOT.md`).
