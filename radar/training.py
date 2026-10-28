"""Analyst training mode: a seeded scenario with known answers. The analyst triages in the dashboard; `training score`
compares their decisions with the key. Explanations are revealed only for alerts the analyst has already decided."""
from . import analytics, privacy

# (kind, user) -> (truth, explanation)
KEY = {
    ("SECRET_LEAK", "u_eng_02"): ("TP", "A real AWS access key pasted into a consumer chatbot. Rotate it, check CloudTrail, coach the user."),
    ("EXFIL_VOLUME", "u_fin_03"): ("TP", "120 MB of customer ledger to a consumer AI at 22:00, 1000x the department's norm. Escalate; also flagged as off-hours."),
    ("PII_LEAK", "u_hr_01"): ("TP", "Employee SSNs sent to Poe on three consecutive days. Privacy incident."),
    ("PII_LEAK", "u_sup_04"): ("TP", "Two Luhn-valid card numbers pasted by support. Check PCI scope and notify the DPO."),
    ("SHADOW_ADOPTION", None): ("TP", "freegpt-writer.io is unknown to the catalog and spread to 6 marketing users in 4 days. Vendor review."),
    ("OFF_HOURS", "u_leg_01"): ("TP", "A legal user with a clean daytime history sent 6 confidential prompts to a consumer chatbot at 02:00. Ask why."),
    ("SECRET_LEAK", "u_eng_05"): ("FP", "AKIAIOSFODNN7EXAMPLE is AWS's published documentation placeholder, not a credential. Mark false_positive; consider an allow-list."),
    ("EXFIL_VOLUME", "u_eng_01"): ("FP", "45 MB went to the SANCTIONED corporate gateway for an approved dataset. Volume alerts need a destination check; mark false_positive."),
}


def _ok(truth, status):
    return status in ("ack", "resolved") if truth == "TP" else status == "false_positive"


def score(db):
    by = {(a["kind"], a["user"]): a for a in analytics.load_alerts(db)}
    rows, correct, decided = [], 0, 0
    for (kind, user), (truth, why) in KEY.items():
        a = by.get((kind, privacy.pseudonym(user) if user else None))
        if a is None:
            rows.append((kind, user, "MISSING", "the tool never raised this alert: a detection gap", False))
            continue
        if a["status"] == "open":
            rows.append((kind, user, "open", "(not triaged yet)", None))
            continue
        decided += 1
        good = _ok(truth, a["status"])
        correct += good
        rows.append((kind, user, a["status"], ("CORRECT. " if good else f"WRONG (this one is a {'real incident' if truth == 'TP' else 'false positive'}). ") + why, good))
    # decoy: a 16-digit order number that fails the Luhn check must not produce an alert
    decoy_ok = ("PII_LEAK", privacy.pseudonym("u_sup_02")) not in {(a["kind"], a["user"]) for a in by.values()}
    return {"rows": rows, "correct": correct, "decided": decided, "total": len(KEY), "decoy_silent": decoy_ok}
