"""Privacy by design (GDPR Art. 25) and data-subject rights (Art. 15/17/20).
Pseudonymization: when RADAR_PSEUDO_KEY is set, user IDs are replaced by a keyed HMAC at ingest, so the database alone
does not identify anyone. Re-identification needs the key AND the HR list (`radar reveal`), and is audited."""
import hashlib
import hmac
import json
import os

from . import analytics

MIN_KEY = 16


def enabled():
    return bool(os.environ.get("RADAR_PSEUDO_KEY"))


def check_key():
    k = os.environ.get("RADAR_PSEUDO_KEY")
    if k is not None and len(k) < MIN_KEY:
        raise SystemExit(f"RADAR_PSEUDO_KEY must be at least {MIN_KEY} characters")


def pseudonym(user):
    k = os.environ.get("RADAR_PSEUDO_KEY")
    if not k:
        return user
    return "p-" + hmac.new(k.encode(), user.encode(), hashlib.sha256).hexdigest()[:12]


def subject_ref(user):
    """Non-reversible reference for audit entries: the audit log must never contain a data subject's name."""
    return "subj-" + hashlib.sha256(user.encode()).hexdigest()[:12]


def reveal(pseud, hr_csv):
    import csv
    for r in csv.DictReader(open(hr_csv, newline="")):
        if pseudonym(r["user"]) == pseud:
            return r["user"]
    return None


def export_subject(db, user):
    """Art. 15/20: everything held about one person, machine-readable."""
    sid = pseudonym(user)
    db.execute(analytics.IDENTITY_DDL)
    cols = lambda cur: [d[0] for d in cur.description]

    def rows(q):
        cur = db.execute(q, (sid,))
        return [dict(zip(cols(cur), r)) for r in cur.fetchall()]
    return {"subject": user, "stored_as": sid, "pseudonymized": enabled(),
            "events": rows("SELECT event_id,ts,host,service,status,bytes_out,category,findings,snippet,risk FROM silver_events WHERE user=?"),
            "alerts": rows("SELECT alert_id,kind,severity,day,title,status,note FROM alerts WHERE user=?"),
            "identity": rows("SELECT user,dept,manager FROM identity WHERE user=?"),
            "note": "Prompt snippets are stored redacted; secrets and PII values are not retained."}


def erase_subject(db, user):
    """Art. 17: delete event-level data and identity; keep security alerts but detach them from the person.
    Whether alert records may be kept is a legal call (legitimate interest / legal claims): confirm with your DPO."""
    sid = pseudonym(user)
    db.execute(analytics.IDENTITY_DDL)
    n_ev = db.execute("DELETE FROM silver_events WHERE user=?", (sid,)).rowcount
    n_id = db.execute("DELETE FROM identity WHERE user=?", (sid,)).rowcount
    n_al = db.execute("UPDATE alerts SET user=NULL, evidence='[erased on data-subject request]', "
                      "note=CASE WHEN note!='' THEN '[erased]' ELSE '' END WHERE user=?", (sid,)).rowcount
    db.commit()
    analytics.build_gold(db)  # aggregates must not retain the person either
    return {"events": n_ev, "identity": n_id, "alerts_detached": n_al}


def dump(db, user, path):
    with open(path, "w") as f:
        json.dump(export_subject(db, user), f, indent=2)
