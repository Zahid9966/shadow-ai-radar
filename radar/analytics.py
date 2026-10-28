"""Gold layer + detection: robust (median/MAD) volume anomalies, shadow-tool adoption, content alerts."""
import hashlib
import json
import math
import statistics
from collections import defaultdict

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
VOLUME_FLOOR = 1_000_000  # ignore anomalies smaller than 1 MB/day
ADOPTION_USERS = 5  # distinct users on an unvetted tool before we call it adoption
VOLUME_Z = 3.5
RETENTION_DAYS = 90  # secure default; 0 disables
OFF_START, OFF_END = 21, 6  # hours (as logged) counted as off-hours: >= 21:00 or < 06:00
OFFHOURS_MIN = 3  # AI requests in off-hours on one day before we look at the user's history
HISTORY_MIN = 20  # need this many other AI requests from the user to know what "normal" is
RARE_SHARE = 0.02  # user's own off-hours share must be at most this for the day to count as unusual
STATUSES = ("open", "ack", "resolved", "false_positive")


def configure(th):
    global VOLUME_FLOOR, ADOPTION_USERS, VOLUME_Z, RETENTION_DAYS, OFF_START, OFF_END, OFFHOURS_MIN, HISTORY_MIN, RARE_SHARE
    VOLUME_FLOOR = th.get("volume_floor_bytes", VOLUME_FLOOR)
    ADOPTION_USERS = th.get("adoption_users", ADOPTION_USERS)
    VOLUME_Z = th.get("volume_z", VOLUME_Z)
    RETENTION_DAYS = th.get("retention_days", RETENTION_DAYS)
    OFF_START = th.get("offhours_start", OFF_START)
    OFF_END = th.get("offhours_end", OFF_END)
    OFFHOURS_MIN = th.get("offhours_min_events", OFFHOURS_MIN)
    HISTORY_MIN = th.get("history_min_events", HISTORY_MIN)
    RARE_SHARE = th.get("offhours_rare_share", RARE_SHARE)


def robust_z(x, sample):
    med = statistics.median(sample)
    mad = statistics.median(abs(v - med) for v in sample) or 0.3  # floor avoids div-by-zero on flat data
    return (x - med) / (1.4826 * mad)


def build_gold(db):
    db.executescript("""
    DROP TABLE IF EXISTS gold_user_day; DROP TABLE IF EXISTS gold_service; DROP TABLE IF EXISTS gold_dept; DROP TABLE IF EXISTS gold_user; DROP TABLE IF EXISTS gold_week;
    CREATE TABLE gold_user_day AS SELECT user, dept, day, COUNT(*) ai_events, SUM(bytes_out) bytes_out, SUM(risk) risk
      FROM silver_events WHERE is_ai=1 GROUP BY user, dept, day;
    CREATE TABLE gold_service AS SELECT service, status, COUNT(*) events, COUNT(DISTINCT user) users,
      SUM(bytes_out) bytes_out, ROUND(SUM(risk),1) risk, MIN(day) first_seen
      FROM silver_events WHERE is_ai=1 GROUP BY service, status;
    CREATE TABLE gold_dept AS SELECT dept, COUNT(*) ai_events,
      ROUND(100.0*SUM(status!='sanctioned')/COUNT(*),1) pct_unsanctioned, ROUND(SUM(risk),1) risk
      FROM silver_events WHERE is_ai=1 GROUP BY dept;
    CREATE TABLE gold_user AS SELECT user, dept, COUNT(*) ai_events, ROUND(SUM(risk),1) risk,
      SUM(status!='sanctioned') unsanctioned, SUM(findings!='[]') leaks
      FROM silver_events WHERE is_ai=1 GROUP BY user, dept;
    CREATE TABLE gold_week AS SELECT date(day,'weekday 0','-6 days') week, COUNT(DISTINCT day) days, COUNT(*) ai_events,
      COUNT(DISTINCT user) users, ROUND(100.0*SUM(status!='sanctioned')/COUNT(*),1) pct_unsanctioned,
      SUM(findings!='[]') leaks, ROUND(SUM(risk),1) risk
      FROM silver_events WHERE is_ai=1 GROUP BY week;
    """)


def detect(db):
    alerts = []

    def add(kind, sev, user, day, title, evidence, action):
        alerts.append({"kind": kind, "severity": sev, "user": user, "day": day, "title": title,
                       "evidence": evidence, "action": action})

    # 1) content alerts straight from silver (already redacted)
    for user, day, svc, st, fnd, snip in db.execute(
            "SELECT user, day, service, status, findings, snippet FROM silver_events WHERE is_ai=1 AND findings!='[]'"):
        f = set(json.loads(fnd))
        if f & {"aws_access_key", "private_key", "api_token", "high_entropy_token"}:
            add("SECRET_LEAK", "critical", user, day, f"Credential pasted into {svc}", snip,
                "Rotate the credential now; coach user; route coding help to the sanctioned gateway.")
        elif f & {"ssn", "credit_card"}:
            add("PII_LEAK", "high", user, day, f"Regulated PII sent to {svc} ({', '.join(sorted(f & {'ssn', 'credit_card'}))})", snip,
                "Open a privacy incident; assess notification duty; block the service for this role.")

    # 2) volume anomaly: user-day AI upload vs department peers (log scale, robust z)
    peers = defaultdict(list)
    rows = db.execute("SELECT user, dept, day, bytes_out FROM gold_user_day").fetchall()
    for _u, d, _day, b in rows:
        peers[d].append(math.log1p(b))
    for user, dept, day, b in rows:
        if b >= VOLUME_FLOOR and robust_z(math.log1p(b), peers[dept]) > VOLUME_Z:
            add("EXFIL_VOLUME", "high", user, day, f"{b / 1e6:.0f} MB uploaded to AI services in one day",
                f"{dept} peer median ≈ {math.expm1(statistics.median(peers[dept])) / 1e3:.0f} KB/day",
                "Review uploaded files with the user's manager; check for bulk export before the upload.")

    # 3) shadow adoption: unvetted tool spreading across users
    for svc, st, users, first in db.execute(
            "SELECT service, status, users, first_seen FROM gold_service WHERE status!='sanctioned'"):
        if st == "suspected" and users >= ADOPTION_USERS:
            add("SHADOW_ADOPTION", "medium", None, first, f"Unvetted AI tool '{svc}' used by {users} employees",
                "Not in catalog; discovered by domain heuristic.",
                "Run a vendor risk review; add to catalog as approved or blocked; offer a sanctioned alternative.")

    # 4) off-hours: a user suddenly active at hours that are rare for THEM (their own baseline, not a global rule)
    hist = defaultdict(lambda: [0] * 24)
    byday = defaultdict(lambda: defaultdict(lambda: [0] * 24))
    for user, day, hour in db.execute("SELECT user, day, CAST(substr(ts,12,2) AS INT) FROM silver_events WHERE is_ai=1"):
        hist[user][hour] += 1
        byday[user][day][hour] += 1
    is_off = lambda h: h >= OFF_START or h < OFF_END
    for user, days in byday.items():
        total = sum(hist[user])
        for day, hrs in days.items():
            n_off = sum(c for h, c in enumerate(hrs) if is_off(h))
            base_n = total - sum(hrs)
            if n_off < OFFHOURS_MIN or base_n < HISTORY_MIN:
                continue
            base_off = sum(hist[user][h] - hrs[h] for h in range(24) if is_off(h))
            if base_off / base_n <= RARE_SHARE:
                when = sorted(h for h, c in enumerate(hrs) if c and is_off(h))
                add("OFF_HOURS", "medium", user, day, f"{n_off} AI requests outside this user's normal hours",
                    f"hours {', '.join(f'{h:02d}:00' for h in when)}; their other {base_n} AI requests had {base_off} off-hours",
                    "Check with the user/manager whether this was expected; look at what was sent and to which tool.")

    # collapse repeats of the same (kind,user,title)
    seen, out = {}, []
    for a in alerts:
        k = (a["kind"], a["user"], a["title"])
        if k in seen:
            seen[k]["count"] += 1
            continue
        a["count"] = 1
        seen[k] = a
        out.append(a)
    # correlate: off-hours activity on a day that already has a stronger alert for the same user is one incident, not two
    main = {(a["user"], a["day"]): a for a in out if a["kind"] != "OFF_HOURS"}
    merged = []
    for a in out:
        host = main.get((a["user"], a["day"])) if a["kind"] == "OFF_HOURS" else None
        if host:
            host["evidence"] = f"{host['evidence']} | also outside the user's normal hours ({a['evidence'].split(';')[0]})"
        else:
            merged.append(a)
    return sorted(merged, key=lambda a: (SEV_ORDER[a["severity"]], a["day"]))


DDL = """CREATE TABLE IF NOT EXISTS alerts(alert_id TEXT PRIMARY KEY, kind TEXT, severity TEXT, user TEXT, day TEXT,
  title TEXT, evidence TEXT, action TEXT, count INT, status TEXT DEFAULT 'open', note TEXT DEFAULT '', updated_at TEXT)"""


IDENTITY_DDL = "CREATE TABLE IF NOT EXISTS identity(user TEXT PRIMARY KEY, dept TEXT, manager TEXT, email TEXT)"


def load_identity(db, path):
    import csv
    db.execute(IDENTITY_DDL)
    from . import privacy
    rows = [(privacy.pseudonym(r["user"]), r.get("dept"), r.get("manager"), None if privacy.enabled() else r.get("email"))
            for r in csv.DictReader(open(path, newline=""))]  # data minimisation: no email stored when pseudonymizing
    db.executemany("INSERT OR REPLACE INTO identity VALUES(?,?,?,?)", rows)
    db.commit()
    return len(rows)


def alert_id(a):
    return hashlib.sha1(f"{a['kind']}|{a['user']}|{a['title']}".encode()).hexdigest()[:10]


def persist(db, alerts):
    """Upsert detections. Human triage state (status/note) survives re-runs;
    a resolved alert reopens if the behaviour recurs (count grows)."""
    db.execute(DDL)
    for a in alerts:
        db.execute("""INSERT INTO alerts(alert_id,kind,severity,user,day,title,evidence,action,count,updated_at)
          VALUES(?,?,?,?,?,?,?,?,?,datetime('now'))
          ON CONFLICT(alert_id) DO UPDATE SET count=excluded.count, severity=excluded.severity, evidence=excluded.evidence,
            status=CASE WHEN excluded.count>alerts.count AND alerts.status IN('resolved','false_positive') THEN 'open' ELSE alerts.status END,
            updated_at=CASE WHEN excluded.count>alerts.count THEN datetime('now') ELSE alerts.updated_at END""",
                   (alert_id(a), a["kind"], a["severity"], a["user"], a["day"], a["title"], str(a["evidence"]), a["action"], a["count"]))
    db.commit()


def load_alerts(db, status=None):
    db.execute(DDL)
    db.execute(IDENTITY_DDL)
    q = ("SELECT a.alert_id,a.kind,a.severity,a.user,a.day,a.title,a.evidence,a.action,a.count,a.status,a.note,i.manager "
         "FROM alerts a LEFT JOIN identity i ON i.user=a.user")
    rows = db.execute(q + (" WHERE a.status=?" if status else "") + " ORDER BY CASE a.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, a.day",
                      (status,) if status else ()).fetchall()
    keys = "alert_id kind severity user day title evidence action count status note manager".split()
    return [dict(zip(keys, r)) for r in rows]


def set_status(db, alert_id, status, note=""):
    if status not in STATUSES:
        raise ValueError(f"status must be one of {STATUSES}")
    cur = db.execute("UPDATE alerts SET status=?, note=CASE WHEN ?!='' THEN ? ELSE note END, updated_at=datetime('now') WHERE alert_id=?",
                     (status, note, note, alert_id))
    db.commit()
    return cur.rowcount == 1
