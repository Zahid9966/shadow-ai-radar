"""Desktop notifications for new critical/high alerts. Uses the system `notify-send` with an argument LIST (never a
shell), `--` to stop option injection, and control-character stripping, because alert text is derived from log data.
Bodies contain only severity, type and tool name: never the user, snippet or evidence."""
import os
import shutil
import subprocess
from datetime import datetime, timezone

SEVERITIES = ("critical", "high")
DDL = "CREATE TABLE IF NOT EXISTS notified(alert_id TEXT PRIMARY KEY, at TEXT, via TEXT)"


def _clean(s, n=120):
    return "".join(c if c.isprintable() else " " for c in str(s))[:n]


def pending(db, severities=SEVERITIES):
    from . import analytics
    db.execute(DDL)
    done = {r[0] for r in db.execute("SELECT alert_id FROM notified")}
    return [a for a in analytics.load_alerts(db, "open") if a["severity"] in severities and a["alert_id"] not in done]


def send(a, out_dir):
    body = _clean(f"{a['severity'].upper()} {a['kind']}: {a['title']}")
    exe = shutil.which("notify-send")
    has_session = any(os.environ.get(k) for k in ("DISPLAY", "WAYLAND_DISPLAY", "DBUS_SESSION_BUS_ADDRESS"))
    via = "terminal"
    if exe and has_session:
        try:
            subprocess.run([exe, "-u", "critical" if a["severity"] == "critical" else "normal", "-a", "Shadow-AI Radar",
                            "--", "Shadow-AI Radar", body], timeout=5, capture_output=True, check=True)
            via = "desktop"
        except (subprocess.SubprocessError, OSError):
            pass
    if via == "terminal":
        print(f"\a[ALERT] {body}", flush=True)
    with open(os.path.join(out_dir, "notifications.log"), "a") as f:  # evidence that someone was told, and when
        f.write(f"{datetime.now(timezone.utc).isoformat(timespec='seconds')}\t{via}\t{a['alert_id']}\t{body}\n")
    return via


def dispatch(db, out_dir):
    n = 0
    for a in pending(db):
        via = send(a, out_dir)
        db.execute("INSERT OR IGNORE INTO notified VALUES(?,datetime('now'),?)", (a["alert_id"], via))
        n += 1
    db.commit()
    return n
