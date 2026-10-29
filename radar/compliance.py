"""`radar doctor`: self-assessment of security/privacy posture. `radar evidence`: auditor-ready snapshot.
Conservative by design: a check that cannot be verified from inside the tool reports WARN, never a silent PASS."""
import glob
import hashlib
import json
import os
import stat
import subprocess
import time
from datetime import datetime, timezone

from . import analytics, audit, privacy, serve

PASS, WARN, FAIL = "PASS", "WARN", "FAIL"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def doctor(db, out_dir, env=None):
    env = os.environ if env is None else env
    r = []
    add = lambda status, name, detail: r.append((status, name, detail))

    m = _mode(out_dir)
    add(PASS if m & 0o077 == 0 else FAIL, "data dir permissions", f"{oct(m)} (want owner-only)")
    dbp = os.path.join(out_dir, "radar.db")
    if os.path.exists(dbp):
        m = _mode(dbp)
        add(PASS if m & 0o077 == 0 else FAIL, "database permissions", oct(m))

    ok, n, head, why = audit.verify(db)
    add(PASS if ok else FAIL, "audit chain integrity", f"{n} rows" if ok else why)
    anchors = os.path.join(out_dir, "audit_anchors.txt")
    if os.path.exists(anchors):
        age = (time.time() - os.path.getmtime(anchors)) / 86400
        add(PASS if age <= 8 else WARN, "audit anchor freshness", f"last anchored {age:.1f} days ago; copy the file OFF this machine")
    else:
        add(WARN, "audit anchor", "none taken: run `radar audit anchor` on a schedule and store it elsewhere")

    users = serve.users_from_env(env)
    add(PASS if users else WARN, "dashboard authentication", f"{len(users)} named users" if users else
        "no users configured: `serve` will refuse to start without --allow-open")
    try:
        privacy.check_key()
        add(PASS if privacy.enabled() else WARN, "pseudonymization", "on" if privacy.enabled() else "off: user IDs stored in clear (set RADAR_PSEUDO_KEY)")
    except SystemExit as e:
        add(FAIL, "pseudonymization key", str(e))
    days = analytics.RETENTION_DAYS
    add(PASS if 0 < days <= 365 else WARN, "retention", f"{days} days" if days else "disabled: data is kept forever")

    bak = glob.glob(os.path.join(out_dir, "*.enc"))
    if bak:
        age = (time.time() - max(os.path.getmtime(b) for b in bak)) / 86400
        add(PASS if age <= 8 else WARN, "encrypted backup", f"newest is {age:.1f} days old")
    else:
        add(WARN, "encrypted backup", "none found in data dir")

    pp = os.path.join(ROOT, "docs", "PRIVACY.md")
    if os.path.exists(pp):
        signed = "____" not in open(pp).read().split("## 6. Sign-off")[-1]
        add(PASS if signed else WARN, "privacy pack sign-off", "completed" if signed else "Legal/DPO, HR, Security sign-off still blank")

    try:
        out = subprocess.run(["lsblk", "-no", "TYPE"], capture_output=True, text=True, timeout=5).stdout
        add(PASS if "crypt" in out else WARN, "disk encryption", "encrypted volume detected" if "crypt" in out else
            "no dm-crypt/LUKS volume detected (cannot verify FileVault/BitLocker/other); the live DB is not encrypted by the tool")
    except Exception:
        add(WARN, "disk encryption", "could not check; confirm the host disk is encrypted")
    add(WARN, "transport security", "dashboard is plain HTTP on 127.0.0.1 only: acceptable single-host, not for network exposure")
    add(WARN, "independent security review", "not performed")
    return r


def manifest():
    files = sorted(glob.glob(os.path.join(ROOT, "radar", "*.py")) + [os.path.join(ROOT, "config", "policy.json"), os.path.join(ROOT, "pyproject.toml")])
    return {os.path.relpath(f, ROOT): hashlib.sha256(open(f, "rb").read()).hexdigest() for f in files if os.path.exists(f)}


def evidence(db, out_dir, env=None):
    """Write a dated evidence folder: posture checks, audit verification, code integrity manifest, settings, counts."""
    env = os.environ if env is None else env
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    d = os.path.join(out_dir, "evidence", day)
    os.makedirs(d, mode=0o700, exist_ok=True)
    checks = doctor(db, out_dir, env)
    ok, n, head, why = audit.verify(db)
    users = serve.users_from_env(env)
    counts = {"events": db.execute("SELECT COUNT(*) FROM silver_events").fetchone()[0],
              "alerts_by_status": dict(db.execute("SELECT status, COUNT(*) FROM alerts GROUP BY status").fetchall()) if db.execute(
                  "SELECT 1 FROM sqlite_master WHERE name='alerts'").fetchone() else {}}
    files = {
        "posture.json": [{"status": s, "check": c, "detail": x} for s, c, x in checks],
        "audit_verification.json": {"ok": ok, "rows": n, "head": head, "problem": why},
        "code_manifest.json": manifest(),
        "settings.json": {"retention_days": analytics.RETENTION_DAYS, "pseudonymization": privacy.enabled(),
                          "dashboard_users": {"analysts": sum(r == "analyst" for r, _ in users.values()),
                                              "viewers": sum(r == "viewer" for r, _ in users.values())},
                          "min_token_length": serve.MIN_TOKEN, "lockout": f"{serve.MAX_FAILS} failures / {serve.LOCK_SECONDS}s"},
        "data_counts.json": counts}
    for name, obj in files.items():
        with open(os.path.join(d, name), "w") as f:
            json.dump(obj, f, indent=2)
    fails = [c for c in checks if c[0] == FAIL]
    with open(os.path.join(d, "SUMMARY.md"), "w") as f:
        f.write(f"# Evidence snapshot {day}\n\nGenerated by `radar evidence`. Machine-generated; not a certification.\n\n")
        f.write("| Status | Check | Detail |\n|---|---|---|\n" + "\n".join(f"| {s} | {c} | {x} |" for s, c, x in checks))
        f.write(f"\n\nAudit chain: {'OK' if ok else 'FAILED'} ({n} rows, head `{head}`).\n")
    return d, len(fails)
