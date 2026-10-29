import json
import os
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from datetime import date

from radar import analytics, audit, compliance, export, generate, pipeline, privacy

try:
    from . import _cleanup  # noqa: F401  (removes temp dirs at exit)
except ImportError:
    import _cleanup  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEY = "k" * 24


def built(env_key=None):
    d = tempfile.mkdtemp()
    log = os.path.join(d, "p.jsonl")
    generate.generate(log)
    if env_key:
        os.environ["RADAR_PSEUDO_KEY"] = env_key
    try:
        db = pipeline.connect(os.path.join(d, "r.db"))
        pipeline.ingest(db, log, workers=2)
    finally:
        os.environ.pop("RADAR_PSEUDO_KEY", None)
    return d, db


def detect(db, env_key=None):
    if env_key:
        os.environ["RADAR_PSEUDO_KEY"] = env_key
    try:
        analytics.build_gold(db)
        analytics.persist(db, analytics.detect(db))
    finally:
        os.environ.pop("RADAR_PSEUDO_KEY", None)


class Pseudonymization(unittest.TestCase):
    def test_no_raw_identifiers_stored_and_reveal_needs_key_and_hr(self):
        d, db = built(KEY)
        detect(db, KEY)
        self.assertEqual(db.execute("SELECT COUNT(*) FROM silver_events WHERE user NOT LIKE 'p-%'").fetchone()[0], 0)
        hr = os.path.join(d, "hr.csv")
        open(hr, "w").write("user,dept,manager,email\nu_eng_02,Engineering,m_lee,e@x.com\n")
        os.environ["RADAR_PSEUDO_KEY"] = KEY
        try:
            self.assertEqual(analytics.load_identity(db, hr), 1)
            self.assertIsNone(db.execute("SELECT email FROM identity").fetchone()[0])  # minimisation
            pid = privacy.pseudonym("u_eng_02")
            self.assertEqual(privacy.reveal(pid, hr), "u_eng_02")
            a = next(x for x in analytics.load_alerts(db) if x["user"] == pid)
            self.assertEqual(a["manager"], "m_lee")
        finally:
            os.environ.pop("RADAR_PSEUDO_KEY", None)
        os.environ["RADAR_PSEUDO_KEY"] = "z" * 24  # wrong key cannot re-identify
        try:
            self.assertIsNone(privacy.reveal(pid, hr))
        finally:
            os.environ.pop("RADAR_PSEUDO_KEY", None)

    def test_short_key_rejected(self):
        os.environ["RADAR_PSEUDO_KEY"] = "short"
        try:
            with self.assertRaises(SystemExit):
                privacy.check_key()
        finally:
            os.environ.pop("RADAR_PSEUDO_KEY", None)


class DataSubjectRights(unittest.TestCase):
    def test_export_then_erase_leaves_no_trace_of_person(self):
        d, db = built()
        detect(db)
        data = privacy.export_subject(db, "u_eng_02")
        self.assertGreater(len(data["events"]), 0)
        self.assertEqual(len(data["alerts"]), 1)
        self.assertNotIn("AKIA", json.dumps(data))  # exports carry redacted data only
        res = privacy.erase_subject(db, "u_eng_02")
        self.assertGreater(res["events"], 0)
        self.assertEqual(res["alerts_detached"], 1)
        for q in ("SELECT COUNT(*) FROM silver_events WHERE user='u_eng_02'",
                  "SELECT COUNT(*) FROM gold_user WHERE user='u_eng_02'",
                  "SELECT COUNT(*) FROM gold_user_day WHERE user='u_eng_02'",
                  "SELECT COUNT(*) FROM alerts WHERE user='u_eng_02'"):
            self.assertEqual(db.execute(q).fetchone()[0], 0, q)
        self.assertEqual(db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0], 5)  # security record kept, detached

    def test_audit_never_contains_subject_name(self):
        ref = privacy.subject_ref("u_eng_02")
        self.assertNotIn("u_eng_02", ref)
        self.assertEqual(ref, privacy.subject_ref("u_eng_02"))


class Retention(unittest.TestCase):
    def test_retain_by_age(self):
        _, db = built()
        total = db.execute("SELECT COUNT(*) FROM silver_events").fetchone()[0]
        self.assertEqual(pipeline.retain(db, 30, today=date(2026, 10, 20)), 0)  # all within 30d
        gone = pipeline.retain(db, 30, today=date(2026, 11, 10))  # cutoff 2026-10-11
        self.assertGreater(gone, 0)
        self.assertEqual(db.execute("SELECT COUNT(*) FROM silver_events WHERE day<'2026-10-11'").fetchone()[0], 0)
        self.assertEqual(db.execute("SELECT COUNT(*) FROM silver_events").fetchone()[0], total - gone)


class AuditAnchors(unittest.TestCase):
    def test_anchor_survives_appends_but_catches_history_edits_and_truncation(self):
        _, db = built()
        for i in range(3):
            audit.log(db, "a", "x", str(i))
        _, n, head, _ = audit.verify(db)
        anchor = (n, head)
        audit.log(db, "a", "x", "later")
        self.assertTrue(audit.verify(db, anchor=anchor)[0])
        db.execute("DELETE FROM audit_log WHERE id>2"); db.commit()
        self.assertFalse(audit.verify(db, anchor=anchor)[0])
        _, db2 = built()
        for i in range(3):
            audit.log(db2, "a", "x", str(i))
        a2 = audit.verify(db2)[1:3]
        db2.execute("UPDATE audit_log SET detail='forged' WHERE id=1"); db2.commit()
        self.assertFalse(audit.verify(db2, anchor=a2)[0])

    def test_log_injection_neutralised(self):
        _, db = built()
        audit.log(db, "bob\nFAKE admin logged in", "x\r\ny", "t", "line1\nline2")
        row = audit.show(db, 1)[0]
        self.assertTrue(all("\n" not in v and "\r" not in v for v in row))


class Hardening(unittest.TestCase):
    def test_blocklist_rejects_injected_hostnames(self):
        d, db = built()
        db.execute("INSERT INTO silver_events(event_id,day,user,dept,host,status,is_ai) VALUES('x1','2026-10-06','u','d',?,'unsanctioned',1)",
                   ("evil.com\nacl all allow",))
        db.commit()
        export.blocklist(db, os.path.join(d, "b.txt"))
        txt = open(os.path.join(d, "b.txt")).read()
        self.assertNotIn("acl all allow", txt)
        self.assertIn(".chatgpt.com", txt)

    def test_no_string_built_sql(self):
        import re
        bad = re.compile(r"execute(?:many|script)?\(\s*(?:f[\"']|[\"'][^\"']*[\"']\s*(?:%|\.format))")
        for f in os.listdir(os.path.join(ROOT, "radar")):
            if f.endswith(".py"):
                src = open(os.path.join(ROOT, "radar", f)).read()
                self.assertIsNone(bad.search(src), f"string-built SQL in {f}")

    def test_serve_refuses_to_start_without_logins(self):
        env = {k: v for k, v in os.environ.items() if not k.startswith("RADAR_")}
        r = subprocess.run([sys.executable, "-m", "radar", "--out", tempfile.mkdtemp(), "serve", "--port", "0"],
                           cwd=ROOT, env=env, capture_output=True, text=True, timeout=30)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("refusing to start without logins", r.stderr + r.stdout)

    def test_short_dashboard_tokens_rejected(self):
        from radar import serve
        self.assertEqual(serve.users_from_env({"RADAR_ANALYST_TOKEN": "short", "RADAR_USERS": "a=analyst:123456789012345"}), {})


class DoctorAndEvidence(unittest.TestCase):
    def test_doctor_flags_open_permissions_then_passes(self):
        d, db = built()
        os.chmod(d, 0o777)
        status = {c: s for s, c, _ in compliance.doctor(db, d, env={})}
        self.assertEqual(status["data dir permissions"], "FAIL")
        os.chmod(d, 0o700)
        os.chmod(os.path.join(d, "r.db"), 0o600)
        res = {c: s for s, c, _ in compliance.doctor(db, d, env={})}
        self.assertEqual(res["data dir permissions"], "PASS")
        self.assertEqual(res["audit chain integrity"], "PASS")
        self.assertEqual(res["dashboard authentication"], "WARN")  # nothing configured
        self.assertEqual(res["independent security review"], "WARN")  # never claims what it can't verify

    def test_evidence_bundle(self):
        d, db = built()
        detect(db)
        path, fails = compliance.evidence(db, d, env={"RADAR_USERS": "alice=analyst:" + "t" * 20})
        for f in ("posture.json", "audit_verification.json", "code_manifest.json", "settings.json", "data_counts.json", "SUMMARY.md"):
            self.assertTrue(os.path.exists(os.path.join(path, f)), f)
        self.assertIn("radar/audit.py", json.load(open(os.path.join(path, "code_manifest.json"))))
        s = json.load(open(os.path.join(path, "settings.json")))
        self.assertEqual(s["dashboard_users"], {"analysts": 1, "viewers": 0})
        self.assertNotIn("t" * 20, open(os.path.join(path, "settings.json")).read())  # tokens never written


if __name__ == "__main__":
    unittest.main()
