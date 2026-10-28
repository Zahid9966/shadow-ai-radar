import http.client
import json
import os
import socket
import sqlite3
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer

from radar import analytics, export, generate, pipeline, serve, triage

try:
    from . import _cleanup  # noqa: F401  (removes temp dirs at exit)
except ImportError:
    import _cleanup  # noqa: F401


def built(policy=None):
    d = tempfile.mkdtemp()
    log = os.path.join(d, "p.jsonl")
    generate.generate(log)
    db = pipeline.connect(os.path.join(d, "r.db"))
    pipeline.ingest(db, log, workers=2, policy=policy)
    analytics.build_gold(db)
    analytics.persist(db, analytics.detect(db))
    return d, log, db


class Lifecycle(unittest.TestCase):
    def test_status_survives_rerun_and_reopens_on_recurrence(self):
        _, _, db = built()
        a = analytics.load_alerts(db)[0]
        self.assertTrue(analytics.set_status(db, a["alert_id"], "resolved", "rotated key"))
        analytics.persist(db, analytics.detect(db))  # same data: stays resolved, note kept
        a2 = next(x for x in analytics.load_alerts(db) if x["alert_id"] == a["alert_id"])
        self.assertEqual((a2["status"], a2["note"]), ("resolved", "rotated key"))
        again = dict(a, count=a["count"] + 1, evidence=a["evidence"])
        analytics.persist(db, [again])  # recurrence
        self.assertEqual(next(x for x in analytics.load_alerts(db) if x["alert_id"] == a["alert_id"])["status"], "open")

    def test_bad_status_rejected(self):
        _, _, db = built()
        with self.assertRaises(ValueError):
            analytics.set_status(db, "x", "deleted")


class Policy(unittest.TestCase):
    def test_policy_reaches_worker_processes(self):
        p = os.path.join(tempfile.mkdtemp(), "pol.json")
        json.dump({"catalog": {"claude.ai": ["Claude", "sanctioned"]}}, open(p, "w"))
        _, _, db = built(policy=p)
        st = db.execute("SELECT DISTINCT status FROM silver_events WHERE host='claude.ai'").fetchall()
        self.assertEqual(st, [("sanctioned",)])


class Incremental(unittest.TestCase):
    def test_appended_leak_detected_next_cycle(self):
        _, log, db = built()
        before = len(analytics.load_alerts(db))
        rec = {"event_id": "new1", "ts": "2026-10-19T10:00:00+00:00", "user": "u_leg_00", "dept": "Legal", "host": "chatgpt.com",
               "bytes_out": 500, "bytes_in": 900, "prompt": "client ssn 123-45-6789 review"}
        with open(log, "a") as f:
            f.write(json.dumps(rec) + "\n")
        self.assertEqual(pipeline.ingest(db, log, workers=2)["loaded"], 1)
        analytics.build_gold(db)
        analytics.persist(db, analytics.detect(db))
        self.assertEqual(len(analytics.load_alerts(db)), before + 1)


class Export(unittest.TestCase):
    def test_blocklist_excludes_sanctioned(self):
        d, _, db = built()
        export.blocklist(db, os.path.join(d, "b.txt"))
        txt = open(os.path.join(d, "b.txt")).read()
        self.assertIn(".chatgpt.com", txt)
        self.assertNotIn("ai-gateway", txt)
        self.assertEqual(export.siem(analytics.load_alerts(db), os.path.join(d, "s.jsonl")), 5)


class Triage(unittest.TestCase):
    def test_offline_fallback(self):
        os.environ.pop("ANTHROPIC_API_KEY", None)
        _, _, db = built()
        text, src = triage.summarize(analytics.load_alerts(db)[0])
        self.assertEqual(src, "offline")
        self.assertIn("rotate", text.lower())


class Dashboard(unittest.TestCase):
    def setUp(self):
        self.d, _, db = built()
        self.aid = analytics.load_alerts(db)[0]["alert_id"]
        s = socket.socket(); s.bind(("127.0.0.1", 0)); self.port = s.getsockname()[1]; s.close()
        self.srv = ThreadingHTTPServer(("127.0.0.1", self.port), serve.make_handler(os.path.join(self.d, "r.db"), self.port))
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown(); self.srv.server_close()

    def req(self, method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port)
        c.request(method, path, body, headers or {})
        r = c.getresponse(); r.read()
        return r.status

    def test_get_and_ack(self):
        self.assertEqual(self.req("GET", "/"), 200)
        self.assertEqual(self.req("POST", f"/alerts/{self.aid}", "status=ack&note=looking", {"Content-Type": "application/x-www-form-urlencoded"}), 303)
        self.assertEqual(analytics.load_alerts(sqlite3.connect(os.path.join(self.d, "r.db")))[0]["status"], "ack")

    def test_foreign_host_and_origin_rejected(self):
        self.assertEqual(self.req("GET", "/", headers={"Host": "evil.com"}), 403)
        self.assertEqual(self.req("POST", f"/alerts/{self.aid}", "status=resolved", {"Origin": "http://evil.com"}), 403)
        self.assertEqual(self.req("POST", f"/alerts/{self.aid}", "status=bogus"), 400)


if __name__ == "__main__":
    unittest.main()
