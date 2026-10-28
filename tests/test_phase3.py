import csv
import http.client
import json
import os
import socket
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer

from radar import adapters, analytics, generate, model, pipeline, serve

try:
    from . import _cleanup  # noqa: F401  (removes temp dirs at exit)
except ImportError:
    import _cleanup  # noqa: F401


class Adapters(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.hr = os.path.join(self.d, "hr.csv")
        with open(self.hr, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["user", "dept", "manager", "email", "ip"])
            w.writerow(["alice", "Finance", "bob", "a@x.com", "10.1.1.5"])

    def test_squid_native(self):
        src = os.path.join(self.d, "access.log")
        open(src, "w").write(
            "1792000000.123 150 10.1.1.5 TCP_TUNNEL/200 5120 CONNECT chatgpt.com:443 - HIER_DIRECT/1.2.3.4 -\n"
            "garbage line\n"
            "1792000010.000 20 10.1.1.5 TCP_MISS/200 900 GET https://claude.ai/api/x carol HIER_DIRECT/1.2.3.5 text/html\n")
        dst = os.path.join(self.d, "out.jsonl")
        self.assertEqual(adapters.convert("squid", src, dst, self.hr), {"converted": 2, "skipped": 1})
        a, b = [json.loads(l) for l in open(dst)]
        self.assertEqual((a["user"], a["dept"], a["host"]), ("alice", "Finance", "chatgpt.com"))  # ip -> user via HR file
        self.assertEqual((b["user"], b["host"]), ("carol", "claude.ai"))

    def test_csv_with_prompt_and_aliases(self):
        src = os.path.join(self.d, "z.csv")
        open(src, "w").write("Time,Username,URL,BytesSent,BytesReceived,Snippet\n"
                             "1792000000,alice,https://poe.com/chat,2000,300,my ssn 123-45-6789\n")
        dst = os.path.join(self.d, "o.jsonl")
        adapters.convert("csv", src, dst, self.hr)
        r = json.loads(open(dst).readline())
        self.assertEqual((r["host"], r["bytes_out"], r["dept"]), ("poe.com", 2000, "Finance"))
        db = pipeline.connect(os.path.join(self.d, "r.db"))
        self.assertEqual(pipeline.ingest(db, dst, workers=1)["loaded"], 1)  # converted output is valid for the pipeline
        self.assertIn("ssn", db.execute("SELECT findings FROM silver_events").fetchone()[0])

    def test_csv_missing_columns(self):
        src = os.path.join(self.d, "bad.csv")
        open(src, "w").write("a,b\n1,2\n")
        with self.assertRaises(ValueError):
            adapters.convert("csv", src, os.path.join(self.d, "x"), None)


class Model(unittest.TestCase):
    def test_eval_save_load_roundtrip(self):
        nb = model.train_default()
        p = os.path.join(tempfile.mkdtemp(), "m.json")
        model.save(nb, p)
        nb2 = model.load(p)
        t = "this java method public void save(User u) { repo.save(u); }"
        self.assertEqual(nb.predict(t)[0], nb2.predict(t)[0])
        rows = [json.loads(l) for l in open("eval/test.jsonl")]
        self.assertGreaterEqual(model.evaluate(nb, rows)["accuracy"], 0.75)  # regression guard on the fresh test set

    def test_train_from_labels_learns_new_term(self):
        nb = model.train_from_labels([{"text": "zorblax quarterly numbers", "label": "confidential"}] * 20)
        self.assertEqual(nb.predict("zorblax numbers")[0], "confidential")


class IdentityAndRetention(unittest.TestCase):
    def test_manager_on_alerts_and_purge_keeps_alerts(self):
        d = tempfile.mkdtemp()
        log = os.path.join(d, "p.jsonl")
        generate.generate(log)
        db = pipeline.connect(os.path.join(d, "r.db"))
        pipeline.ingest(db, log, workers=2)
        analytics.build_gold(db)
        analytics.persist(db, analytics.detect(db))
        hr = os.path.join(d, "hr.csv")
        open(hr, "w").write("user,dept,manager,email\nu_eng_02,Engineering,m_lee,e@x.com\n")
        self.assertEqual(analytics.load_identity(db, hr), 1)
        a = next(x for x in analytics.load_alerts(db) if x["user"] == "u_eng_02")
        self.assertEqual(a["manager"], "m_lee")
        deleted = pipeline.purge(db, "2026-10-12")
        self.assertGreater(deleted, 0)
        self.assertEqual(db.execute("SELECT COUNT(*) FROM silver_events WHERE day<'2026-10-12'").fetchone()[0], 0)
        self.assertEqual(len(analytics.load_alerts(db)), 5)


class Auth(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp()
        log = os.path.join(d, "p.jsonl")
        generate.generate(log)
        db = pipeline.connect(os.path.join(d, "r.db"))
        pipeline.ingest(db, log, workers=2)
        analytics.build_gold(db)
        analytics.persist(db, analytics.detect(db))
        self.aid = analytics.load_alerts(db)[0]["alert_id"]
        s = socket.socket(); s.bind(("127.0.0.1", 0)); self.port = s.getsockname()[1]; s.close()
        h = serve.make_handler(os.path.join(d, "r.db"), self.port, {"analyst": ("analyst", "AAA"), "viewer": ("viewer", "VVV")})
        self.srv = ThreadingHTTPServer(("127.0.0.1", self.port), h)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown(); self.srv.server_close()

    def req(self, method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port)
        c.request(method, path, body, headers or {})
        r = c.getresponse(); r.read()
        return r.status

    def test_roles(self):
        self.assertEqual(self.req("GET", "/api/alerts"), 401)
        self.assertEqual(self.req("GET", "/api/alerts", headers={"Authorization": "Bearer nope"}), 401)
        self.assertEqual(self.req("GET", "/api/alerts", headers={"Authorization": "Bearer VVV"}), 200)
        self.assertEqual(self.req("POST", f"/alerts/{self.aid}", "status=ack", {"Authorization": "Bearer VVV"}), 403)
        self.assertEqual(self.req("POST", f"/alerts/{self.aid}", "status=ack", {"Authorization": "Bearer AAA"}), 303)
        self.assertEqual(self.req("GET", "/?token=AAA"), 303)  # login link sets cookie


if __name__ == "__main__":
    unittest.main()


class Labeling(unittest.TestCase):
    def test_least_confident_first_and_resumable(self):
        from radar import labeling
        d = tempfile.mkdtemp()
        log = os.path.join(d, "p.jsonl")
        generate.generate(log)
        db = pipeline.connect(os.path.join(d, "r.db"))
        pipeline.ingest(db, log, workers=2)
        cands = labeling.candidates(db, set(), 5)
        ps = [c[3] for c in cands]
        self.assertEqual(ps, sorted(ps))
        path = os.path.join(d, "labels.jsonl")
        answers = iter(["x", "c", "k", "p", "q"])  # invalid key is re-asked; skip; quit
        self.assertEqual(labeling.run(db, path, 10, inp=lambda _: next(answers), out=lambda *_: None), 2)
        rows = [json.loads(l) for l in open(path)]
        self.assertEqual([r["label"] for r in rows], ["confidential", "public"])
        again = labeling.candidates(db, {r["event_id"] for r in rows}, 10)  # labelled ones not offered twice
        self.assertFalse({r["event_id"] for r in rows} & {c[0] for c in again})
        nb = model.train_from_labels(rows)  # labels flow straight into training
        self.assertTrue(nb.predict(rows[0]["text"]))


class Timestamps(unittest.TestCase):
    def test_zulu_timestamp_accepted(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "z.jsonl")
        open(p, "w").write(json.dumps({"event_id": "z1", "ts": "2026-10-05T10:00:00Z", "user": "u", "dept": "d",
                                       "host": "chatgpt.com", "bytes_out": 1, "bytes_in": 1}) + "\n")
        db = pipeline.connect(os.path.join(d, "r.db"))
        self.assertEqual(pipeline.ingest(db, p, workers=1)["loaded"], 1)


class SquidRealWorld(unittest.TestCase):
    """Lines taken from / modelled on Squid's documented native format (Elastic integration sample + Squid wiki caveats)."""

    def conv(self, text):
        d = tempfile.mkdtemp()
        src, dst = os.path.join(d, "a.log"), os.path.join(d, "o.jsonl")
        open(src, "w").write(text)
        res = adapters.convert("squid", src, dst)
        return res, [json.loads(l) for l in open(dst)]

    def test_official_documented_sample_line(self):
        res, rows = self.conv("1157689312.049   5006 10.105.21.199 TCP_MISS/200 19763 CONNECT login.yahoo.com:443 badeyek DIRECT/175.16.199.115 -\n")
        self.assertEqual((rows[0]["user"], rows[0]["host"], rows[0]["bytes_in"], rows[0]["method"]), ("badeyek", "login.yahoo.com", 19763, "CONNECT"))

    def test_url_with_spaces_does_not_shift_user(self):
        # The Squid docs: "the log file may contain whitespace for the URI". A blind split() used to blame user 'path'/'b'.
        _, rows = self.conv("1157689340.300 45 10.0.0.9 TCP_MISS/200 2048 GET http://claude.ai/some path with spaces alice DIRECT/1.2.3.4 text/html\n"
                            "1157689341.300 45 10.0.0.9 TCP_MISS/200 900 GET http://example.com/a b c.html - DIRECT/1.2.3.4 text/html\n")
        self.assertEqual([r["user"] for r in rows], ["alice", "10.0.0.9"])  # '-' falls back to client IP
        self.assertEqual([r["host"] for r in rows], ["claude.ai", "example.com"])

    def test_error_aborted_and_garbage_lines_skipped(self):
        res, rows = self.conv("1157689350.400 0 10.0.0.1 NONE_NONE/000 0 - error:transaction-end-before-headers - HIER_NONE/- -\n"
                              "not a log line at all\n"
                              "1157689351.400 1 10.0.0.1 TCP_MISS/200 NaN GET http://x.com/ - DIRECT/1.1.1.1 -\n"
                              "9999999999999999999 1 10.0.0.1 TCP_MISS/200 5 GET http://x.com/ - DIRECT/1.1.1.1 -\n")
        self.assertEqual((res, rows), ({"converted": 0, "skipped": 4}, []))

    def test_missing_or_odd_content_type_and_timeout_hierarchy_and_ipv6(self):
        _, rows = self.conv("1157689370.600 60 10.0.0.2 TCP_MISS/200 700 GET https://Gemini.Google.com/app dave DIRECT/142.250.0.1\n"
                            "1157689380.700 60 10.0.0.3 TCP_MISS/200 700 GET https://poe.com/x erin TIMEOUT_DIRECT/1.2.3.4 :\n"
                            "1157689360.500 60 10.0.0.4 TCP_TUNNEL/200 3000 CONNECT [2001:db8::1]:443 carol DIRECT/2001:db8::1 -\n")
        self.assertEqual([(r["user"], r["host"]) for r in rows], [("dave", "gemini.google.com"), ("erin", "poe.com"), ("carol", "[2001:db8::1]")])

    def test_converted_output_detects_shadow_ai_by_domain_alone(self):
        d = tempfile.mkdtemp()
        _, rows = self.conv("1157689320.100 120 10.0.0.1 TCP_MISS/200 5120 CONNECT chatgpt.com:443 badeyek DIRECT/104.18.32.47 -\n")
        p = os.path.join(d, "x.jsonl")
        open(p, "w").write(json.dumps(rows[0]) + "\n")
        db = pipeline.connect(os.path.join(d, "r.db"))
        pipeline.ingest(db, p, workers=1)
        self.assertEqual(db.execute("SELECT status, is_ai FROM silver_events").fetchone(), ("unsanctioned", 1))
