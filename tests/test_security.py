import http.client
import os
import socket
import stat
import sqlite3
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer

from radar import analytics, audit, backup, detectors, generate, pipeline, serve

try:
    from . import _cleanup  # noqa: F401  (removes temp dirs at exit)
except ImportError:
    import _cleanup  # noqa: F401


def built():
    d = tempfile.mkdtemp()
    log = os.path.join(d, "p.jsonl")
    generate.generate(log)
    db = pipeline.connect(os.path.join(d, "r.db"))
    pipeline.ingest(db, log, workers=2)
    analytics.build_gold(db)
    analytics.persist(db, analytics.detect(db))
    return d, db


class AntiReDoS(unittest.TestCase):
    @staticmethod
    def cpu(text):
        t0 = time.process_time()  # CPU time, not wall-clock: immune to a loaded machine (the old wall-clock test flaked)
        detectors.scan(text)
        return time.process_time() - t0

    def test_adversarial_input_costs_about_as_much_as_harmless_text(self):
        """Calibrated against harmless text measured in the same process, so machine speed and load cancel out (the old
        wall-clock test flaked under load). Scanning is windowed, so a bad regex shows up as a large constant factor, not
        super-linear growth: an unbounded URL-scheme regex made 'a1-a1-…' ~35x slower per character than benign text.
        Fixed code measures ~1.5-3x; the buggy code measured ~20-30x (verified by swapping the old regex back in)."""
        n = 200_000
        benign = min(self.cpu("a" * n), self.cpu("a" * n)) / n
        for unit in ("1", "a1-", "a@", "a-", "1 ", "a.", "a:/", "A1_"):
            # a long run of `unit`, then '://' inside the same 4 KB window so the substring guards let every regex run
            seg = unit * (3500 // len(unit)) + " ://x "
            text = (seg * (n // len(seg) + 1))[:n]
            ratio = self.cpu(text) / n / max(benign, 1e-7)
            self.assertLess(ratio, 10, f"{unit!r} is {ratio:.0f}x slower per char than harmless text")  # fixed ~1.5-3x, buggy ~20-30x

    def test_adversarial_inputs_have_an_absolute_ceiling_too(self):
        for t in ("1" * 200_000, "a1-" * 70_000, "a-" * 100_000, "a." * 100_000):
            self.assertLess(self.cpu(t), 8, f"slow on {t[:6]!r}…")  # generous: protects against gross regressions only

    def test_long_prompt_still_finds_buried_secret_with_absolute_offsets(self):
        key = "AKIA" + "ABCDEFGHIJKLMNOP"  # fake fixture, split so the literal never appears in source (GitHub push protection)
        text = "x " * 6000 + key + " y" * 6000
        f = [x for x in detectors.scan(text) if x[0] == "aws_access_key"]
        self.assertEqual(len(f), 1)
        a, b = f[0][3]
        self.assertEqual(text[a:b], key)

    def test_cards_still_found(self):
        names = [f[0] for f in detectors.scan("card 4111 1111 1111 1111 exp 11/28, other 5555-5555-5555-4444")]
        self.assertEqual(names.count("credit_card"), 2)
        self.assertNotIn("credit_card", [f[0] for f in detectors.scan("order 1234 5678 9012 3456")])


class AuditChain(unittest.TestCase):
    def test_chain_detects_edit_delete_and_truncation(self):
        _, db = built()
        for i in range(4):
            audit.log(db, "alice", "alert_status", f"id{i}", "status=ack")
        ok, n, head, _ = audit.verify(db)
        self.assertTrue(ok)
        self.assertEqual(n, 4)
        db.execute("UPDATE audit_log SET actor='mallory' WHERE id=2"); db.commit()
        self.assertFalse(audit.verify(db)[0])
        db.execute("UPDATE audit_log SET actor='alice' WHERE id=2"); db.commit()
        self.assertTrue(audit.verify(db)[0])
        db.execute("DELETE FROM audit_log WHERE id=2"); db.commit()
        self.assertFalse(audit.verify(db)[0])

    def test_truncation_caught_by_anchored_head(self):
        _, db = built()
        for i in range(3):
            audit.log(db, "a", "x", str(i))
        head = audit.verify(db)[2]
        db.execute("DELETE FROM audit_log WHERE id=3"); db.commit()
        self.assertTrue(audit.verify(db)[0])  # chain alone cannot see tail removal...
        self.assertFalse(audit.verify(db, head)[0])  # ...an anchored head can


class NamedUsersAndLockout(unittest.TestCase):
    def setUp(self):
        self.d, db = built()
        self.aid = analytics.load_alerts(db)[0]["alert_id"]
        s = socket.socket(); s.bind(("127.0.0.1", 0)); self.port = s.getsockname()[1]; s.close()
        users = {"alice": ("analyst", "alice-token-1"), "bob": ("viewer", "bob-token-22")}
        self.srv = ThreadingHTTPServer(("127.0.0.1", self.port), serve.make_handler(os.path.join(self.d, "r.db"), self.port, users))
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown(); self.srv.server_close()

    def req(self, method, path, body=None, tok=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port)
        c.request(method, path, body, {"Authorization": f"Bearer {tok}"} if tok else {})
        r = c.getresponse(); r.read()
        return r.status

    def audit_rows(self):
        return audit.show(sqlite3.connect(os.path.join(self.d, "r.db")), 50)

    def test_actions_attributed_and_chain_valid(self):
        self.assertEqual(self.req("GET", "/", tok="bob-token-22"), 200)
        self.assertEqual(self.req("POST", f"/alerts/{self.aid}", "status=resolved&note=ok", "bob-token-22"), 403)
        self.assertEqual(self.req("POST", f"/alerts/{self.aid}", "status=resolved&note=ok", "alice-token-1"), 303)
        rows = {(r[1], r[2]) for r in self.audit_rows()}
        self.assertIn(("bob", "view_dashboard"), rows)
        self.assertIn(("bob", "denied_write"), rows)
        self.assertIn(("alice", "alert_status"), rows)
        self.assertTrue(audit.verify(sqlite3.connect(os.path.join(self.d, "r.db")))[0])

    def test_lockout_after_repeated_failures(self):
        codes = [self.req("GET", "/api/alerts", tok="wrong") for _ in range(6)]
        self.assertEqual(codes, [401] * 5 + [429])
        self.assertEqual(self.req("GET", "/api/alerts", tok="alice-token-1"), 429)  # even a good token waits out the lock
        self.assertEqual(sum(r[2] == "auth_fail" for r in self.audit_rows()), 5)

    def test_users_from_env(self):
        u = serve.users_from_env({"RADAR_USERS": "alice=analyst:abcdefgh12345678;bob=viewer:short;eve=root:abcdefgh12345678",
                                  "RADAR_VIEWER_TOKEN": "viewer-token-9-long"})
        self.assertEqual(u, {"alice": ("analyst", "abcdefgh12345678"), "viewer": ("viewer", "viewer-token-9-long")})  # weak/invalid rejected


@unittest.skipUnless(os.system("which openssl >/dev/null 2>&1") == 0, "openssl missing")
class Backup(unittest.TestCase):
    def test_roundtrip_wrong_passphrase_and_no_plaintext(self):
        d, db = built()
        audit.log(db, "a", "x")
        dbp = os.path.join(d, "r.db")
        enc = os.path.join(d, "b.enc")
        os.environ[backup.ENV] = "correct horse battery"
        backup.backup(dbp, enc)
        self.assertNotIn(b"SQLite format", open(enc, "rb").read(64))  # really encrypted
        self.assertEqual(oct(os.stat(enc).st_mode & 0o777), "0o600")
        new = os.path.join(d, "restored.db")
        n, _ = backup.restore(enc, new)
        self.assertEqual(n, 1)
        self.assertEqual(sqlite3.connect(new).execute("SELECT COUNT(*) FROM alerts").fetchone()[0], 5)
        os.environ[backup.ENV] = "wrong passphrase!!"
        with self.assertRaises(SystemExit):
            backup.restore(enc, os.path.join(d, "bad.db"))
        self.assertFalse(os.path.exists(os.path.join(d, "bad.db")))
        os.environ[backup.ENV] = "correct horse battery"
        with self.assertRaises(SystemExit):  # refuses to overwrite without --force
            backup.restore(enc, new)


if __name__ == "__main__":
    unittest.main()


class BlockedRequestsAudited(NamedUsersAndLockout):
    def req_h(self, path, headers):
        c = http.client.HTTPConnection("127.0.0.1", self.port)
        c.request("GET", path, None, headers)
        r = c.getresponse(); r.read()
        return r.status

    def test_foreign_host_logged_then_flood_guarded(self):
        codes = [self.req_h("/", {"Host": "evil.com", "Authorization": "Bearer alice-token-1"}) for _ in range(8)]
        self.assertEqual(codes, [403] * 5 + [429] * 3)  # counts toward lockout
        blocked = [r for r in self.audit_rows() if r[2] == "blocked_request"]
        self.assertEqual(len(blocked), 5)  # exactly 5 rows: no unbounded log growth
        self.assertIn("evil.com", blocked[0][4])
        self.assertTrue(audit.verify(sqlite3.connect(os.path.join(self.d, "r.db")))[0])

    def test_log_injection_via_host_header_neutralised(self):
        c = http.client.HTTPConnection("127.0.0.1", self.port)
        c.putrequest("GET", "/", skip_host=True)
        c.putheader("Host", "x.com\tFAKE_ACTOR=alice")
        c.endheaders()
        c.getresponse().read()
        row = [r for r in self.audit_rows() if r[2] == "blocked_request"][0]
        self.assertEqual(row[1], "?")  # attacker text cannot masquerade as an actor
        self.assertTrue(all("\t" not in v and "\n" not in v for v in row))


class ExistingDirTightened(unittest.TestCase):
    def test_paths_fixes_loose_existing_dir(self):
        import argparse
        from radar import __main__ as cli
        d = tempfile.mkdtemp()
        os.chmod(d, 0o775)
        cli._paths(argparse.Namespace(out=d, logs=None))
        self.assertEqual(stat.S_IMODE(os.stat(d).st_mode), 0o700)


class EntropyPrecisionFromRealData(unittest.TestCase):
    """Regression: URL slugs and share links must not raise critical SECRET_LEAK alerts from the entropy detector."""

    def names(self, t):
        return [f[0] for f in detectors.scan(t)]

    def test_url_slugs_and_paths_not_secrets(self):
        for t in ("see https://medium.com/@someauthor/how-to-build-a-scalable-selenium-framework-in-python-guide",
                  "Via https://twitter.com/SomeAccountNameHere/status/ and more",
                  "https://stackoverflow.com/questions/12345678/how-do-i-parse-json-in-python-without-a-library"):
            self.assertEqual(self.names(t), [], t)

    def test_real_looking_secrets_still_caught(self):
        # AWS's published documentation example secret, split so the literal never appears in source (GitHub push protection)
        aws_doc_secret = "aws_secret_access_key=" + "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY"
        self.assertIn("high_entropy_token", self.names(aws_doc_secret))
        self.assertIn("high_entropy_token", self.names("use this: Zk3Qx9LmT2vBn7YpR4sWc8HdJ5aGe1UfXo6NiK0q"))
        self.assertIn("secret_assignment", self.names('api_key = "9f86d081884c7d659a2feaa0c55ad015"'))
        self.assertIn("secret_assignment", self.names("password: k8Jd92LpQ4zX"))

    def test_code_and_placeholders_not_secrets(self):
        for t in ("password = input('enter your password')", "set api_key = YOUR_API_KEY_HERE_123 before running",
                  "token = os.environ['GITHUB_TOKEN']", "the quick brown fox jumps over the lazy dog many times today"):
            self.assertEqual(self.names(t), [], t)

    def test_urls_with_mixed_case_and_ids_not_secrets_but_url_secrets_are(self):
        # realistic URL shapes: author handle (caps) + trailing hex id; share link with random tracking param
        for t in ("https://medium.com/@SomeAuthorName/building-a-selenium-framework-8f3a9c2b1d4e",
                  "Via https://twitter.com/SomeAccountNameHere/status/1234567890123?t=c6P3gH_GtvJ9VMXEmvI-zA"):
            self.assertEqual(self.names(t), [], t)
        self.assertIn("secret_assignment", self.names("curl https://api.example.com/v1?api_key=9f86d081884c7d659a2feaa0c55ad015"))
        self.assertIn("url_credentials", self.names("postgres://admin:S3cr3tP4ssw0rd@db.corp.example.com/app"))


class BootstrapClassifierIsDownWeighted(unittest.TestCase):
    def test_benign_confidential_looking_prompt_cannot_dominate_risk_until_model_is_trained(self):
        import json
        d = tempfile.mkdtemp()
        rec = {"event_id": "e1", "ts": "2026-10-06T10:00:00+00:00", "user": "u", "dept": "d", "host": "chatgpt.com", "bytes_out": 10,
               "bytes_in": 10, "prompt": "analyze our q3 revenue forecast and churn risk for customer acme"}
        log = os.path.join(d, "l.jsonl")
        open(log, "w").write(json.dumps(rec) + "\n")
        db = pipeline.connect(os.path.join(d, "a.db"))
        pipeline.ingest(db, log, workers=1)
        low = db.execute("SELECT sensitivity, risk FROM silver_events").fetchone()
        from radar import model
        mp = os.path.join(d, "m.json")
        model.save(model.train_default(), mp)
        db2 = pipeline.connect(os.path.join(d, "b.db"))
        pipeline.ingest(db2, log, workers=1, model_path=mp)
        full = db2.execute("SELECT sensitivity, risk FROM silver_events").fetchone()
        self.assertLess(low[0], full[0])
        self.assertAlmostEqual(low[0], 0.6 * 0.35, places=2)
        self.assertAlmostEqual(full[0], 0.6, places=2)
