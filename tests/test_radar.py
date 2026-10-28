import json
import os
import tempfile
import unittest

from radar import analytics, catalog, detectors, generate, model, pipeline

try:
    from . import _cleanup  # noqa: F401  (removes temp dirs at exit)
except ImportError:
    import _cleanup  # noqa: F401


class Detectors(unittest.TestCase):
    def test_luhn_filters_random_digits(self):
        self.assertTrue(detectors.luhn_ok("4111 1111 1111 1111"))
        self.assertFalse(detectors.luhn_ok("1234 5678 9012 3456"))
        self.assertEqual(detectors.scan("order 1234567890123456"), [])

    def test_redaction_removes_secret(self):
        t = "key AKIA" + "ABCDEFGHIJKLMNOP" + " here"  # fake fixture, split so the literal never appears in source (GitHub push protection)
        out = detectors.redact(t, detectors.scan(t))
        self.assertNotIn("AKIA", out)
        self.assertIn("[AWS_ACCESS_KEY]", out)


class Catalog(unittest.TestCase):
    def test_classify(self):
        self.assertEqual(catalog.classify("chat.chatgpt.com")[1], "unsanctioned")
        self.assertEqual(catalog.classify("freegpt-writer.io")[1:], ("suspected", True))
        self.assertFalse(catalog.classify("github.com")[2])


class Model(unittest.TestCase):
    def test_classifies_code(self):
        nb = model.train_default()
        self.assertEqual(nb.predict("why does this sql query SELECT * FROM prod_customers time out")[0], "source_code")


class EndToEnd(unittest.TestCase):
    def test_planted_incidents_found_without_false_positives(self):
        d = tempfile.mkdtemp()
        log = os.path.join(d, "p.jsonl")
        generate.generate(log)
        db = pipeline.connect(os.path.join(d, "r.db"))
        stats = pipeline.ingest(db, log)
        self.assertEqual(stats["rejected"], 3)
        analytics.build_gold(db)
        found = {(a["kind"], a["user"]) for a in analytics.detect(db)}
        self.assertEqual(found, {("SECRET_LEAK", "u_eng_02"), ("EXFIL_VOLUME", "u_fin_03"),
                                 ("PII_LEAK", "u_hr_01"), ("PII_LEAK", "u_sup_04"), ("SHADOW_ADOPTION", None)})
        leaked = db.execute("SELECT COUNT(*) FROM silver_events WHERE snippet LIKE '%AKIA%'").fetchone()[0]
        self.assertEqual(leaked, 0)


if __name__ == "__main__":
    unittest.main()
