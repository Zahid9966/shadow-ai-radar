import csv
import os
import stat
import subprocess
import sys
import tempfile
import unittest

from radar import analytics, audit, export, generate, notify, pipeline, report, schedule, training

try:
    from . import _cleanup  # noqa: F401  (removes temp dirs at exit)
except ImportError:
    import _cleanup  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def built(scenario="standard"):
    d = tempfile.mkdtemp()
    log = os.path.join(d, "p.jsonl")
    generate.generate(log, scenario=scenario)
    db = pipeline.connect(os.path.join(d, "r.db"))
    pipeline.ingest(db, log, workers=2)
    analytics.build_gold(db)
    analytics.persist(db, analytics.detect(db))
    return d, db


def alert(**kw):
    a = {"kind": "SECRET_LEAK", "severity": "critical", "user": "u1", "day": "2026-10-08", "title": "t", "evidence": "e",
         "action": "a", "count": 1}
    a.update(kw)
    return a


class Trend(unittest.TestCase):
    def test_weekly_gold_and_report(self):
        _, db = built()
        weeks = db.execute("SELECT week, days, risk FROM gold_week ORDER BY week").fetchall()
        self.assertEqual([w[0] for w in weeks], ["2026-10-05", "2026-10-12"])  # Mondays
        self.assertEqual(sum(w[1] for w in weeks), db.execute("SELECT COUNT(DISTINCT day) FROM silver_events WHERE is_ai=1").fetchone()[0])
        html = report.render(db, analytics.load_alerts(db))
        self.assertIn("Week-over-week trend", html)
        self.assertRegex(html, r"[▲▼] \d+%")
        self.assertIn("normalised per active day", html)


class OffHours(unittest.TestCase):
    def test_standard_data_has_no_off_hours_alert_and_incident_is_correlated(self):
        _, db = built()
        kinds = [a["kind"] for a in analytics.load_alerts(db)]
        self.assertNotIn("OFF_HOURS", kinds)  # u_fin_03's 22:00 burst is folded into its EXFIL alert, not a second alert
        self.assertEqual(len(kinds), 5)
        ex = next(a for a in analytics.load_alerts(db) if a["kind"] == "EXFIL_VOLUME")
        self.assertIn("also outside the user's normal hours", ex["evidence"])

    def test_training_scenario_catches_night_user_and_ignores_decoy(self):
        _, db = built("training")
        al = analytics.load_alerts(db)
        self.assertEqual(len(al), 8)
        self.assertIn(("OFF_HOURS", "u_leg_01"), {(a["kind"], a["user"]) for a in al})
        self.assertNotIn("u_sup_02", {a["user"] for a in al})  # Luhn-invalid number must stay silent

    def test_needs_history_before_calling_something_unusual(self):
        _, db = built()
        # a brand-new user with only night traffic has no baseline -> no alert
        for i in range(5):
            db.execute("INSERT INTO silver_events(event_id,ts,day,user,dept,host,service,status,is_ai,bytes_out,bytes_in,findings,risk,sensitivity)"
                       " VALUES(?,?,?,?,?,?,?,?,1,100,100,'[]',1,0)", (f"n{i}", f"2026-10-07T02:0{i}:00+00:00", "2026-10-07", "newbie", "IT", "chatgpt.com", "ChatGPT", "unsanctioned"))
        db.commit()
        self.assertNotIn("newbie", {a["user"] for a in analytics.detect(db)})


class TrainingMode(unittest.TestCase):
    def test_scoring(self):
        _, db = built("training")
        r = training.score(db)
        self.assertEqual((r["decided"], r["total"], r["decoy_silent"]), (0, 8, True))
        self.assertTrue(all("not triaged" in row[3] for row in r["rows"]))  # nothing spoiled before the analyst decides
        for a in analytics.load_alerts(db):
            truth = training.KEY[(a["kind"], a["user"])][0]
            analytics.set_status(db, a["alert_id"], "resolved" if truth == "TP" else "false_positive")
        r = training.score(db)
        self.assertEqual((r["correct"], r["decided"]), (8, 8))

    def test_wrong_decisions_are_scored_and_explained(self):
        _, db = built("training")
        fp = next(a for a in analytics.load_alerts(db) if a["user"] == "u_eng_05")
        analytics.set_status(db, fp["alert_id"], "resolved")  # treating a doc-example key as a real incident
        r = training.score(db)
        row = next(x for x in r["rows"] if x[1] == "u_eng_05")
        self.assertIs(row[4], False)
        self.assertIn("WRONG", row[3])
        self.assertIn("documentation placeholder", row[3])

    def test_key_matches_what_the_tool_actually_raises(self):
        _, db = built("training")
        self.assertEqual({(a["kind"], a["user"]) for a in analytics.load_alerts(db)}, set(training.KEY))


class CsvExport(unittest.TestCase):
    def test_formula_injection_neutralised_and_audit_rehashable(self):
        d, db = built()
        a = analytics.load_alerts(db)[0]
        analytics.set_status(db, a["alert_id"], "ack", '=HYPERLINK("http://evil","click")')
        audit.log(db, "=cmd|' /C calc'!A0", "x", "@SUM(1)", "+1")
        p = os.path.join(d, "alerts.csv")
        export.alerts_csv(analytics.load_alerts(db), p)
        rows = list(csv.DictReader(open(p)))
        self.assertEqual(len(rows), 5)
        self.assertTrue(next(r for r in rows if r["alert_id"] == a["alert_id"])["note"].startswith("'="))
        self.assertFalse(any(c[:1] in "=+-@" for r in rows for c in r.values() if c))
        ap = os.path.join(d, "audit.csv")
        self.assertEqual(export.audit_csv(db, ap), 1)
        r = next(csv.DictReader(open(ap)))
        self.assertEqual(len(r["hash"]), 64)
        self.assertTrue(r["actor"].startswith("'="))
        self.assertEqual(r["prev_hash"], audit.GENESIS)


class Schedule(unittest.TestCase):
    def test_units_hardened_secret_free_and_nothing_installed(self):
        d = tempfile.mkdtemp()
        out, files = schedule.generate(d, os.path.join(d, "p.jsonl"), os.path.join(d, "radar.env"))
        self.assertEqual(set(files), {"radar-watch.service", "radar-weekly.service", "radar-weekly.timer", "radar.env.example", "crontab.example", "INSTALL.txt"})
        for f in ("radar-watch.service", "radar-weekly.service"):
            t = open(os.path.join(out, f)).read()
            for needle in ("NoNewPrivileges=yes", "ProtectSystem=strict", "UMask=0077", f"ReadWritePaths={d}", "EnvironmentFile=-"):
                self.assertIn(needle, t, f"{f} missing {needle}")
            self.assertNotIn("CHANGE_ME", t)
            self.assertNotIn("RADAR_USERS", t)  # secrets never inside a unit file
        self.assertIn("--notify", open(os.path.join(out, "radar-watch.service")).read())
        system = schedule.generate(d, os.path.join(d, "p.jsonl"), os.path.join(d, "radar.env"), system=True)[0]
        self.assertNotIn("--notify", open(os.path.join(system, "radar-watch.service")).read())  # no session bus for system units
        self.assertTrue(open(os.path.join(out, "radar-weekly.service")).read().rstrip().split("ExecStart=")[-1].split("\n")[0].endswith("doctor"))

    def test_refuses_paths_systemd_would_misparse(self):
        base = tempfile.mkdtemp()
        with self.assertRaises(SystemExit):
            schedule.generate(os.path.join(base, "has space"), os.path.join(base, "p"), os.path.join(base, "e"))
        with self.assertRaises(SystemExit):
            schedule.generate(base, os.path.join(base, "p"), "/etc/radar/%h.env")


class Notifications(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.out = os.path.join(self.d, "args.txt")
        bin_ = os.path.join(self.d, "bin")
        os.makedirs(bin_)
        fake = os.path.join(bin_, "notify-send")
        open(fake, "w").write('#!/bin/sh\nprintf "%s\\n" "$@" > "$NOTIFY_OUT"\n')
        os.chmod(fake, 0o755)
        self.env = {k: os.environ.get(k) for k in ("PATH", "DISPLAY", "NOTIFY_OUT")}
        os.environ.update(PATH=bin_ + os.pathsep + os.environ["PATH"], DISPLAY=":0", NOTIFY_OUT=self.out)
        _, self.db = built()

    def tearDown(self):
        for k, v in self.env.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)

    def test_hostile_text_is_inert_and_each_alert_notified_once(self):
        pwn = os.path.join(self.d, "PWNED")
        analytics.persist(self.db, [alert(title=f"$(touch {pwn}) `touch {pwn}2` -u low\n\x1b[31mred", alert_id=None)])
        n = notify.dispatch(self.db, self.d)
        self.assertEqual(n, 5)  # the demo's 1 critical + 3 high, plus the hostile one we just added
        self.assertFalse(os.path.exists(pwn) or os.path.exists(pwn + "2"))  # no shell ever saw the text
        args = open(self.out).read().split("\n")
        self.assertIn("--", args)  # option-injection stop
        self.assertEqual(args.index("--") + 1, args.index("Shadow-AI Radar", args.index("--")))
        body = args[args.index("--") + 2]
        self.assertTrue(all(c.isprintable() for c in body))
        self.assertEqual(notify.dispatch(self.db, self.d), 0)  # never repeats
        log = open(os.path.join(self.d, "notifications.log")).read()
        self.assertIn("desktop", log)
        self.assertNotIn("u1", body)  # user is not put in the popup

    def test_only_critical_and_high_and_terminal_fallback(self):
        os.environ.pop("DISPLAY"); os.environ.pop("WAYLAND_DISPLAY", None); os.environ.pop("DBUS_SESSION_BUS_ADDRESS", None)
        sev = {a["severity"] for a in notify.pending(self.db)}
        self.assertEqual(sev, {"critical", "high"})  # the medium SHADOW_ADOPTION alert is not pushed
        notify.dispatch(self.db, self.d)
        self.assertIn("terminal", open(os.path.join(self.d, "notifications.log")).read())
        self.assertFalse(os.path.exists(self.out))


if __name__ == "__main__":
    unittest.main()
