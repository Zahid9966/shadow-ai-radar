import argparse
import os
import sqlite3
import time

import getpass
import json
from datetime import datetime, timezone

from . import adapters, analytics, audit, backup, catalog, compliance, notify, privacy, schedule, training, export, generate, labeling, model, pipeline, report, serve, triage


def _actor():
    return "cli:" + getpass.getuser()


def _paths(a):
    os.makedirs(a.out, mode=0o700, exist_ok=True)
    try:
        if os.stat(a.out).st_mode & 0o077:
            os.chmod(a.out, 0o700)  # makedirs' mode only applies to NEW dirs; tighten a pre-existing one
    except PermissionError:
        raise SystemExit(f"{a.out} is group/world accessible and not owned by you; fix its permissions first")
    return os.path.join(a.out, "radar.db"), a.logs or os.path.join(a.out, "proxy.jsonl")


def _policy(a):
    if a.policy:
        analytics.configure(catalog.load_policy(a.policy))


def cycle(a, db, logs, retain=True):
    privacy.check_key()
    stats = pipeline.ingest(db, logs, a.workers, a.policy, a.model)
    if retain and analytics.RETENTION_DAYS:
        stats["expired"] = pipeline.retain(db, analytics.RETENTION_DAYS)
    analytics.build_gold(db)
    analytics.persist(db, analytics.detect(db))
    return stats


def cmd_run(a):
    dbp, logs = _paths(a)
    _policy(a)
    if not a.logs and (a.rebuild or not os.path.exists(logs)):
        print(f"generated {generate.generate(logs)} synthetic events")
    db = pipeline.connect(dbp, rebuild=a.rebuild)
    print("ingest:", cycle(a, db, logs, retain=bool(a.logs)))  # synthetic demo data is dated, not "now"
    alerts = analytics.load_alerts(db)
    for x in alerts:
        print(f"[{x['severity']:8}] {x['alert_id']} {x['kind']:16} {x['day']} {x['user'] or '-':10} {x['status']:6} {x['title']}")
    report.render(db, alerts, os.path.join(a.out, "report.html"))
    print("report:", os.path.join(a.out, "report.html"))


def cmd_watch(a):
    dbp, logs = _paths(a)
    _policy(a)
    db = pipeline.connect(dbp)
    n = 0
    while True:
        s = cycle(a, db, logs)
        print(time.strftime("%H:%M:%S"), "cycle:", s, "| open alerts:", len(analytics.load_alerts(db, "open")), flush=True)
        if a.notify:
            notify.dispatch(db, a.out)
        n += 1
        if a.max_cycles and n >= a.max_cycles:
            return
        time.sleep(a.interval)


def cmd_alerts(a):
    db = sqlite3.connect(_paths(a)[0])
    for x in analytics.load_alerts(db, a.status):
        print(f"{x['alert_id']} {x['severity']:8} {x['status']:14} {x['user'] or '-':10} {x['title']}")


def cmd_ack(a):
    db = sqlite3.connect(_paths(a)[0])
    ok = analytics.set_status(db, a.alert_id, a.status, a.note)
    if ok:
        audit.log(db, _actor(), "alert_status", a.alert_id, f"status={a.status} note={a.note}")
    print("updated" if ok else "no such alert")


def cmd_triage(a):
    db = sqlite3.connect(_paths(a)[0])
    hit = [x for x in analytics.load_alerts(db) if x["alert_id"] == a.alert_id]
    if not hit:
        return print("no such alert")
    text, src = triage.summarize(hit[0])
    print(f"({src})\n{text}")


def cmd_export(a):
    dbp, _ = _paths(a)
    db = sqlite3.connect(dbp)
    hosts = export.blocklist(db, os.path.join(a.out, "blocklist.txt"))
    n = export.siem(analytics.load_alerts(db), os.path.join(a.out, "siem_alerts.jsonl"))
    audit.log(db, _actor(), "export", a.out, f"{hosts} hosts, {n} alerts")
    print("blocklist:", hosts, "hosts")
    print("siem:", n, "alerts")


def cmd_export_csv(a):
    dbp, _ = _paths(a)
    db = sqlite3.connect(dbp)
    na = export.alerts_csv(analytics.load_alerts(db), os.path.join(a.out, "alerts.csv"))
    nl = export.audit_csv(db, os.path.join(a.out, "audit_log.csv"))
    audit.log(db, _actor(), "export_csv", a.out, f"{na} alerts, {nl} audit rows")
    print(f"alerts.csv: {na} rows, audit_log.csv: {nl} rows -> {a.out}")


def cmd_schedule(a):
    d, files = schedule.generate(a.out, a.logs or os.path.join(a.out, "proxy.jsonl"), a.env_file, a.system, a.interval)
    print(f"wrote {len(files)} files to {d} (nothing installed):")
    print("  " + "\n  ".join(files))
    print(f"read {d}/INSTALL.txt next")


def cmd_training(a):
    dbp, logs = _paths(a)
    _policy(a)
    if a.action == "start":
        print(f"generated {generate.generate(logs, scenario='training')} events with 8 hidden cases (6 real incidents, 2 false positives, 1 decoy)")
        db = pipeline.connect(dbp, rebuild=True)
        print("ingest:", cycle(a, db, logs, retain=False))
        report.render(db, analytics.load_alerts(db), os.path.join(a.out, "report.html"))
        print(f"\nYour task: triage every alert. Real incidents -> ack or resolved. False positives -> false_positive.\n"
              f"  python3 -m radar --out {a.out} serve        (dashboard; needs RADAR_USERS, or --allow-open)\n"
              f"  python3 -m radar --out {a.out} alerts / ack <id> <status>   (or use the CLI)\n"
              f"  python3 -m radar --out {a.out} training score")
        return
    db = sqlite3.connect(dbp)
    res = training.score(db)
    for kind, user, status, msg, good in res["rows"]:
        mark = {True: "✔", False: "✘", None: "·"}[good]
        print(f" {mark} {kind:16} {str(user or '-'):10} [{status:14}] {msg}")
    print(f"\nscore: {res['correct']}/{res['decided']} decided correctly, {res['total'] - res['decided']} not triaged yet; "
          f"decoy {'correctly silent' if res['decoy_silent'] else 'WRONGLY ALERTED'}")


def cmd_serve(a):
    users = serve.users_from_env(os.environ)
    if not users and not a.allow_open:
        raise SystemExit("refusing to start without logins. Set RADAR_USERS (tokens >= 16 chars) "
                         "or pass --allow-open for a throwaway local demo.")
    serve.serve(_paths(a)[0], a.port, users)


def cmd_convert(a):
    print(adapters.convert(a.format, a.src, a.dst, a.identity))


def cmd_identity(a):
    db = sqlite3.connect(_paths(a)[0])
    n = analytics.load_identity(db, a.csv)
    audit.log(db, _actor(), "identity_load", a.csv, f"{n} rows")
    print("identities loaded:", n)


def cmd_purge(a):
    db = sqlite3.connect(_paths(a)[0])
    n = pipeline.purge(db, a.before)
    audit.log(db, _actor(), "purge", a.before, f"{n} events deleted")
    print("events deleted:", n)


def cmd_eval(a):
    nb = model.load(a.model) if a.model else model.train_default()
    print(json.dumps(model.evaluate(nb, [json.loads(l) for l in open(a.data)]), indent=1))


def cmd_label(a):
    db = sqlite3.connect(_paths(a)[0])
    n = labeling.run(db, a.file, a.n)
    by_class, total = labeling.stats(a.file)
    print(f"added {n}; total {total} labels {by_class}")
    if total < 500:
        print(f"pilot gate needs >= 500 labels ({500 - total} to go)")


def cmd_audit(a):
    db = sqlite3.connect(_paths(a)[0])
    anchors = os.path.join(a.out, "audit_anchors.txt")
    if a.what == "anchor":
        ok, n, head, why = audit.verify(db)
        if not ok:
            raise SystemExit(f"refusing to anchor a broken chain: {why}")
        with open(anchors, "a") as f:
            f.write(f"{datetime.now(timezone.utc).isoformat(timespec='seconds')} rows={n} head={head}\n")
        print(f"anchored rows={n} head={head}\nCopy {anchors} OFF this machine (ticket, email, WORM storage).")
        return
    if a.what == "verify":
        anchor = None
        if a.against and os.path.exists(a.against):
            last = open(a.against).read().strip().splitlines()[-1].split()
            anchor = (int(last[1].split("=")[1]), last[2].split("=")[1])
        ok, n, head, why = audit.verify(db, a.head, anchor)
        print(f"{'OK' if ok else 'FAILED: ' + why}  rows={n}  head={head}")
        raise SystemExit(0 if ok else 1)
    for ts, actor, action, target, detail in reversed(audit.show(db, a.n)):
        print(f"{ts}  {actor:14} {action:14} {target:12} {detail}")


def cmd_dsr(a):
    db = sqlite3.connect(_paths(a)[0])
    ref = privacy.subject_ref(a.user)
    if a.action == "export":
        path = os.path.join(a.out, f"dsr_{ref}.json")
        privacy.dump(db, a.user, path)
        audit.log(db, _actor(), "dsr_export", ref)
        print("written:", path)
    else:
        if not a.yes:
            raise SystemExit("erasure is irreversible; re-run with --yes after your DPO has approved the request")
        res = privacy.erase_subject(db, a.user)
        audit.log(db, _actor(), "dsr_erase", ref, json.dumps(res))
        print("erased:", res)


def cmd_reveal(a):
    who = privacy.reveal(a.pseudonym, a.hr)
    db = sqlite3.connect(_paths(a)[0])
    audit.log(db, _actor(), "reveal", a.pseudonym, "re-identification " + ("succeeded" if who else "found no match"))
    print(who or "no match in that HR file")


def cmd_doctor(a):
    db = sqlite3.connect(_paths(a)[0])
    res = compliance.doctor(db, a.out)
    for s, c, d in res:
        print(f"{s:5} {c:30} {d}")
    raise SystemExit(1 if any(s == compliance.FAIL for s, _, _ in res) else 0)


def cmd_evidence(a):
    db = sqlite3.connect(_paths(a)[0])
    d, fails = compliance.evidence(db, a.out)
    audit.log(db, _actor(), "evidence_snapshot", d)
    print("evidence written to", d, f"({fails} failing checks)")


def cmd_backup(a):
    dbp = _paths(a)[0]
    backup.backup(dbp, a.to)
    audit.log(sqlite3.connect(dbp), _actor(), "backup", a.to)
    print("encrypted backup:", a.to)


def cmd_restore(a):
    n, head = backup.restore(a.src, _paths(a)[0], a.force)
    db = sqlite3.connect(_paths(a)[0])
    audit.log(db, _actor(), "restore", a.src, f"audit rows={n}")
    print(f"restored; audit chain verified ({n} rows, head {head[:12]}…)")


def cmd_train(a):
    nb = model.train_from_labels([json.loads(l) for l in open(a.labels)])
    model.save(nb, a.save)
    print("model saved:", a.save)


def main():
    os.umask(0o077)  # everything we create (db, labels, exports, reports) is owner-only
    ap = argparse.ArgumentParser(prog="radar", description="Shadow-AI Radar")
    ap.add_argument("--out", default="out")
    ap.add_argument("--logs", help="JSONL proxy logs; omit to generate a synthetic demo set")
    ap.add_argument("--policy", help="policy JSON (see config/policy.json)")
    ap.add_argument("--workers", type=int, help="parallel workers (default: all cores)")
    ap.add_argument("--model", help="trained model JSON (from `radar train`); default: synthetic bootstrap model")
    sub = ap.add_subparsers(dest="cmd")
    r = sub.add_parser("run", help="ingest + detect + report (default)")
    r.add_argument("--rebuild", action="store_true", help="drop DB and reprocess from scratch")
    r.set_defaults(fn=cmd_run)
    w = sub.add_parser("watch", help="repeat ingest+detect on an interval")
    w.add_argument("--interval", type=int, default=30)
    w.add_argument("--max-cycles", type=int, default=0)
    w.add_argument("--notify", action="store_true", help="desktop/terminal notification for new critical/high alerts")
    w.set_defaults(fn=cmd_watch)
    l = sub.add_parser("alerts", help="list alerts")
    l.add_argument("--status", choices=analytics.STATUSES)
    l.set_defaults(fn=cmd_alerts)
    k = sub.add_parser("ack", help="set alert status")
    k.add_argument("alert_id")
    k.add_argument("status", choices=analytics.STATUSES)
    k.add_argument("--note", default="")
    k.set_defaults(fn=cmd_ack)
    t = sub.add_parser("triage", help="AI summary + next steps for an alert")
    t.add_argument("alert_id")
    t.set_defaults(fn=cmd_triage)
    sub.add_parser("export", help="write proxy blocklist + SIEM JSONL").set_defaults(fn=cmd_export)
    s = sub.add_parser("serve", help="localhost triage dashboard")
    s.add_argument("--port", type=int, default=8765)
    s.add_argument("--allow-open", action="store_true", help="start WITHOUT logins (demo only)")
    s.set_defaults(fn=cmd_serve)
    c = sub.add_parser("convert", help="convert squid/csv proxy logs to Radar JSONL")
    c.add_argument("format", choices=("squid", "csv"))
    c.add_argument("src")
    c.add_argument("dst")
    c.add_argument("--identity", help="HR CSV: user,dept,manager,email[,ip]")
    c.set_defaults(fn=cmd_convert)
    i = sub.add_parser("identity", help="load HR/IdP CSV so alerts show managers")
    i.add_argument("csv")
    i.set_defaults(fn=cmd_identity)
    pg = sub.add_parser("purge", help="retention: delete events older than a date (alerts kept)")
    pg.add_argument("--before", required=True, help="YYYY-MM-DD")
    pg.set_defaults(fn=cmd_purge)
    ev = sub.add_parser("eval", help="measure classifier precision/recall on a labelled JSONL")
    ev.add_argument("--data", default="eval/test.jsonl")
    ev.set_defaults(fn=cmd_eval)
    lb = sub.add_parser("label", help="label least-confident prompts (active learning)")
    lb.add_argument("--file", default="out/labels.jsonl")
    lb.add_argument("-n", type=int, default=25)
    lb.set_defaults(fn=cmd_label)
    sub.add_parser("export-csv", help="alerts.csv + audit_log.csv for auditors (formula-injection safe)").set_defaults(fn=cmd_export_csv)
    sc = sub.add_parser("schedule", help="generate systemd units / cron lines (nothing is installed)")
    sc.add_argument("--env-file", default="/etc/radar/radar.env")
    sc.add_argument("--system", action="store_true", help="system-wide units (default: per-user)")
    sc.add_argument("--interval", type=int, default=60)
    sc.set_defaults(fn=cmd_schedule)
    tn = sub.add_parser("training", help="analyst training scenario with a hidden answer key")
    tn.add_argument("action", choices=("start", "score"))
    tn.set_defaults(fn=cmd_training)
    ds = sub.add_parser("dsr", help="data-subject request: export or erase everything held about one person")
    ds.add_argument("action", choices=("export", "erase"))
    ds.add_argument("user")
    ds.add_argument("--yes", action="store_true")
    ds.set_defaults(fn=cmd_dsr)
    rv = sub.add_parser("reveal", help="re-identify a pseudonym using the HR list (audited)")
    rv.add_argument("pseudonym")
    rv.add_argument("--hr", required=True)
    rv.set_defaults(fn=cmd_reveal)
    sub.add_parser("doctor", help="security/privacy posture self-check").set_defaults(fn=cmd_doctor)
    sub.add_parser("evidence", help="write an auditor-ready evidence snapshot").set_defaults(fn=cmd_evidence)
    au = sub.add_parser("audit", help="show or verify the tamper-evident audit log")
    au.add_argument("what", choices=("show", "verify", "anchor"))
    au.add_argument("--against", help="anchors file written by `audit anchor` (verify against its latest entry)")
    au.add_argument("-n", type=int, default=20)
    au.add_argument("--head", help="anchored head hash to compare against")
    au.set_defaults(fn=cmd_audit)
    bk = sub.add_parser("backup", help=f"encrypted DB backup (needs {backup.ENV})")
    bk.add_argument("--to", required=True)
    bk.set_defaults(fn=cmd_backup)
    rs = sub.add_parser("restore", help="restore an encrypted backup (verifies integrity + audit chain)")
    rs.add_argument("src")
    rs.add_argument("--force", action="store_true")
    rs.set_defaults(fn=cmd_restore)
    tr = sub.add_parser("train", help="train classifier on labelled JSONL {text,label}")
    tr.add_argument("labels")
    tr.add_argument("--save", default="out/model.json")
    tr.set_defaults(fn=cmd_train)
    a = ap.parse_args()
    if not a.cmd:
        a = ap.parse_args(["--out", a.out] + (["--logs", a.logs] if a.logs else []) + (["--policy", a.policy] if a.policy else []) + (["--model", a.model] if a.model else []) + ["run"])
    a.fn(a)


if __name__ == "__main__":
    main()
