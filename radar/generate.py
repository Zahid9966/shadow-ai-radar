"""Synthetic egress-proxy log generator with planted incidents (ground truth for testing)."""
import hashlib
import json
import random
from datetime import datetime, timedelta, timezone

from . import corpus

START = datetime(2026, 10, 5, tzinfo=timezone.utc)
DAYS = 14
NON_AI = ["github.com", "news.example.org", "docs.python.org", "slack.com", "salesforce.com"]
AI_MIX = [("ai-gateway.corp.example.com", 6), ("copilot.microsoft.com", 3), ("chatgpt.com", 3),
          ("claude.ai", 1), ("gemini.google.com", 1)]
_AWS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def _id(*parts):
    return hashlib.sha1("|".join(map(str, parts)).encode()).hexdigest()[:16]


def generate(path, seed=42, n_users=60, scenario="standard"):
    rng = random.Random(seed)
    users = [{"user": f"u_{d[:3].lower()}_{i:02d}", "dept": d, "ip": f"10.{k % 8}.{i}.{10 + k}"}
             for k, d in enumerate(corpus.DEPTS) for i in range(n_users // len(corpus.DEPTS))]
    by = {u["user"]: u for u in users}
    ev = []

    def add(day, user, host, prompt=None, bytes_out=None, hour=None, tag=None):
        u = by[user]
        ts = START + timedelta(days=day, hours=hour if hour is not None else rng.randint(8, 18),
                               minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
        ev.append({"event_id": _id(len(ev), user, ts.isoformat()), "ts": ts.isoformat(), "user": user,
                   "dept": u["dept"], "src_ip": u["ip"], "host": host, "method": "POST",
                   "bytes_out": bytes_out if bytes_out is not None else int(rng.lognormvariate(8.3, 0.6)),
                   "bytes_in": int(rng.lognormvariate(9, 0.7)), "prompt": prompt, "_truth": tag})

    # --- baseline traffic ---
    hosts, weights = zip(*AI_MIX)
    for day in range(DAYS):
        if (START + timedelta(days=day)).weekday() >= 5:
            continue
        for u in users:
            for _ in range(rng.randint(8, 20)):
                add(day, u["user"], rng.choice(NON_AI))
            for _ in range(rng.randint(0, 6)):
                cat = rng.choices(list(corpus.TEMPLATES), weights=[4, 3, 1, 2])[0]
                add(day, u["user"], rng.choices(hosts, weights)[0], corpus.sample(cat, rng))

    # --- planted incidents ---
    key = "AKIA" + "".join(rng.choice(_AWS) for _ in range(16))
    add(3, "u_eng_02", "chatgpt.com", f"debug this boto3 call, aws_access_key_id='{key}' fails with 403", tag="SECRET_LEAK")
    for _ in range(3):
        add(6, "u_fin_03", "claude.ai", "analyze this attached customer ledger export", bytes_out=40_000_000, hour=22, tag="EXFIL_VOLUME")
    for i in range(3):
        ssn = f"{rng.randint(100, 899)}-{rng.randint(10, 99)}-{rng.randint(1000, 9999)}"
        add(8 + i, "u_hr_01", "poe.com", f"summarize this employee case file, employee ssn {ssn} on leave", tag="PII_LEAK")
    for d in range(7, 11):
        for i in range(6):
            for _ in range(3):
                add(d, f"u_mar_{i:02d}", "freegpt-writer.io", corpus.sample("public", rng), tag="SHADOW_ADOPTION")
    for card in ("4111 1111 1111 1111", "5555-5555-5555-4444"):
        add(11, "u_sup_04", "chatgpt.com", f"customer says charge failed, card {card} exp 11/28, what next", tag="PII_LEAK")

    if scenario == "training":
        _training_extras(add, rng)
    ev.sort(key=lambda e: e["ts"])
    with open(path, "w") as f:
        for e in ev:
            f.write(json.dumps(e) + "\n")
    # corrupt a few lines on purpose so data-quality checks have something to catch
        f.write("{not json\n")
        f.write(json.dumps({"event_id": "bad1", "ts": "yesterday", "user": "x"}) + "\n")
        f.write(json.dumps(ev[0]) + "\n")  # duplicate
    return len(ev)


def _training_extras(add, rng):
    """Extra cases for analyst training: one more true positive and two realistic false positives. Answer key: training.py."""
    for d in range(0, 9):  # give u_leg_01 a daytime baseline so "unusual hours" means something
        for _ in range(4):
            add(d, "u_leg_01", "ai-gateway.corp.example.com", corpus.sample("internal", rng))
    for _ in range(6):
        add(10, "u_leg_01", "chatgpt.com", corpus.sample("confidential", rng), hour=2, tag="OFF_HOURS")
    # FALSE POSITIVE 1: AWS's published documentation example key, pasted to ask what it means
    add(5, "u_eng_05", "chatgpt.com", "what does the example key AKIAIOSFODNN7EXAMPLE in the aws iam docs mean", tag="TRAINING_FP_DOC_KEY")
    # FALSE POSITIVE 2: big upload, but to the SANCTIONED gateway for an approved data-science project
    for _ in range(3):
        add(8, "u_eng_01", "ai-gateway.corp.example.com", "embed the approved public dataset", bytes_out=15_000_000, hour=14, tag="TRAINING_FP_SANCTIONED")
    # DECOY: looks like a card number but fails the Luhn check: must NOT alert
    add(7, "u_sup_02", "chatgpt.com", "order 1234 5678 9012 3456 shipped late, draft an apology", tag="TRAINING_DECOY")
