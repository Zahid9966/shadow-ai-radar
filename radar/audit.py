"""Tamper-evident audit log: each row's hash covers the previous row's hash (hash chain).
Editing or deleting a past row breaks verification. Someone who can rewrite the WHOLE database can rebuild the chain,
so record `radar audit verify` head hashes somewhere else (ticket, email, printout) to anchor it."""
import hashlib
import json
from datetime import datetime, timezone

DDL = """CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, actor TEXT, action TEXT,
  target TEXT, detail TEXT, prev_hash TEXT, hash TEXT)"""
GENESIS = "0" * 64


def _h(prev, ts, actor, action, target, detail):
    return hashlib.sha256((prev + json.dumps([ts, actor, action, target, detail])).encode()).hexdigest()


def log(db, actor, action, target="", detail=""):
    db.execute(DDL)
    try:
        db.execute("BEGIN IMMEDIATE")  # serialize concurrent writers so the chain never forks
    except Exception:
        pass  # already inside a transaction
    row = db.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    prev = row[0] if row else GENESIS
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    clean = lambda v, n: "".join(c if c.isprintable() else " " for c in str(v))[:n]  # no log injection via newlines
    actor, action, target, detail = clean(actor, 64), clean(action, 64), clean(target, 128), clean(detail, 300)
    db.execute("INSERT INTO audit_log(ts,actor,action,target,detail,prev_hash,hash) VALUES(?,?,?,?,?,?,?)",
               (ts, actor, action, target, detail, prev, _h(prev, ts, actor, action, target, detail)))
    db.commit()


def verify(db, expected_head=None, anchor=None):
    """Return (ok, rows_checked, head_hash, problem).
    expected_head: the chain must END at this hash. anchor=(rows, hash): row number `rows` must have this hash, which
    still holds after later entries are appended (use for periodic off-box anchors)."""
    db.execute(DDL)
    prev, n = GENESIS, 0
    for id_, ts, actor, action, target, detail, p, h in db.execute(
            "SELECT id,ts,actor,action,target,detail,prev_hash,hash FROM audit_log ORDER BY id"):
        n += 1
        if p != prev or h != _h(prev, ts, actor, action, target, detail):
            return False, n, prev, f"chain broken at row id={id_}"
        prev = h
        if anchor and n == anchor[0] and h != anchor[1]:
            return False, n, prev, f"history before row {n} differs from the anchored hash"
    if anchor and n < anchor[0]:
        return False, n, prev, f"log has {n} rows but anchor was taken at {anchor[0]} (rows removed)"
    if expected_head and expected_head != prev:
        return False, n, prev, "head hash does not match the anchored value (rows removed from the end?)"
    return True, n, prev, None


def show(db, n=20):
    db.execute(DDL)
    return db.execute("SELECT ts,actor,action,target,detail FROM audit_log ORDER BY id DESC LIMIT ?", (n,)).fetchall()
