"""Medallion pipeline on SQLite: bronze (raw) -> silver (validated, enriched, redacted) -> gold (aggregates).
Raw prompt text is NEVER persisted: silver stores only redacted snippets.

Scaling design (local):
  * enrich_chunk() is a pure function  lines -> (rows, rejects) and is the unit of parallelism (process pool).
  * Storage is isolated in connect()/_write(), so the detection logic never touches SQL directly.
  * Ingest is incremental: byte offset checkpoint per file, so re-runs (or `radar watch`) read only new data.
"""
import json
import os
import sqlite3
from collections import deque
from datetime import datetime
from multiprocessing import Pool

from . import catalog, detectors, model, privacy

SCHEMA = """
PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;
CREATE TABLE IF NOT EXISTS silver_events(event_id TEXT PRIMARY KEY, ts TEXT, day TEXT, user TEXT, dept TEXT, host TEXT,
  service TEXT, status TEXT, is_ai INT, bytes_out INT, bytes_in INT, category TEXT, category_p REAL,
  findings TEXT, snippet TEXT, sensitivity REAL, risk REAL);
CREATE INDEX IF NOT EXISTS ix_silver_ai_day ON silver_events(is_ai, day);
CREATE TABLE IF NOT EXISTS dq_rejects(line_no INT, reason TEXT, raw TEXT);
CREATE TABLE IF NOT EXISTS ingest_state(path TEXT PRIMARY KEY, byte_offset INT, line_no INT);
"""
REQUIRED = ("event_id", "ts", "user", "dept", "host", "bytes_out", "bytes_in")
CHUNK = 5000
_nb = None
_validated = False
BOOTSTRAP_WEIGHT = 0.35  # the synthetic bootstrap classifier scored 62% on real prompts (below a 80% 'always public' baseline)


def connect(path, rebuild=False):
    if rebuild and os.path.exists(path):
        os.remove(path)
    db = sqlite3.connect(path)
    db.executescript(SCHEMA)
    return db


def _validate(rec):
    miss = [k for k in REQUIRED if rec.get(k) in (None, "")]
    if miss:
        return f"missing:{','.join(miss)}"
    try:
        datetime.fromisoformat(rec["ts"].replace("Z", "+00:00"))  # py<3.11 rejects a bare Z
    except (ValueError, TypeError):
        return "bad_timestamp"
    if not all(isinstance(rec[k], int) and rec[k] >= 0 for k in ("bytes_out", "bytes_in")):
        return "bad_bytes"
    return None


def _init_worker(policy=None, model_path=None, pseudo_key=None):
    global _nb, _validated
    _validated = bool(model_path)  # only a model the operator trained/loaded earns full weight
    if pseudo_key:  # explicit hand-off: pooled/forkserver workers may predate the parent's env change
        os.environ["RADAR_PSEUDO_KEY"] = pseudo_key
    else:
        os.environ.pop("RADAR_PSEUDO_KEY", None)
    if policy:
        catalog.load_policy(policy)  # workers are fresh processes: re-apply policy in each
    _nb = model.load(model_path) if model_path else model.train_default()


def enrich_chunk(args):
    """Pure CPU work: (start_line_no, [raw lines]) -> (rows, rejects)."""
    global _nb
    if _nb is None:
        _init_worker()
    start, lines = args
    rows, rejects = [], []
    for i, line in enumerate(lines):
        n = start + i
        try:
            rec = json.loads(line)
            reason = _validate(rec)
        except (json.JSONDecodeError, UnicodeDecodeError):
            rec, reason = None, "malformed_json"
        if reason:
            rejects.append((n, reason, line[:200].decode("utf-8", "replace")))
            continue
        service, status, is_ai = catalog.classify(rec["host"])
        prompt = rec.get("prompt") or ""
        fnd = detectors.scan(prompt) if prompt else []
        cat, p = _nb.predict(prompt) if prompt else (None, None)
        sens = max([f[1] for f in fnd] + [model.SENSITIVITY.get(cat, 0.0) * (1.0 if _validated else BOOTSTRAP_WEIGHT)])
        risk = round(100 * catalog.STATUS_WEIGHT[status] * (0.15 + 0.85 * sens), 1) if is_ai else 0.0
        rows.append((n, (rec["event_id"], rec["ts"], rec["ts"][:10], privacy.pseudonym(rec["user"]), rec["dept"], rec["host"], service,
                         status, int(is_ai), rec["bytes_out"], rec["bytes_in"], cat, p,
                         json.dumps(sorted({f[0] for f in fnd})),
                         detectors.redact(prompt, fnd)[:160] if prompt else None, sens, risk)))
    return rows, rejects


def _chunks(path, offset, line_no):
    """Yield (start_line, lines, end_offset); only complete (newline-terminated) lines are consumed."""
    with open(path, "rb") as f:
        f.seek(offset)
        buf, start, pos = [], line_no + 1, offset
        for line in f:
            if not line.endswith(b"\n"):
                break  # partial trailing write; pick it up next run
            buf.append(line)
            pos += len(line)
            if len(buf) == CHUNK:
                yield start, buf, pos
                start, buf = start + len(buf), []
        if buf:
            yield start, buf, pos


def _write(db, path, rows, rejects, end_offset, last_line, stats):
    for n, r in rows:
        cur = db.execute("INSERT OR IGNORE INTO silver_events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", r)
        if cur.rowcount:
            stats["loaded"] += 1
        else:
            rejects.append((n, "duplicate", r[0]))
    db.executemany("INSERT INTO dq_rejects VALUES(?,?,?)", rejects)
    stats["rejected"] += len(rejects)
    db.execute("INSERT OR REPLACE INTO ingest_state VALUES(?,?,?)", (path, end_offset, last_line))
    db.commit()  # one transaction per chunk: crash-safe, resumable


def ingest(db, path, workers=None, policy=None, model_path=None):
    """Incremental, parallel ingest. Returns stats for THIS run."""
    workers = workers or os.cpu_count() or 1
    path = os.path.abspath(path)
    row = db.execute("SELECT byte_offset, line_no FROM ingest_state WHERE path=?", (path,)).fetchone()
    offset, line_no = row or (0, 0)
    stats = {"read": 0, "loaded": 0, "rejected": 0}
    pending = deque()

    def drain(block):
        while pending and (block or pending[0][0].ready()):
            res, end, last = pending.popleft()
            rows, rejects = res.get()
            _write(db, path, rows, rejects, end, last, stats)

    with Pool(workers, initializer=_init_worker, initargs=(policy, model_path, os.environ.get("RADAR_PSEUDO_KEY"))) as pool:
        for start, lines, end in _chunks(path, offset, line_no):
            stats["read"] += len(lines)
            pending.append((pool.apply_async(enrich_chunk, ((start, lines),)), end, start + len(lines) - 1))
            if len(pending) >= workers * 2:  # bounded memory: never read far ahead of the writers
                drain(False)
                if len(pending) >= workers * 2:
                    res, end, last = pending.popleft()
                    _write(db, path, *res.get(), end, last, stats)
        drain(True)
    return stats


def purge(db, before_day):
    """Retention: delete event-level data older than before_day (YYYY-MM-DD). Alerts (the audit trail) are kept."""
    n = db.execute("DELETE FROM silver_events WHERE day < ?", (before_day,)).rowcount
    db.execute("DELETE FROM dq_rejects")
    db.commit()
    if n:
        db.execute("VACUUM")
    return n


def retain(db, days, today=None):
    """Automatic retention (GDPR Art. 5(1)(e)): drop events older than `days` days. Returns rows deleted."""
    from datetime import date, timedelta
    return purge(db, ((today or date.today()) - timedelta(days=days)).isoformat())
