"""Local scaling benchmark: python3 bench/bench.py [n_users] [workers]"""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from radar import analytics, generate, pipeline  # noqa: E402

if __name__ == "__main__":
    users = int(sys.argv[1]) if len(sys.argv) > 1 else 300
    workers = int(sys.argv[2]) if len(sys.argv) > 2 else None
    d = tempfile.mkdtemp()
    n = generate.generate(d + "/p.jsonl", n_users=users)
    db = pipeline.connect(d + "/r.db")
    t = time.time(); s = pipeline.ingest(db, d + "/p.jsonl", workers); dt = time.time() - t
    print(f"{n:,} events  ingest {dt:.1f}s  ({n / dt:,.0f} ev/s)  {s}")
    t = time.time(); s = pipeline.ingest(db, d + "/p.jsonl", workers)
    print(f"re-run (nothing new): {time.time() - t:.2f}s  {s}")
    with open(d + "/p.jsonl", "a") as f:  # append new data, only that should be read
        f.write(open(d + "/p.jsonl").readline().replace('"event_id": "', '"event_id": "z'))
    print("append 1 line:", pipeline.ingest(db, d + "/p.jsonl", workers))
    t = time.time(); analytics.build_gold(db); analytics.detect(db); print(f"analyze {time.time() - t:.2f}s")
