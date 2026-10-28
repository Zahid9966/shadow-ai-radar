"""Active-learning labeller: shows the prompts the model is LEAST sure about first, so each label teaches it the most.
Works on stored (already redacted) snippets, so labellers never see raw secrets/PII."""
import json
import os

KEYS = {"p": "public", "i": "internal", "c": "confidential", "s": "source_code"}


def candidates(db, labelled_ids, n):
    seen, out = set(), []
    for eid, snip, cat, p in db.execute(
            "SELECT event_id, snippet, category, category_p FROM silver_events "
            "WHERE is_ai=1 AND snippet IS NOT NULL AND snippet!='' ORDER BY category_p ASC"):
        if eid in labelled_ids or snip in seen:
            continue
        seen.add(snip)
        out.append((eid, snip, cat, p))
        if len(out) == n:
            break
    return out


def run(db, path, n=25, inp=input, out=print):
    """Interactive loop. Returns number of new labels. inp/out injectable for tests."""
    done = set()
    if os.path.exists(path):
        done = {json.loads(l).get("event_id") for l in open(path) if l.strip()}
    added = 0
    with open(path, "a") as f:
        for eid, snip, cat, p in candidates(db, done, n):
            out(f"\n{snip}\n  model says: {cat} ({p:.0%})")
            while True:
                k = inp("  [p]ublic [i]nternal [c]onfidential [s]ource_code  s[k]ip  [q]uit > ").strip().lower()
                if k in KEYS or k in ("k", "q"):
                    break
            if k == "q":
                break
            if k == "k":
                continue
            f.write(json.dumps({"event_id": eid, "text": snip, "label": KEYS[k]}) + "\n")
            f.flush()
            added += 1
    return added


def stats(path):
    from collections import Counter
    c = Counter(json.loads(l)["label"] for l in open(path) if l.strip()) if os.path.exists(path) else Counter()
    return dict(c), sum(c.values())
