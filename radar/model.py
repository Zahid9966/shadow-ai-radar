"""Prompt-sensitivity classifier: multinomial Naive Bayes, stdlib only.
Classes: public / internal / confidential / source_code."""
import math
import random
import re
from collections import Counter, defaultdict

from . import corpus

SENSITIVITY = {"public": 0.0, "internal": 0.2, "confidential": 0.6, "source_code": 0.5}
_TOK = re.compile(r"[a-z_]{2,}|=>|==|[{}()\[\];=<>$]")
_SYM = {"=>": "sym_arrow", "==": "sym_eqeq"}


def tokens(text):
    """Words plus code-structure symbols (braces, arrows, ...) which strongly signal source code."""
    return [_SYM.get(t, "sym_" + str(ord(t[0]))) if not t[0].isalpha() and t[0] != "_" else t
            for t in _TOK.findall(text.lower())]


class NaiveBayes:
    def __init__(self):
        self.vocab, self.counts, self.totals, self.docs = set(), defaultdict(Counter), Counter(), Counter()

    def fit(self, rows):
        for text, label in rows:
            self.docs[label] += 1
            for t in tokens(text):
                self.counts[label][t] += 1
                self.totals[label] += 1
                self.vocab.add(t)
        return self

    def predict(self, text):
        """Return (label, probability)."""
        n, v = sum(self.docs.values()), len(self.vocab)
        scores = {}
        for label in self.docs:
            s = math.log(self.docs[label] / n)
            for t in tokens(text):
                s += math.log((self.counts[label][t] + 1) / (self.totals[label] + v))
            scores[label] = s
        m = max(scores.values())
        z = sum(math.exp(s - m) for s in scores.values())
        best = max(scores, key=scores.get)
        return best, math.exp(scores[best] - m) / z


def train_default(seed=7, per_class=300):
    rng = random.Random(seed)
    rows = [(corpus.sample(c, rng), c) for c in corpus.TEMPLATES for _ in range(per_class)]
    return NaiveBayes().fit(rows)


def evaluate(nb, rows):
    """rows: [{text,label}] -> accuracy, per-class precision/recall, confusion pairs."""
    conf = Counter()
    for r in rows:
        conf[(r["label"], nb.predict(r["text"])[0])] += 1
    labels = sorted({a for a, _ in conf} | {b for _, b in conf})
    per = {}
    for c in labels:
        tp = conf[(c, c)]
        pred = sum(n for (a, b), n in conf.items() if b == c)
        true = sum(n for (a, b), n in conf.items() if a == c)
        per[c] = {"precision": round(tp / pred, 2) if pred else 0.0, "recall": round(tp / true, 2) if true else 0.0, "n": true}
    acc = round(sum(n for (a, b), n in conf.items() if a == b) / len(rows), 3)
    return {"accuracy": acc, "per_class": per, "errors": {f"{a}->{b}": n for (a, b), n in conf.items() if a != b}}


def save(nb, path):
    import json
    json.dump({"docs": nb.docs, "counts": {k: dict(v) for k, v in nb.counts.items()}}, open(path, "w"))


def load(path):
    import json
    d = json.load(open(path))
    nb = NaiveBayes()
    nb.docs = Counter(d["docs"])
    for k, v in d["counts"].items():
        nb.counts[k] = Counter(v)
        nb.totals[k] = sum(v.values())
        nb.vocab.update(v)
    return nb


def train_from_labels(rows):
    """Train on real labelled data [{text,label}] (+ the synthetic bootstrap so rare classes keep coverage)."""
    nb = train_default()
    return nb.fit([(r["text"], r["label"]) for r in rows])
