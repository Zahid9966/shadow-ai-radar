"""Content inspection: secrets and PII. Pure stdlib, regex + Luhn + entropy."""
import math
import re
from collections import Counter

# name -> (regex, severity 0..1, kind)
PATTERNS = {
    "aws_access_key": (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 1.0, "secret"),
    "private_key": (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), 1.0, "secret"),
    "api_token": (re.compile(r"\b(?:ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{20,}|xox[bp]-[A-Za-z0-9-]{10,})\b"), 1.0, "secret"),
    "url_credentials": (re.compile(r"\b[a-z][a-z0-9+.-]{1,15}://[^/\s:@]{1,64}:[^/\s@]{3,128}@[\w.-]{1,128}"), 0.9, "secret"),
    "ssn": (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), 0.9, "pii"),
    "internal_host": (re.compile(r"\b[\w-]{1,63}\.corp\.example\.com\b"), 0.3, "internal"),
    "email": (re.compile(r"\b[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63}){1,5}\b"), 0.1, "pii"),
}
# Literal text each pattern needs in order to match at all. Checked before running the regex (performance + ReDoS hardening).
_GUARD = {"aws_access_key": ("AKIA", "ASIA"), "private_key": ("-----BEGIN",), "api_token": ("ghp_", "sk-", "xox"),
          "url_credentials": ("://",), "ssn": ("-",), "internal_host": (".corp.example.com",), "email": ("@",)}
_ASSIGN_HINTS = ("key", "secret", "token", "pass", "bearer")
_URL = re.compile(r"\b[a-z][a-z0-9+.-]{1,15}://[^\s'\"<>)\]]{1,2048}")  # scheme length is bounded: an unbounded one is quadratic on "a-a-a-…"
_TOKEN = re.compile(r"[A-Za-z0-9+/_\-]{24,}")
_ASSIGN = re.compile(r"(?i)\b(?:api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|token|passw(?:or)?d|bearer)\s*[:=]\s*[\"']?([A-Za-z0-9+/_\-=.]{12,})")
_PLACEHOLDER = re.compile(r"(?i)^(?:your|my|the|example|sample|changeme|xxx|\*+|<|\$\{|env|os\.|process\.|input|none|null|true|false|getenv)")


def _looks_random(tok: str) -> bool:
    """Blog slugs and URL paths are long and high-entropy but lowercase words joined by hyphens. Real random secrets mix
    upper, lower and digits. (Found on real WildChat prompts: URL slugs caused 100% false critical alerts.)"""
    return any(c.isupper() for c in tok) and any(c.islower() for c in tok) and any(c.isdigit() for c in tok)


def _plausible_secret_value(v: str) -> bool:
    return (not _PLACEHOLDER.match(v) and any(c.isdigit() for c in v) and any(c.isalpha() for c in v) and entropy(v) >= 3.0)


def luhn_ok(s: str) -> bool:
    d = [int(c) for c in s if c.isdigit()]
    if not 13 <= len(d) <= 19:
        return False
    total = 0
    for i, n in enumerate(reversed(d)):
        if i % 2:
            n *= 2
            n -= 9 if n > 9 else 0
        total += n
    return total % 10 == 0


def entropy(s: str) -> float:
    c = Counter(s)
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values())


_DIGIT_RUN = re.compile(r"\d[\d -]*\d")  # linear: no nested quantifiers
WINDOW, OVERLAP = 4096, 256  # bound worst-case regex cost per call (anti-ReDoS)


def scan(text: str):
    """Return list of (finding_name, severity, kind, span). Long inputs are scanned in overlapping windows so a
    crafted prompt cannot stall the pipeline; findings keep absolute offsets."""
    if len(text) <= WINDOW:
        return _scan(text)
    seen, out = set(), []
    for start in range(0, len(text), WINDOW - OVERLAP):
        for name, sev, kind, (a, b) in _scan(text[start:start + WINDOW]):
            key = (name, start + a, start + b)
            if key not in seen:
                seen.add(key)
                out.append((name, sev, kind, (start + a, start + b)))
    return out


def _scan(text: str):
    out = []
    for m in _DIGIT_RUN.finditer(text):
        digits = re.sub(r"\D", "", m.group())
        if 13 <= len(digits) <= 19 and luhn_ok(digits):
            out.append(("credit_card", 0.9, "pii", m.span()))
    for name, (rx, sev, kind) in PATTERNS.items():
        g = _GUARD.get(name)
        if g and not any(s in text for s in g):  # C-speed substring test: skip a regex that cannot possibly match
            continue
        for m in rx.finditer(text):
            out.append((name, sev, kind, m.span()))
    taken = [sp for *_, sp in out]
    # URL paths/params are identifiers, not secrets (real-data finding)
    plain = _URL.sub(lambda m: " " * len(m.group()), text) if "://" in text else text
    for m in _TOKEN.finditer(plain):
        if any(a <= m.start() < b for a, b in taken):
            continue
        tok = m.group()
        if entropy(tok) > 4.2 and _looks_random(tok):
            out.append(("high_entropy_token", 0.5, "secret", m.span()))
    low = text.lower()
    for m in (_ASSIGN.finditer(text) if any(h in low for h in _ASSIGN_HINTS) else ()):  # context beats entropy: `api_key = <value>` is a secret even if plain hex
        val = m.group(1)
        if (m.start(1), m.end(1)) not in [sp for *_, sp in out] and _plausible_secret_value(val) \
                and not any(a <= m.start(1) < b for a, b in taken):
            out.append(("secret_assignment", 0.8, "secret", m.span(1)))
    return out


def redact(text: str, findings) -> str:
    """Replace every finding with [NAME] so raw secrets are never stored."""
    limit = len(text)
    for name, _s, _k, (a, b) in sorted(findings, key=lambda f: -f[3][0]):
        if b > limit:  # overlaps a span already redacted
            continue
        text = text[:a] + f"[{name.upper()}]" + text[b:]
        limit = a
    return text
