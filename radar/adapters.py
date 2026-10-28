"""Convert real proxy logs into Radar's common JSONL schema. Pure functions."""
import csv
import hashlib
import json
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

ALIASES = {"ts": ("ts", "time", "timestamp", "datetime"), "user": ("user", "username", "login", "ident"),
           "dept": ("dept", "department"), "host": ("host", "hostname", "domain"), "url": ("url", "uri", "request"),
           "bytes_out": ("bytes_out", "sent", "bytessent", "request_bytes"), "bytes_in": ("bytes_in", "received", "bytesreceived", "response_bytes"),
           "prompt": ("prompt", "snippet", "content")}


def load_identity(path):
    """HR/IdP export: user,dept[,manager,email,ip] -> ({user: row}, {ip: user})."""
    by_user, by_ip = {}, {}
    if path:
        for r in csv.DictReader(open(path, newline="")):
            by_user[r["user"]] = r
            if r.get("ip"):
                by_ip[r["ip"]] = r["user"]
    return by_user, by_ip


def _host(url):
    url = url.strip()
    if "://" not in url:  # squid CONNECT form: host:port
        return url.rsplit(":", 1)[0].lower()
    return (urlparse(url).hostname or "").lower()


def _eid(raw):
    return hashlib.sha1(raw.encode()).hexdigest()[:16]


_HIER = re.compile(r"^(?:TIMEOUT_)?[A-Z][A-Z_]*/\S+$")  # hierarchy/peer, e.g. DIRECT/1.2.3.4, HIER_NONE/-
_RESULT = re.compile(r"^[A-Z][A-Z_]*/\d{3}$")  # result/status, e.g. TCP_MISS/200


def squid_line(line, by_user, by_ip):
    """Native squid access.log: ts elapsed client code/status bytes method URL ident hier/peer [content-type].
    The Squid docs warn the URL may contain spaces, so fields are anchored from BOTH ends (the hierarchy token marks the
    end of the URL) rather than split blindly. Error/aborted requests (NONE_NONE/000, error:* URLs) are skipped.
    Native format has no request size, so bytes_out is 0 -> volume-exfil detection is blind unless you add %>st to logformat."""
    f = line.split()
    if len(f) < 9 or not _RESULT.match(f[3]):
        return None
    h = next((i for i in range(len(f) - 1, 7, -1) if _HIER.match(f[i])), None)
    if h is None:
        return None
    url, ident = " ".join(f[6:h - 1]), f[h - 1]
    if f[3].startswith("NONE_NONE") or f[5] == "-" or url.startswith("error:"):
        return None
    try:
        ts = datetime.fromtimestamp(float(f[0]), timezone.utc).isoformat()
        nbytes = int(f[4])
    except (ValueError, OverflowError, OSError):
        return None
    host = _host(url)
    if not host:
        return None
    user = ident if ident != "-" else by_ip.get(f[2], f[2])
    return {"event_id": _eid(line), "ts": ts, "user": user, "dept": by_user.get(user, {}).get("dept", "Unknown"),
            "src_ip": f[2], "host": host, "method": f[5], "bytes_out": 0, "bytes_in": nbytes, "prompt": None}


def csv_rows(path, by_user, by_ip):
    rd = csv.DictReader(open(path, newline=""))
    col = {k: next((c for c in rd.fieldnames if c.lower() in al), None) for k, al in ALIASES.items()}
    if not col["ts"] or not col["user"] or not (col["host"] or col["url"]):
        raise ValueError(f"CSV needs time, user and host/url columns; found {rd.fieldnames}")
    for r in rd:
        raw = json.dumps(r, sort_keys=True)
        host = r[col["host"]] if col["host"] else _host(r[col["url"]])
        user = r[col["user"]]
        ts = r[col["ts"]]
        if ts.replace(".", "", 1).isdigit():
            ts = datetime.fromtimestamp(float(ts), timezone.utc).isoformat()
        num = lambda k: int(float(r[col[k]])) if col[k] and r[col[k]] not in ("", None) else 0
        yield {"event_id": _eid(raw), "ts": ts, "user": user,
               "dept": (r[col["dept"]] if col["dept"] else "") or by_user.get(user, {}).get("dept", "Unknown"),
               "host": host.lower(), "bytes_out": num("bytes_out"), "bytes_in": num("bytes_in"),
               "prompt": (r[col["prompt"]] if col["prompt"] else None) or None}


def convert(fmt, src, dst, identity=None):
    by_user, by_ip = load_identity(identity)
    n = skipped = 0
    with open(dst, "w") as out:
        if fmt == "squid":
            recs = (squid_line(l, by_user, by_ip) for l in open(src, errors="replace"))
        elif fmt == "csv":
            recs = csv_rows(src, by_user, by_ip)
        else:
            raise ValueError("format must be squid or csv")
        for r in recs:
            if r is None:
                skipped += 1
                continue
            out.write(json.dumps(r) + "\n")
            n += 1
    return {"converted": n, "skipped": skipped}
