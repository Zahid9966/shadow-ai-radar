"""Local triage dashboard. Binds to 127.0.0.1 only; rejects foreign Host/Origin (CSRF + DNS-rebinding guard).
Named users (role analyst|viewer) -> every view and change is attributed in the tamper-evident audit log.
Repeated bad tokens lock the client out briefly."""
import hmac
import json
import re
import sqlite3
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from . import analytics, audit, report

_ID = re.compile(r"^/alerts/([0-9a-f]{10})$")
MAX_FAILS, LOCK_SECONDS, MIN_TOKEN = 5, 60, 16


def users_from_env(env):
    """RADAR_USERS="alice=analyst:tokA;bob=viewer:tokB" (+ legacy RADAR_ANALYST_TOKEN / RADAR_VIEWER_TOKEN)."""
    users = {}
    for part in filter(None, (env.get("RADAR_USERS") or "").split(";")):
        name, _, rest = part.partition("=")
        role, _, tok = rest.partition(":")
        if name and role in ("analyst", "viewer") and len(tok) >= MIN_TOKEN:
            users[name.strip()] = (role, tok)
    for role in ("analyst", "viewer"):
        if len(env.get(f"RADAR_{role.upper()}_TOKEN") or "") >= MIN_TOKEN:
            users.setdefault(role, (role, env[f"RADAR_{role.upper()}_TOKEN"]))
    return users


def make_handler(db_path, port, users=None):
    """users: {name: (role, token)}. None/empty = open mode (localhost only, actor 'local')."""
    users = users or {}
    allowed = {f"127.0.0.1:{port}", f"localhost:{port}"}
    fails = {}  # client ip -> (count, window_start)

    class H(BaseHTTPRequestHandler):
        def _ok(self):
            origin = self.headers.get("Origin")
            host = self.headers.get("Host")
            if host not in allowed or (origin and origin.split("//")[-1] not in allowed):
                if self._locked():  # already locked out: refuse without writing more log rows (log-flood guard)
                    self.send_error(429, "too many failed attempts")
                else:
                    self._note_fail()
                    self._audit("?", "blocked_request", self.client_address[0],
                                f"{self.command} {self.path.split('?')[0]} host={host!r} origin={origin!r}")
                    self.send_error(403, "forbidden host/origin")
                return False
            return True

        def _audit(self, actor, action, target, detail=""):
            db = sqlite3.connect(db_path)
            try:
                audit.log(db, actor, action, target, detail)
            finally:
                db.close()

        def _locked(self):
            c, t0 = fails.get(self.client_address[0], (0, 0))
            return c >= MAX_FAILS and time.time() - t0 < LOCK_SECONDS

        def _note_fail(self):
            ip = self.client_address[0]
            c, t0 = fails.get(ip, (0, 0))
            fails[ip] = (1, time.time()) if time.time() - t0 >= LOCK_SECONDS else (c + 1, t0)

        def _auth(self, supplied=None):
            """Return (name, role) or None."""
            if not users:
                return "local", "analyst"
            cands = [supplied, self.headers.get("Authorization", "").removeprefix("Bearer ").strip()]
            ck = SimpleCookie(self.headers.get("Cookie", ""))
            if "radar_token" in ck:
                cands.append(ck["radar_token"].value)
            hit = None
            for name, (role, tok) in users.items():  # compare against all users: no early exit on timing
                if any(c and hmac.compare_digest(c, tok) for c in cands) and (hit is None or role == "analyst"):
                    hit = (name, role)
            return hit

        def _deny(self, _db_path=None):
            self._note_fail()
            self._audit("?", "auth_fail", self.client_address[0], self.path.split("?")[0])
            self.send_error(401, "token required")

        def _send(self, code, body, ctype="text/html; charset=utf-8"):
            data = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if not self._ok():
                return
            if self._locked():
                return self.send_error(429, "too many failed attempts")
            u = urlsplit(self.path)
            supplied = parse_qs(u.query).get("token", [None])[0]
            who = self._auth(supplied)
            if who is None:
                return self._deny(db_path)
            name, role = who
            if supplied and u.path == "/":  # one-time login link -> HttpOnly cookie, token leaves the URL
                self.send_response(303)
                self.send_header("Set-Cookie", f"radar_token={supplied}; HttpOnly; SameSite=Strict; Path=/")
                self.send_header("Location", "/")
                return self.end_headers()
            db = sqlite3.connect(db_path)
            try:
                if u.path == "/api/alerts":
                    audit.log(db, name, "api_read", "alerts")
                    self._send(200, json.dumps(analytics.load_alerts(db)), "application/json")
                elif u.path == "/":
                    audit.log(db, name, "view_dashboard")
                    self._send(200, report.render(db, analytics.load_alerts(db), interactive=role == "analyst"))
                else:
                    self.send_error(404)
            finally:
                db.close()

        def do_POST(self):
            if not self._ok():
                return
            if self._locked():
                return self.send_error(429, "too many failed attempts")
            who = self._auth()
            if who is None:
                return self._deny(db_path)
            name, role = who
            if role != "analyst":
                db = sqlite3.connect(db_path)
                try:
                    audit.log(db, name, "denied_write", self.path)
                finally:
                    db.close()
                return self.send_error(403, "read-only role")
            m = _ID.match(self.path)
            if not m:
                return self.send_error(404)
            form = parse_qs(self.rfile.read(min(int(self.headers.get("Content-Length", 0)), 4096)).decode())
            status, note = form.get("status", [""])[0], form.get("note", [""])[0][:200]
            db = sqlite3.connect(db_path)
            try:
                ok = analytics.set_status(db, m.group(1), status, note)
                if ok:
                    audit.log(db, name, "alert_status", m.group(1), f"status={status} note={note}")
            except ValueError:
                return self.send_error(400, "bad status")
            finally:
                db.close()
            if ok:
                self.send_response(303)
                self.send_header("Location", "/")
                self.end_headers()
            else:
                self.send_error(404)

        def log_message(self, *a):
            pass

    return H


def serve(db_path, port=8765, users=None):
    srv = ThreadingHTTPServer(("127.0.0.1", port), make_handler(db_path, port, users))
    print(f"dashboard: http://127.0.0.1:{port}  ({'auth on: ' + str(len(users)) + ' users' if users else 'OPEN mode, localhost only'}; Ctrl-C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
