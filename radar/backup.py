"""Encrypted backups using the system OpenSSL (AES-256-CBC, PBKDF2 600k iterations). The Python stdlib has no vetted
cipher, and rolling our own crypto is a vulnerability, so we shell out to OpenSSL. Passphrase comes from the environment
(never argv, so it does not appear in `ps`). CBC is unauthenticated: restore therefore verifies SQLite integrity and
the audit-log hash chain before accepting the file."""
import os
import shutil
import sqlite3
import subprocess
import tempfile

from . import audit

ENV = "RADAR_BACKUP_PASSPHRASE"


def _openssl(mode, src, dst):
    if not os.environ.get(ENV) or len(os.environ[ENV]) < 12:
        raise SystemExit(f"set {ENV} (>= 12 chars)")
    if not shutil.which("openssl"):
        raise SystemExit("openssl not found")
    r = subprocess.run(["openssl", "enc", mode, "-aes-256-cbc", "-pbkdf2", "-iter", "600000", "-salt",
                        "-in", src, "-out", dst, "-pass", f"env:{ENV}"], capture_output=True)
    if r.returncode:
        raise SystemExit("openssl failed (wrong passphrase or corrupt file)")


def backup(db_path, dst):
    d = tempfile.mkdtemp()
    try:
        tmp = os.path.join(d, "snap.db")
        src = sqlite3.connect(db_path)
        out = sqlite3.connect(tmp)
        src.backup(out)  # consistent snapshot even while the dashboard is writing
        out.close(); src.close()
        _openssl("-e", tmp, dst)
        os.chmod(dst, 0o600)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def restore(src, db_path, force=False):
    if os.path.exists(db_path) and not force:
        raise SystemExit(f"{db_path} exists; pass --force to overwrite")
    d = tempfile.mkdtemp()
    try:
        tmp = os.path.join(d, "snap.db")
        _openssl("-d", src, tmp)
        db = sqlite3.connect(tmp)
        try:
            if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise SystemExit("restored file failed SQLite integrity check; not installed")
            ok, n, head, why = audit.verify(db)
        except sqlite3.DatabaseError:
            raise SystemExit("restored file is not a valid database (wrong passphrase?); not installed")
        finally:
            db.close()
        if not ok:
            raise SystemExit(f"audit chain broken ({why}); not installed")
        shutil.move(tmp, db_path)
        os.chmod(db_path, 0o600)
        return n, head
    finally:
        shutil.rmtree(d, ignore_errors=True)
