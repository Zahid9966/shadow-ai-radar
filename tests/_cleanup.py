"""Imported by every test module: remove every temp directory the tests create when the test process exits.

Why: tests build 10k-event logs and SQLite databases in tempfile.mkdtemp() folders. They were never deleted, so ~150-200 MB
leaked per full run. On a RAM-backed /tmp with a quota that filled up (4.3 GB after ~25 runs) and made tests fail at random
(EDQUOT / 'database or disk is full'). Tracking mkdtemp covers every test without editing each one.
"""
import atexit
import shutil
import tempfile

_made = []
_orig = tempfile.mkdtemp


def _tracked(*args, **kwargs):
    d = _orig(*args, **kwargs)
    _made.append(d)
    return d


if tempfile.mkdtemp is _orig:  # idempotent if imported twice
    tempfile.mkdtemp = _tracked


@atexit.register
def _remove_all():
    for d in _made:
        shutil.rmtree(d, ignore_errors=True)
