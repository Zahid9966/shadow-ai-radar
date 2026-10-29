#!/usr/bin/env python3
"""Rebuild the PDF and Word versions of a Markdown document. Standard library only, plus Chrome/Chromium for the PDF.

    python3 tools/build_docs.py                      # docs/PROJECT_SUMMARY.md -> .pdf and .docx next to it
    python3 tools/build_docs.py docs/PILOT.md        # any Markdown file
    python3 tools/build_docs.py --formats docx       # skip the PDF (no browser needed)
    python3 tools/build_docs.py --out-dir /some/dir

The Word file is checked by verify_docx.py after it is written; the command fails if the check does. The PDF is rendered by
headless Chrome/Chromium (the first of google-chrome, chromium, ... found on PATH).
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import md2docx  # noqa: E402
import md2html  # noqa: E402
import verify_docx  # noqa: E402

BROWSERS = ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome")


def find_browser():
    for name in BROWSERS:
        path = shutil.which(name)
        if path:
            return path
    return None


def title_of(md_text):
    return next((l[2:].strip() for l in md_text.splitlines() if l.startswith("# ")), "Document")


def make_pdf(md_path, out_pdf):
    browser = find_browser()
    if not browser:
        raise SystemExit("PDF output needs Chrome or Chromium (headless) on PATH; none found. Use --formats docx, or install one.")
    md = open(md_path, encoding="utf-8").read()
    out_pdf = os.path.abspath(out_pdf)
    with tempfile.TemporaryDirectory() as d:
        page = os.path.join(d, "doc.html")
        with open(page, "w", encoding="utf-8") as f:
            f.write(md2html.to_html(md, title_of(md)))
        base = [browser, "--headless=new", "--disable-gpu", "--disable-extensions", "--no-pdf-header-footer",
                f"--user-data-dir={os.path.join(d, 'profile')}", f"--print-to-pdf={out_pdf}", "file://" + page]
        for extra in ([], ["--no-sandbox"]):  # try with the browser sandbox first; some containers need it off
            try:
                os.remove(out_pdf)
            except FileNotFoundError:
                pass
            r = subprocess.run(base[:1] + extra + base[1:], capture_output=True, text=True, timeout=120)
            if os.path.exists(out_pdf) and open(out_pdf, "rb").read(5) == b"%PDF-":
                if extra:
                    print("note: needed --no-sandbox for the browser; only our own local HTML was rendered", file=sys.stderr)
                return out_pdf
        raise SystemExit(f"browser did not produce a PDF (exit {r.returncode}): {r.stderr.strip()[-300:]}")


def make_docx(md_path, out_docx):
    md = open(md_path, encoding="utf-8").read()
    md2docx.build(md_path, out_docx, title_of(md))
    problems, info = verify_docx.verify(out_docx, md_path)
    if problems:
        raise SystemExit("docx verification FAILED:\n  " + "\n  ".join(problems))
    return out_docx, info


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("files", nargs="*", help="Markdown files (default: docs/PROJECT_SUMMARY.md)")
    ap.add_argument("--formats", default="pdf,docx", help="comma list from: pdf, docx (default both)")
    ap.add_argument("--out-dir", help="write outputs here instead of next to each source")
    a = ap.parse_args(argv)
    fmts = {f.strip() for f in a.formats.split(",") if f.strip()}
    if not fmts or fmts - {"pdf", "docx"}:
        raise SystemExit("--formats must be a comma list of pdf and/or docx")
    files = a.files or [os.path.join(ROOT, "docs", "PROJECT_SUMMARY.md")]
    for src in files:
        src = os.path.abspath(src)
        if not src.lower().endswith(".md") or not os.path.isfile(src):
            raise SystemExit(f"not a Markdown file: {src}")
        out_dir = os.path.abspath(a.out_dir) if a.out_dir else os.path.dirname(src)
        os.makedirs(out_dir, exist_ok=True)
        stem = os.path.join(out_dir, os.path.splitext(os.path.basename(src))[0])
        if "docx" in fmts:
            path, info = make_docx(src, stem + ".docx")
            print(f"docx: {path}  (verified: {info['tables']} tables, {info['headings']} headings, {info['words']} distinct words)")
        if "pdf" in fmts:
            print(f"pdf:  {make_pdf(src, stem + '.pdf')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
