import os
import shutil
import sys
import tempfile
import unittest
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import build_docs  # noqa: E402
import md2docx  # noqa: E402
import md2html  # noqa: E402
import verify_docx  # noqa: E402

try:
    from . import _cleanup  # noqa: F401  (removes temp dirs at exit)
except ImportError:
    import _cleanup  # noqa: F401

SAMPLE = r"""# Sample & Title <b>

Intro with **bold**, *italic*, `code <tag> & amp` and a < b > c & d.

## Table

| Name | Value |
|---|---|
| `a\|b` stays | 1 < 2 & 3 |
| plain | **bold** |

```
code line one
  indented <not html> & stuff
```

- bullet one
- bullet two

1. first
2. second

---

### Second list

1. alpha
2. beta
"""


def write_md(text=SAMPLE):
    d = tempfile.mkdtemp()
    p = os.path.join(d, "doc.md")
    open(p, "w", encoding="utf-8").write(text)
    return d, p


class Html(unittest.TestCase):
    def test_markup_is_escaped_not_injected(self):
        out = md2html.convert("hello <script>alert(1)</script> & `<img src=x onerror=1>`\n\n| h |\n|---|\n| <b>x</b> |\n")
        self.assertNotIn("<script>", out)
        self.assertNotIn("<img", out)
        self.assertNotIn("<b>x</b>", out)
        self.assertIn("&lt;script&gt;", out)

    def test_dangerous_links_never_become_anchors(self):
        for bad in ("javascript:alert(1)", "JaVaScRiPt:alert(1)", "data:text/html,x", "vbscript:x"):
            self.assertNotIn("<a ", md2html.convert(f"[click]({bad})"), bad)
        out = md2html.convert('[ok](https://example.com/a"b)')
        self.assertIn('href="https://example.com/a&quot;b"', out)  # a quote cannot break out of the attribute
        self.assertNotIn('a"b"', out)

    def test_structure(self):
        out = md2html.convert(SAMPLE)
        self.assertEqual((out.count("<table"), out.count("<pre>"), out.count("<ul>"), out.count("<ol>")), (1, 1, 1, 2))
        self.assertIn("<h1>", out)
        self.assertIn("  indented &lt;not html&gt; &amp; stuff", out)  # code keeps leading spaces and is escaped


class Docx(unittest.TestCase):
    def test_sample_builds_and_verifies(self):
        d, p = write_md()
        out = os.path.join(d, "doc.docx")
        md2docx.build(p, out, "Sample & Title <b>")
        problems, info = verify_docx.verify(out, p)
        self.assertEqual(problems, [])
        self.assertEqual(info["tables"], 1)

    def test_xml_special_characters_survive_and_ordered_lists_restart(self):
        d, p = write_md()
        out = os.path.join(d, "doc.docx")
        md2docx.build(p, out, "T")
        z = zipfile.ZipFile(out)
        doc = z.read("word/document.xml").decode()
        self.assertIn("1 &lt; 2 &amp; 3", doc)
        self.assertIn(">a|b</w:t>", doc)  # an escaped pipe inside a table cell is a literal pipe, not a column break
        self.assertIn("indented &lt;not html&gt; &amp; stuff", doc)
        self.assertEqual(doc.count('<w:numId w:val="2"/>'), 2)  # first ordered list
        self.assertEqual(doc.count('<w:numId w:val="3"/>'), 2)  # second ordered list has its own id, so it restarts at 1
        self.assertIn('w:startOverride w:val="1"', z.read("word/numbering.xml").decode())

    def test_verifier_catches_out_of_order_xml(self):
        d, p = write_md()
        out = os.path.join(d, "doc.docx")
        md2docx.build(p, out, "T")
        bad = os.path.join(d, "bad.docx")
        with zipfile.ZipFile(out) as zin, zipfile.ZipFile(bad, "w", zipfile.ZIP_DEFLATED) as zout:
            for n in zin.namelist():
                data = zin.read(n)
                if n == "word/document.xml":  # put <w:ind> before <w:spacing> in a paragraph, which Word rejects
                    data = data.replace(b'<w:spacing w:after="60"/>', b'<w:jc w:val="left"/><w:spacing w:after="60"/>', 1)
                zout.writestr(n, data)
        problems, _ = verify_docx.verify(bad, p)
        self.assertTrue(any("out of schema order" in x for x in problems), problems)

    def test_verifier_catches_dropped_content_and_broken_xml(self):
        d, p = write_md()
        out = os.path.join(d, "doc.docx")
        md2docx.build(p, out, "T")
        open(p, "a", encoding="utf-8").write("\nAn extra sentence zebra missing from the document.\n")
        problems, _ = verify_docx.verify(out, p)
        self.assertTrue(any("text differs" in x for x in problems), problems)
        broken = os.path.join(d, "broken.docx")
        with zipfile.ZipFile(out) as zin, zipfile.ZipFile(broken, "w") as zout:
            for n in zin.namelist():
                zout.writestr(n, b"<w:document><oops>" if n == "word/document.xml" else zin.read(n))
        problems, _ = verify_docx.verify(broken, p)
        self.assertTrue(any("not well-formed" in x for x in problems), problems)

    def test_project_summary_converts_and_verifies(self):
        """Guards the real document: if someone edits PROJECT_SUMMARY.md with Markdown the converters do not support, this fails."""
        src = os.path.join(ROOT, "docs", "PROJECT_SUMMARY.md")
        out = os.path.join(tempfile.mkdtemp(), "s.docx")
        md2docx.build(src, out, "Shadow-AI Radar: Project Summary")
        problems, info = verify_docx.verify(out, src)
        self.assertEqual(problems, [])
        self.assertEqual(info["tables"], 5)


class Driver(unittest.TestCase):
    def test_docx_only_run_and_output_dir(self):
        d, p = write_md()
        out = os.path.join(d, "out")
        self.assertEqual(build_docs.main([p, "--formats", "docx", "--out-dir", out]), 0)
        self.assertTrue(os.path.exists(os.path.join(out, "doc.docx")))
        self.assertFalse(os.path.exists(os.path.join(out, "doc.pdf")))

    def test_rejects_bad_input(self):
        d, _ = write_md()
        for argv in ([os.path.join(d, "nope.md")], [os.path.join(d, "doc.md"), "--formats", "rtf"]):
            with self.assertRaises(SystemExit):
                build_docs.main(argv)
        txt = os.path.join(d, "x.txt")
        open(txt, "w").write("hi")
        with self.assertRaises(SystemExit):
            build_docs.main([txt])

    @unittest.skipUnless(build_docs.find_browser(), "no Chrome/Chromium on PATH")
    def test_pdf_is_produced(self):
        d, p = write_md()
        self.assertEqual(build_docs.main([p, "--formats", "pdf"]), 0)
        pdf = os.path.join(d, "doc.pdf")
        with open(pdf, "rb") as f:
            head = f.read(5)
        self.assertEqual(head, b"%PDF-")
        self.assertGreater(os.path.getsize(pdf), 1000)

    def test_missing_browser_gives_clear_error(self):
        d, p = write_md()
        saved, build_docs.find_browser = build_docs.find_browser, lambda: None
        try:
            with self.assertRaises(SystemExit) as cm:
                build_docs.make_pdf(p, os.path.join(d, "x.pdf"))
            self.assertIn("Chrome or Chromium", str(cm.exception))
        finally:
            build_docs.find_browser = saved


if __name__ == "__main__":
    unittest.main()


class ContentLossIsLoud(unittest.TestCase):
    def test_unescaped_pipe_that_creates_an_extra_cell_fails_verification_instead_of_dropping_text(self):
        d, p = write_md("# T\n\n| A | B |\n|---|---|\n| one | two | 777 |\n")  # 3 cells under a 2-column header
        out = os.path.join(d, "x.docx")
        md2docx.build(p, out, "T")
        problems, _ = verify_docx.verify(out, p)
        self.assertTrue(any("text differs" in x for x in problems), problems)  # the stray "777" is not silently lost
        with self.assertRaises(SystemExit):
            build_docs.main([p, "--formats", "docx"])

    def test_single_character_and_digit_loss_detected(self):
        d, p = write_md("# T\n\nSome text 5 here.\n")
        out = os.path.join(d, "x.docx")
        md2docx.build(p, out, "T")
        self.assertEqual(verify_docx.verify(out, p)[0], [])
        open(p, "w", encoding="utf-8").write("# T\n\nSome text 5 here and 9.\n")  # the document no longer matches its source
        self.assertTrue(verify_docx.verify(out, p)[0])
