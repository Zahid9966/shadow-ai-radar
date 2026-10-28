"""Minimal Markdown -> HTML (stdlib only) for printing to PDF. Handles the Markdown this project uses: headings, tables,
fenced code, lists, bold/italic/code spans, links, rules. Not a general Markdown implementation."""
import html, re, sys

def inline(s):
    s = html.escape(s, quote=False)
    codes = []
    s = re.sub(r"`([^`]+)`", lambda m: codes.append(m.group(1)) or f"\x00{len(codes)-1}\x00", s)
    s = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", s)
    s = re.sub(r"(?<![\w*])\*([^*\n]+)\*(?![\w*])", r"<em>\1</em>", s)
    # only http(s), mailto and relative links become anchors: a javascript:/data: URL in a document must never become clickable
    s = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)",
               lambda m: f'<a href="{m.group(2).replace(chr(34), "&quot;")}">{m.group(1)}</a>' if re.match(r"^(https?://|mailto:|[./#\w-])", m.group(2)) and not re.match(r"^(javascript|data|vbscript):", m.group(2), re.I) else m.group(1), s)
    return re.sub(r"\x00(\d+)\x00", lambda m: f"<code>{codes[int(m.group(1))]}</code>", s)

def convert(md):
    out, lines, i = [], md.split("\n"), 0
    while i < len(lines):
        ln = lines[i]
        if ln.startswith("```"):
            j = i + 1; buf = []
            while j < len(lines) and not lines[j].startswith("```"):
                buf.append(lines[j]); j += 1
            out.append("<pre>" + html.escape("\n".join(buf)) + "</pre>"); i = j + 1; continue
        if re.match(r"^\|.*\|\s*$", ln) and i + 1 < len(lines) and re.match(r"^\|[\s:|-]+\|\s*$", lines[i + 1]):
            cells = lambda r: [c.strip().replace("\\|", "|") for c in re.split(r"(?<!\\)\|", r.strip().strip("|"))]  # \| is a literal pipe
            head = cells(ln); j = i + 2; rows = []
            while j < len(lines) and re.match(r"^\|.*\|\s*$", lines[j]):
                rows.append(cells(lines[j])); j += 1
            t = "<table><thead><tr>" + "".join(f"<th>{inline(c)}</th>" for c in head) + "</tr></thead><tbody>"
            t += "".join("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in r) + "</tr>" for r in rows) + "</tbody></table>"
            out.append(t); i = j; continue
        m = re.match(r"^(#{1,4})\s+(.*)$", ln)
        if m:
            n = len(m.group(1)); out.append(f"<h{n}>{inline(m.group(2))}</h{n}>"); i += 1; continue
        if re.match(r"^---+\s*$", ln):
            out.append("<hr>"); i += 1; continue
        if re.match(r"^(\s*)([-*]|\d+\.)\s+", ln):
            ordered = bool(re.match(r"^\s*\d+\.\s", ln)); tag = "ol" if ordered else "ul"; items = []
            while i < len(lines) and re.match(r"^(\s*)([-*]|\d+\.)\s+", lines[i]):
                cur = re.sub(r"^\s*([-*]|\d+\.)\s+", "", lines[i]); i += 1
                while i < len(lines) and lines[i].startswith("  ") and lines[i].strip() and not re.match(r"^\s*([-*]|\d+\.)\s+", lines[i]):
                    cur += " " + lines[i].strip(); i += 1
                items.append(cur)
            out.append(f"<{tag}>" + "".join(f"<li>{inline(x)}</li>" for x in items) + f"</{tag}>"); continue
        if ln.strip() == "":
            i += 1; continue
        para = [ln]; i += 1
        while i < len(lines) and lines[i].strip() and not re.match(r"^(#{1,4}\s|```|\||---|\s*([-*]|\d+\.)\s)", lines[i]):
            para.append(lines[i]); i += 1
        nxt = next((l for l in lines[i:] if l.strip()), "")
        cls = ' class="kn"' if re.match(r"^\|.*\|\s*$", nxt) else ""  # keep an intro paragraph on the same page as its table
        out.append(f"<p{cls}>" + inline(" ".join(p.strip() for p in para)) + "</p>")
    return "\n".join(out)

CSS = """
@page { size: A4; margin: 18mm 16mm 18mm 16mm; }
* { box-sizing: border-box; }
body { font: 10.5pt/1.5 -apple-system, "Segoe UI", "DejaVu Sans", Arial, sans-serif; color: #1a202c; }
h1 { font-size: 22pt; margin: 0 0 4pt; color: #12355b; line-height: 1.2; }
h2 { font-size: 14pt; margin: 20pt 0 6pt; color: #12355b; border-bottom: 1.5px solid #cbd5e0; padding-bottom: 3pt; break-after: avoid; }
h3 { font-size: 11.5pt; margin: 12pt 0 4pt; break-after: avoid; }
p { margin: 5pt 0; }
p.kn { break-after: avoid; }
em { color: #4a5568; }
hr { border: 0; border-top: 1px solid #cbd5e0; margin: 12pt 0; }
table { border-collapse: collapse; width: 100%; margin: 8pt 0; font-size: 9.2pt; }
th, td { border: 1px solid #cbd5e0; padding: 4pt 6pt; text-align: left; vertical-align: top; }
th { background: #edf2f7; }
tr { break-inside: avoid; }
code { font: 8.8pt "DejaVu Sans Mono", Consolas, monospace; background: #f1f5f9; padding: 0 2pt; border-radius: 2pt; }
pre { font: 8pt/1.4 "DejaVu Sans Mono", Consolas, monospace; background: #f7fafc; border: 1px solid #e2e8f0; border-left: 3px solid #2b6cb0;
      padding: 7pt 9pt; white-space: pre-wrap; word-break: break-word; break-inside: avoid; margin: 8pt 0; }
ul, ol { margin: 5pt 0 5pt 16pt; padding: 0; } li { margin: 2.5pt 0; }
"""

def to_html(md_text, title):
    return (f'<!doctype html><html lang="en"><meta charset="utf-8"><title>{html.escape(title)}</title>'
            f'<style>{CSS}</style><body>{convert(md_text)}</body></html>')


if __name__ == "__main__":
    src, dst = sys.argv[1], sys.argv[2]
    md = open(src, encoding="utf-8").read()
    first = next((l[2:].strip() for l in md.splitlines() if l.startswith("# ")), "Document")
    open(dst, "w", encoding="utf-8").write(to_html(md, first))
    print("html written:", dst)
