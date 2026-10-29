"""Minimal Markdown -> .docx writer using only the standard library (no python-docx, docx-js or LibreOffice needed).
Handles the Markdown this project uses: headings, tables, fenced code, lists, bold/italic/code spans, rules.
Links are rendered as plain text. Run verify_docx.py on the result to check it against the source."""
import re, sys, zipfile, datetime
from xml.sax.saxutils import escape

W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"'
PAGE_W, MARGIN = 11906, 1000           # A4 in DXA (1440 = 1 inch)
TEXT_W = PAGE_W - 2 * MARGIN           # 9906
NAVY, GREY, BORDER = "12355B", "4A5568", "CBD5E0"

def t(text): return f'<w:t xml:space="preserve">{escape(text)}</w:t>'

def run(text, bold=False, italic=False, code=False, color=None, size=None):
    pr = ""
    if code: pr += '<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:cs="Consolas"/>'
    if bold: pr += "<w:b/>"
    if italic: pr += "<w:i/>"
    if color: pr += f'<w:color w:val="{color}"/>'
    if code: pr += '<w:sz w:val="18"/><w:shd w:val="clear" w:color="auto" w:fill="EDF2F7"/>'
    elif size: pr += f'<w:sz w:val="{size}"/>'
    return f"<w:r>{'<w:rPr>' + pr + '</w:rPr>' if pr else ''}{t(text)}</w:r>"

TOKEN = re.compile(r"(`[^`]+`|\*\*[^*]+\*\*|(?<![\w*])\*[^*\n]+\*(?![\w*]))")
def inline(s, base_bold=False, color=None, size=None):
    out = []
    for part in TOKEN.split(s):
        if not part: continue
        if part.startswith("`"): out.append(run(part[1:-1], code=True, bold=base_bold))
        elif part.startswith("**"): out.append(run(part[2:-2], bold=True, color=color, size=size))
        elif part.startswith("*") and part.endswith("*") and len(part) > 2: out.append(run(part[1:-1], italic=True, bold=base_bold, color=GREY))
        else: out.append(run(part, bold=base_bold, color=color, size=size))
    return "".join(out)

def para(inner, style=None, extra=""):
    ppr = (f'<w:pStyle w:val="{style}"/>' if style else "") + extra
    return f"<w:p>{'<w:pPr>' + ppr + '</w:pPr>' if ppr else ''}{inner}</w:p>"

def plain(s): return re.sub(r"[`*]", "", s)

def table(head, rows):
    n = len(head)
    wts = []
    for c in range(n):
        lens = [len(plain(r[c])) for r in rows if c < len(r)] + [len(plain(head[c]))]
        wts.append(max(6, min(sum(lens) / len(lens), 80)) ** 0.8)
    widths = [max(900, int(TEXT_W * w / sum(wts))) for w in wts]
    widths[-1] += TEXT_W - sum(widths)        # make columns sum exactly to the table width
    b = lambda side: f'<w:{side} w:val="single" w:sz="4" w:space="0" w:color="{BORDER}"/>'
    x = (f'<w:tbl><w:tblPr><w:tblW w:w="{TEXT_W}" w:type="dxa"/><w:tblBorders>{"".join(b(s) for s in ("top","left","bottom","right","insideH","insideV"))}</w:tblBorders>'
         '<w:tblLayout w:type="fixed"/><w:tblCellMar><w:top w:w="50" w:type="dxa"/><w:left w:w="100" w:type="dxa"/><w:bottom w:w="50" w:type="dxa"/><w:right w:w="100" w:type="dxa"/></w:tblCellMar></w:tblPr>'
         "<w:tblGrid>" + "".join(f'<w:gridCol w:w="{w}"/>' for w in widths) + "</w:tblGrid>")
    def row(cells, header=False):
        trpr = "<w:trPr><w:cantSplit/>" + ("<w:tblHeader/>" if header else "") + "</w:trPr>"
        tcs = ""
        for i in range(n):
            txt = cells[i] if i < len(cells) else ""
            shd = '<w:shd w:val="clear" w:color="auto" w:fill="EDF2F7"/>' if header else ""
            tcs += (f'<w:tc><w:tcPr><w:tcW w:w="{widths[i]}" w:type="dxa"/>{shd}</w:tcPr>'
                    + para(inline(txt, base_bold=header, size=18), "TableText") + "</w:tc>")
        return f"<w:tr>{trpr}{tcs}</w:tr>"
    return x + row(head, True) + "".join(row(r) for r in rows) + "</w:tbl>" + para("", extra='<w:spacing w:after="60"/>')

def convert(md):
    lines, body, i, ordered_lists = md.split("\n"), [], 0, 0
    while i < len(lines):
        ln = lines[i]
        if ln.startswith("```"):
            j, buf = i + 1, []
            while j < len(lines) and not lines[j].startswith("```"): buf.append(lines[j]); j += 1
            for k, code in enumerate(buf):
                sp = ('<w:spacing w:before="100" w:after="0"/>' if k == 0 else "") + ('<w:spacing w:before="0" w:after="140"/>' if k == len(buf) - 1 and k else "")
                if k == 0 and len(buf) == 1: sp = '<w:spacing w:before="100" w:after="140"/>'
                body.append(para(f'<w:r><w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:cs="Consolas"/><w:sz w:val="17"/></w:rPr>{t(code)}</w:r>', "CodeBlock", sp))
            i = j + 1; continue
        if re.match(r"^\|.*\|\s*$", ln) and i + 1 < len(lines) and re.match(r"^\|[\s:|-]+\|\s*$", lines[i + 1]):
            cells = lambda r: [c.strip().replace("\\|", "|") for c in re.split(r"(?<!\\)\|", r.strip().strip("|"))]  # \| is a literal pipe
            head, j, rows = cells(ln), i + 2, []
            while j < len(lines) and re.match(r"^\|.*\|\s*$", lines[j]): rows.append(cells(lines[j])); j += 1
            body.append(table(head, rows)); i = j; continue
        m = re.match(r"^(#{1,4})\s+(.*)$", ln)
        if m:
            n = len(m.group(1)); body.append(para(inline(m.group(2)), "Title" if n == 1 else f"Heading{n - 1}")); i += 1; continue
        if re.match(r"^---+\s*$", ln):
            body.append(para("", extra='<w:pBdr><w:bottom w:val="single" w:sz="6" w:space="1" w:color="CBD5E0"/></w:pBdr><w:spacing w:after="120"/>')); i += 1; continue
        if re.match(r"^\s*([-*]|\d+\.)\s+", ln):
            ordered = bool(re.match(r"^\s*\d+\.\s", ln))
            if ordered: ordered_lists += 1
            numid = 1 if not ordered else 1 + ordered_lists
            while i < len(lines) and re.match(r"^\s*([-*]|\d+\.)\s+", lines[i]):
                cur = re.sub(r"^\s*([-*]|\d+\.)\s+", "", lines[i]); i += 1
                while i < len(lines) and lines[i].startswith("  ") and lines[i].strip() and not re.match(r"^\s*([-*]|\d+\.)\s+", lines[i]):
                    cur += " " + lines[i].strip(); i += 1
                body.append(para(inline(cur), "ListParagraph", f'<w:numPr><w:ilvl w:val="0"/><w:numId w:val="{numid}"/></w:numPr>'))
            continue
        if not ln.strip(): i += 1; continue
        buf = [ln]; i += 1
        while i < len(lines) and lines[i].strip() and not re.match(r"^(#{1,4}\s|```|\||---|\s*([-*]|\d+\.)\s)", lines[i]): buf.append(lines[i]); i += 1
        nxt = next((l for l in lines[i:] if l.strip()), "")
        keep = "<w:keepNext/>" if re.match(r"^\|.*\|\s*$", nxt) else ""
        body.append(para(inline(" ".join(b.strip() for b in buf)), extra=keep))
    return "".join(body), ordered_lists

def styles():
    def hs(i, sz, before, after, outline):
        return (f'<w:style w:type="paragraph" w:styleId="Heading{i}"><w:name w:val="heading {i}"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:uiPriority w:val="9"/><w:qFormat/>'
                f'<w:pPr><w:keepNext/><w:keepLines/>'
                + ('<w:pBdr><w:bottom w:val="single" w:sz="6" w:space="2" w:color="CBD5E0"/></w:pBdr>' if i == 1 else "")
                + f'<w:spacing w:before="{before}" w:after="{after}"/><w:outlineLvl w:val="{outline}"/></w:pPr><w:rPr><w:b/><w:color w:val="{NAVY}"/><w:sz w:val="{sz}"/></w:rPr></w:style>')
    return (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:styles {W}>'
        '<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:eastAsia="Calibri" w:cs="Calibri"/><w:sz w:val="21"/><w:szCs w:val="21"/><w:lang w:val="en-GB"/></w:rPr></w:rPrDefault>'
        '<w:pPrDefault><w:pPr><w:spacing w:after="100" w:line="276" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>'
        '<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:qFormat/></w:style>'
        f'<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:uiPriority w:val="10"/><w:qFormat/><w:pPr><w:spacing w:after="60"/></w:pPr><w:rPr><w:b/><w:color w:val="{NAVY}"/><w:sz w:val="44"/></w:rPr></w:style>'
        + hs(1, 28, 320, 120, 0) + hs(2, 23, 200, 80, 1) + hs(3, 21, 160, 60, 2) +
        '<w:style w:type="paragraph" w:styleId="ListParagraph"><w:name w:val="List Paragraph"/><w:basedOn w:val="Normal"/><w:uiPriority w:val="34"/><w:qFormat/><w:pPr><w:spacing w:after="50"/><w:contextualSpacing w:val="0"/></w:pPr></w:style>'
        '<w:style w:type="paragraph" w:styleId="TableText"><w:name w:val="Table Text"/><w:basedOn w:val="Normal"/><w:qFormat/><w:pPr><w:spacing w:after="0" w:line="252" w:lineRule="auto"/></w:pPr><w:rPr><w:sz w:val="18"/></w:rPr></w:style>'
        '<w:style w:type="paragraph" w:styleId="CodeBlock"><w:name w:val="Code Block"/><w:basedOn w:val="Normal"/><w:qFormat/><w:pPr><w:keepLines/><w:pBdr><w:left w:val="single" w:sz="18" w:space="6" w:color="2B6CB0"/></w:pBdr>'
        '<w:shd w:val="clear" w:color="auto" w:fill="F7FAFC"/><w:spacing w:after="0" w:line="240" w:lineRule="auto"/><w:ind w:left="200"/></w:pPr><w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:cs="Consolas"/><w:sz w:val="17"/></w:rPr></w:style>'
        '<w:style w:type="paragraph" w:styleId="Footer"><w:name w:val="footer"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:after="0"/><w:jc w:val="center"/></w:pPr><w:rPr><w:color w:val="718096"/><w:sz w:val="17"/></w:rPr></w:style>'
        '</w:styles>')

def numbering(n_ordered):
    lvl = lambda fmt, txt, font="": (f'<w:lvl w:ilvl="0"><w:start w:val="1"/><w:numFmt w:val="{fmt}"/><w:lvlText w:val="{txt}"/><w:lvlJc w:val="left"/>'
                                    f'<w:pPr><w:ind w:left="540" w:hanging="300"/></w:pPr>{font}</w:lvl>')
    x = (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:numbering {W}>'
         f'<w:abstractNum w:abstractNumId="0"><w:multiLevelType w:val="hybridMultilevel"/>{lvl("bullet", chr(8226))}</w:abstractNum>'
         f'<w:abstractNum w:abstractNumId="1"><w:multiLevelType w:val="hybridMultilevel"/>{lvl("decimal", "%1.")}</w:abstractNum>'
         '<w:num w:numId="1"><w:abstractNumId w:val="0"/></w:num>')
    for k in range(n_ordered):  # each ordered list gets its own num so numbering restarts at 1
        x += f'<w:num w:numId="{2 + k}"><w:abstractNumId w:val="1"/><w:lvlOverride w:ilvl="0"><w:startOverride w:val="1"/></w:lvlOverride></w:num>'
    return x + "</w:numbering>"

def build(md_path, out_path, title):
    body, n_ord = convert(open(md_path, encoding="utf-8").read())
    sect = (f'<w:sectPr><w:footerReference w:type="default" r:id="rId3"/><w:pgSz w:w="{PAGE_W}" w:h="16838"/>'
            f'<w:pgMar w:top="1000" w:right="{MARGIN}" w:bottom="1000" w:left="{MARGIN}" w:header="500" w:footer="500" w:gutter="0"/></w:sectPr>')
    doc = f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document {W}><w:body>{body}{sect}</w:body></w:document>'
    fld = lambda name: f'<w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText xml:space="preserve"> {name} </w:instrText></w:r><w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t>1</w:t></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r>'
    footer = (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:ftr {W}><w:p><w:pPr><w:pStyle w:val="Footer"/></w:pPr>'
              f'<w:r><w:t xml:space="preserve">{escape(title)}  ·  Page </w:t></w:r>{fld("PAGE")}<w:r><w:t xml:space="preserve"> of </w:t></w:r>{fld("NUMPAGES")}</w:p></w:ftr>')
    ct = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
          '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>'
          '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
          '<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>'
          '<Override PartName="/word/numbering.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml"/>'
          '<Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>'
          '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
          '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/></Types>')
    rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
            '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/></Relationships>')
    drels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
             '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
             '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/numbering" Target="numbering.xml"/>'
             '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/></Relationships>')
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    core = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            f'<dc:title>{escape(title)}</dc:title><dc:creator>Shadow-AI Radar project</dc:creator><dcterms:created xsi:type="dcterms:W3CDTF">{now}</dcterms:created></cp:coreProperties>')
    app = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Application>Shadow-AI Radar md2docx</Application></Properties>'
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", ct); z.writestr("_rels/.rels", rels)
        z.writestr("word/document.xml", doc); z.writestr("word/_rels/document.xml.rels", drels)
        z.writestr("word/styles.xml", styles()); z.writestr("word/numbering.xml", numbering(n_ord))
        z.writestr("word/footer1.xml", footer); z.writestr("docProps/core.xml", core); z.writestr("docProps/app.xml", app)

if __name__ == "__main__":
    md = open(sys.argv[1], encoding="utf-8").read()
    first = next((l[2:].strip() for l in md.splitlines() if l.startswith("# ")), "Document")
    build(sys.argv[1], sys.argv[2], first); print("written", sys.argv[2])
