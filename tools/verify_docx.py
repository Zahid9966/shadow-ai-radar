"""Structural verification of a generated .docx, for machines with no Word/LibreOffice to open it.

Checks: zip integrity, well-formed XML, relationships and content types resolve, child-element order in the elements Word is
strict about, table grids and cell widths, styles/numbering references exist, and that every word of the source Markdown
appears in the document, in order (an exact alphanumeric comparison: nothing lost, duplicated or invented). It cannot judge how the document LOOKS: open it in Word once to be sure.

Usage: python3 tools/verify_docx.py file.docx source.md
"""
import re
import sys
import zipfile
import xml.etree.ElementTree as ET

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"

ORDER = {
    "pPr": ["pStyle", "keepNext", "keepLines", "pageBreakBefore", "framePr", "widowControl", "numPr", "suppressLineNumbers", "pBdr",
            "shd", "tabs", "suppressAutoHyphens", "kinsoku", "wordWrap", "overflowPunct", "topLinePunct", "autoSpaceDE", "autoSpaceDN",
            "bidi", "adjustRightInd", "snapToGrid", "spacing", "ind", "contextualSpacing", "mirrorIndents", "suppressOverlap", "jc",
            "textDirection", "textAlignment", "textboxTightWrap", "outlineLvl", "divId", "cnfStyle", "rPr", "sectPr", "pPrChange"],
    "rPr": ["rStyle", "rFonts", "b", "bCs", "i", "iCs", "caps", "smallCaps", "strike", "dstrike", "outline", "shadow", "emboss", "imprint",
            "noProof", "snapToGrid", "vanish", "webHidden", "color", "spacing", "w", "kern", "position", "sz", "szCs", "highlight", "u",
            "effect", "bdr", "shd", "fitText", "vertAlign", "rtl", "cs", "em", "lang", "eastAsianLayout", "specVanish", "oMath"],
    "tblPr": ["tblStyle", "tblpPr", "tblOverlap", "bidiVisual", "tblStyleRowBandSize", "tblStyleColBandSize", "tblW", "jc",
              "tblCellSpacing", "tblInd", "tblBorders", "shd", "tblLayout", "tblCellMar", "tblLook"],
    "tcPr": ["cnfStyle", "tcW", "gridSpan", "hMerge", "vMerge", "tcBorders", "shd", "noWrap", "tcMar", "textDirection", "tcFitText",
             "vAlign", "hideMark"],
    "sectPr": ["headerReference", "footerReference", "footnotePr", "endnotePr", "type", "pgSz", "pgMar", "paperSrc", "pgBorders",
               "lnNumType", "pgNumType", "cols", "formProt", "vAlign", "noEndnote", "titlePg", "textDirection", "bidi", "rtlGutter",
               "docGrid"],
    "lvl": ["start", "numFmt", "lvlRestart", "pStyle", "isLgl", "suff", "lvlText", "lvlPicBulletId", "legacy", "lvlJc", "pPr", "rPr"],
}


def _words(s):
    return re.findall(r"[A-Za-z0-9_<>%$\-]{2,}", s)


def verify(docx_path, md_path):
    """Return (problems, info). problems is empty when every check passes."""
    problems, info = [], {}
    z = zipfile.ZipFile(docx_path)
    bad = z.testzip()
    if bad is not None:
        problems.append(f"zip member corrupt: {bad}")
    parts = {n: z.read(n) for n in z.namelist()}
    info["parts"] = sorted(parts)
    for n, data in parts.items():
        try:
            ET.fromstring(data)
        except ET.ParseError as e:
            problems.append(f"{n} not well-formed: {e}")
    if problems:
        return problems, info  # nothing below is meaningful on broken XML

    for rel in ("_rels/.rels", "word/_rels/document.xml.rels"):
        base = "" if rel == "_rels/.rels" else "word/"
        for r in ET.fromstring(parts[rel]):
            if base + r.get("Target") not in parts:
                problems.append(f"{rel}: missing target {base + r.get('Target')}")
    for o in ET.fromstring(parts["[Content_Types].xml"]):
        if o.get("PartName") and o.get("PartName").lstrip("/") not in parts:
            problems.append(f"content-type override for missing part {o.get('PartName')}")

    for name in ("word/document.xml", "word/styles.xml", "word/numbering.xml", "word/footer1.xml"):
        if name not in parts:
            continue
        root = ET.fromstring(parts[name])
        for tag, order in ORDER.items():
            for el in root.iter(W + tag):
                idx = []
                for c in el:
                    local = c.tag.replace(W, "")
                    if local in order:
                        idx.append(order.index(local))
                    else:
                        problems.append(f"{name}: unexpected <{local}> in <{tag}>")
                if idx != sorted(idx):
                    problems.append(f"{name}: children out of schema order in <{tag}>: {[c.tag.replace(W, '') for c in el]}")
                tags = [c.tag for c in el]
                if len(tags) != len(set(tags)):
                    problems.append(f"{name}: duplicate child in <{tag}>")

    doc = ET.fromstring(parts["word/document.xml"])
    tbls = list(doc.iter(W + "tbl"))
    info["tables"] = len(tbls)
    for k, t in enumerate(tbls):
        tw = int(t.find(f"{W}tblPr/{W}tblW").get(W + "w"))
        grid = [int(g.get(W + "w")) for g in t.find(W + "tblGrid")]
        if sum(grid) != tw:
            problems.append(f"table {k}: grid {sum(grid)} != width {tw}")
        for tr in t.iter(W + "tr"):
            tcs = tr.findall(W + "tc")
            if len(tcs) != len(grid):
                problems.append(f"table {k}: row has {len(tcs)} cells, grid has {len(grid)}")
            for tc in tcs:
                if tc.find(f"{W}tcPr/{W}tcW") is None:
                    problems.append(f"table {k}: cell without width")
                if tc.find(W + "p") is None:
                    problems.append(f"table {k}: cell without paragraph")

    styles = {s.get(W + "styleId") for s in ET.fromstring(parts["word/styles.xml"]).iter(W + "style")}
    used = {e.get(W + "val") for e in doc.iter(W + "pStyle")}
    if used - styles:
        problems.append(f"undefined styles used: {sorted(used - styles)}")
    nums = {n.get(W + "numId") for n in ET.fromstring(parts["word/numbering.xml"]).iter(W + "num")}
    usednum = {e.get(W + "val") for e in doc.iter(W + "numId")}
    if usednum - nums:
        problems.append(f"undefined numIds: {sorted(usednum - nums)}")

    docx_text = " ".join("".join(t.text or "" for t in p.iter(W + "t")) for p in doc.iter(W + "p"))
    md = open(md_path, encoding="utf-8").read()
    md = re.sub(r"^```.*$|^\|[-\s:|]+\|$|^---+$", "", md, flags=re.M)  # fence lines and table separator rows first
    md = re.sub(r"[`*]", "", md).replace("|", " ")
    info["words"] = len(set(_words(docx_text)))
    # Exact content check: keep only letters/digits, in order, from both sides. Any lost, duplicated, reordered or invented
    # text makes them differ (punctuation and Markdown syntax are non-alphanumeric, so they drop out of both).
    md = re.sub(r"^\s*(?:[-*]|\d+\.)\s+", "", md, flags=re.M)  # list markers: Word renders them as numbering, not text
    na = "".join(c.lower() for c in md if c.isalnum())
    nb = "".join(c.lower() for c in docx_text if c.isalnum())
    if na != nb:
        i = next((k for k in range(min(len(na), len(nb))) if na[k] != nb[k]), min(len(na), len(nb)))
        problems.append(f"document text differs from the Markdown at alphanumeric position {i}: "
                        f"markdown ...{na[max(0, i - 25):i + 25]}... vs docx ...{nb[max(0, i - 25):i + 25]}... "
                        f"(lengths {len(na)} vs {len(nb)})")
    heads = [p for p in doc.iter(W + "p") if p.find(f"{W}pPr/{W}pStyle") is not None
             and p.find(f"{W}pPr/{W}pStyle").get(W + "val") in ("Title", "Heading1")]
    info["headings"] = len(heads)
    return problems, info


if __name__ == "__main__":
    probs, inf = verify(sys.argv[1], sys.argv[2])
    print(f"tables={inf.get('tables')} headings={inf.get('headings')} words={inf.get('words')}")
    print("PROBLEMS:", probs if probs else "none")
    sys.exit(1 if probs else 0)
