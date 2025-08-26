from pathlib import Path
from typing import List, Dict, Any
from jinja2 import Environment, FileSystemLoader, select_autoescape
import json
from datetime import datetime

def save_json(results: List[Dict[str, Any]], outdir: Path, summary: Dict[str, Any] | None = None):
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / 'report.json').write_text(json.dumps({'findings': results, 'summary': summary or {}}, indent=2, ensure_ascii=False), encoding='utf-8')

def save_html(results: List[Dict[str, Any]], outdir: Path, summary: Dict[str, Any] | None = None):
    env = Environment(
        loader=FileSystemLoader((outdir / 'templates').as_posix()),
        autoescape=select_autoescape()
    )
    tpl = env.get_template('report.html')
    html = tpl.render(results=results, summary=summary or {}, generated=datetime.utcnow().isoformat()+'Z')
    (outdir / 'report.html').write_text(html, encoding='utf-8')


def save_pdf_summary(summary: Dict[str, Any], outdir: Path):
    """
    Create a minimalist, single-page PDF executive summary without external deps.
    This is NOT a full typesetting engine; it prints a few lines of text.
    """
    def esc(s: str) -> str:
        return s.replace('\\', '\\').replace('(', '\(').replace(')', '\)')
    lines = []
    lines.append("XSSentinel Executive Summary")
    lines.append(f"Total findings: {summary.get('total_findings',0)}")
    sev = summary.get('counts_by_severity', {})
    lines.append("By severity: Critical {c} · High {h} · Medium {m} · Low {l} · Info {i}".format(
        c=sev.get('Critical',0), h=sev.get('High',0), m=sev.get('Medium',0), l=sev.get('Low',0), i=sev.get('Info',0)))
    bymode = summary.get('counts_by_mode', {})
    if bymode:
        mode_str = ' · '.join(f"{k} {v}" for k,v in bymode.items())
        lines.append(f"By mode: {mode_str}")
    lines.append("Top findings:")
    for t in summary.get('top_findings') or []:
        lines.append(f"- [{t.get('severity','')}] {t.get('url','')}  field/param={t.get('field','')}  executed={t.get('executed')} reflected={t.get('reflected')} score={t.get('score')}")

    # PDF content stream (Helvetica 12pt)
    y = 770
    content_cmds = ["BT /F1 16 Tf 50 %d Td (%s) Tj ET" % (y, esc(lines[0]))]
    y -= 24
    for ln in lines[1:]:
        content_cmds.append("BT /F1 12 Tf 50 %d Td (%s) Tj ET" % (y, esc(ln)))
        y -= 16
        if y < 60:
            break  # keep single page

    content_stream = "\n".join(content_cmds).encode("utf-8")
    length = len(content_stream)

    # Build a minimal PDF
    objs = []
    # 1: Catalog
    objs.append(("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n").encode("utf-8"))
    # 2: Pages
    objs.append(("2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n").encode("utf-8"))
    # 3: Page
    objs.append(("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n").encode("utf-8"))
    # 4: Contents
    objs.append(("4 0 obj\n<< /Length %d >>\nstream\n" % length).encode("utf-8") + content_stream + b"\nendstream\nendobj\n")
    # 5: Font
    objs.append(("5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n").encode("utf-8"))

    # xref
    pdf = [b"%PDF-1.4\n"]
    offsets = [0]
    pos = len(pdf[0])
    for obj in objs:
        offsets.append(pos)
        pdf.append(obj)
        pos += len(obj)
    xref_pos = pos
    xref_lines = ["xref", f"0 {len(objs)+1}", "0000000000 65535 f "]
    for off in offsets[1:]:
        xref_lines.append(f"{off:010d} 00000 n ")
    trailer = f"""trailer
<< /Size {len(objs)+1} /Root 1 0 R >>
startxref
{xref_pos}
%%EOF
"""
    pdf.append(("\n".join(xref_lines) + "\n").encode("utf-8"))
    pdf.append(trailer.encode("utf-8"))

    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "executive_summary.pdf").write_bytes(b"".join(pdf))
