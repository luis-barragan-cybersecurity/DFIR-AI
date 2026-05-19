#!/usr/bin/env python3
"""MemoryHound — PDF report renderer.

Wraps the markdown output of `exec-report.py` (or any case markdown) in a
branded HTML shell and renders via WeasyPrint.

CLI:
    python3 generate_pdf_report.py <case-dir>
        Reads <case-dir>/output/exec-report.md, writes <case-dir>/output/report.pdf
    python3 generate_pdf_report.py <case-dir> --source=<file.md> --out=<file.pdf>
        Render a specific markdown source to a specific PDF path.

Programmatic:
    from generate_pdf_report import render_pdf
    render_pdf(case_dir=Path("cases/case-001"))

Optional dep — `pip install markdown weasyprint`. Both surface clear install
hints on ImportError so a missing dep doesn't fail the wider IR pipeline.

Design notes:
- Generic IR styling (no client / engagement / "CONFIDENTIAL" tag baked in;
  pass via the metadata dict if needed).
- CSS embedded in the script — no remote fonts loaded at render time
  (offline-safe; survives air-gapped DFIR labs).
- Cover page draws case-id + generation date + finding count from
  output/findings.json when present.
- Layout adapted from the protocol-sift baseline (teamdfir/protocol-sift),
  rebranded for MemoryHound and made generic.
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path
from typing import Any


def _require_weasyprint() -> Any:
    try:
        from weasyprint import HTML  # type: ignore
    except ImportError:
        sys.stderr.write(
            "weasyprint not installed. Install with one of:\n"
            "  pip install weasyprint\n"
            "  mh init --with-forensics    # if you have a working .venv\n"
            "  sudo apt-get install -y python3-gi python3-gi-cairo gir1.2-gtk-3.0 libpango-1.0-0   # Linux runtime libs\n"
        )
        sys.exit(1)
    return HTML


def _require_markdown() -> Any:
    try:
        import markdown  # type: ignore
    except ImportError:
        sys.stderr.write(
            "python-markdown not installed. Install with: pip install markdown\n"
        )
        sys.exit(1)
    return markdown


# ── Embedded stylesheet (offline; no remote fonts) ─────────────────────────────

CSS_STYLE = r"""
@page {
    size: A4;
    margin: 0;
    @bottom-right {
        content: "Page " counter(page) " of " counter(pages);
        font-family: -apple-system, "Helvetica Neue", Arial, sans-serif;
        font-size: 8pt;
        color: #9ca3af;
        margin-right: 1.5cm;
        margin-bottom: 0.6cm;
    }
    @bottom-left {
        content: "MemoryHound — DFIR Internal Report";
        font-family: -apple-system, "Helvetica Neue", Arial, sans-serif;
        font-size: 8pt;
        color: #9ca3af;
        margin-left: 1.5cm;
        margin-bottom: 0.6cm;
    }
}

* { box-sizing: border-box; margin: 0; padding: 0; }

body {
    font-family: -apple-system, "Helvetica Neue", Arial, sans-serif;
    font-size: 9.5pt;
    color: #1f2937;
    background: #ffffff;
    line-height: 1.55;
}

/* ── Cover ── */
.cover {
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 60%, #312e81 100%);
    color: white;
    padding: 2.5cm 2cm 2cm 2cm;
    page-break-after: always;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
}
.cover .tag {
    font-size: 8pt;
    font-weight: 600;
    letter-spacing: 0.2em;
    text-transform: uppercase;
    color: #93c5fd;
    margin-bottom: 0.4cm;
}
.cover h1 {
    font-size: 30pt;
    font-weight: 700;
    line-height: 1.1;
    margin: 0.6cm 0 0.4cm 0;
}
.cover .subtitle {
    font-size: 13pt;
    color: #cbd5e1;
    font-weight: 300;
    margin-bottom: 0.8cm;
}
.cover .divider {
    height: 2px;
    background: #3b82f6;
    width: 4cm;
    margin: 0.6cm 0 0.8cm 0;
}
.cover .meta { font-size: 10pt; }
.cover .meta-row { display: flex; padding: 0.18cm 0; border-bottom: 1px solid rgba(255,255,255,0.08); }
.cover .meta-label { width: 5cm; color: #93c5fd; font-weight: 600; }
.cover .meta-value { flex: 1; color: white; }
.cover .bottom { font-size: 8pt; color: #94a3b8; display: flex; justify-content: space-between; }

/* ── Body ── */
.content { padding: 1.6cm 2cm 1.2cm 2cm; }

h2 {
    font-size: 14pt;
    font-weight: 700;
    color: #0f172a;
    margin-top: 0.8cm;
    margin-bottom: 0.4cm;
    padding-bottom: 0.18cm;
    border-bottom: 2px solid #3b82f6;
}
h2 .num {
    display: inline-block;
    background: #3b82f6;
    color: white;
    width: 0.9cm;
    height: 0.9cm;
    line-height: 0.9cm;
    text-align: center;
    border-radius: 50%;
    font-size: 9pt;
    margin-right: 0.3cm;
    vertical-align: middle;
}
h3 {
    font-size: 11pt;
    font-weight: 600;
    color: #1f2937;
    margin: 0.6cm 0 0.25cm 0;
}
h4 { font-size: 10pt; font-weight: 600; color: #374151; margin: 0.4cm 0 0.18cm 0; }

p { margin: 0.18cm 0 0.3cm 0; }

ul, ol { margin: 0.18cm 0 0.3cm 0.5cm; padding-left: 0.4cm; }
li { margin-bottom: 0.1cm; }

code {
    font-family: "SF Mono", "Roboto Mono", Menlo, Consolas, monospace;
    font-size: 8.5pt;
    background: #f3f4f6;
    color: #be123c;
    padding: 0.05cm 0.15cm;
    border-radius: 0.1cm;
}

pre {
    background: #0f172a;
    color: #e2e8f0;
    padding: 0.4cm;
    border-radius: 0.2cm;
    overflow-x: auto;
    margin: 0.3cm 0;
    font-family: "SF Mono", "Roboto Mono", Menlo, Consolas, monospace;
    font-size: 8.5pt;
    line-height: 1.4;
}
pre code { background: transparent; color: inherit; padding: 0; }

blockquote {
    border-left: 4px solid #3b82f6;
    padding: 0.18cm 0.4cm;
    margin: 0.3cm 0;
    background: #eff6ff;
    color: #1e3a8a;
    font-size: 9pt;
}

table {
    width: 100%;
    border-collapse: collapse;
    margin: 0.4cm 0;
    font-size: 8.5pt;
}
th {
    background: #1e293b;
    color: white;
    text-align: left;
    padding: 0.18cm 0.25cm;
    font-weight: 600;
    font-size: 8.5pt;
}
td {
    border-bottom: 1px solid #e5e7eb;
    padding: 0.18cm 0.25cm;
    vertical-align: top;
}
tr:nth-child(even) td { background: #f9fafb; }

hr { border: 0; border-top: 1px solid #e5e7eb; margin: 0.6cm 0; }

.page-header {
    position: running(pageheader);
    font-size: 8pt;
    color: #6b7280;
    padding-bottom: 0.2cm;
    border-bottom: 1px solid #e5e7eb;
}

.footer-note {
    margin-top: 1cm;
    padding-top: 0.4cm;
    border-top: 1px solid #e5e7eb;
    font-size: 7.5pt;
    color: #9ca3af;
    font-style: italic;
}

.page-break { page-break-before: always; }
"""


# ── Markdown → HTML ────────────────────────────────────────────────────────────

def markdown_to_html(text: str) -> str:
    md = _require_markdown()
    return md.markdown(
        text,
        extensions=["tables", "fenced_code", "toc", "sane_lists"],
        output_format="html5",
    )


# ── Case metadata extraction ───────────────────────────────────────────────────

def _read_case_metadata(case_dir: Path) -> dict:
    """Best-effort extraction from findings.json + state.json. Never raises."""
    meta: dict[str, Any] = {
        "case_id": case_dir.name,
        "finding_count": 0,
        "severity": "unknown",
        "started": None,
        "finalized": None,
    }
    findings_path = case_dir / "output" / "findings.json"
    if findings_path.exists():
        try:
            findings = json.loads(findings_path.read_text(encoding="utf-8"))
            if isinstance(findings, list):
                meta["finding_count"] = len(findings)
        except Exception:  # noqa: BLE001 — best-effort metadata
            pass
    state_path = case_dir / "output" / "state.json"
    if state_path.exists():
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
            meta["case_id"] = state.get("incident_id", meta["case_id"])
            meta["severity"] = state.get("severity", meta["severity"])
            meta["started"] = state.get("_started_at")
            meta["finalized"] = state.get("_finalized_at")
        except Exception:  # noqa: BLE001
            pass
    return meta


# ── HTML shell ─────────────────────────────────────────────────────────────────

def build_html(*, title: str, subtitle: str, meta: dict, body_html: str) -> str:
    date_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<style>{CSS_STYLE}</style>
</head>
<body>

<div class="cover">
  <div>
    <div class="tag">Digital Forensics &amp; Incident Response</div>
    <div style="font-size: 10pt; color: #cbd5e1; margin-bottom: 0.3cm;">MemoryHound Investigation Report</div>
    <h1>{title}</h1>
    <div class="subtitle">{subtitle}</div>
    <div class="divider"></div>
    <div class="meta">
      <div class="meta-row"><div class="meta-label">Case ID</div><div class="meta-value">{meta.get('case_id', '—')}</div></div>
      <div class="meta-row"><div class="meta-label">Severity</div><div class="meta-value">{meta.get('severity', 'unknown')}</div></div>
      <div class="meta-row"><div class="meta-label">Findings</div><div class="meta-value">{meta.get('finding_count', 0)}</div></div>
      <div class="meta-row"><div class="meta-label">Started</div><div class="meta-value">{meta.get('started') or '—'}</div></div>
      <div class="meta-row"><div class="meta-label">Finalized</div><div class="meta-value">{meta.get('finalized') or '—'}</div></div>
      <div class="meta-row"><div class="meta-label">Report Generated</div><div class="meta-value">{date_str}</div></div>
    </div>
  </div>
  <div class="bottom">
    <div>MemoryHound · autonomous DFIR triage</div>
    <div>{date_str}</div>
  </div>
</div>

<div class="content">
{body_html}
<div class="footer-note">
This report is generated by MemoryHound, an autonomous DFIR triage system. Every finding is pinned to a specific tool call against a specific artifact and verified by an independent Verifier subagent.
Evidence integrity is maintained via a sha256-chained audit log and SHA256 manifest of inputs.
Run <code>mh verify {meta.get('case_id', '—')}</code> to re-confirm chain-of-custody.
</div>
</div>

</body>
</html>"""


# ── Public renderer ────────────────────────────────────────────────────────────

def render_pdf(
    *,
    case_dir: Path,
    source_md: Path | None = None,
    out_path: Path | None = None,
    title: str | None = None,
    subtitle: str = "Executive incident report",
) -> Path:
    case_dir = Path(case_dir).resolve()
    if not case_dir.is_dir():
        raise FileNotFoundError(f"case dir not found: {case_dir}")

    output_dir = case_dir / "output"
    output_dir.mkdir(exist_ok=True)

    source_md = source_md or (output_dir / "exec-report.md")
    if not source_md.exists():
        raise FileNotFoundError(
            f"source markdown not found: {source_md}. "
            "Run `mh report --exec <case-id>` first to produce exec-report.md."
        )

    out_path = out_path or (output_dir / "report.pdf")

    meta = _read_case_metadata(case_dir)
    body_html = markdown_to_html(source_md.read_text(encoding="utf-8"))
    title_final = title or f"DFIR Investigation — {meta.get('case_id', case_dir.name)}"

    html_doc = build_html(
        title=title_final,
        subtitle=subtitle,
        meta=meta,
        body_html=body_html,
    )

    HTML = _require_weasyprint()
    HTML(string=html_doc).write_pdf(out_path, presentational_hints=True)
    return out_path


# ── CLI ────────────────────────────────────────────────────────────────────────

def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Render a MemoryHound case markdown report to PDF (WeasyPrint).",
    )
    p.add_argument("case_dir", help="Path to case directory (cases/<id>/)")
    p.add_argument("--source", default=None,
                   help="Path to source markdown (default: <case-dir>/output/exec-report.md)")
    p.add_argument("--out", default=None,
                   help="Output PDF path (default: <case-dir>/output/report.pdf)")
    p.add_argument("--title", default=None,
                   help="Override report title (default: DFIR Investigation — <case-id>)")
    p.add_argument("--subtitle", default="Executive incident report",
                   help="Cover-page subtitle")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        out = render_pdf(
            case_dir=Path(args.case_dir),
            source_md=Path(args.source) if args.source else None,
            out_path=Path(args.out) if args.out else None,
            title=args.title,
            subtitle=args.subtitle,
        )
    except FileNotFoundError as e:
        sys.stderr.write(f"error: {e}\n")
        return 2
    print(f"PDF written: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
