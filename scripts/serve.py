#!/usr/bin/env python3
"""MemoryHound local case viewer — pure-local Python http server.

No CDN. No external resources. Renders cases/<id>/output/*.md to HTML
with inline CSS so it works fully air-gapped. Lists cases on the index,
makes the trust-stack story easy to demo on a screen.

Usage:
    python3 scripts/serve.py [--port 8765] [--host 127.0.0.1]
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote

try:
    import markdown as md
except ImportError:
    print(
        "ERROR: markdown library missing. Install with:\n"
        "  pip install -e mcp-server[dev]\n"
        "or pass --with-forensics to mh init.",
        file=sys.stderr,
    )
    sys.exit(1)


REPO_ROOT = Path(__file__).resolve().parent.parent
CASES_DIR = REPO_ROOT / "cases"

CSS = """
:root {
    --bg: #0a0e14;
    --panel: #0f141b;
    --border: #1f2937;
    --text: #e5e7eb;
    --muted: #9ca3af;
    --accent: #22d3ee;
    --good: #34d399;
    --warn: #fbbf24;
    --bad: #f87171;
    --code-bg: #1a1f29;
    --link: #60a5fa;
}
* { box-sizing: border-box; }
body {
    margin: 0; padding: 0;
    background: var(--bg); color: var(--text);
    font: 14px/1.6 -apple-system, system-ui, sans-serif;
}
.shell {
    max-width: 1200px; margin: 0 auto; padding: 24px;
}
header {
    border-bottom: 1px solid var(--border);
    padding-bottom: 16px; margin-bottom: 24px;
    display: flex; justify-content: space-between; align-items: baseline;
}
header h1 { margin: 0; font-size: 22px; font-weight: 600; }
header h1 a { color: var(--accent); text-decoration: none; }
header .meta { color: var(--muted); font-size: 12px; }
.cases-grid {
    display: grid; gap: 12px;
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
}
.case {
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 8px; padding: 16px;
    transition: border-color .12s;
}
.case:hover { border-color: var(--accent); }
.case h3 { margin: 0 0 8px; font-size: 15px; }
.case h3 a { color: var(--text); text-decoration: none; }
.case .stats { color: var(--muted); font-size: 12px; }
.case .files { margin-top: 10px; display: flex; flex-wrap: wrap; gap: 6px; }
.pill {
    background: var(--code-bg); color: var(--accent);
    padding: 2px 8px; border-radius: 12px; font-size: 11px;
    font-family: ui-monospace, SFMono-Regular, monospace;
    text-decoration: none;
}
.pill:hover { background: var(--accent); color: var(--bg); }
.pill.warn { color: var(--warn); }
.pill.good { color: var(--good); }
.pill.bad { color: var(--bad); }
.tabs {
    display: flex; gap: 4px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 16px;
}
.tab {
    padding: 8px 14px; color: var(--muted);
    text-decoration: none; border-bottom: 2px solid transparent;
}
.tab.active {
    color: var(--accent); border-bottom-color: var(--accent);
}
.tab:hover { color: var(--text); }
article {
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 8px; padding: 24px 32px;
}
article h1, article h2, article h3, article h4 {
    border-bottom: 1px solid var(--border);
    padding-bottom: 4px; margin-top: 24px;
}
article h1 { font-size: 24px; }
article h2 { font-size: 18px; }
article h3 { font-size: 15px; }
article p { margin: 10px 0; }
article a { color: var(--link); }
article code {
    background: var(--code-bg); color: var(--accent);
    padding: 2px 6px; border-radius: 3px;
    font-family: ui-monospace, SFMono-Regular, monospace;
    font-size: 12.5px;
}
article pre {
    background: var(--code-bg); padding: 14px 18px;
    border-radius: 6px; overflow-x: auto;
    border: 1px solid var(--border);
}
article pre code { background: transparent; padding: 0; color: var(--text); }
article table {
    border-collapse: collapse; width: 100%; margin: 14px 0;
    font-size: 13px;
}
article table th, article table td {
    border: 1px solid var(--border);
    padding: 8px 12px; text-align: left;
}
article table th {
    background: var(--code-bg); color: var(--accent);
    font-weight: 600;
}
article blockquote {
    border-left: 3px solid var(--accent);
    margin: 12px 0; padding: 4px 16px;
    background: var(--code-bg);
    color: var(--muted);
}
article ul, article ol { padding-left: 24px; }
article hr { border: none; border-top: 1px solid var(--border); margin: 24px 0; }
.crumb { color: var(--muted); font-size: 13px; margin-bottom: 12px; }
.crumb a { color: var(--accent); text-decoration: none; }
.crumb a:hover { text-decoration: underline; }
.empty {
    text-align: center; padding: 60px 20px;
    color: var(--muted);
}
.banner {
    background: var(--code-bg); border: 1px solid var(--border);
    border-left: 3px solid var(--accent);
    padding: 12px 16px; border-radius: 4px; margin-bottom: 16px;
    font-size: 13px;
}
.audit-entry {
    background: var(--code-bg); border: 1px solid var(--border);
    border-radius: 4px; padding: 10px 14px; margin-bottom: 6px;
    font-family: ui-monospace, monospace; font-size: 12px;
    overflow-x: auto;
}
.audit-entry .event { color: var(--accent); font-weight: 600; }
.audit-entry .ts { color: var(--muted); }
.audit-entry .from { color: var(--good); }
.audit-entry .to { color: var(--warn); }
"""


def page_layout(title: str, body: str, breadcrumb: str = "") -> bytes:
    crumb_html = f'<div class="crumb">{breadcrumb}</div>' if breadcrumb else ""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{html.escape(title)} — MemoryHound</title>
<style>{CSS}</style>
<style>
.mermaid {{
  background: #1f2430;
  border: 1px solid #2a3142;
  border-radius: 6px;
  padding: 18px;
  margin: 18px 0;
  overflow-x: auto;
}}
.mermaid svg {{ max-width: 100%; height: auto; }}
</style>
</head>
<body>
<div class="shell">
<header>
  <h1><a href="/">MemoryHound</a></h1>
  <span class="meta">{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} · all-local · no network</span>
</header>
{crumb_html}
{body}
</div>
<script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
<script>
  // Mermaid 10 — initialize on load. Dark theme matches MemoryHound's
  // monokai-adjacent palette so timelines stay readable next to code blocks.
  if (typeof mermaid !== 'undefined') {{
    mermaid.initialize({{
      startOnLoad: true,
      theme: 'dark',
      flowchart: {{ curve: 'basis', useMaxWidth: true }},
      gantt: {{ useMaxWidth: true, fontSize: 12 }},
      timeline: {{ useMaxWidth: true }},
    }});
  }}
</script>
</body>
</html>""".encode()


_MERMAID_FENCE_RE = re.compile(
    r"```mermaid\s*\n(.*?)\n```", re.DOTALL,
)


def _extract_mermaid_blocks(text: str) -> tuple[str, list[str]]:
    """Pull mermaid fenced blocks out of the markdown source BEFORE handing
    to python-markdown (which would syntax-highlight them as plain code).

    Replaces each block with a unique placeholder; returns the rewritten
    markdown plus the list of original mermaid sources in order.
    """
    blocks: list[str] = []

    def _take(match: re.Match) -> str:
        idx = len(blocks)
        blocks.append(match.group(1))
        return f"\n\nMERMAID_PLACEHOLDER_{idx}\n\n"

    rewritten = _MERMAID_FENCE_RE.sub(_take, text)
    return rewritten, blocks


def _inject_mermaid_divs(html_text: str, blocks: list[str]) -> str:
    """After python-markdown rendering, swap each placeholder back to a
    `<div class="mermaid">…</div>` so the Mermaid.js script we load in
    page_layout can render it client-side.
    """
    for idx, block in enumerate(blocks):
        # python-markdown wraps single-line placeholders in <p>...</p>.
        for variant in (
            f"<p>MERMAID_PLACEHOLDER_{idx}</p>",
            f"MERMAID_PLACEHOLDER_{idx}",
        ):
            html_text = html_text.replace(
                variant,
                f'<div class="mermaid">{html.escape(block)}</div>',
                1,
            )
    return html_text


def render_md_file(path: Path) -> str:
    text = path.read_text()
    rewritten, mermaid_blocks = _extract_mermaid_blocks(text)
    rendered = md.markdown(
        rewritten,
        extensions=["tables", "fenced_code", "toc", "sane_lists", "nl2br", "codehilite"],
        extension_configs={"codehilite": {"noclasses": True, "pygments_style": "monokai"}},
    )
    return _inject_mermaid_divs(rendered, mermaid_blocks)


def render_json_file(path: Path) -> str:
    try:
        data = json.loads(path.read_text())
        return f"<pre><code>{html.escape(json.dumps(data, indent=2, default=str))}</code></pre>"
    except json.JSONDecodeError as exc:
        return f"<p>JSON parse error: {html.escape(str(exc))}</p>"


def render_audit_jsonl(path: Path) -> str:
    """Plain append-only audit log — {ts, event, data} entries."""
    rows: list[str] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        event = entry.get("event", "?")
        ts = entry.get("ts", "")
        data_str = json.dumps(entry.get("data", {}), default=str)
        if len(data_str) > 240:
            data_str = data_str[:237] + "..."
        rows.append(
            f'<div class="audit-entry">'
            f'<span class="event">{html.escape(event)}</span> '
            f'<span class="ts">@ {html.escape(ts)}</span>'
            f'<br><code>{html.escape(data_str)}</code>'
            f'</div>'
        )
    title = "<h2>Audit Log</h2>"
    return title + "".join(rows) if rows else title + "<p>Empty audit log.</p>"


def render_messages_jsonl(path: Path) -> str:
    """Inter-agent message stream — {ts, from_agent, to_agent, role, content, metadata}."""
    rows: list[str] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        ts = entry.get("ts", "")
        frm = entry.get("from_agent", "?")
        to = entry.get("to_agent", "?")
        role = entry.get("role", "")
        content = entry.get("content", "")
        meta_str = json.dumps(entry.get("metadata", {}), default=str)
        if len(meta_str) > 200:
            meta_str = meta_str[:197] + "..."
        rows.append(
            f'<div class="audit-entry">'
            f'<span class="from">{html.escape(frm)}</span> → '
            f'<span class="to">{html.escape(to)}</span> '
            f'<span class="event">[{html.escape(role)}]</span> '
            f'<span class="ts">@ {html.escape(ts)}</span>'
            f'<br>{html.escape(content)}'
            f'<br><code>{html.escape(meta_str)}</code>'
            f'</div>'
        )
    title = "<h2>Agent Messages</h2>"
    return title + "".join(rows) if rows else title + "<p>No messages.</p>"


def render_history_jsonl(path: Path) -> str:
    """Per-node state snapshots — one JSON object per line."""
    rows: list[str] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        node = entry.get("node", "?")
        phase = entry.get("phase", "?")
        ts = entry.get("ts", "")
        rows.append(
            f'<div class="audit-entry">'
            f'<span class="event">{html.escape(node)}</span> '
            f'<span class="from">phase={html.escape(phase)}</span> '
            f'<span class="ts">@ {html.escape(ts)}</span>'
            f'</div>'
        )
    title = "<h2>State History</h2>"
    return title + "".join(rows) if rows else title + "<p>No history entries.</p>"


# Recognized output artifacts (path -> (tab label, renderer kind)). Order
# matters — used as the tab order in case views.
TABS: list[tuple[str, str, str]] = [
    ("Summary",     "incident_summary.md",        "md"),
    ("Narrative",   "narrative.md",               "md"),
    ("Accuracy",    "accuracy-report.md",         "md"),
    ("Findings",    "findings.json",              "json"),
    ("Lessons",     "lessons_learned.md",         "md"),
    ("Compliance",  "compliance_map.json",        "json"),
    ("Remediation", "remediation_plan.json",      "json"),
    ("Containment", "containment_actions.jsonl",  "audit"),
    ("Recovery",    "recovery_verification.json", "json"),
    ("State",       "state.json",                 "json"),
    ("History",     "state.history.jsonl",        "history"),
    ("Messages",    "agent_messages.jsonl",       "messages"),
    ("Audit",       "audit.jsonl",                "audit"),
]


def case_card(case_dir: Path) -> str:
    cid = case_dir.name
    out = case_dir / "output"
    if not out.exists():
        return ""

    files = list(out.glob("*"))
    file_count = len(files)
    pills: list[str] = []
    pill_classes = {
        "Summary": "good",
        "Findings": "",
        "Audit": "warn",
        "Compliance": "",
    }
    for label, fname, _kind in TABS:
        if (out / fname).exists() and label in pill_classes:
            cls = pill_classes[label]
            cls_attr = f"pill {cls}".strip()
            pills.append(
                f'<a class="{cls_attr}" href="/case/{cid}/{fname}">{label.lower()}</a>'
            )

    inputs = case_dir / "input"
    in_count = sum(1 for _ in inputs.rglob("*") if _.is_file()) if inputs.exists() else 0

    return f"""
<div class="case">
  <h3><a href="/case/{cid}/">{html.escape(cid)}</a></h3>
  <div class="stats">{in_count} input artifacts · {file_count} output files</div>
  <div class="files">{''.join(pills)}</div>
</div>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        sys.stderr.write(f"  {self.address_string()} {fmt % args}\n")

    def _send(self, status: int, body: bytes, ctype: str = "text/html; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        try:
            path = unquote(self.path.split("?", 1)[0])
            if path == "/" or path == "/index.html":
                return self._index()
            if path.startswith("/case/"):
                return self._case(path[len("/case/"):])
            self._send(404, page_layout("404", "<article><h1>Not Found</h1></article>"))
        except Exception as exc:
            err = f"<article><h1>500</h1><pre>{html.escape(str(exc))}</pre></article>"
            self._send(500, page_layout("500", err))

    def _index(self) -> None:
        if not CASES_DIR.exists():
            body = '<div class="empty"><h2>No cases yet</h2><p>Run <code>./bin/mh demo</code> to create one.</p></div>'
            self._send(200, page_layout("Cases", body))
            return
        cards: list[str] = []
        for case_dir in sorted(CASES_DIR.iterdir()):
            if case_dir.is_dir() and not case_dir.name.startswith("."):
                card = case_card(case_dir)
                if card:
                    cards.append(card)
        if not cards:
            body = '<div class="empty"><h2>No completed cases</h2><p>Run <code>./bin/mh demo</code> to make one.</p></div>'
        else:
            body = (
                '<div class="banner">'
                f'<strong>{len(cards)} case(s)</strong> · '
                'Click a case to view summary, narrative, accuracy, chain of custody.'
                '</div>'
                f'<div class="cases-grid">{"".join(cards)}</div>'
            )
        self._send(200, page_layout("Cases", body))

    def _case(self, sub: str) -> None:
        sub = sub.strip("/")
        parts = sub.split("/", 1) if sub else [""]
        case_id = parts[0]
        rest = parts[1] if len(parts) > 1 else ""

        case_dir = CASES_DIR / case_id
        if not case_dir.exists() or not case_dir.is_dir():
            self._send(404, page_layout("404", "<article><h1>Case not found</h1></article>"))
            return

        if rest == "" or rest == "/":
            return self._case_index(case_id, case_dir)
        return self._case_file(case_id, case_dir, rest)

    def _case_index(self, case_id: str, case_dir: Path) -> None:
        out = case_dir / "output"
        crumb = '<a href="/">cases</a> / ' + html.escape(case_id)
        # Land on the first existing artifact in TABS order.
        for _label, fname, _kind in TABS:
            if (out / fname).exists():
                return self._case_file(case_id, case_dir, fname)
        body = '<article><p>No reports yet for this case.</p></article>'
        self._send(200, page_layout(case_id, body, crumb))

    def _case_file(self, case_id: str, case_dir: Path, rel: str) -> None:
        rel = rel.replace("..", "")
        target = case_dir / "output" / rel
        if not target.exists() or not target.is_file():
            self._send(404, page_layout("404", "<article><h1>File not found</h1></article>"))
            return

        out = case_dir / "output"
        kind_by_name = {fname: kind for _label, fname, kind in TABS}
        tabs: list[str] = []
        for label, fname, _kind in TABS:
            if (out / fname).exists():
                active = "active" if rel == fname else ""
                tabs.append(
                    f'<a class="tab {active}" href="/case/{case_id}/{fname}">{label}</a>'
                )

        kind = kind_by_name.get(rel, "raw")
        if kind == "md":
            content = render_md_file(target)
        elif kind == "json":
            content = render_json_file(target)
        elif kind == "audit":
            content = render_audit_jsonl(target)
        elif kind == "messages":
            content = render_messages_jsonl(target)
        elif kind == "history":
            content = render_history_jsonl(target)
        elif rel.endswith(".md"):
            content = render_md_file(target)
        elif rel.endswith(".jsonl"):
            content = render_audit_jsonl(target)
        elif rel.endswith(".json"):
            content = render_json_file(target)
        else:
            content = f'<pre>{html.escape(target.read_text())}</pre>'

        body = f'<div class="tabs">{"".join(tabs)}</div><article>{content}</article>'
        crumb = (
            f'<a href="/">cases</a> / '
            f'<a href="/case/{case_id}/">{html.escape(case_id)}</a> / {html.escape(rel)}'
        )
        self._send(200, page_layout(f"{case_id} — {rel}", body, crumb))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    args = ap.parse_args()

    server = HTTPServer((args.host, args.port), Handler)
    url = f"http://{args.host}:{args.port}/"
    print(f"MemoryHound viewer running at {url}")
    print("Press Ctrl-C to stop.")
    print()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
