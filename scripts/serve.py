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
.chain-entry {
    background: var(--code-bg); border: 1px solid var(--border);
    border-radius: 4px; padding: 10px 14px; margin-bottom: 6px;
    font-family: ui-monospace, monospace; font-size: 12px;
    overflow-x: auto;
}
.chain-entry .seq { color: var(--accent); font-weight: 600; }
.chain-entry .event { color: var(--good); }
.chain-entry .hash { color: var(--muted); }
"""


def page_layout(title: str, body: str, breadcrumb: str = "") -> bytes:
    crumb_html = f'<div class="crumb">{breadcrumb}</div>' if breadcrumb else ""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{html.escape(title)} — MemoryHound</title>
<style>{CSS}</style>
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
</body>
</html>""".encode()


def render_md_file(path: Path) -> str:
    text = path.read_text()
    return md.markdown(
        text,
        extensions=["tables", "fenced_code", "toc", "sane_lists", "nl2br", "codehilite"],
        extension_configs={"codehilite": {"noclasses": True, "pygments_style": "monokai"}},
    )


def render_json_file(path: Path) -> str:
    try:
        data = json.loads(path.read_text())
        return f"<pre><code>{html.escape(json.dumps(data, indent=2, default=str))}</code></pre>"
    except json.JSONDecodeError as exc:
        return f"<p>JSON parse error: {html.escape(str(exc))}</p>"


def render_chain_jsonl(path: Path) -> str:
    rows: list[str] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        seq = entry.get("seq", "?")
        event = entry.get("event", "?")
        ts = entry.get("ts", "")
        h = (entry.get("hash") or "")[:16]
        prev = (entry.get("prev_hash") or "")[:16]
        data_str = json.dumps(entry.get("data", {}), default=str)
        if len(data_str) > 200:
            data_str = data_str[:197] + "..."
        rows.append(
            f'<div class="chain-entry">'
            f'<span class="seq">seq={seq}</span> '
            f'<span class="event">{html.escape(event)}</span> '
            f'<span class="hash">prev={prev}… → hash={h}…</span> '
            f'<span style="color:var(--muted)"> @ {html.escape(ts)}</span>'
            f'<br><code>{html.escape(data_str)}</code>'
            f'</div>'
        )
    return "<h2>Chain of Custody</h2>" + "".join(rows) if rows else "<p>Empty chain.</p>"


def case_card(case_dir: Path) -> str:
    cid = case_dir.name
    out = case_dir / "output"
    if not out.exists():
        return ""

    files = list(out.glob("*"))
    file_count = len(files)
    pills: list[str] = []
    has = lambda n: (out / n).exists()
    if has("summary.md"):
        pills.append(f'<a class="pill good" href="/case/{cid}/summary.md">summary</a>')
    if has("narrative.md"):
        pills.append(f'<a class="pill" href="/case/{cid}/narrative.md">narrative</a>')
    if has("accuracy-report.md"):
        pills.append(f'<a class="pill" href="/case/{cid}/accuracy-report.md">accuracy</a>')
    if has("findings.json"):
        pills.append(f'<a class="pill" href="/case/{cid}/findings.json">findings</a>')
    if has("audit.jsonl"):
        pills.append(f'<a class="pill warn" href="/case/{cid}/audit.jsonl">audit</a>')

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
        if (out / "summary.md").exists():
            return self._case_file(case_id, case_dir, "summary.md")
        if (out / "narrative.md").exists():
            return self._case_file(case_id, case_dir, "narrative.md")
        body = '<article><p>No reports yet for this case.</p></article>'
        self._send(200, page_layout(case_id, body, crumb))

    def _case_file(self, case_id: str, case_dir: Path, rel: str) -> None:
        rel = rel.replace("..", "")
        target = case_dir / "output" / rel
        if not target.exists() or not target.is_file():
            self._send(404, page_layout("404", "<article><h1>File not found</h1></article>"))
            return

        out = case_dir / "output"
        tabs: list[str] = []
        for label, fname in [
            ("Summary", "summary.md"),
            ("Narrative", "narrative.md"),
            ("Accuracy", "accuracy-report.md"),
            ("Findings", "findings.json"),
        ]:
            if (out / fname).exists():
                active = "active" if rel == fname else ""
                tabs.append(f'<a class="tab {active}" href="/case/{case_id}/{fname}">{label}</a>')

        if (out / "audit.jsonl").exists():
            active = "active" if rel == "audit.jsonl" else ""
            tabs.append(f'<a class="tab {active}" href="/case/{case_id}/audit.jsonl">Audit</a>')

        if rel.endswith(".md"):
            content = render_md_file(target)
            body = f'<div class="tabs">{"".join(tabs)}</div><article>{content}</article>'
        elif rel.endswith(".jsonl"):
            content = render_chain_jsonl(target)
            body = f'<div class="tabs">{"".join(tabs)}</div><article>{content}</article>'
        elif rel.endswith(".json"):
            content = render_json_file(target)
            body = f'<div class="tabs">{"".join(tabs)}</div><article>{content}</article>'
        else:
            content = f'<pre>{html.escape(target.read_text())}</pre>'
            body = f'<div class="tabs">{"".join(tabs)}</div><article>{content}</article>'

        crumb = f'<a href="/">cases</a> / <a href="/case/{case_id}/">{html.escape(case_id)}</a> / {html.escape(rel)}'
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
