"""macOS DFIR primitives.

mac_plist_get + mac_knowledgec_query use Python stdlib (plistlib, sqlite3) so
they work without the [forensics] extra. Heavier APFS / tracev3 / Spotlight
parsers stay stubbed for W3 mid-week (need apfs-fuse / libtracev3).
"""

from __future__ import annotations

import plistlib
import sqlite3
from typing import Any

from ..sandbox import assert_input_path


class PlistToolError(Exception):
    """Boundary error for plist parse failures."""


class KnowledgeCToolError(Exception):
    """Boundary error for knowledgeC.db queries."""


def mac_plist_get(plist_path: str, key_path: str = "") -> dict[str, Any]:
    """Parse a macOS property list (XML or binary).

    Args:
        plist_path: path under /input to .plist file
        key_path: slash-separated traversal (e.g. ``"NSRecentDocuments/0/URL"`` or
            ``"Apps/com.apple.dock/RecentDocs/0"``). Slash is used because bundle
            identifiers contain dots. Empty string returns full root.

    Returns:
        {path, format ("xml"|"binary"|"unknown"), root_keys, value, value_type, size}
        - root_keys: top-level keys when root is a dict (else empty list)
        - value: traversed value at key_path, JSON-coerced (bytes → hex)
        - value_type: Python type name of the value pre-coercion

    Raises:
        SandboxViolation if path escapes /input.
        PlistToolError on parse or traversal failure.
    """
    p = assert_input_path(plist_path)
    try:
        with p.open("rb") as f:
            head = f.read(256)
            f.seek(0)
            data = plistlib.load(f)
    except plistlib.InvalidFileException as exc:
        raise PlistToolError(f"Not a valid plist: {p.name}") from exc
    except Exception as exc:
        raise PlistToolError(f"Failed to parse plist {p.name}: {exc}") from exc

    if head.startswith(b"bplist00"):
        fmt = "binary"
    elif b"<?xml" in head or b"<plist" in head:
        fmt = "xml"
    else:
        fmt = "unknown"

    root_keys: list[str] = []
    if isinstance(data, dict):
        root_keys = list(data.keys())

    value: Any = data
    if key_path:
        try:
            value = _traverse(data, key_path)
        except (KeyError, IndexError, TypeError) as exc:
            raise PlistToolError(f"Key path not found: {key_path!r}") from exc

    return {
        "path": str(p),
        "format": fmt,
        "size": p.stat().st_size,
        "root_keys": root_keys,
        "key_path": key_path,
        "value_type": type(value).__name__,
        "value": _coerce(value),
    }


def mac_knowledgec_query(
    db_path: str,
    *,
    sql: str | None = None,
    table: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Query macOS knowledgeC.db (app usage, screen time, focus, locations).

    Located at ``~/Library/Application Support/Knowledge/knowledgeC.db``.
    Read-only SQLite. Either pass a custom ``sql`` string (SELECT only) or
    a ``table`` name to dump rows from.

    Returns: list of row dicts. Bytes coerced to hex.

    Raises:
        KnowledgeCToolError on connection or query failure.
        ValueError if both/neither of sql and table supplied, or if sql
        contains a non-SELECT statement.
    """
    p = assert_input_path(db_path)
    if (sql is None) == (table is None):
        raise ValueError("Provide exactly one of sql or table")

    if sql is not None:
        stripped = sql.strip().lower()
        if not stripped.startswith("select") and not stripped.startswith("with"):
            raise ValueError("Only SELECT / WITH queries allowed")
    else:
        if not _is_safe_table_name(table or ""):
            raise ValueError(f"Invalid table name: {table!r}")
        # Table name validated by _is_safe_table_name (alphanumeric + underscore only).
        sql = f"SELECT * FROM {table} LIMIT ?"  # noqa: S608 — table name allowlisted above

    try:
        conn = sqlite3.connect(f"file:{p}?mode=ro&immutable=1", uri=True)
    except sqlite3.Error as exc:
        raise KnowledgeCToolError(f"Failed to open {p.name}: {exc}") from exc

    try:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        try:
            params: tuple[Any, ...] = (limit,) if table is not None else ()
            cur.execute(sql, params)
            rows = cur.fetchmany(limit)
        except sqlite3.Error as exc:
            raise KnowledgeCToolError(f"Query failed: {exc}") from exc
        return [{k: _coerce(row[k]) for k in row.keys()} for row in rows]
    finally:
        conn.close()


class ApfsToolError(Exception):
    """Boundary error for mac_apfs_inspect."""


class TracevToolError(Exception):
    """Boundary error for mac_tracev3_query — missing external tool."""


class SpotlightToolError(Exception):
    """Boundary error for mac_spotlight_query — missing external tool."""


def _resolve_binary(name: str) -> str | None:
    """Locate a system binary on PATH. None if not found."""
    import shutil
    return shutil.which(name)


def mac_apfs_inspect(image_path: str) -> dict[str, Any]:
    """Inspect APFS metadata (container, volumes, snapshots).

    Delegates to Sleuth Kit's `fsstat -f apfs <image>`. Sleuth Kit ships in
    every supported install path (apt: sleuthkit, brew: sleuthkit, dnf:
    sleuthkit), so this is portable across SIFT / macOS / Linux.

    Args:
        image_path: path under /input to APFS image (.dmg, .raw, .E01-mount).

    Returns:
        dict with parsed fsstat output:
          {
            "container": {"uuid", "block_size", "block_count", ...},
            "volumes":   [{"role", "name", "uuid", "encrypted", ...}],
            "snapshots": [{"volume", "name", "uuid", "created_at"}],
            "raw":       full fsstat stdout (truncated to 256 KiB)
          }

    Raises:
        SandboxViolation, ApfsToolError on fsstat missing / non-APFS image.
    """
    p = assert_input_path(image_path)
    fsstat = _resolve_binary("fsstat")
    if not fsstat:
        raise ApfsToolError(
            "fsstat (Sleuth Kit) not on PATH. Install: apt install sleuthkit / brew install sleuthkit."
        )
    import subprocess
    try:
        proc = subprocess.run(  # noqa: S603 — fsstat resolved via PATH lookup
            [fsstat, "-f", "apfs", str(p)],
            capture_output=True, text=True, timeout=120, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ApfsToolError(f"fsstat timed out on {p.name}") from exc
    raw = proc.stdout
    if proc.returncode != 0 or not raw.strip():
        raise ApfsToolError(f"fsstat failed: {proc.stderr.strip() or 'no output (image may not be APFS)'}")

    container: dict[str, Any] = {}
    volumes: list[dict[str, Any]] = []
    snapshots: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    mode = "container"
    for line in raw.splitlines():
        s = line.strip()
        if not s:
            continue
        # Section headers from Sleuth Kit fsstat -f apfs:
        if s.startswith("VOLUME INFORMATION") or s.startswith("Volume "):
            current = {}
            volumes.append(current)
            mode = "volume"
            continue
        if "SNAPSHOT" in s.upper() and "INFORMATION" in s.upper():
            mode = "snapshot"
            continue
        # Key: Value pattern. Best-effort key normalisation.
        if ":" in s:
            k, _, v = s.partition(":")
            key = k.strip().lower().replace(" ", "_").replace("-", "_")
            value = v.strip()
            target = current if mode == "volume" and current is not None else container
            target[key] = value
            if mode == "snapshot" and key in {"name", "uuid", "creation_time", "created"}:
                if not snapshots or "name" in snapshots[-1]:
                    snapshots.append({})
                snapshots[-1][key] = value

    return {
        "container": container,
        "volumes": volumes,
        "snapshots": snapshots,
        "raw": raw[:256 * 1024],
    }


def mac_tracev3_query(
    archive_path: str, predicate: str | None = None, *, limit: int = 10_000
) -> list[dict[str, Any]]:
    """Query a macOS Unified Logs archive (.logarchive or tracev3 dir).

    The tracev3 binary format is proprietary; there is no pure-Python parser
    that handles it completely. We delegate to the most reliable backends in
    order:

    1. **`log` command** (macOS host only). `log show --archive <path> [--predicate ...]`
       is the canonical reader. Works only when MemoryHound runs on macOS.
    2. **`unifiedlog_parser` Rust binary** (cross-platform). If installed on
       PATH (`cargo install unifiedlog_parser`), we shell out. Output is JSON
       lines per record.

    If neither is available we raise TracevToolError with install hints
    instead of returning empty rows.

    Args:
        archive_path: path under /input to .logarchive (directory) or single
            .tracev3 file.
        predicate: optional NSPredicate filter string (only honored by `log`).
        limit: max rows returned (default 10k).

    Raises:
        SandboxViolation, TracevToolError if neither backend present.
    """
    p = assert_input_path(archive_path)
    import subprocess

    # Backend 1 — macOS `log` command.
    log_bin = _resolve_binary("log")
    if log_bin:
        cmd: list[str] = [log_bin, "show", "--archive", str(p), "--style", "ndjson"]
        if predicate:
            cmd += ["--predicate", predicate]
        try:
            proc = subprocess.run(  # noqa: S603 — log resolved via PATH lookup
                cmd, capture_output=True, text=True, timeout=300, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise TracevToolError("`log show` timed out (300s)") from exc
        import json as _json
        out: list[dict[str, Any]] = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(_json.loads(line))
            except _json.JSONDecodeError:
                continue
            if len(out) >= limit:
                break
        return out

    # Backend 2 — unifiedlog_parser (Rust crate from Mandiant fork).
    ulp = _resolve_binary("unifiedlog_parser")
    if ulp:
        try:
            proc = subprocess.run(  # noqa: S603
                [ulp, "--archive", str(p), "--output", "json"],
                capture_output=True, text=True, timeout=600, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise TracevToolError("unifiedlog_parser timed out (600s)") from exc
        import json as _json
        try:
            data = _json.loads(proc.stdout)
        except _json.JSONDecodeError as exc:
            raise TracevToolError(f"unifiedlog_parser produced non-JSON output: {exc}") from exc
        if isinstance(data, list):
            return data[:limit]
        return [data] if isinstance(data, dict) else []

    raise TracevToolError(
        "No Unified Logs backend on PATH. Install one of:\n"
        "  - macOS host: built-in `log show` (no install needed; this Linux box can't run it)\n"
        "  - Cross-platform: `cargo install unifiedlog_parser` "
        "    (from mandiant/macos-UnifiedLogs)\n"
        "  - Or pre-decode to ndjson on a macOS host:\n"
        "      log show --archive <path> --style ndjson > archive.ndjson\n"
        "    Then read the ndjson via plain file tools."
    )


def mac_spotlight_query(volume_path: str, query: str, *, limit: int = 1_000) -> list[dict[str, Any]]:
    """Query Spotlight metadata for a volume.

    Two paths supported:

    1. **`mdfind` on macOS host**: live Spotlight index lookup. Best path
       when MemoryHound runs on the analyst's macOS workstation against a
       mounted evidence volume.
    2. **`spotlight_parser` (Yogesh Khatri)**: dead-box parser for the
       Store-V2 binary at `.Spotlight-V100/Store-V2/<UUID>/store.db`. If a
       wrapper is on PATH we'd invoke it; not bundled.

    For Linux/SIFT (where MemoryHound usually runs) `mdfind` is absent and
    Store-V2 parsing is hard — we raise SpotlightToolError with the install
    hint rather than returning empty.

    Args:
        volume_path: path under /input to volume root (e.g. /input/Macintosh HD).
        query: Spotlight query string (e.g. `kMDItemContentType == "public.png"`).
        limit: max paths returned.

    Raises:
        SandboxViolation, SpotlightToolError on missing backend.
    """
    p = assert_input_path(volume_path)
    import subprocess

    mdfind = _resolve_binary("mdfind")
    if mdfind:
        try:
            proc = subprocess.run(  # noqa: S603 — mdfind resolved via PATH lookup
                [mdfind, "-onlyin", str(p), query],
                capture_output=True, text=True, timeout=60, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise SpotlightToolError("mdfind timed out (60s)") from exc
        rows: list[dict[str, Any]] = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            rows.append({"path": line})
            if len(rows) >= limit:
                break
        return rows

    raise SpotlightToolError(
        "No Spotlight backend on PATH. Install one of:\n"
        "  - macOS host: `mdfind` is built-in (this Linux box can't run it)\n"
        "  - Dead-box: use Yogesh Khatri's spotlight_parser against "
        ".Spotlight-V100/Store-V2/<UUID>/store.db\n"
        "    (https://github.com/ydkhatri/spotlight_parser)"
    )


# ─── helpers ─────────────────────────────────────────────────────────────────


def _traverse(data: Any, key_path: str) -> Any:
    """Walk a slash-separated path through a plist tree (dicts + lists).

    Slash chosen because bundle IDs (com.apple.dock) contain dots — using
    dot as separator would break the most common plist key shape.
    """
    cur = data
    for part in key_path.split("/"):
        if not part:
            continue
        if isinstance(cur, list):
            cur = cur[int(part)]
        elif isinstance(cur, dict):
            cur = cur[part]
        else:
            raise TypeError(
                f"Cannot traverse {part!r} on non-container at {type(cur).__name__}"
            )
    return cur


def _coerce(v: Any) -> Any:
    """Reduce plist/SQLite values to JSON-safe form. Bytes → hex string."""
    if isinstance(v, (bytes, bytearray)):
        return v.hex()
    if isinstance(v, dict):
        return {str(k): _coerce(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_coerce(x) for x in v]
    if hasattr(v, "isoformat"):
        try:
            return v.isoformat()
        except Exception:  # noqa: S110 — fall through to repr if isoformat impl missing/broken
            pass
    return v


def _is_safe_table_name(name: str) -> bool:
    return bool(name) and name.replace("_", "").isalnum()
