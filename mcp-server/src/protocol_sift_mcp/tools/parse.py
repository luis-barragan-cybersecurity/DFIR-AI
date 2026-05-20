"""Common parsing primitives + cross-OS detection.

os_detect is the routing primitive used by triage-orchestrator. It must
return a structured verdict that the orchestrator can use to dispatch the
correct OS-specialist subagent without ambiguity.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from ..sandbox import assert_input_path


def magic_check(path: str) -> dict[str, Any]:
    """Read first 16 bytes + file size for type fingerprinting."""
    p = assert_input_path(path)
    head = p.open("rb").read(16)
    return {"path": str(p), "head_hex": head.hex(), "size": p.stat().st_size}


# ─── OS Detection ────────────────────────────────────────────────────────────


_WINDOWS_FILE_MAGIC: list[tuple[bytes, str, str]] = [
    (b"regf", "regf", "windows registry hive"),
    (b"SCCA", "SCCA", "windows prefetch (uncompressed)"),
    (b"MAM\x04", "MAM", "windows prefetch (XPRESS-Huffman compressed, Win10+)"),
    (b"ElfFile\x00", "ElfFile", "windows event log (.evtx)"),
    (b"\xff\xfeM\x00", "MZ-utf16", "windows shortcut (.lnk header signature subset)"),
    (b"L\x00\x00\x00\x01\x14\x02\x00", "LNK", "windows shortcut (.lnk)"),
]


_MACOS_FILE_MAGIC: list[tuple[bytes, str, str]] = [
    (b"bplist00", "bplist00", "macOS binary plist"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64 LE", "macOS Mach-O 64-bit"),
    (b"\xfe\xed\xfa\xce", "Mach-O 32 BE", "macOS Mach-O 32-bit"),
    (b"\xfe\xed\xfa\xcf", "Mach-O 64 BE", "macOS Mach-O 64-bit"),
    (b"\xca\xfe\xba\xbe", "Mach-O Fat", "macOS universal binary"),
]


_LINUX_FILE_MAGIC: list[tuple[bytes, str, str]] = [
    (b"\x7fELF", "ELF", "ELF executable / core dump"),
    (b"hsqs", "squashfs", "squashfs filesystem"),
    (b"EMiL", "EMiL", "LiME memory dump"),
]


_FS_OFFSET_MAGIC: list[tuple[int, bytes, str, str]] = [
    (0x438, b"\x53\xef", "ext", "ext2/3/4 filesystem (offset 0x438)"),
    (32, b"NXSB", "NXSB", "APFS container superblock (offset 32)"),
    (1024, b"H+", "HFS+", "HFS+ filesystem (offset 1024)"),
    (3, b"NTFS    ", "NTFS", "NTFS volume boot record"),
]


_DIR_MARKERS: list[tuple[str, str, str]] = [
    ("Windows/System32", "windows", "presence of Windows/System32"),
    ("Windows/Prefetch", "windows", "presence of Windows/Prefetch"),
    ("System/Library/CoreServices", "macos", "presence of System/Library/CoreServices"),
    ("Library/LaunchAgents", "macos", "presence of Library/LaunchAgents"),
    ("etc/passwd", "linux", "presence of /etc/passwd"),
    ("var/log/auth.log", "linux", "presence of /var/log/auth.log"),
    ("etc/systemd/system", "linux", "presence of /etc/systemd/system"),
]


_OS_OF_FAMILY: dict[str, str] = {
    "windows registry hive": "windows",
    "windows prefetch (uncompressed)": "windows",
    "windows prefetch (XPRESS-Huffman compressed, Win10+)": "windows",
    "windows event log (.evtx)": "windows",
    "windows shortcut (.lnk)": "windows",
    "windows shortcut (.lnk header signature subset)": "windows",
    "NTFS volume boot record": "windows",
    "macOS binary plist": "macos",
    "macOS Mach-O 32-bit": "macos",
    "macOS Mach-O 64-bit": "macos",
    "macOS universal binary": "macos",
    "APFS container superblock (offset 32)": "macos",
    "HFS+ filesystem (offset 1024)": "macos",
    "ELF executable / core dump": "linux",
    "squashfs filesystem": "linux",
    "ext2/3/4 filesystem (offset 0x438)": "linux",
    "LiME memory dump": "linux_or_memory",
}


def os_detect(path: str) -> dict[str, Any]:
    """Identify which OS produced this evidence artifact.

    Returns a structured verdict the triage-orchestrator can route on:

        {
          "os": "windows" | "macos" | "linux" | "memory_dump" | "unknown",
          "confidence": 0.0–1.0,
          "evidence_class": "registry" | "evtx" | "prefetch" | "lnk" | "plist"
                          | "filesystem_image" | "memory_dump" | "directory"
                          | "unknown",
          "signals": [{"source": "...", "match": "...", "weight": float}, ...],
          "is_directory": bool,
          "size": int | None,
        }

    Confidence calculus:
      - 1.0  → definitive magic match (e.g. regf, NXSB, ElfFile)
      - 0.8  → 2 independent signals agree
      - 0.6  → 1 magic signal
      - 0.4  → directory marker only
      - 0.0  → no signals
    """
    p = assert_input_path(path)
    signals: list[dict[str, Any]] = []
    size: int | None = None
    is_dir = p.is_dir()

    if is_dir:
        for marker, os_name, desc in _DIR_MARKERS:
            if (p / marker).exists():
                signals.append({"source": "dir_marker", "match": desc, "os": os_name, "weight": 0.4})
        os_votes = _tally(signals)
        chosen, conf = _decide(os_votes, signals)
        return {
            "os": chosen,
            "confidence": conf,
            "evidence_class": "directory",
            "signals": signals,
            "is_directory": True,
            "size": None,
        }

    size = p.stat().st_size
    head = p.open("rb").read(64)

    for magic, _, desc in _WINDOWS_FILE_MAGIC + _MACOS_FILE_MAGIC + _LINUX_FILE_MAGIC:
        if head.startswith(magic):
            signals.append(
                {
                    "source": "file_magic",
                    "match": desc,
                    "os": _OS_OF_FAMILY.get(desc, "unknown"),
                    "weight": 1.0,
                }
            )
            break

    for offset, magic, _, desc in _FS_OFFSET_MAGIC:
        if size > offset + len(magic):
            with p.open("rb") as f:
                f.seek(offset)
                if f.read(len(magic)) == magic:
                    signals.append(
                        {
                            "source": "fs_offset",
                            "match": desc,
                            "os": _OS_OF_FAMILY.get(desc, "unknown"),
                            "weight": 1.0,
                        }
                    )
                    break

    if not signals:
        ext = p.suffix.lower()
        ext_map = {
            ".evtx": ("windows", "evtx extension"),
            ".pf": ("windows", "prefetch extension"),
            ".lnk": ("windows", "shortcut extension"),
            ".dat": ("windows", "registry hive extension (NTUSER.DAT etc)"),
            ".plist": ("macos", "plist extension"),
            ".tracev3": ("macos", "Unified Logs archive extension"),
            ".dmp": ("memory_dump", "raw memory dump extension"),
            ".vmem": ("memory_dump", "VMware memory snapshot extension"),
            ".raw": ("memory_dump", "raw memory image extension"),
            ".mem": ("memory_dump", "raw memory dump extension"),
            ".lime": ("linux", "LiME memory dump extension"),
            ".aff": ("memory_dump", "Advanced Forensic Format"),
            ".e01": ("filesystem_image", "EnCase image format"),
        }
        if ext in ext_map:
            os_name, desc = ext_map[ext]
            signals.append({"source": "extension", "match": desc, "os": os_name, "weight": 0.5})

    chosen, conf = _decide(_tally(signals), signals)
    evidence_class = _classify_evidence(signals)

    return {
        "os": chosen,
        "confidence": conf,
        "evidence_class": evidence_class,
        "signals": signals,
        "is_directory": False,
        "size": size,
    }


def _tally(signals: list[dict[str, Any]]) -> dict[str, float]:
    votes: dict[str, float] = {}
    for s in signals:
        os_name = s.get("os", "unknown")
        votes[os_name] = votes.get(os_name, 0.0) + float(s["weight"])
    return votes


def _decide(votes: dict[str, float], signals: list[dict[str, Any]]) -> tuple[str, float]:
    if not votes:
        return "unknown", 0.0
    chosen = max(votes.items(), key=lambda kv: kv[1])
    name, score = chosen
    if name == "unknown":
        return "unknown", 0.0
    if name == "linux_or_memory":
        return "linux", min(score, 0.8)
    independent = {s["source"] for s in signals if s.get("os") == name}
    if len(independent) >= 2:
        return name, min(1.0, 0.8 + 0.2 * (len(independent) - 2))
    if score >= 1.0:
        return name, min(1.0, 0.6 + 0.4 * (score - 1.0) / max(score, 1.0))
    return name, min(score, 0.6)


def _classify_evidence(signals: list[dict[str, Any]]) -> str:
    matches = [s["match"] for s in signals]
    text = " ".join(matches).lower()
    if "registry" in text:
        return "registry"
    if "event log" in text or ".evtx" in text:
        return "evtx"
    if "prefetch" in text:
        return "prefetch"
    if "shortcut" in text or ".lnk" in text:
        return "lnk"
    if "plist" in text:
        return "plist"
    if "memory" in text or "core dump" in text:
        return "memory_dump"
    if "filesystem" in text or "ntfs" in text or "apfs" in text or "hfs" in text:
        return "filesystem_image"
    if not signals:
        return "unknown"
    return "unknown"


# ─── Other parse primitives ──────────────────────────────────────────────────


def hex_inspect(path: str, offset: int, length: int) -> str:
    """Read a byte range and return hex. Bounded length to prevent OOM."""
    p = assert_input_path(path)
    if length > 1 << 16:
        raise ValueError("length > 64KiB; chunk your reads")
    with p.open("rb") as f:
        f.seek(offset)
        return f.read(length).hex()


class PeToolError(Exception):
    """Boundary error for pe_inspect — pefile missing or PE parse failure."""


def _import_pefile() -> Any:
    """Lazy-import pefile so module load works without [forensics] installed."""
    try:
        import pefile as _pefile  # type: ignore
    except ImportError as exc:
        raise PeToolError(
            "pefile not installed. "
            "Install via the [forensics] extra: `pip install 'protocol-sift-mcp[forensics]'`."
        ) from exc
    return _pefile


def pe_inspect(path: str, *, max_section_data: int = 0) -> dict[str, Any]:
    """Inspect a Windows PE (Portable Executable) file.

    Extracts the DOS header, COFF header, optional header (image base, entry
    point, subsystem, characteristics), sections (name, size, virtual address,
    entropy), imports (DLL → function names), and exports. Static analysis
    primitive covering .exe, .dll, .sys, .scr, drivers, and any PE format.

    Args:
        path: path under /input to a PE file
        max_section_data: if >0, include this many bytes of raw section data
            per section as hex (capped at 4 KiB/section). Default 0 (omit).

    Returns:
        Structured dict with: file (path/size/md5/sha256), dos, coff, opt,
        sections, imports, exports, indicators (suspicious-flag rollup).

    Raises:
        SandboxViolation if path escapes /input.
        PeToolError on missing pefile or malformed PE.
    """
    p = assert_input_path(path)
    if max_section_data < 0 or max_section_data > 4096:
        raise ValueError("max_section_data must be 0..4096")

    pefile = _import_pefile()
    try:
        pe = pefile.PE(str(p), fast_load=False)
    except Exception as exc:  # noqa: BLE001 — pefile raises many concrete types
        raise PeToolError(f"Failed to parse PE {p.name}: {exc}") from exc

    import hashlib
    raw_bytes = p.read_bytes()
    md5 = hashlib.md5(raw_bytes, usedforsecurity=False).hexdigest()
    sha256 = hashlib.sha256(raw_bytes).hexdigest()

    dos = {
        "magic": f"0x{pe.DOS_HEADER.e_magic:04x}",
        "lfanew": pe.DOS_HEADER.e_lfanew,
    }
    coff = {
        "machine": f"0x{pe.FILE_HEADER.Machine:04x}",
        "number_of_sections": pe.FILE_HEADER.NumberOfSections,
        "timestamp": pe.FILE_HEADER.TimeDateStamp,
        "characteristics": f"0x{pe.FILE_HEADER.Characteristics:04x}",
    }
    opt = {
        "magic": f"0x{pe.OPTIONAL_HEADER.Magic:04x}",  # 0x10b=32-bit, 0x20b=64-bit
        "image_base": f"0x{pe.OPTIONAL_HEADER.ImageBase:x}",
        "entry_point": f"0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:x}",
        "subsystem": pe.OPTIONAL_HEADER.Subsystem,
        "dll_characteristics": f"0x{pe.OPTIONAL_HEADER.DllCharacteristics:04x}",
        "size_of_image": pe.OPTIONAL_HEADER.SizeOfImage,
    }

    sections: list[dict[str, Any]] = []
    for s in pe.sections:
        try:
            name = s.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            name = "?"
        entry: dict[str, Any] = {
            "name": name,
            "virtual_address": f"0x{s.VirtualAddress:x}",
            "virtual_size": s.Misc_VirtualSize,
            "raw_size": s.SizeOfRawData,
            "characteristics": f"0x{s.Characteristics:08x}",
            "entropy": round(s.get_entropy(), 3),
        }
        if max_section_data:
            try:
                entry["data_hex"] = s.get_data()[:max_section_data].hex()
            except Exception:  # noqa: BLE001, S110 — section may be unreadable; non-blocking
                entry["data_hex"] = ""
        sections.append(entry)

    imports: list[dict[str, Any]] = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("utf-8", errors="replace") if entry.dll else "?"
            funcs: list[str] = []
            for imp in entry.imports:
                if imp.name:
                    funcs.append(imp.name.decode("utf-8", errors="replace"))
                elif imp.ordinal:
                    funcs.append(f"#ord{imp.ordinal}")
            imports.append({"dll": dll, "functions": funcs})

    exports: list[str] = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                exports.append(exp.name.decode("utf-8", errors="replace"))
            elif exp.ordinal is not None:
                exports.append(f"#ord{exp.ordinal}")

    high_entropy_sections = [s["name"] for s in sections if s["entropy"] > 7.0]
    indicators = {
        "high_entropy_sections": high_entropy_sections,  # >7.0 suggests packing/encryption
        "is_64bit": opt["magic"] == "0x20b",
        "is_dll": bool(pe.FILE_HEADER.Characteristics & 0x2000),  # IMAGE_FILE_DLL
        "is_signed_hint": False,  # full sig validation = separate code path; signal stays False
        "import_count": sum(len(i["functions"]) for i in imports),
        "export_count": len(exports),
    }

    return {
        "file": {
            "path": str(p),
            "size": p.stat().st_size,
            "md5": md5,
            "sha256": sha256,
        },
        "dos": dos,
        "coff": coff,
        "opt": opt,
        "sections": sections,
        "imports": imports,
        "exports": exports,
        "indicators": indicators,
    }


class SqliteToolError(Exception):
    """Boundary error for sqlite_query — connect / query / iteration failures."""


def sqlite_query(
    db_path: str,
    query: str,
    *,
    params: tuple[Any, ...] | list[Any] | None = None,
    limit: int = 10_000,
) -> list[dict[str, Any]]:
    """Read-only SQLite query against an evidence DB file.

    Used for Chrome/Edge/Firefox history, ActivitiesCache.db, WhatsApp/Signal
    chat DBs, places.sqlite, photos.sqlite, and any other SQLite-backed
    artifact. Mirrors the safety contract of mac_knowledgec_query.

    Args:
        db_path: path under /input to a .sqlite/.db file
        query: SQL statement. MUST start with SELECT or WITH (case-insensitive).
        params: optional parameter tuple/list for ?-substitution in query.
        limit: max rows returned (default 10k; query LIMIT clause still wins
            if smaller).

    Returns:
        list of row dicts (column-name → value). Bytes are hex-coerced for
        JSON safety; sqlite3.Row date/datetime values pass through to _coerce.

    Raises:
        SandboxViolation if path escapes /input.
        SqliteToolError on connect/query failure.
        ValueError on non-SELECT/WITH queries.
    """
    p = assert_input_path(db_path)
    stripped = query.strip().lower()
    if not (stripped.startswith("select") or stripped.startswith("with")):
        raise ValueError("Only SELECT / WITH queries allowed")
    if limit <= 0 or limit > 1_000_000:
        raise ValueError("limit must be 1..1_000_000")

    try:
        # mode=ro — read-only. immutable=1 — promises caller won't change the
        # file, lets sqlite skip journal/WAL recovery, useful when reading
        # detached evidence DBs (Chrome History etc. with no -wal/-journal).
        conn = sqlite3.connect(f"file:{p}?mode=ro&immutable=1", uri=True)
    except sqlite3.Error as exc:
        raise SqliteToolError(f"Failed to open {p.name}: {exc}") from exc

    try:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        try:
            cur.execute(query, tuple(params or ()))
            rows = cur.fetchmany(limit)
        except sqlite3.Error as exc:
            raise SqliteToolError(f"Query failed: {exc}") from exc
        return [{k: _coerce_value(row[k]) for k in row.keys()} for row in rows]
    finally:
        conn.close()


def _coerce_value(v: Any) -> Any:
    """Reduce SQLite values to JSON-safe form. Mirrors macos._coerce."""
    if isinstance(v, (bytes, bytearray)):
        return v.hex()
    if hasattr(v, "isoformat"):
        try:
            return v.isoformat()
        except Exception:  # noqa: S110, BLE001 — fall through to repr if isoformat broken
            pass
    return v


class YaraToolError(Exception):
    """yara-python missing, rules compilation failure, or scan boundary error."""


def yara_scan(
    target_path: str,
    rule_path: str,
    *,
    recursive: bool = True,
    max_hits: int = 10000,
) -> list[dict[str, Any]]:
    """Compile a YARA ruleset and scan target_path for matches.

    target_path: file or directory under EVIDENCE_PATH. If a directory and
        recursive=True, every regular file is scanned.
    rule_path: path to a .yar/.yara rule file (NOT sandbox-asserted —
        rules ship from the analyst's library, not from evidence).

    Returns a flat list of hit records:
        [{path, rule, namespace, tags, strings: [{identifier, offset, data_hex}]}]

    Bounded by `max_hits` to prevent OOM on noisy rules. Skips files that
    error on open (records the error in the result for visibility).
    """
    target = assert_input_path(target_path)
    rules_path = Path(rule_path)
    if not rules_path.exists():
        raise YaraToolError(f"rule file does not exist: {rules_path}")

    try:
        import yara  # type: ignore[import-not-found]
    except ImportError as exc:
        raise YaraToolError(
            "yara-python not installed. Install with: pip install yara-python"
        ) from exc

    try:
        rules = yara.compile(filepath=str(rules_path))
    except Exception as exc:  # yara.SyntaxError, etc. — keep broad
        raise YaraToolError(f"failed to compile {rules_path}: {exc}") from exc

    hits: list[dict[str, Any]] = []

    def _scan_one(path: Path) -> None:
        try:
            matches = rules.match(str(path), timeout=120)
        except Exception as exc:  # IOError, MemoryError, yara timeouts
            hits.append({"path": str(path), "error": f"{type(exc).__name__}: {exc}"})
            return
        for m in matches:
            if len(hits) >= max_hits:
                return
            string_rows: list[dict[str, Any]] = []
            for s in getattr(m, "strings", []) or []:
                # yara-python's StringMatch API varies by version — be defensive.
                try:
                    identifier = getattr(s, "identifier", None) or s[1]
                    instances = getattr(s, "instances", None) or [(s[0], s[2])]
                    for inst in instances:
                        offset = getattr(inst, "offset", None) if hasattr(inst, "offset") else inst[0]
                        data = getattr(inst, "matched_data", None) if hasattr(inst, "matched_data") else inst[1]
                        string_rows.append({
                            "identifier": identifier,
                            "offset": offset,
                            "data_hex": bytes(data or b"").hex()[:512],
                        })
                except Exception:
                    string_rows.append({"identifier": "<opaque>", "offset": -1, "data_hex": ""})
            hits.append({
                "path": str(path),
                "rule": m.rule,
                "namespace": getattr(m, "namespace", "default"),
                "tags": list(getattr(m, "tags", []) or []),
                "strings": string_rows,
            })

    if target.is_file():
        _scan_one(target)
    elif target.is_dir() and recursive:
        for p in sorted(target.rglob("*")):
            if p.is_file():
                _scan_one(p)
                if len(hits) >= max_hits:
                    break
    elif target.is_dir():
        for p in sorted(target.iterdir()):
            if p.is_file():
                _scan_one(p)
                if len(hits) >= max_hits:
                    break
    return hits
