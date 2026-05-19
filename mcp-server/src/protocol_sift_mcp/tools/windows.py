"""Windows DFIR primitives.

Each function is a typed forensic primitive. No shell exec, no destructive ops.
"""

from __future__ import annotations

from typing import Any

from ..sandbox import assert_input_path


class RegistryToolError(Exception):
    """Wraps any failure surfaced from python-registry into a single boundary error.

    Lets the agent treat 'key missing' the same as 'hive corrupted' at the API
    layer, while preserving the original cause for the chain log.
    """


def _import_registry() -> Any:
    """Lazy-import python-registry so module load works without [forensics] extra installed.

    Tests stub this via sys.modules patching. Raises a clear error if the
    optional dep is missing on a real run.
    """
    try:
        from Registry import Registry as _Registry
    except ImportError as exc:
        raise RegistryToolError(
            "python-registry not installed. "
            "Install with: pip install -e 'mcp-server[forensics]'"
        ) from exc
    return _Registry


def win_registry_get(hive_path: str, registry_path: str = "") -> dict[str, Any]:
    """Read a registry key from a Windows hive file.

    Args:
        hive_path: Path inside the evidence sandbox to the hive file
            (NTUSER.DAT, SOFTWARE, SYSTEM, SAM, USRCLASS.DAT, etc.)
        registry_path: Backslash-delimited path under the hive root.
            Empty string returns the root key.

    Returns:
        dict with: path, timestamp (ISO), hive_type, subkeys (names), values
        (each: name, value_type, value, raw_hex). raw_hex enables evidence
        pinning — the agent cites this hex in finding pins.

    Raises:
        SandboxViolation if hive_path escapes /input.
        RegistryToolError on any python-registry failure (key not found,
        corrupted hive, missing optional dep).
    """
    p = assert_input_path(hive_path)
    _Registry = _import_registry()

    try:
        reg = _Registry.Registry(str(p))
    except Exception as exc:
        raise RegistryToolError(f"Failed to open hive {p}: {exc}") from exc

    try:
        key = reg.open(registry_path) if registry_path else reg.root()
    except Exception as exc:
        raise RegistryToolError(
            f"Registry path not found: {registry_path!r} in {p.name}"
        ) from exc

    values: list[dict[str, Any]] = []
    for v in key.values():
        try:
            decoded = v.value()
        except Exception:
            decoded = None
        try:
            raw = v.raw_data() if hasattr(v, "raw_data") else b""
            raw_hex = raw.hex() if isinstance(raw, (bytes, bytearray)) else ""
        except Exception:
            raw_hex = ""
        try:
            type_str = v.value_type_str()
        except Exception:
            type_str = "UNKNOWN"
        values.append(
            {
                "name": v.name() or "(default)",
                "value_type": type_str,
                "value": _coerce_value(decoded),
                "raw_hex": raw_hex,
            }
        )

    subkey_names: list[str] = []
    for sk in key.subkeys():
        try:
            subkey_names.append(sk.name())
        except Exception:  # noqa: S112 — skip individual corrupted subkey, surface rest
            continue

    timestamp = None
    try:
        ts = key.timestamp()
        if ts is not None:
            timestamp = ts.isoformat()
    except Exception:
        timestamp = None

    hive_type = None
    try:
        hive_type = str(reg.hive_type()) if hasattr(reg, "hive_type") else None
    except Exception:
        hive_type = None

    return {
        "path": _safe_path(key, registry_path),
        "timestamp": timestamp,
        "hive_type": hive_type,
        "subkeys": subkey_names,
        "values": values,
    }


def _coerce_value(v: Any) -> Any:
    """Reduce decoded values to JSON-serializable forms. Bytes → hex string."""
    if isinstance(v, (bytes, bytearray)):
        return v.hex()
    if isinstance(v, list):
        return [_coerce_value(x) for x in v]
    return v


def _safe_path(key: Any, fallback: str) -> str:
    try:
        return key.path()
    except Exception:
        return fallback or "(root)"


class PrefetchToolError(Exception):
    """Boundary error for windowsprefetch failures."""


class EvtxToolError(Exception):
    """Boundary error for python-evtx failures."""


class LnkToolError(Exception):
    """Boundary error for pylnk3 failures."""


def _import_prefetch() -> Any:
    try:
        from windowsprefetch import Prefetch
    except ImportError as exc:
        raise PrefetchToolError(
            "windowsprefetch not installed. "
            "Install with: pip install -e 'mcp-server[forensics]'"
        ) from exc
    return Prefetch


def _import_evtx() -> Any:
    try:
        import Evtx.Evtx as evtx
    except ImportError as exc:
        raise EvtxToolError(
            "python-evtx not installed. "
            "Install with: pip install -e 'mcp-server[forensics]'"
        ) from exc
    return evtx


def _import_lnk() -> Any:
    try:
        import pylnk3
    except ImportError as exc:
        raise LnkToolError(
            "pylnk3 not installed. "
            "Install with: pip install -e 'mcp-server[forensics]'"
        ) from exc
    return pylnk3


def win_prefetch_parse(prefetch_path: str) -> dict[str, Any]:
    """Parse a Windows .pf prefetch file.

    Returns: executable_name, run_count, last_run_times (up to 8 for Win8+),
    version (17/23/26/30=XP/7/8/10), volumes, files_accessed, directories.
    Win10 prefetch is XPRESS-Huffman compressed; the underlying library
    handles decompression. raw_excerpt for pins should cite the .pf path
    and a specific timestamp index.
    """
    p = assert_input_path(prefetch_path)
    Prefetch = _import_prefetch()
    try:
        pf = Prefetch(str(p))
    except Exception as exc:
        raise PrefetchToolError(f"Failed to parse prefetch {p.name}: {exc}") from exc

    last_run_times: list[str] = []
    raw_lrt = getattr(pf, "lastRunTime", None) or getattr(pf, "lastRunTimes", None)
    if raw_lrt is not None:
        items = raw_lrt if isinstance(raw_lrt, list) else [raw_lrt]
        for ts in items:
            try:
                last_run_times.append(ts.isoformat())
            except Exception:  # noqa: S112 — skip a single malformed timestamp
                continue

    return {
        "path": str(p),
        "executable_name": getattr(pf, "executableName", None),
        "version": getattr(pf, "version", None),
        "run_count": getattr(pf, "runCount", None),
        "last_run_times": last_run_times,
        "volumes": list(getattr(pf, "volumesInformation", []) or []),
        "files_accessed": list(getattr(pf, "filesAccessed", []) or []),
        "directories": list(getattr(pf, "directoryStrings", []) or []),
    }


def win_evtx_query(
    log_path: str,
    *,
    event_ids: list[int] | None = None,
    time_range: tuple[str, str] | None = None,
    limit: int = 1000,
) -> list[dict[str, Any]]:
    """Query a Windows Event Log (.evtx) file.

    Args:
        log_path: path under /input to .evtx file
        event_ids: optional list of EID filters (e.g. [4624, 4625, 4648])
        time_range: optional (since_iso, until_iso) tuple, inclusive
        limit: max records returned (default 1000)

    Returns: list of {record_id, eid, channel, time_created, computer, xml}.
    XML field is the raw record XML — agent cites it in pin raw_excerpt.
    """
    p = assert_input_path(log_path)
    evtx = _import_evtx()

    eid_filter = set(event_ids) if event_ids else None
    since_iso, until_iso = time_range if time_range else (None, None)

    try:
        log = evtx.Evtx(str(p))
    except Exception as exc:
        raise EvtxToolError(f"Failed to open evtx {p.name}: {exc}") from exc

    results: list[dict[str, Any]] = []
    try:
        with log as opened:
            for record in opened.records():
                if len(results) >= limit:
                    break
                xml = record.xml()
                eid = _parse_evtx_eid(xml)
                if eid_filter and eid not in eid_filter:
                    continue
                ts = _parse_evtx_time(xml)
                if since_iso and ts and ts < since_iso:
                    continue
                if until_iso and ts and ts > until_iso:
                    continue
                results.append(
                    {
                        "record_id": _parse_evtx_record_id(xml),
                        "eid": eid,
                        "channel": _parse_evtx_channel(xml),
                        "time_created": ts,
                        "computer": _parse_evtx_computer(xml),
                        "xml": xml,
                    }
                )
    except Exception as exc:
        raise EvtxToolError(f"Failed to iterate evtx {p.name}: {exc}") from exc
    return results


def win_lnk_parse(lnk_path: str) -> dict[str, Any]:
    """Parse a Windows shortcut (.lnk) file.

    Returns: target path, target MACB timestamps, volume info, network share,
    working directory, command-line arguments, original file size,
    machine name (system that created the shortcut). Useful for tracking
    USB activity, file/folder opens, and timeline reconstruction.
    """
    p = assert_input_path(lnk_path)
    pylnk3 = _import_lnk()
    try:
        with open(str(p), "rb") as fh:  # noqa: PTH123 — pylnk3 expects file handle
            link = pylnk3.parse(fh)
    except Exception as exc:
        raise LnkToolError(f"Failed to parse lnk {p.name}: {exc}") from exc

    return {
        "path": str(p),
        "target": getattr(link, "path", None) or getattr(link, "lnk_path", None),
        "working_dir": getattr(link, "working_dir", None),
        "arguments": getattr(link, "arguments", None),
        "description": getattr(link, "description", None),
        "machine_id": getattr(link, "machine_id", None),
        "drive_serial": getattr(link, "drive_serial", None),
        "drive_type": str(getattr(link, "drive_type", None)) if hasattr(link, "drive_type") else None,
        "creation_time": _to_iso(getattr(link, "creation_time", None)),
        "modification_time": _to_iso(getattr(link, "modification_time", None)),
        "access_time": _to_iso(getattr(link, "access_time", None)),
        "file_size": getattr(link, "file_size", None),
        "network_share": getattr(link, "network_share_name", None),
    }


def _to_iso(v: Any) -> str | None:
    if v is None:
        return None
    try:
        return v.isoformat()
    except Exception:
        return str(v)


def _parse_evtx_eid(xml: str) -> int | None:
    import re

    m = re.search(r"<EventID[^>]*>(\d+)</EventID>", xml)
    return int(m.group(1)) if m else None


def _parse_evtx_record_id(xml: str) -> str | None:
    import re

    m = re.search(r'EventRecordID="?(\d+)"?', xml) or re.search(
        r"<EventRecordID>(\d+)</EventRecordID>", xml
    )
    return m.group(1) if m else None


def _parse_evtx_channel(xml: str) -> str | None:
    import re

    m = re.search(r"<Channel>([^<]+)</Channel>", xml)
    return m.group(1) if m else None


def _parse_evtx_time(xml: str) -> str | None:
    import re

    m = re.search(r'SystemTime="([^"]+)"', xml)
    return m.group(1) if m else None


def _parse_evtx_computer(xml: str) -> str | None:
    import re

    m = re.search(r"<Computer>([^<]+)</Computer>", xml)
    return m.group(1) if m else None


_SHELLBAG_PATHS = (
    # USRCLASS.DAT — primary location on Win7+
    "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
    # NTUSER.DAT — older systems / network folders
    "Software\\Microsoft\\Windows\\Shell\\BagMRU",
    "Software\\Microsoft\\Windows\\ShellNoRoam\\BagMRU",
)


def _filetime_to_iso(ft: int) -> str | None:
    """Convert Windows FILETIME (100-ns intervals since 1601-01-01) to ISO."""
    if not ft:
        return None
    import datetime as _dt
    try:
        # 11644473600 seconds between 1601 and 1970 epoch
        ts = ft / 10_000_000 - 11644473600
        return _dt.datetime.fromtimestamp(ts, tz=_dt.UTC).isoformat()
    except (OSError, OverflowError, ValueError):
        return None


def _decode_shell_item(blob: bytes) -> dict[str, Any]:
    """Best-effort decode of a SHITEMID blob.

    The full shell-item taxonomy is enormous (network, MTP, libraries, GUIDs).
    For DFIR triage the high-value subset is file/directory items
    (class 0x30-0x3F). This decoder extracts the user-visible Unicode name
    when present and returns the type byte + size for everything else,
    plus the raw hex for the analyst to inspect.

    Shell-item layout (LE):
        [u16 size][u8 class][...class-specific...]
    """
    out: dict[str, Any] = {"size": len(blob), "raw_hex": blob.hex()}
    if len(blob) < 3:
        return out
    item_size = int.from_bytes(blob[0:2], "little")
    out["size"] = item_size
    cls = blob[2]
    out["class_byte"] = f"0x{cls:02x}"
    # File/folder item class range: 0x30..0x3F.
    # Layout (Win7+, the common case):
    #   u16 size | u8 class | u8 unk | u32 filesize | u32 dos_date
    #   ... ANSI name (legacy) ... pad ... ExtensionBlock with UTF-16 name
    if 0x30 <= cls <= 0x3F:
        out["kind"] = "file" if cls & 0x02 else "folder"
        # ExtensionBlock0xBEEF0004 contains the unicode long name.
        # Find the BEEF tag (LE u16 0x0004 followed by 0xBEEF). Conservative
        # search; if not found, fall back to the legacy ANSI name.
        bf = blob.find(b"\x04\x00\xef\xbe")
        if bf > 0 and bf + 12 < item_size:
            # Walk to the UTF-16 string after the extension header.
            # Header layout: u16 ext_size | u32 sig | u16 ver | u16 unk |
            # u32 modtime | u32 unk2 | (filetime CreationTime/AccessTime — newer)
            # then null-terminated UTF-16LE LongName.
            cursor = bf + 12  # skip sig+ver+two u16s
            # Newer extensions include 8-byte filetimes; skip if present.
            # Heuristic: try parsing UTF-16 from a few candidate offsets.
            for skip in (0, 4, 8, 12, 16):
                start = cursor + skip
                if start >= item_size - 2:
                    continue
                try:
                    end = blob.index(b"\x00\x00", start)
                    if (end - start) % 2 != 0:
                        end += 1
                    name = blob[start:end].decode("utf-16-le", errors="replace")
                    if name and all(c.isprintable() or c.isspace() for c in name):
                        out["name"] = name
                        break
                except ValueError:
                    continue
        if "name" not in out and item_size > 14:
            # Legacy ANSI fallback: name starts at byte 14, null-terminated.
            try:
                ansi = blob[14:].split(b"\x00", 1)[0]
                out["name"] = ansi.decode("latin-1", errors="replace")
            except Exception:  # noqa: BLE001, S110 — best-effort ANSI name fallback; not logging keeps the row JSON-shaped
                pass
    return out


def win_shellbag_parse(hive_path: str) -> list[dict[str, Any]]:
    """Parse ShellBags from a registry hive (USRCLASS.DAT or NTUSER.DAT).

    Walks the BagMRU tree at all three known root paths, decodes each entry's
    shell-item blob, and emits one row per BagMRU node with the user-visible
    name (when extractable) plus the registry key's LastWriteTime as the
    canonical "this folder was browsed" timestamp.

    Args:
        hive_path: path under /input to USRCLASS.DAT or NTUSER.DAT

    Returns:
        list of {root, key_path, mru_index, last_write, name, kind, class_byte, raw_hex, size}

    Raises:
        SandboxViolation, RuntimeError (no python-registry installed).
    """
    p = assert_input_path(hive_path)
    Registry = _import_registry()
    reg = Registry.Registry(str(p))
    rows: list[dict[str, Any]] = []

    def walk(key: Any, path_so_far: str) -> None:
        # Each BagMRU node holds numbered values 0..N where each value is a
        # shell-item blob, plus a NodeSlot and MRUListEx.
        last_write = None
        try:
            ts = key.timestamp()
            last_write = ts.isoformat() if ts else None
        except Exception:  # noqa: BLE001, S110 — timestamp may be unavailable on some hives
            pass

        # Numbered subkeys hold deeper folders. Numbered VALUES hold shell items.
        for v in key.values():
            name = v.name()
            if name.isdigit():
                try:
                    blob = v.value()
                    if isinstance(blob, (bytes, bytearray)):
                        decoded = _decode_shell_item(bytes(blob))
                        rows.append({
                            "root": path_so_far.split("\\")[0] if path_so_far else None,
                            "key_path": path_so_far,
                            "mru_index": int(name),
                            "last_write": last_write,
                            **decoded,
                        })
                except Exception:  # noqa: BLE001, S112 — skip unparseable entries, never crash the whole walk
                    continue

        for sub in key.subkeys():
            walk(sub, f"{path_so_far}\\{sub.name()}" if path_so_far else sub.name())

    for root_path in _SHELLBAG_PATHS:
        try:
            key = reg.open(root_path)
        except Exception:  # noqa: BLE001, S112 — most hives only have one of these three BagMRU roots
            continue
        walk(key, root_path)

    return rows


def win_recyclebin_parse(recycle_dir: str) -> list[dict[str, Any]]:
    """Parse $I###### header files in a Recycle Bin directory.

    Vista+ Recycle Bin layout: each deleted file becomes a $R###### copy
    plus a $I###### header. The $I files are tiny (typically 540 or
    metadata-size bytes) and contain the original filename, file size,
    and deletion timestamp.

    Two known header versions:
        v1 (Vista..Win10 1709): fixed UTF-16LE name, 520 bytes
        v2 (Win10 1803+):        u32 name_length + variable-length UTF-16LE

    Args:
        recycle_dir: path under /input to a directory containing $I/$R pairs
            (e.g. `\\$Recycle.Bin\\S-1-5-21-...`)

    Returns:
        list of {marker, version, deleted_size, deleted_at, original_name,
                 i_file, r_file_present}
    """
    p = assert_input_path(recycle_dir)
    if not p.is_dir():
        raise ValueError(f"Not a directory: {p}")

    rows: list[dict[str, Any]] = []
    for i_path in sorted(p.glob("$I*")):
        try:
            data = i_path.read_bytes()
        except OSError:
            continue
        if len(data) < 24:
            continue
        version = int.from_bytes(data[0:8], "little", signed=False)
        deleted_size = int.from_bytes(data[8:16], "little", signed=False)
        deleted_ft = int.from_bytes(data[16:24], "little", signed=False)
        original_name = ""
        if version == 1 and len(data) >= 24 + 520:
            original_name = data[24:24 + 520].decode("utf-16-le", errors="replace").rstrip("\x00")
        elif version == 2 and len(data) >= 28:
            name_len = int.from_bytes(data[24:28], "little", signed=False)
            if name_len > 0 and 28 + name_len * 2 <= len(data):
                original_name = data[28:28 + name_len * 2].decode("utf-16-le", errors="replace").rstrip("\x00")
        r_path = i_path.with_name(i_path.name.replace("$I", "$R", 1))
        rows.append({
            "marker": i_path.stem,
            "version": version,
            "deleted_size": deleted_size,
            "deleted_at": _filetime_to_iso(deleted_ft),
            "original_name": original_name,
            "i_file": str(i_path),
            "r_file_present": r_path.exists(),
        })
    return rows


class EseToolError(Exception):
    """ESE parser missing or query failure."""


def _import_dissect_esedb() -> Any:
    try:
        from dissect.esedb import EseDB  # type: ignore
    except ImportError as exc:
        raise EseToolError(
            "dissect.esedb not installed. Install via the [forensics] extra: "
            "`pip install 'protocol-sift-mcp[forensics]'` or "
            "`pip install dissect.esedb`."
        ) from exc
    return EseDB


def win_ese_query(
    db_path: str,
    table: str,
    *,
    columns: list[str] | None = None,
    limit: int = 10_000,
) -> list[dict[str, Any]]:
    """Read rows from an ESE (Extensible Storage Engine) database.

    Covers SRUDB.dat (System Resource Usage Monitor), Windows.edb (Search),
    WebCacheV01.dat (IE/Edge cache), and Mailbox-derived EDBs.

    Uses `dissect.esedb` (pure-Python, in the [forensics] extra). The ESE
    format predates SQLite by 20 years and isn't readable with the stdlib —
    a custom parser is the only path.

    Args:
        db_path: path under /input to .edb / .dat
        table: ESE table name (e.g. `SruDbIdMapTable`, `Containers`, etc.)
        columns: optional list of column names to project (default: all)
        limit: max rows (default 10k)

    Returns:
        list of row dicts. Bytes are hex-coerced.

    Raises:
        SandboxViolation, EseToolError on missing parser / failed open.
    """
    p = assert_input_path(db_path)
    if limit <= 0 or limit > 1_000_000:
        raise ValueError("limit must be 1..1_000_000")
    EseDB = _import_dissect_esedb()
    try:
        # dissect.esedb takes a file-like object.
        with p.open("rb") as fh:
            db = EseDB(fh)
            try:
                tbl = db.table(table)
            except Exception as exc:  # noqa: BLE001 — surface as boundary error
                raise EseToolError(f"Table {table!r} not found in {p.name}: {exc}") from exc
            out: list[dict[str, Any]] = []
            for record in tbl.records():
                row: dict[str, Any] = {}
                col_names = columns or [c.name for c in tbl.columns]
                for col in col_names:
                    try:
                        v = record.get(col)
                    except Exception:  # noqa: BLE001 — skip bad columns
                        v = None
                    if isinstance(v, (bytes, bytearray)):
                        row[col] = v.hex()
                    elif hasattr(v, "isoformat"):
                        try:
                            row[col] = v.isoformat()
                        except Exception:  # noqa: BLE001
                            row[col] = repr(v)
                    else:
                        row[col] = v
                out.append(row)
                if len(out) >= limit:
                    break
            return out
    except EseToolError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise EseToolError(f"ESE open/read failed for {p.name}: {exc}") from exc
