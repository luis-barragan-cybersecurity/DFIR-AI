"""High-value handle-dump registry — what to extract before claiming memory cap.

The Rocba case (2026-05) surfaced a doctrine miss: the OneDrive AODL log was
held as an open file handle on PID 9648, but the agent recorded the gap
"specific files exfiltrated unknowable from memory" without first running
`windows.dumpfiles --pid 9648` to recover the cached pages. After the fix,
two derivative artifacts (`downloads3.txt` and the user-state `.dat`) closed
the gap with concrete filenames.

This module codifies which processes routinely hold high-value cached files,
so the triage agent (and any future skill) can ALWAYS attempt extraction
before declaring memory cap.

Pattern matching: `process_name_lc` is matched case-insensitively against
the basename of `_EPROCESS.ImageFileName` from `pslist` / `psscan`.

Each entry lists the *kinds* of cached files worth dumping. Filenames in
the dumpfiles output are emitted as
``file.<EPROCESS_addr>.<FileObject_addr>.<CacheType>.<basename>.{dat|vacb|img}``
where `CacheType` is one of `DataSectionObject`, `SharedCacheMap`,
`ImageSectionObject`. Dumping by `--pid` extracts every cache type for
every file the process has open; analysts then filter by the patterns below.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class HandleTarget:
    process_name_lc: str          # lowercase basename of ImageFileName
    artifact_patterns: tuple[str, ...]   # filename substrings to grep for
    why_it_matters: str           # one-sentence forensic value
    minimum_volatility_plugin: str = "windows.dumpfiles"


# Single source of truth. Add to this list when a new high-value artifact
# is discovered in a real case (and update the `case_reference` field).
REGISTRY: tuple[HandleTarget, ...] = (
    HandleTarget(
        process_name_lc="onedrive.exe",
        artifact_patterns=(
            ".aodl",                       # SyncEngine append-only log
            "downloads3.txt",              # client-side download log
            "telemetryCache.otc",          # telemetry cache
            "Downloader_",                 # per-session HTTP fetch log
            "aria-debug-",                 # Microsoft Aria telemetry
            ".dat",                        # per-user state files (GUID-named)
        ),
        why_it_matters=(
            "OneDrive's client logs name SharePoint UniqueIds + per-user "
            "filenames; collapses 'memory cap' on file-level exfil questions"
        ),
    ),
    HandleTarget(
        process_name_lc="googledrivefs.exe",
        artifact_patterns=(
            "drive_fs.db",
            "drive_fs.txt",
            "log_",
            "experiments_data",
        ),
        why_it_matters=(
            "Drive FS local DB names every synced item with full path"
        ),
    ),
    HandleTarget(
        process_name_lc="googledrivesync.exe",
        artifact_patterns=("snapshot.db", "sync_log", "config.db"),
        why_it_matters="Legacy Drive client sync DB — same role as drive_fs.db",
    ),
    HandleTarget(
        process_name_lc="dropbox.exe",
        artifact_patterns=("filecache.dbx", "config.dbx", "deleted.dbx", ".log"),
        why_it_matters="Dropbox stores file metadata + deletion log in DBX SQLite",
    ),
    HandleTarget(
        process_name_lc="slack.exe",
        artifact_patterns=("local_log_session.json", "Cache", ".log", "Cookies"),
        why_it_matters="Slack file-upload events + DM file references",
    ),
    HandleTarget(
        process_name_lc="teams.exe",
        artifact_patterns=("sqlite", ".log", "settings.json", "media-stack"),
        why_it_matters="Teams file-share + meeting-recording references",
    ),
    HandleTarget(
        process_name_lc="outlook.exe",
        artifact_patterns=(".ost", ".nst", ".pst", "RoamCache", ".dat"),
        why_it_matters="Email cache + nickname cache + roaming attachments",
    ),
    HandleTarget(
        process_name_lc="chrome.exe",
        artifact_patterns=(
            "History",                     # SQLite browser history
            "Cookies",
            "Login Data",
            "Web Data",
            "Bookmarks",
            "Sessions/",
            "Tabs/",
            "Cache_Data",
        ),
        why_it_matters="Chromium history + form data + session restore",
    ),
    HandleTarget(
        process_name_lc="msedge.exe",
        artifact_patterns=(
            "History", "Cookies", "Login Data", "Web Data",
            "Sessions/", "Tabs/", "Cache_Data",
        ),
        why_it_matters="Edge (Chromium) — same artifacts as Chrome",
    ),
    HandleTarget(
        process_name_lc="firefox.exe",
        artifact_patterns=(
            "places.sqlite", "cookies.sqlite", "formhistory.sqlite",
            "sessionstore.jsonlz4", "logins.json",
        ),
        why_it_matters="Firefox profile DBs + session restore",
    ),
    HandleTarget(
        process_name_lc="icloudie.exe",
        artifact_patterns=("CKDatabase", ".db", "CloudKit", "Photos"),
        why_it_matters="iCloud sync state + photo-library entries",
    ),
    HandleTarget(
        process_name_lc="applephotostream.exe",
        artifact_patterns=("PhotoStream", "Cache", ".db"),
        why_it_matters="Apple Photo Stream sync metadata",
    ),
    HandleTarget(
        process_name_lc="explorer.exe",
        artifact_patterns=(
            "thumbcache_",                 # WindowsImageDB thumb cache
            "iconcache_",
            "WebCacheV01.dat",             # IE/Edge/WebView2 unified cache
        ),
        why_it_matters="Shell thumbnail cache + IE-stack web cache",
    ),
)


def targets_for_process(process_name: str) -> tuple[HandleTarget, ...]:
    """Return all registry entries that match a given EPROCESS ImageFileName.

    Match is case-insensitive on the bare basename. Truncated names from
    Volatility (max 14 chars on older builds) are handled by
    prefix-matching the registered name (e.g. `googledrivesy` matches
    `googledrivesync.exe`).
    """
    name_lc = process_name.lower().strip()
    out: list[HandleTarget] = []
    for entry in REGISTRY:
        target_lc = entry.process_name_lc.lower()
        if name_lc == target_lc:
            out.append(entry)
            continue
        # Volatility truncation tolerance — match by 14-char prefix.
        if len(name_lc) >= 4 and target_lc.startswith(name_lc[:14]):
            out.append(entry)
    return tuple(out)


def all_registered_processes() -> tuple[str, ...]:
    """Sorted list of every process name in the registry. Used by the
    triage skill to enumerate dump targets and by tests."""
    return tuple(sorted({e.process_name_lc for e in REGISTRY}))


def coverage_summary() -> dict[str, list[str]]:
    """`{process_name_lc: [patterns]}` for diagnostics + skill rendering."""
    out: dict[str, list[str]] = {}
    for e in REGISTRY:
        out.setdefault(e.process_name_lc, []).extend(e.artifact_patterns)
    for k in out:
        out[k] = sorted(set(out[k]))
    return out
