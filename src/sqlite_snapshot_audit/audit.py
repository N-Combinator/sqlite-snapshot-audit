"""Discover SQLite backup units under a directory and verify copies of them.

Nothing under the scanned directory is ever opened for writing: ``scan`` reads
at most the first 16 bytes of each regular file, and ``verify`` only opens
SQLite on copies placed in a temporary directory outside the scanned tree.
"""

from __future__ import annotations

import os
import sqlite3
import stat
import tempfile
import urllib.parse

SQLITE_HEADER = b"SQLite format 3\x00"
SIDECAR_SUFFIXES = ("-wal", "-shm")
DB_EXTENSIONS = (".db", ".sqlite", ".sqlite3")

STANDALONE = "standalone"
WAL_FAMILY = "wal-family"
ORPHAN_SIDECAR = "orphan-sidecar"
NOT_SQLITE = "not-sqlite"

VERIFIABLE = (STANDALONE, WAL_FAMILY)

# integrity prefix for units the tool itself could not check (temporary directory problems)
NOT_CHECKED = "not-checked: "
COPY_CHUNK_SIZE = 1024 * 1024


class AuditError(Exception):
    """Usage or IO problem that prevents auditing the tree (exit code 2)."""


class _SourceError(Exception):
    """OSError while reading a file under the audited tree, as opposed to the temp dir."""


def _is_sqlite(path: str) -> bool:
    with open(path, "rb") as f:
        return f.read(len(SQLITE_HEADER)) == SQLITE_HEADER


def _walk_regular_files(root: str) -> list[str]:
    """Return paths of regular files under root, relative and "/"-separated."""

    def raise_error(err: OSError) -> None:
        raise err

    found = []
    for dirpath, dirnames, filenames in os.walk(root, onerror=raise_error):
        dirnames.sort()
        for name in filenames:
            full = os.path.join(dirpath, name)
            try:
                st = os.stat(full)
            except FileNotFoundError:
                # dangling symlink, or the file vanished while walking
                continue
            if not stat.S_ISREG(st.st_mode):
                # FIFOs, sockets, devices: reading them could block or be destructive
                continue
            rel = os.path.relpath(full, root)
            found.append(rel.replace(os.sep, "/"))
    return sorted(found)


def scan(root: str) -> list[dict]:
    """Classify every SQLite database, sidecar and would-be database under root.

    Returns entries sorted by ``main`` (then ``class``); paths are relative to root.
    Raises AuditError if root is not a directory or a file cannot be read.
    """
    if not os.path.isdir(root):
        raise AuditError(f"not a directory: {root}")

    try:
        files = _walk_regular_files(root)
        databases = set()
        others = []
        for rel in files:
            if _is_sqlite(os.path.join(root, rel)):
                databases.add(rel)
            else:
                others.append(rel)
    except OSError as exc:
        raise AuditError(str(exc)) from exc

    sidecars: dict[str, list[str]] = {}
    not_sqlite = []
    for rel in others:
        if rel.endswith(SIDECAR_SUFFIXES):
            sidecars.setdefault(rel[: -len("-wal")], []).append(rel)
        elif rel.lower().endswith(DB_EXTENSIONS):
            not_sqlite.append(rel)

    entries = []
    for main in databases:
        family = sorted(sidecars.get(main, []))
        if not family:
            cls, reason = STANDALONE, "SQLite database without -wal/-shm sidecars"
        elif len(family) == 2:
            cls, reason = WAL_FAMILY, "SQLite database with -wal and -shm sidecars"
        elif family[0].endswith("-wal"):
            cls, reason = WAL_FAMILY, "SQLite database with -wal sidecar, no -shm"
        else:
            cls, reason = WAL_FAMILY, "SQLite database with -shm sidecar but no -wal"
        entries.append({"main": main, "sidecars": family, "class": cls, "reason": reason})

    regular = set(files)
    for main, family in sidecars.items():
        if main in databases:
            continue
        if main in regular:
            reason = "main file exists but has no SQLite header"
        elif os.path.lexists(os.path.join(root, main)):
            reason = "main path exists but is not a regular file"
        else:
            reason = "main file is missing"
        entries.append(
            {"main": main, "sidecars": sorted(family), "class": ORPHAN_SIDECAR, "reason": reason}
        )

    for main in not_sqlite:
        try:
            empty = os.path.getsize(os.path.join(root, main)) == 0
        except OSError as exc:
            raise AuditError(str(exc)) from exc
        reason = "empty file" if empty else "database file name but no SQLite header"
        entries.append({"main": main, "sidecars": [], "class": NOT_SQLITE, "reason": reason})

    entries.sort(key=lambda e: (e["main"], e["class"]))
    return entries


def _quote_identifier(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _check_copy(db_path: str) -> tuple[str, dict]:
    """Run integrity_check and count rows per table on a (copied) database."""
    uri = "file:" + urllib.parse.quote(os.fsencode(db_path)) + "?mode=ro"
    tables: dict[str, int | None] = {}
    try:
        conn = sqlite3.connect(uri, uri=True)
    except sqlite3.Error as exc:
        return str(exc), tables
    try:
        try:
            rows = conn.execute("PRAGMA integrity_check").fetchall()
            integrity = str(rows[0][0]) if rows else "integrity_check returned no rows"
        except sqlite3.Error as exc:
            integrity = str(exc)
        try:
            names = [
                r[0]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
                )
            ]
        except sqlite3.Error:
            names = []
        for name in names:
            try:
                (count,) = conn.execute(
                    "SELECT COUNT(*) FROM " + _quote_identifier(name)
                ).fetchone()
            except sqlite3.Error:
                # unreadable table (corrupt page, unavailable virtual table module)
                count = None
            tables[name] = count
    finally:
        conn.close()
    return integrity, tables


def _copy_file(src_path: str, dst_path: str) -> None:
    """Copy src_path to dst_path; errors reading the source are raised as _SourceError.

    Any other OSError (creating or writing the copy: ENOSPC, EDQUOT, EACCES...) is the
    temporary directory's problem and propagates unchanged.
    """
    try:
        src = open(src_path, "rb")
    except OSError as exc:
        raise _SourceError(exc) from exc
    with src, open(dst_path, "wb") as dst:
        while True:
            try:
                chunk = src.read(COPY_CHUNK_SIZE)
            except OSError as exc:
                raise _SourceError(exc) from exc
            if not chunk:
                break
            dst.write(chunk)


def _inside(path: str, root: str) -> bool:
    path, root = os.path.realpath(path), os.path.realpath(root)
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        # different drives on Windows
        return False


def verify(root: str) -> list[dict]:
    """Scan root, then check a temporary copy of every standalone/wal-family unit.

    Verified entries gain ``integrity`` and ``tables`` keys; other entries are
    returned as ``scan`` produced them. If the temporary copy cannot be made for a
    reason on the tool's side, ``integrity`` is ``"not-checked: <error>"``.
    """
    entries = scan(root)
    if _inside(tempfile.gettempdir(), root):
        raise AuditError(
            f"temporary directory {tempfile.gettempdir()} is inside {root}; "
            "set TMPDIR to a location outside the audited tree"
        )
    for entry in entries:
        if entry["class"] not in VERIFIABLE:
            continue
        try:
            tmp_dir = tempfile.TemporaryDirectory(prefix="sqlite-snapshot-audit-")
        except OSError as exc:
            entry["integrity"], entry["tables"] = NOT_CHECKED + str(exc), {}
            continue
        with tmp_dir as tmp:
            copy = os.path.join(tmp, os.path.basename(entry["main"]))
            try:
                for rel in [entry["main"], *entry["sidecars"]]:
                    _copy_file(os.path.join(root, rel), os.path.join(tmp, os.path.basename(rel)))
            except _SourceError as exc:
                entry["integrity"], entry["tables"] = f"copy failed: {exc}", {}
                continue
            except OSError as exc:
                entry["integrity"], entry["tables"] = NOT_CHECKED + str(exc), {}
                continue
            entry["integrity"], entry["tables"] = _check_copy(copy)
    return entries


def not_checked(entries: list[dict]) -> list[dict]:
    """Entries verify could not check because of the tool's environment (exit code 2)."""
    return [e for e in entries if str(e.get("integrity", "")).startswith(NOT_CHECKED)]


def has_problems(entries: list[dict]) -> bool:
    """True if verify should exit 1 for these entries."""
    for entry in entries:
        if entry["class"] not in VERIFIABLE:
            return True
        if entry.get("integrity") != "ok":
            return True
    return False
