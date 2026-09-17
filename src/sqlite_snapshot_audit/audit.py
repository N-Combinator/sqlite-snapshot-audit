"""Discover SQLite backup units under a directory and verify copies of them.

Nothing under the scanned directory is ever opened for writing: ``scan`` reads
at most the first 16 bytes of each regular file (symlinks are reported, not followed), and ``verify`` only opens
SQLite (and reads -wal headers) on copies placed in a temporary directory outside the scanned tree.
"""

from __future__ import annotations

import os
import sqlite3
import stat
import struct
import tempfile
import urllib.parse

SQLITE_HEADER = b"SQLite format 3\x00"
SIDECAR_SUFFIXES = ("-wal", "-shm")
DB_EXTENSIONS = (".db", ".sqlite", ".sqlite3")

STANDALONE = "standalone"
WAL_FAMILY = "wal-family"
ORPHAN_SIDECAR = "orphan-sidecar"
NOT_SQLITE = "not-sqlite"
SKIPPED_SYMLINK = "skipped-symlink"

VERIFIABLE = (STANDALONE, WAL_FAMILY)

# integrity prefix for units the tool itself could not check (temporary directory problems)
NOT_CHECKED = "not-checked: "
COPY_CHUNK_SIZE = 1024 * 1024

# https://www.sqlite.org/fileformat.html#the_write_ahead_log
WAL_MAGIC_LITTLE_ENDIAN = 0x377F0682
WAL_MAGIC_BIG_ENDIAN = 0x377F0683
WAL_VERSION = 3007000
WAL_HEADER_SIZE = 32
WAL_FRAME_HEADER_SIZE = 24


class AuditError(Exception):
    """Usage or IO problem that prevents auditing the tree (exit code 2)."""


class _SourceError(Exception):
    """OSError while reading a file under the audited tree, as opposed to the temp dir."""


def _is_sqlite(path: str) -> bool:
    with open(path, "rb") as f:
        return f.read(len(SQLITE_HEADER)) == SQLITE_HEADER


def _walk_files(root: str) -> tuple[list[str], list[str]]:
    """Return (regular files, symlinks to files) under root, relative and "/"-separated.

    Symlinks are never followed: their targets may lie outside root.
    """

    def raise_error(err: OSError) -> None:
        raise err

    regular, symlinks = [], []
    for dirpath, dirnames, filenames in os.walk(root, onerror=raise_error):
        dirnames.sort()
        for name in filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            try:
                st = os.lstat(full)
            except FileNotFoundError:
                # the file vanished while walking
                continue
            if stat.S_ISLNK(st.st_mode):
                # dangling symlinks point at nothing and are ignored
                if os.path.exists(full):
                    symlinks.append(rel)
                continue
            if not stat.S_ISREG(st.st_mode):
                # FIFOs, sockets, devices: reading them could block or be destructive
                continue
            regular.append(rel)
    return sorted(regular), sorted(symlinks)


def scan(root: str) -> list[dict]:
    """Classify every SQLite database, sidecar, would-be database and file symlink under root.

    Returns entries sorted by ``main`` (then ``class``); paths are relative to root.
    Raises AuditError if root is not a directory or a file cannot be read.
    """
    if not os.path.isdir(root):
        raise AuditError(f"not a directory: {root}")

    try:
        files, symlinks = _walk_files(root)
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

    for main in symlinks:
        entries.append(
            {
                "main": main,
                "sidecars": [],
                "class": SKIPPED_SYMLINK,
                "reason": "symbolic link to a file; not followed",
            }
        )

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


def _wal_checksum(data: bytes, big_endian: bool) -> tuple[int, int]:
    """SQLite's WAL checksum (walChecksumBytes) over data, whose length is a multiple of 8."""
    s1 = s2 = 0
    words = struct.unpack((">" if big_endian else "<") + f"{len(data) // 4}I", data)
    for i in range(0, len(words), 2):
        s1 = (s1 + words[i] + s2) & 0xFFFFFFFF
        s2 = (s2 + words[i + 1] + s1) & 0xFFFFFFFF
    return s1, s2


def _database_page_size(db_path: str) -> int | None:
    with open(db_path, "rb") as f:
        header = f.read(18)
    if len(header) < 18:
        return None
    size = int.from_bytes(header[16:18], "big")
    return 65536 if size == 1 else size


def _check_wal(wal_path: str, db_path: str) -> str:
    """Check a (copied) -wal file against its database, which SQLite does not do.

    SQLite silently ignores a -wal with a bad header, so integrity_check says "ok" for a
    database whose uncheckpointed transactions were lost. Returns "empty",
    "ok (<N> frames)" or "invalid: <reason>"; N counts the complete frames, from the
    first, that carry the header's salt (later frames are left over and ignored by SQLite).
    """
    wal_size = os.path.getsize(wal_path)
    if wal_size == 0:
        return "empty"
    with open(wal_path, "rb") as f:
        header = f.read(WAL_HEADER_SIZE)
        if len(header) < WAL_HEADER_SIZE:
            return f"invalid: header truncated to {len(header)} bytes"
        magic, version, page_size, _, salt1, salt2, cksum1, cksum2 = struct.unpack(">8I", header)
        if magic not in (WAL_MAGIC_LITTLE_ENDIAN, WAL_MAGIC_BIG_ENDIAN):
            return f"invalid: bad magic number 0x{magic:08x}"
        if version != WAL_VERSION:
            return f"invalid: unsupported format version {version}"
        if _wal_checksum(header[:24], magic == WAL_MAGIC_BIG_ENDIAN) != (cksum1, cksum2):
            return "invalid: header checksum mismatch"
        db_page_size = _database_page_size(db_path)
        if page_size != db_page_size:
            return f"invalid: page size {page_size} does not match database page size {db_page_size}"
        frame_size = WAL_FRAME_HEADER_SIZE + page_size
        frames = 0
        while WAL_HEADER_SIZE + (frames + 1) * frame_size <= wal_size:
            f.seek(WAL_HEADER_SIZE + frames * frame_size)
            frame_salts = struct.unpack(">2I", f.read(WAL_FRAME_HEADER_SIZE)[8:16])
            if frame_salts != (salt1, salt2):
                if frames == 0:
                    return "invalid: first frame salt does not match header salt"
                break
            frames += 1
    return f"ok ({frames} frames)"


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
    reason on the tool's side, ``integrity`` is ``"not-checked: <error>"``. Checked
    entries with a -wal sidecar also gain ``wal`` (see _check_wal).
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
            wals = [rel for rel in entry["sidecars"] if rel.endswith("-wal")]
            if wals:
                # before SQLite opens the copy, so the -wal is read exactly as it was copied
                try:
                    wal = _check_wal(os.path.join(tmp, os.path.basename(wals[0])), copy)
                except OSError as exc:
                    wal = NOT_CHECKED + str(exc)
            entry["integrity"], entry["tables"] = _check_copy(copy)
            if wals:
                entry["wal"] = wal
    return entries


def not_checked(entries: list[dict]) -> list[dict]:
    """Entries verify could not check because of the tool's environment (exit code 2)."""
    return [
        e
        for e in entries
        if str(e.get("integrity", "")).startswith(NOT_CHECKED)
        or e.get("wal", "").startswith(NOT_CHECKED)
    ]


def has_problems(entries: list[dict]) -> bool:
    """True if verify should exit 1 for these entries."""
    for entry in entries:
        if entry["class"] == SKIPPED_SYMLINK:
            # not a problem with the backup itself; the entry is still reported
            continue
        if entry["class"] not in VERIFIABLE:
            return True
        if entry.get("integrity") != "ok":
            return True
        if entry.get("wal", "").startswith("invalid"):
            return True
    return False
