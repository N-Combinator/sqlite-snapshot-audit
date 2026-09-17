"""Discover SQLite backup units under a directory and verify copies of them.

Nothing under the scanned directory is ever opened for writing: ``scan`` reads
at most the first 16 bytes of each regular file (symlinks are reported, not followed), and ``verify`` only opens
SQLite (and reads -wal headers) on copies placed in a temporary directory outside the scanned tree.

Paths that cannot be read are collected in a ``warnings`` list and skipped, so one
unreadable directory or file does not hide the rest of the tree.
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

VERIFIABLE = (STANDALONE, WAL_FAMILY)

# value of the "skipped" key on an entry whose own path is a symbolic link that was not followed
SKIPPED_SYMLINK = "symlink"
# integrity prefix for units the tool itself could not check (temporary directory problems)
NOT_CHECKED = "not-checked: "
# wal value for a unit whose sidecar is a symlink, so the unit could not be copied as it stands
SYMLINK_SKIPPED = "symlink-skipped"
# wal prefix for a unit whose sidecar could not be read from the audited tree
UNREADABLE = "unreadable: "
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


def _relative(root: str, path: str) -> str:
    return os.path.relpath(path, root).replace(os.sep, "/")


def _warning(root: str, path: str, exc: OSError) -> str:
    return f"skipped {_relative(root, path)}: {exc.strerror or exc}"


def _walk_files(root: str, warnings: list[str]) -> tuple[list[str], list[str], set[str]]:
    """Return (regular files, symlinks, dangling ones) under root, relative and "/"-separated.

    Symlinks are never followed: their targets may lie outside root. Whether a link
    resolves is recorded but never decides whether it is reported -- a broken ``-wal``
    link still belongs to its database, and dropping it would make that database look
    standalone and be verified without the WAL it needs.

    A directory that cannot be read (a root-only ``lost+found``, say) is recorded in
    ``warnings`` and skipped; the rest of the tree is still audited. Only root itself
    being unreadable is fatal. A symlinked directory is not descended into either, and is
    recorded in ``warnings`` too, so an unaudited subtree is never silently passed over.
    """

    def on_error(err: OSError) -> None:
        if err.filename is None or os.path.abspath(err.filename) == os.path.abspath(root):
            raise err
        warnings.append(_warning(root, err.filename, err))

    regular, symlinks, dangling = [], [], set()
    for dirpath, dirnames, filenames in os.walk(root, onerror=on_error):
        dirnames.sort()
        for name in dirnames:
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                # os.walk is called with followlinks=False, so the subtree behind the link
                # (which may lie outside root entirely) is not audited: say so.
                warnings.append(f"symlinked directory not followed: {_relative(root, full)}")
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = _relative(root, full)
            try:
                st = os.lstat(full)
            except FileNotFoundError:
                # the file vanished while walking
                continue
            except OSError as exc:
                warnings.append(_warning(root, full, exc))
                continue
            if stat.S_ISLNK(st.st_mode):
                # classified from lstat alone: a link that does not resolve is still a file
                # in the tree and still part of its unit, it just cannot be restored from
                symlinks.append(rel)
                if not os.path.exists(full):
                    dangling.add(rel)
                continue
            if not stat.S_ISREG(st.st_mode):
                # FIFOs, sockets, devices: reading them could block or be destructive
                continue
            regular.append(rel)
    return sorted(regular), sorted(symlinks), dangling


def _note_links(reason: str, family: list[str], links: set[str], dangling: set[str]) -> str:
    """Add the sidecars of a unit that are symlinks (and so were not read) to its reason."""
    linked = [rel + (" (dangling)" if rel in dangling else "") for rel in family if rel in links]
    if not linked:
        return reason
    return reason + "; symbolic link not followed: " + ", ".join(linked)


def scan(root: str, warnings: list[str] | None = None) -> list[dict]:
    """Classify every SQLite database, sidecar, would-be database and file symlink under root.

    A file symlink that is not a sidecar is reported with ``"skipped": "symlink"`` and the
    ``not-sqlite`` class: it is not followed, so no header was read to classify it.

    Returns entries sorted by ``main`` (then ``class``); paths are relative to root.
    Paths that cannot be read are appended to ``warnings`` and left out of the entries;
    AuditError is raised only if root itself is not a readable directory.
    """
    if warnings is None:
        warnings = []
    if not os.path.isdir(root):
        raise AuditError(f"not a directory: {root}")

    try:
        files, symlinks, dangling = _walk_files(root, warnings)
    except OSError as exc:
        raise AuditError(str(exc)) from exc

    # A sidecar is recognised by its name alone: symlink or not, readable or not, and before
    # any header is read. Leaving a sidecar out of its family -- because it is a link, or
    # because its permissions deny reading it -- would make its database look standalone and
    # be verified without the WAL it needs.
    links = set(symlinks)
    sidecars: dict[str, list[str]] = {}
    for rel in sorted(files + symlinks):
        if rel.endswith(SIDECAR_SUFFIXES) and len(os.path.basename(rel)) > len("-wal"):
            sidecars.setdefault(rel[: -len("-wal")], []).append(rel)
    # paths reported inside the unit they belong to instead of on their own
    adopted = {rel for family in sidecars.values() for rel in family}

    databases = set()
    not_sqlite = []
    unreadable: dict[str, str] = {}
    for rel in files:
        if rel in adopted:
            # its name already places it in a unit; its content is -wal/-shm, not a header
            continue
        try:
            is_database = _is_sqlite(os.path.join(root, rel))
        except OSError as exc:
            warnings.append(_warning(root, os.path.join(root, rel), exc))
            unreadable[rel] = exc.strerror or str(exc)
            continue
        if is_database:
            databases.add(rel)
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
        entries.append(
            {
                "main": main,
                "sidecars": family,
                "class": cls,
                "reason": _note_links(reason, family, links, dangling),
            }
        )

    regular = set(files)
    for main, family in sidecars.items():
        if main in databases:
            continue
        if main in unreadable:
            reason = f"main file could not be read: {unreadable[main]}"
        elif main in regular:
            reason = "main file exists but has no SQLite header"
        elif main in dangling:
            reason = "main path is a symbolic link whose target is missing"
        elif main in links:
            reason = "main path is a symbolic link; not followed, so no SQLite header was read"
        elif os.path.lexists(os.path.join(root, main)):
            reason = "main path exists but is not a regular file"
        else:
            reason = "main file is missing"
        family = sorted(family)
        entries.append(
            {
                "main": main,
                "sidecars": family,
                "class": ORPHAN_SIDECAR,
                "reason": _note_links(reason, family, links, dangling),
            }
        )

    for main in not_sqlite:
        try:
            empty = os.path.getsize(os.path.join(root, main)) == 0
        except OSError as exc:
            warnings.append(_warning(root, os.path.join(root, main), exc))
            continue
        reason = "empty file" if empty else "database file name but no SQLite header"
        entries.append({"main": main, "sidecars": [], "class": NOT_SQLITE, "reason": reason})

    for main in symlinks:
        if main in adopted:
            # already reported in the sidecars of the unit it belongs to
            continue
        entries.append(
            {
                "main": main,
                "sidecars": [],
                # every class is decided by reading a header, which a symlink is never read for;
                # "skipped" tells a consumer that the class was not established, not that the
                # target is junk, and keeps the class field to the four documented values
                "class": NOT_SQLITE,
                "reason": (
                    "dangling symbolic link (target is missing)"
                    if main in dangling
                    else "symbolic link to a file"
                )
                + "; not followed, so no SQLite header was read",
                "skipped": SKIPPED_SYMLINK,
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


def _wal_checksum(data: bytes, big_endian: bool, seed: tuple[int, int] = (0, 0)) -> tuple[int, int]:
    """SQLite's WAL checksum (walChecksumBytes) over data, whose length is a multiple of 8.

    ``seed`` continues a running checksum: frames are checksummed in order, each one
    starting from the previous frame's result (the header's checksum seeds frame 1).
    """
    s1, s2 = seed
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


def _wal_generation_tail(f, first: int, frame_size: int, salts: bytes) -> tuple[int, int | None]:
    """Count the frames of this WAL generation from frame ``first`` on, commit frames included.

    SQLite stops reading at ``first``, but the file usually goes on, and everything from
    there is what a restore loses -- so the loss has to be measured over the rest of the
    file, not over the one frame that broke the chain. Frames carrying an earlier
    generation's salts are not counted: they were checkpointed into the database long ago
    and hold nothing. Frame ``first`` itself is counted without re-checking its salts; the
    caller has already decided it belongs to this generation.

    Returns (frames present from ``first`` on, number of the first complete frame among
    them that commits a transaction, or None). A frame the file cuts short counts as
    present but never as a commit: a transaction whose last frame is torn was never
    durable, which is the ordinary state of a copy taken from a live database.
    """
    count, commit = 0, None
    f.seek(WAL_HEADER_SIZE + (first - 1) * frame_size)
    while True:
        frame = f.read(frame_size)
        if not frame:
            break
        if count and len(frame) >= WAL_FRAME_HEADER_SIZE and frame[8:16] != salts:
            break
        count += 1
        if len(frame) < frame_size:
            break
        if commit is None and frame[4:8] != b"\0\0\0\0":
            commit = first + count - 1
    return count, commit


def _check_wal(wal_path: str, db_path: str) -> str:
    """Check a (copied) -wal file the way SQLite's recovery reads it, which it does not report.

    SQLite silently ignores a -wal it cannot replay, so integrity_check says "ok" for a
    database whose uncheckpointed transactions were lost. This repeats the checks of
    walIndexRecover(): header, then each frame's salt and its link in the running
    checksum chain, and only up to the last commit frame is replayed.

    Returns "empty", "ok (<N> frames)" with N the number of frames SQLite would replay,
    or "invalid: <reason>" when SQLite would replay nothing at all. Frames past the last
    commit frame (the torn or uncommitted tail every copy of a live WAL database has) are
    reported in the "ok" value: dropping them is SQLite's crash recovery, not data loss --
    unless one of the dropped frames is itself a commit frame, in which case a transaction
    that was fully written is being thrown away and the -wal is reported as invalid.
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
        big_endian = magic == WAL_MAGIC_BIG_ENDIAN
        frame_size = WAL_FRAME_HEADER_SIZE + page_size
        checksum = (cksum1, cksum2)
        good = 0  # frames that decode; SQLite stops reading at the first one that does not
        replayed = 0  # SQLite's mxFrame: frames up to and including the last commit frame
        broken = None  # (number of the first unusable frame, why it is not usable)
        f.seek(WAL_HEADER_SIZE)
        while f.tell() < wal_size:
            frame, number = f.read(frame_size), good + 1
            if len(frame) < frame_size:
                broken = (number, f"frame {number} stops after {len(frame)} of {frame_size} bytes")
                break
            page_number, truncate, fsalt1, fsalt2, fcksum1, fcksum2 = struct.unpack(
                ">6I", frame[:WAL_FRAME_HEADER_SIZE]
            )
            if (fsalt1, fsalt2) != (salt1, salt2):
                if good == 0:
                    return "invalid: first frame salt does not match header salt"
                # left over from an earlier WAL generation; SQLite stops here and so do we
                break
            checksum = _wal_checksum(frame[:8], big_endian, checksum)
            checksum = _wal_checksum(frame[WAL_FRAME_HEADER_SIZE:], big_endian, checksum)
            if (fcksum1, fcksum2) != checksum:
                broken = (number, f"frame {number} fails its checksum")
                break
            if page_number == 0:
                broken = (number, f"frame {number} has page number 0")
                break
            good = number
            if truncate:
                replayed = good
        if broken is not None:
            number, reason = broken
            # the frames after the break are dropped too, and they are usually the bulk of it
            tail, commit = _wal_generation_tail(f, number, frame_size, header[16:24])
            present, dropped_because = number - 1 + tail, reason
        elif replayed < good:
            present, commit = good, None
            reason = "the last transaction has no commit frame"
            dropped_because = "they were never committed"
        else:
            return f"ok ({replayed} frames)"
    if replayed == 0:
        # nothing is replayed: everything the -wal holds is lost and the copy is only
        # the main file, which is what makes this worth failing on
        return f"invalid: 0 of {present} frames will be replayed ({reason})"
    if commit is not None:
        # the dropped frames are not the uncommitted tail of a live copy: one of them
        # commits, so a transaction that was written in full does not survive the restore
        return (
            f"invalid: {replayed} of {present} frames will be replayed ({reason}; "
            f"dropped frame {commit} is a commit frame, so a committed transaction is lost)"
        )
    # A prefix up to the last commit frame is replayed and the rest is discarded, which
    # is exactly what SQLite does after a crash; no committed transaction is lost.
    return (
        f"ok ({replayed} frames; {present - replayed} further frames will be dropped, "
        f"as SQLite does: {dropped_because})"
    )


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


def _discard(path: str) -> None:
    """Remove a partial copy in the temporary directory, if one was created at all."""
    try:
        os.remove(path)
    except OSError:
        pass


def _inside(path: str, root: str) -> bool:
    path, root = os.path.realpath(path), os.path.realpath(root)
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        # different drives on Windows
        return False


def verify(root: str, warnings: list[str] | None = None) -> list[dict]:
    """Scan root, then check a temporary copy of every standalone/wal-family unit.

    Verified entries gain ``integrity`` and ``tables`` keys; other entries are
    returned as ``scan`` produced them. If the temporary copy cannot be made for a
    reason on the tool's side, ``integrity`` is ``"not-checked: <error>"``. Checked
    entries with a -wal sidecar also gain ``wal`` (see _check_wal); so do units whose
    sidecar is a symlink (not followed) or cannot be read, since neither is copied and
    what it holds is therefore unknown.
    """
    entries = scan(root, warnings)
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
            # a symlinked sidecar may point outside root, so it is neither read nor copied;
            # the unit is then not the one that would be restored, whatever the copy says
            linked = [rel for rel in entry["sidecars"] if os.path.islink(os.path.join(root, rel))]
            copied = [rel for rel in entry["sidecars"] if rel not in linked]
            unreadable = []
            try:
                _copy_file(os.path.join(root, entry["main"]), copy)
                for rel in copied:
                    dst = os.path.join(tmp, os.path.basename(rel))
                    try:
                        _copy_file(os.path.join(root, rel), dst)
                    except _SourceError as exc:
                        # SQLite must not replay half a file, so the partial copy goes; but the
                        # unit is then not the one that would be restored, and says so below
                        _discard(dst)
                        cause = exc.args[0]
                        unreadable.append(f"{rel}: {getattr(cause, 'strerror', None) or cause}")
            except _SourceError as exc:
                entry["integrity"], entry["tables"] = f"copy failed: {exc}", {}
                continue
            except OSError as exc:
                entry["integrity"], entry["tables"] = NOT_CHECKED + str(exc), {}
                continue
            wal = None
            wals = [rel for rel in copied if rel.endswith("-wal")]
            if linked:
                wal = SYMLINK_SKIPPED
            elif unreadable:
                wal = UNREADABLE + "; ".join(unreadable)
            elif wals:
                # before SQLite opens the copy, so the -wal is read exactly as it was copied
                try:
                    wal = _check_wal(os.path.join(tmp, os.path.basename(wals[0])), copy)
                except OSError as exc:
                    wal = NOT_CHECKED + str(exc)
            entry["integrity"], entry["tables"] = _check_copy(copy)
            if wal is not None:
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
        if entry["class"] not in VERIFIABLE:
            return True
        if entry.get("integrity") != "ok":
            return True
        wal = entry.get("wal", "")
        if wal and not (wal == "empty" or wal.startswith(("ok", NOT_CHECKED))):
            # "invalid:", "symlink-skipped", "unreadable:": the -wal that would be replayed
            # is either unsound or was never seen at all
            return True
    return False
