"""Discover SQLite backup units under a directory and verify copies of them.

Nothing under the scanned directory is ever opened for writing: ``scan`` reads at most
the first 16 bytes of each file, and ``verify`` only opens SQLite (and reads -wal
headers) on copies placed in a temporary directory outside the scanned tree.

A symbolic link whose target resolves inside the scanned directory is an ordinary file
here: what it points at is part of the tree that would be restored. A link that leaves
the tree, or that does not resolve, is not followed.

Paths that cannot be read or followed are collected in a ``warnings`` list and skipped,
so one unreadable directory or file does not hide the rest of the tree; the paths whose
content never reached the audit are counted separately (``unaudited``), because a tree
that could not be audited in full is not a tree that passed.
"""

from __future__ import annotations

import os
import sqlite3
import stat
import struct
import tempfile
import urllib.parse
from typing import NamedTuple

SQLITE_HEADER = b"SQLite format 3\x00"
SIDECAR_SUFFIXES = ("-wal", "-shm")
DB_EXTENSIONS = (".db", ".sqlite", ".sqlite3")

STANDALONE = "standalone"
WAL_FAMILY = "wal-family"
ORPHAN_SIDECAR = "orphan-sidecar"
NOT_SQLITE = "not-sqlite"

VERIFIABLE = (STANDALONE, WAL_FAMILY)

# values of the "skipped" key (and of "wal"/"shm") for links that are not followed
SKIPPED_OUTSIDE = "symlink-outside"
SKIPPED_DANGLING = "symlink-dangling"
LINK_NOTE = {
    SKIPPED_OUTSIDE: "target is outside the audited directory",
    SKIPPED_DANGLING: "target is missing",
}
# integrity prefix for units the tool itself could not check (temporary directory problems)
NOT_CHECKED = "not-checked: "
# wal/shm prefix for a unit whose sidecar could not be read from the audited tree
UNREADABLE = "unreadable: "
# wal prefix for a unit whose -shm is present without the -wal that must have existed with it
MISSING = "missing: "
# integrity prefix for a unit whose files are shorter than their own headers say they are
TRUNCATED = "truncated: "
COPY_CHUNK_SIZE = 1024 * 1024

# https://www.sqlite.org/fileformat.html#the_database_header
DB_HEADER_SIZE = 100

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


class Warnings(list):
    """The warning lines, plus the paths whose content never reached the audit.

    ``unaudited`` is what makes "nothing wrong was found" different from "the tree was
    checked": a path in it was not read at all, so no statement about it was ever made.
    A plain list works everywhere a ``Warnings`` does; it just does not count.
    """

    def __init__(self, items=()):
        super().__init__(items)
        self.unaudited: list[str] = []


def unaudited(warnings) -> list[str]:
    """The paths the audit could not look at, for callers holding a plain list too."""
    return list(getattr(warnings, "unaudited", []))


def _warn(warnings: list[str], message: str, unaudited_path: str | None = None) -> None:
    warnings.append(message)
    if unaudited_path is not None and isinstance(warnings, Warnings):
        warnings.unaudited.append(unaudited_path)


def _carries_no_data(rel: str) -> bool:
    """True for a ``-shm`` sidecar: a wal-index SQLite rebuilds, holding no rows of its own."""
    name = os.path.basename(rel)
    return name.endswith("-shm") and len(name) > len("-shm")


def _shm_without_wal(sidecars: list[str]) -> bool:
    """True for a unit that has a ``-shm`` but no ``-wal``.

    SQLite never leaves that pair behind: a clean close deletes both, a live database
    has both, and ``wal_checkpoint(TRUNCATE)`` leaves a 0-byte ``-wal`` that is still
    there. A lone ``-shm`` therefore proves a ``-wal`` existed beside it and did not
    reach this copy, taking every transaction that lived only in it.
    """
    return any(_carries_no_data(rel) for rel in sidecars) and not any(
        rel.endswith("-wal") for rel in sidecars
    )


def _warn_skipped(warnings: list[str], message: str, rel: str) -> None:
    """Warn about a path that was not read, counting it unless it is a -shm."""
    if _carries_no_data(rel):
        # not seeing a -shm costs nothing: it holds no data, SQLite rebuilds it from the -wal
        warnings.append(message + " (a -shm holds no data; its unit is still checked)")
    else:
        _warn(warnings, message, rel)


def _is_sqlite(path: str) -> bool:
    with open(path, "rb") as f:
        return f.read(len(SQLITE_HEADER)) == SQLITE_HEADER


def _relative(root: str, path: str) -> str:
    return os.path.relpath(path, root).replace(os.sep, "/")


def _warning(root: str, path: str, exc: OSError) -> str:
    return f"skipped {_relative(root, path)}: {exc.strerror or exc}"


def _link_status(root: str, path: str) -> str | None:
    """Why ``path`` is a symbolic link that is not followed, or None if it is followed.

    A link resolving to something inside root points at a file the audit covers anyway,
    so it is read like any other file. A link leaving root reaches outside the tree that
    would be restored (and could reach anywhere on the host), and a link that does not
    resolve has nothing to read: both are reported instead of followed.
    """
    try:
        if not stat.S_ISLNK(os.lstat(path).st_mode):
            return None
    except OSError:
        return None
    if not os.path.exists(path):
        return SKIPPED_DANGLING
    return None if _inside(path, root) else SKIPPED_OUTSIDE


def _walk_files(root: str, warnings: list[str]) -> tuple[list[str], dict[str, str]]:
    """Return (files, links not followed) under root, relative and "/"-separated.

    The first value holds every file whose content is part of the audited tree: regular
    files, and symlinks resolving to a regular file inside root, which are read exactly
    like the file they point at. The second maps the links that are *not* followed --
    those leaving root, and those that do not resolve -- to why (see _link_status).

    A link that is not followed is still reported: a broken or outward ``-wal`` link
    belongs to its database, and dropping it would make that database look standalone
    and be verified without the WAL it needs.

    A directory that cannot be read (a root-only ``lost+found``, say) is recorded in
    ``warnings`` and skipped; the rest of the tree is still audited. Only root itself
    being unreadable is fatal. A symlinked directory is not descended into either, and is
    recorded in ``warnings`` too, so an unaudited subtree is never silently passed over.
    """

    def on_error(err: OSError) -> None:
        if err.filename is None or os.path.abspath(err.filename) == os.path.abspath(root):
            raise err
        _warn(warnings, _warning(root, err.filename, err), _relative(root, err.filename))

    regular: list[str] = []
    skipped: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root, onerror=on_error):
        dirnames.sort()
        for name in dirnames:
            full = os.path.join(dirpath, name)
            rel = _relative(root, full)
            if not os.path.islink(full):
                continue
            # os.walk is called with followlinks=False, so the subtree behind the link is
            # not descended into (a link back up the tree would loop forever): say so.
            if _link_status(root, full) is None:
                # it points inside root, so the same files are walked under their real
                # path: nothing is missing from the audit and nothing is counted skipped
                warnings.append(
                    f"symlinked directory not followed: {rel} "
                    "(its target is inside the audited directory and is audited there)"
                )
            else:
                _warn(warnings, f"symlinked directory not followed: {rel}", rel)
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = _relative(root, full)
            try:
                st = os.lstat(full)
            except FileNotFoundError:
                # the file vanished while walking
                continue
            except OSError as exc:
                _warn_skipped(warnings, _warning(root, full, exc), rel)
                continue
            if stat.S_ISLNK(st.st_mode):
                status = _link_status(root, full)
                if status is not None:
                    skipped[rel] = status
                    _warn_skipped(
                        warnings, f"symbolic link not followed: {rel} ({LINK_NOTE[status]})", rel
                    )
                    continue
                try:
                    st = os.stat(full)  # the target, which lies inside the audited tree
                except OSError as exc:
                    _warn_skipped(warnings, _warning(root, full, exc), rel)
                    continue
            if not stat.S_ISREG(st.st_mode):
                # FIFOs, sockets, devices: reading them could block or be destructive
                continue
            regular.append(rel)
    return sorted(regular), skipped


def _note_links(reason: str, family: list[str], skipped: dict[str, str]) -> str:
    """Add the sidecars of a unit that are links not followed (so not read) to its reason."""
    linked = [
        rel + (" (dangling)" if skipped[rel] == SKIPPED_DANGLING else "")
        for rel in family
        if rel in skipped
    ]
    if not linked:
        return reason
    return reason + "; symbolic link not followed: " + ", ".join(linked)


def scan(root: str, warnings: list[str] | None = None) -> list[dict]:
    """Classify every SQLite database, sidecar, would-be database and unfollowed link under root.

    A symlink resolving to a regular file inside root is classified from its target's
    header like any other file. A link that leaves root or does not resolve is not
    followed: if it is not a sidecar it gets an entry of its own with the ``not-sqlite``
    class and ``"skipped": "symlink-outside"`` / ``"symlink-dangling"``.

    Returns entries sorted by ``main`` (then ``class``); paths are relative to root.
    Paths that cannot be read are appended to ``warnings`` and left out of the entries;
    AuditError is raised only if root itself is not a readable directory.
    """
    if warnings is None:
        warnings = Warnings()
    if not os.path.isdir(root):
        raise AuditError(f"not a directory: {root}")

    try:
        files, skipped = _walk_files(root, warnings)
    except OSError as exc:
        raise AuditError(str(exc)) from exc

    # A sidecar is recognised by its name alone: link or not, readable or not, and before
    # any header is read. Leaving a sidecar out of its family -- because it is a link that
    # was not followed, or because its permissions deny reading it -- would make its
    # database look standalone and be verified without the WAL it needs.
    sidecars: dict[str, list[str]] = {}
    for rel in sorted(files + list(skipped)):
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
            _warn_skipped(warnings, _warning(root, os.path.join(root, rel), exc), rel)
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
                "reason": _note_links(reason, family, skipped),
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
        elif main in skipped:
            reason = (
                f"main path is a symbolic link whose {LINK_NOTE[skipped[main]]}; "
                "not followed, so no SQLite header was read"
            )
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
                "reason": _note_links(reason, family, skipped),
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

    for main, status in sorted(skipped.items()):
        if main in adopted:
            # already reported in the sidecars of the unit it belongs to
            continue
        entries.append(
            {
                "main": main,
                "sidecars": [],
                # every class is decided by reading a header, which such a link is never read
                # for; "skipped" tells a consumer that the class was not established, not that
                # the target is junk, and keeps the class field to the four documented values
                "class": NOT_SQLITE,
                "reason": (
                    "dangling symbolic link (target is missing)"
                    if status == SKIPPED_DANGLING
                    else "symbolic link to a file outside the audited directory"
                )
                + "; not followed, so no SQLite header was read",
                "skipped": status,
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


def _check_truncation(db_path: str, wal_pages: frozenset[int] | None = None) -> str | None:
    """Why a (copied) database file is shorter than its own header says, or None if it is whole.

    ``PRAGMA integrity_check`` only reads the pages its b-tree walk reaches, so it says "ok"
    for a file whose tail is simply gone: cutting a single byte off a valid database still
    reports "ok" and the full row count. That is the worst answer a backup checker can give,
    so the file's length is compared with what its own header says it should be, and that
    verdict outranks whatever ``integrity_check`` makes of the pages that did survive.

    Three ways a file can be too short, all from the issue:

    * its size is not a multiple of the page size (header bytes 16-17, 1 meaning 65536) --
      the last page is a fragment;
    * it is shorter than ``page_count * page_size`` (bytes 28-31). That field is only
      believed when the change counter (24-27) equals version-valid-for (92-95), which is
      exactly the condition SQLite itself uses: otherwise the file was last written by a
      pre-3.7.0 library that never maintained it, and the file size is authoritative;
    * the last page does not read back in full.

    A file *longer* than ``page_count * page_size`` is not an error: a hot copy of a live
    database, or one whose tail pages were freed, legitimately carries pages past the count.

    ``wal_pages`` is the set of page numbers the ``-wal`` beside this file will actually
    restore (the pages of the frames ``_check_wal`` counts as replayed), or None when no
    ``-wal`` was read at all. It is what switches the page-count comparison off, and only
    for the pages it really covers. A checkpoint writes page 1 -- which carries the new
    page count -- before it writes the pages that count covers, so a copy taken inside that
    window holds a main file shorter than its own header while the ``-wal`` beside it still
    holds every one of the missing pages: SQLite replays them and the restore is whole.
    That window is not rare (a stress run of hot copies during passive checkpoints hit it
    in 38 of 400), and calling it truncation would fail exactly the live backups this tool
    exists to bless. But the mere presence of a ``-wal`` proves none of that: a ``-wal``
    holding one frame for page 4 does not bring back pages 17..36, and excusing the gap
    because some ``-wal`` is there turns the commonest shape of a live backup -- main file
    plus ``-wal`` -- into the one shape where a plainly truncated file passes. So the claim
    is dropped only when every missing page number is in ``wal_pages``, which is exactly
    the checkpoint window and nothing else. Frames past the last commit frame do not count:
    SQLite drops them, so they restore nothing.

    The other two checks stay on whatever the ``-wal`` holds: a checkpoint only ever writes
    whole pages, so a fragment page is a torn copy no ``-wal`` can explain.
    """
    try:
        size = os.path.getsize(db_path)
    except OSError as exc:
        return f"file size unavailable: {exc.strerror or exc}"
    if size < DB_HEADER_SIZE:
        return f"file is {size} bytes, shorter than the {DB_HEADER_SIZE}-byte database header"
    try:
        with open(db_path, "rb") as f:
            header = f.read(DB_HEADER_SIZE)
    except OSError as exc:
        return f"header unreadable: {exc.strerror or exc}"
    page_size = int.from_bytes(header[16:18], "big")
    page_size = 65536 if page_size == 1 else page_size
    if page_size < 512 or page_size & (page_size - 1):
        # not a power of two in [512, 65536]: no page count can be derived, and SQLite will
        # reject the file on its own, so leave the verdict to integrity_check
        return None
    if size % page_size:
        return (
            f"file is {size} bytes, not a multiple of the {page_size}-byte page size: "
            f"the last page is {size % page_size} of {page_size} bytes"
        )
    page_count = int.from_bytes(header[28:32], "big")
    # the page count is only believed when SQLite itself believes it (change counter ==
    # version-valid-for); otherwise a pre-3.7.0 writer left it stale and it claims nothing
    believed = header[24:28] == header[92:96]
    if believed and page_count and size < page_count * page_size:
        missing = frozenset(range(size // page_size + 1, page_count + 1))
        restored = missing & wal_pages if wal_pages is not None else frozenset()
        if missing - restored:
            return (
                f"file is {size} bytes, short of the {page_count * page_size} bytes its "
                f"header claims ({page_count} pages of {page_size}): {len(missing)} page(s) "
                f"are missing from the end{_wal_cover(wal_pages, restored)}"
            )
    try:
        with open(db_path, "rb") as f:
            f.seek(size - page_size)
            last = f.read(page_size)
    except OSError as exc:
        return f"last page unreadable: {exc.strerror or exc}"
    if len(last) < page_size:
        return (
            f"last page stops after {len(last)} of {page_size} bytes "
            f"(the file shrank while it was being read)"
        )
    return None


def _wal_cover(wal_pages: frozenset[int] | None, restored: frozenset[int]) -> str:
    """How much of a truncation the -wal beside the file makes good, for the verdict's text."""
    if wal_pages is None:
        return ""
    if not restored:
        return ", and the -wal beside it restores none of them"
    return f", and the -wal beside it restores only {len(restored)} of them"


def _wal_truncation(wal_path: str, page_size: int | None, verdict: str) -> str | None:
    """Why a (copied) ``-wal`` is cut short in a way that costs data, or None if it is not.

    A ``-wal`` holds a 32-byte header and then frames of ``24 + page_size`` bytes each, so
    any other length means the copy caught the file mid-frame. That alone is *not* a
    failure: a ``cp``/rsync of a live WAL database almost always ends inside the frame that
    was being written, and SQLite drops exactly that uncommitted tail on recovery without
    losing a transaction. Only a short ``-wal`` that ``_check_wal`` already judges
    ``invalid`` -- because the frames it cuts off include a commit, or because nothing is
    left to replay at all -- costs rows that the main file does not have, and only that
    fails the unit's integrity as well as its ``wal`` key: the main file beside it verifies
    "ok" and reports its own row count, which is precisely the false pass worth failing on.

    A 0-byte ``-wal`` is whole (``wal_checkpoint(TRUNCATE)`` leaves exactly that), and a
    ``-wal`` whose page size does not match the database's is a mismatch rather than a
    truncation -- ``_check_wal`` reports both, so neither is claimed here.
    """
    if not verdict.startswith("invalid"):
        return None
    try:
        size = os.path.getsize(wal_path)
    except OSError:
        return None  # _check_wal reports what it could not read
    if size == 0:
        return None
    if size < WAL_HEADER_SIZE:
        return f"-wal is {size} bytes, shorter than its {WAL_HEADER_SIZE}-byte header"
    if not page_size:
        return None
    frame_size = WAL_FRAME_HEADER_SIZE + page_size
    body = size - WAL_HEADER_SIZE
    if body % frame_size:
        return (
            f"-wal is {size} bytes: {body // frame_size} whole frames of {frame_size} bytes "
            f"plus {body % frame_size} bytes of an incomplete one, and what it holds can no "
            "longer be replayed in full onto the database beside it"
        )
    return None


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


class _Wal(NamedTuple):
    """What _check_wal found: its verdict, and the pages the -wal really restores.

    ``pages`` holds the page numbers of the frames SQLite would replay -- the prefix up to
    the last commit frame -- so it is the only evidence that the -wal makes good a gap at
    the end of the main file (see _check_truncation). It is empty whenever nothing is
    replayed, including for a -wal whose whole generation is an uncommitted tail.
    """

    verdict: str
    pages: frozenset[int]


def _check_wal(wal_path: str, db_path: str) -> _Wal:
    """Check a (copied) -wal file the way SQLite's recovery reads it, which it does not report.

    SQLite silently ignores a -wal it cannot replay, so integrity_check says "ok" for a
    database whose uncheckpointed transactions were lost. This repeats the checks of
    walIndexRecover(): header, then each frame's salt and its link in the running
    checksum chain, and only up to the last commit frame is replayed.

    Returns a _Wal: the verdict -- "empty", "ok (<N> frames)" with N the number of frames
    SQLite would replay, or "invalid: <reason>" -- and the page numbers those N frames
    carry, which is what a caller needs to know whether the -wal makes good a gap at the
    end of the main file. Frames past the last commit frame (the uncommitted tail every
    copy of a live WAL database has) are reported in the "ok" value, even when they are
    the whole generation and N is 0: dropping them is SQLite's crash recovery, not data
    loss. A frame that does not decode at all is different -- it can hide a commit the
    main file does not have -- so it is "invalid" when it leaves nothing to replay, or
    when one of the frames it drops is itself a complete commit frame.
    """
    nothing = frozenset()  # no frame is replayed, so the -wal restores no page
    wal_size = os.path.getsize(wal_path)
    if wal_size == 0:
        return _Wal("empty", nothing)
    with open(wal_path, "rb") as f:
        header = f.read(WAL_HEADER_SIZE)
        if len(header) < WAL_HEADER_SIZE:
            return _Wal(f"invalid: header truncated to {len(header)} bytes", nothing)
        magic, version, page_size, _, salt1, salt2, cksum1, cksum2 = struct.unpack(">8I", header)
        if magic not in (WAL_MAGIC_LITTLE_ENDIAN, WAL_MAGIC_BIG_ENDIAN):
            return _Wal(f"invalid: bad magic number 0x{magic:08x}", nothing)
        if version != WAL_VERSION:
            return _Wal(f"invalid: unsupported format version {version}", nothing)
        if _wal_checksum(header[:24], magic == WAL_MAGIC_BIG_ENDIAN) != (cksum1, cksum2):
            return _Wal("invalid: header checksum mismatch", nothing)
        db_page_size = _database_page_size(db_path)
        if page_size != db_page_size:
            return _Wal(
                f"invalid: page size {page_size} does not match database page size "
                f"{db_page_size}",
                nothing,
            )
        big_endian = magic == WAL_MAGIC_BIG_ENDIAN
        frame_size = WAL_FRAME_HEADER_SIZE + page_size
        checksum = (cksum1, cksum2)
        good = 0  # frames that decode; SQLite stops reading at the first one that does not
        replayed = 0  # SQLite's mxFrame: frames up to and including the last commit frame
        broken = None  # (number of the first unusable frame, why it is not usable)
        pages: list[int] = []  # the page each decoded frame carries, in frame order
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
                    return _Wal("invalid: first frame salt does not match header salt", nothing)
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
            pages.append(page_number)
            if truncate:
                replayed = good
        replays = frozenset(pages[:replayed])
        if broken is None:
            if replayed == good:
                return _Wal(f"ok ({replayed} frames)", replays)
            # Every frame decoded; the generation just ends inside a transaction that was
            # never committed, which is the ordinary state of a copy of a live database.
            # SQLite drops exactly those frames, so nothing durable is lost -- not even
            # when there is no commit frame at all and the replayed prefix is empty.
            return _Wal(
                f"ok ({replayed} frames; {good - replayed} further frames will be dropped, "
                "as SQLite does: they were never committed)",
                replays,
            )
        number, reason = broken
        # the frames after the break are dropped too, and they are usually the bulk of it
        tail, commit = _wal_generation_tail(f, number, frame_size, header[16:24])
        present = number - 1 + tail
    if replayed == 0:
        # a frame is unusable and nothing is replayed: everything the -wal holds is lost,
        # the copy is only the main file, and the break can hide a commit the main file
        # does not have -- which is what makes this worth failing on
        return _Wal(f"invalid: 0 of {present} frames will be replayed ({reason})", replays)
    if commit is not None:
        # the dropped frames are not the uncommitted tail of a live copy: one of them
        # commits, so a transaction that was written in full does not survive the restore
        return _Wal(
            f"invalid: {replayed} of {present} frames will be replayed ({reason}; "
            f"dropped frame {commit} is a commit frame, so a committed transaction is lost)",
            replays,
        )
    # A prefix up to the last commit frame is replayed and the rest is discarded, which
    # is exactly what SQLite does after a crash; no committed transaction is lost.
    return _Wal(
        f"ok ({replayed} frames; {present - replayed} further frames will be dropped, "
        f"as SQLite does: {reason})",
        replays,
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
    ``-wal`` is a link that is not followed or cannot be read, since neither is copied
    and what it holds is therefore unknown, and units that have a ``-shm`` but no
    ``-wal`` at all (see _shm_without_wal). A ``-shm`` that could not be copied gains
    ``shm`` instead and a warning: it holds no data of its own, SQLite rebuilds it from
    the ``-wal``, so the unit is checked as usual and still passes.
    """
    if warnings is None:
        warnings = Warnings()
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
            # a link that leaves the tree (or resolves nowhere) is neither read nor copied;
            # the unit is then not the one that would be restored, whatever the copy says
            problems: dict[str, str] = {}
            copied = []
            try:
                _copy_file(os.path.join(root, entry["main"]), copy)
                for rel in entry["sidecars"]:
                    status = _link_status(root, os.path.join(root, rel))
                    if status is not None:
                        problems[rel] = status
                        continue
                    dst = os.path.join(tmp, os.path.basename(rel))
                    try:
                        _copy_file(os.path.join(root, rel), dst)
                    except _SourceError as exc:
                        # SQLite must not replay half a file, so the partial copy goes; but the
                        # unit is then not the one that would be restored, and says so below
                        _discard(dst)
                        cause = exc.args[0]
                        error = getattr(cause, "strerror", None) or cause
                        problems[rel] = UNREADABLE + f"{rel}: {error}"
                        _warn_skipped(warnings, f"skipped {rel}: {error}", rel)
                    else:
                        copied.append(rel)
            except _SourceError as exc:
                entry["integrity"], entry["tables"] = f"copy failed: {exc}", {}
                continue
            except OSError as exc:
                entry["integrity"], entry["tables"] = NOT_CHECKED + str(exc), {}
                continue
            # A -shm that could not be copied does not hurt: it is a wal-index, SQLite
            # rebuilds it from the -wal, so the check goes on and the unit can still pass.
            shm = [text for rel, text in problems.items() if _carries_no_data(rel)]
            wal_problems = [text for rel, text in problems.items() if not _carries_no_data(rel)]
            wal = None
            wal_pages = None  # the pages a copied, readable -wal will actually restore
            wals = [rel for rel in copied if rel.endswith("-wal")]
            if wal_problems:
                wal = "; ".join(sorted(wal_problems))
            elif wals:
                # before SQLite opens the copy, so the -wal is read exactly as it was copied
                try:
                    wal, wal_pages = _check_wal(
                        os.path.join(tmp, os.path.basename(wals[0])), copy
                    )
                except OSError as exc:
                    # what the -wal holds stays unknown, so it excuses nothing below
                    wal = NOT_CHECKED + str(exc)
            elif _shm_without_wal(entry["sidecars"]):
                # the main file alone verifies fine, which is exactly the trap: it is missing
                # every row the -wal held, and nothing else in the unit can show that
                wal = MISSING + (
                    f"{os.path.basename(entry['main'])}-wal is absent although its -shm is "
                    "present, so the -wal was lost in the copy"
                )
            # Length before content: integrity_check reads only the pages its b-tree walk
            # reaches, so a file (or a -wal) whose tail is missing passes it while the rows
            # that lived in the lost tail are gone. Whatever SQLite would say about such a
            # copy, it is not a copy anything should be restored from.
            short = _check_truncation(copy, wal_pages=wal_pages)
            if short is None and wals and wal:
                try:
                    page_size = _database_page_size(copy)
                except OSError:
                    page_size = None
                short = _wal_truncation(
                    os.path.join(tmp, os.path.basename(wals[0])), page_size, wal
                )
            integrity, tables = _check_copy(copy)
            # The row counts are still worth reporting -- they say how much of the backup is
            # readable -- but they are counted over a file that is missing its tail, so the
            # verdict is the truncation, not whatever integrity_check made of what remains.
            entry["integrity"] = TRUNCATED + short if short is not None else integrity
            entry["tables"] = tables
            if wal is not None:
                entry["wal"] = wal
            if shm:
                entry["shm"] = "; ".join(sorted(shm))
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
            # "invalid:", "symlink-outside", "symlink-dangling", "unreadable:", "missing:":
            # the -wal that would be replayed is either unsound, was never seen at all, or is
            # not in the copy although the -shm beside it proves it existed. A -shm that could
            # not be copied is in "shm" instead and does not land here: it holds no data.
            return True
    return False
