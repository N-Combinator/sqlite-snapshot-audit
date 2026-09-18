import errno
import hashlib
import json
import os
import random
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from sqlite_snapshot_audit import audit, scan, verify
from sqlite_snapshot_audit.cli import main

SRC = Path(__file__).resolve().parents[1] / "src"
# the four classes the tool promises; "skipped" carries the symlink fact instead of a fifth one
CONTRACT_CLASSES = ("standalone", "wal-family", "orphan-sidecar", "not-sqlite")
LIVE_ROWS_COMMITTED_BEFORE_WAL = 2
LIVE_ROWS_IN_WAL = 25


def make_db(path, rows, table="items"):
    conn = sqlite3.connect(path)
    conn.execute(f"CREATE TABLE {table} (id INTEGER PRIMARY KEY, body TEXT)")
    conn.executemany(
        f"INSERT INTO {table} (body) VALUES (?)", [(f"row {i} " + "x" * 200,) for i in range(rows)]
    )
    conn.commit()
    conn.close()


def corrupt_page(path, page_number, offset, data):
    """Overwrite bytes inside a page, leaving page 1 (and the SQLite header) intact."""
    with open(path, "rb") as f:
        header = f.read(100)
    page_size = int.from_bytes(header[16:18], "big")
    assert page_number >= 2 and offset + len(data) <= page_size
    with open(path, "r+b") as f:
        f.seek(page_size * (page_number - 1) + offset)
        f.write(data)


@pytest.fixture
def live_wal_db(tmp_path):
    """A WAL-mode database whose latest committed rows exist only in its -wal file.

    The connection stays open for the whole test, like a backup taken from a live app.
    """
    tree = tmp_path / "tree"
    (tree / "live").mkdir(parents=True)
    path = tree / "live" / "app.db"
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, body TEXT)")
    conn.executemany(
        "INSERT INTO events (body) VALUES (?)", [("early",)] * LIVE_ROWS_COMMITTED_BEFORE_WAL
    )
    conn.commit()
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.executemany("INSERT INTO events (body) VALUES (?)", [("late",)] * LIVE_ROWS_IN_WAL)
    conn.commit()
    yield path
    conn.close()


@pytest.fixture
def tree(live_wal_db):
    root = live_wal_db.parent.parent
    make_db(root / "standalone.db", rows=3)
    (root / "nested" / "deeper").mkdir(parents=True)
    make_db(root / "nested" / "deeper" / "customers.bak", rows=4, table="customers")
    (root / "orphans").mkdir()
    (root / "orphans" / "gone.db-wal").write_bytes(b"\x37\x7f\x06\x82" + b"\x00" * 28)
    (root / "orphans" / "shm-only.sqlite-shm").write_bytes(b"\x00" * 32)
    (root / "notes.db").write_text("these are not the rows you are looking for\n")
    # Garbage over the table's root page: SQLite raises "database disk image is malformed".
    make_db(root / "corrupt.sqlite3", rows=60)
    corrupt_page(root / "corrupt.sqlite3", 2, 0, b"\xa5" * 2048)
    # Zeroed cells inside a leaf page: integrity_check returns an error message. (Corruption
    # that points outside the page is avoided: SQLite's result then depends on process memory.)
    make_db(root / "bad-cell.db", rows=60)
    corrupt_page(root / "bad-cell.db", 3, 3000, b"\x00" * 500)
    (root / "readme.txt").write_text("not a database, ignored\n")
    return root


def tree_hashes(root):
    hashes = {}
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            path = os.path.join(dirpath, name)
            with open(path, "rb") as f:
                hashes[os.path.relpath(path, root)] = hashlib.sha256(f.read()).hexdigest()
    return hashes


def run_cli(capsys, *argv):
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def by_main(entries):
    result = {}
    for entry in entries:
        result.setdefault(entry["main"], []).append(entry)
    return {main: e[0] if len(e) == 1 else e for main, e in result.items()}


def test_live_fixture_really_has_uncheckpointed_rows(live_wal_db, tmp_path):
    wal = Path(str(live_wal_db) + "-wal")
    assert wal.stat().st_size > 0
    # The main file alone (without its -wal) must not contain the late rows.
    alone = tmp_path / "alone"
    alone.mkdir()
    shutil.copyfile(live_wal_db, alone / "app.db")
    conn = sqlite3.connect(f"file:{alone / 'app.db'}?mode=ro", uri=True)
    try:
        (count,) = conn.execute("SELECT COUNT(*) FROM events").fetchone()
    finally:
        conn.close()
    assert count == LIVE_ROWS_COMMITTED_BEFORE_WAL


def test_scan_classifies_every_fixture(tree):
    assert scan(str(tree)) == [
        {
            "main": "bad-cell.db",
            "sidecars": [],
            "class": "standalone",
            "reason": "SQLite database without -wal/-shm sidecars",
        },
        {
            "main": "corrupt.sqlite3",
            "sidecars": [],
            "class": "standalone",
            "reason": "SQLite database without -wal/-shm sidecars",
        },
        {
            "main": "live/app.db",
            "sidecars": ["live/app.db-shm", "live/app.db-wal"],
            "class": "wal-family",
            "reason": "SQLite database with -wal and -shm sidecars",
        },
        {
            "main": "nested/deeper/customers.bak",
            "sidecars": [],
            "class": "standalone",
            "reason": "SQLite database without -wal/-shm sidecars",
        },
        {
            "main": "notes.db",
            "sidecars": [],
            "class": "not-sqlite",
            "reason": "database file name but no SQLite header",
        },
        {
            "main": "orphans/gone.db",
            "sidecars": ["orphans/gone.db-wal"],
            "class": "orphan-sidecar",
            "reason": "main file is missing",
        },
        {
            "main": "orphans/shm-only.sqlite",
            "sidecars": ["orphans/shm-only.sqlite-shm"],
            "class": "orphan-sidecar",
            "reason": "main file is missing",
        },
        {
            "main": "standalone.db",
            "sidecars": [],
            "class": "standalone",
            "reason": "SQLite database without -wal/-shm sidecars",
        },
    ]


def test_scan_json_is_byte_identical_across_runs(tree, capsys):
    code1, out1, _ = run_cli(capsys, "scan", str(tree), "--json")
    code2, out2, _ = run_cli(capsys, "scan", str(tree), "--json")
    assert code1 == code2 == 0
    assert out1 == out2
    entries = json.loads(out1)
    assert [e["main"] for e in entries] == sorted(e["main"] for e in entries)
    assert str(tree) not in out1
    assert os.uname().nodename not in out1


def test_verify_json_is_byte_identical_across_runs(tree, capsys):
    _, out1, _ = run_cli(capsys, "verify", str(tree), "--json")
    _, out2, _ = run_cli(capsys, "verify", str(tree), "--json")
    assert out1 == out2


def test_verify_reports_integrity_and_row_counts(tree, capsys):
    code, out, _ = run_cli(capsys, "verify", str(tree), "--json")
    assert code == 1
    entries = by_main(json.loads(out))
    assert len(json.loads(out)) == 8  # every discovered entry is still reported

    assert entries["standalone.db"]["integrity"] == "ok"
    assert entries["standalone.db"]["tables"] == {"items": 3}
    assert entries["nested/deeper/customers.bak"]["integrity"] == "ok"
    assert entries["nested/deeper/customers.bak"]["tables"] == {"customers": 4}

    live = entries["live/app.db"]
    assert live["class"] == "wal-family"
    assert live["integrity"] == "ok"
    assert live["tables"] == {"events": LIVE_ROWS_COMMITTED_BEFORE_WAL + LIVE_ROWS_IN_WAL}
    wal_size = (tree / "live" / "app.db-wal").stat().st_size
    assert live["wal"] == f"ok ({(wal_size - 32) // (24 + 4096)} frames)"
    assert wal_size >= 32 + 24 + 4096

    corrupt = entries["corrupt.sqlite3"]
    assert corrupt["class"] == "standalone"
    assert corrupt["integrity"] == "database disk image is malformed"
    assert corrupt["tables"] == {"items": None}

    bad_cell = entries["bad-cell.db"]
    assert bad_cell["class"] == "standalone"
    assert bad_cell["integrity"] != "ok"
    assert "page 3" in bad_cell["integrity"]

    for main in ("notes.db", "orphans/gone.db", "orphans/shm-only.sqlite"):
        assert "integrity" not in entries[main]
        assert "tables" not in entries[main]
        assert "wal" not in entries[main]
    assert "wal" not in entries["standalone.db"]


def test_scan_and_verify_do_not_modify_source_tree(tree, capsys):
    before = tree_hashes(tree)
    assert "live/app.db-wal" in before and "corrupt.sqlite3" in before
    run_cli(capsys, "scan", str(tree), "--json")
    run_cli(capsys, "scan", str(tree))
    run_cli(capsys, "verify", str(tree), "--json")
    run_cli(capsys, "verify", str(tree))
    assert tree_hashes(tree) == before


def test_verify_deletes_temporary_copies(tree, tmp_path, monkeypatch, capsys):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    run_cli(capsys, "verify", str(tree), "--json")
    assert list(scratch.iterdir()) == []


def test_verify_refuses_temp_dir_inside_audited_tree(tree, monkeypatch, capsys):
    before = tree_hashes(tree)
    monkeypatch.setattr(tempfile, "tempdir", str(tree / "nested"))
    code, out, err = run_cli(capsys, "verify", str(tree), "--json")
    assert code == 2
    assert out == ""
    assert "inside" in err
    assert tree_hashes(tree) == before


def assert_not_checked_exit_2(capsys, tree, message):
    before = tree_hashes(tree)
    code, out, err = run_cli(capsys, "verify", str(tree), "--json")
    assert code == 2
    assert "not checked" in err
    entries = json.loads(out)
    assert len(entries) == 8  # every discovered entry is still reported
    for entry in entries:
        if entry["class"] in ("standalone", "wal-family"):
            assert entry["integrity"].startswith("not-checked: ")
            assert message in entry["integrity"]
            assert entry["tables"] == {}
        else:
            assert "integrity" not in entry
    assert tree_hashes(tree) == before


def test_verify_exits_2_when_temp_dir_is_missing(tree, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path / "no-such-tmp"))
    assert_not_checked_exit_2(capsys, tree, "no-such-tmp")


@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() == 0, reason="root can write anywhere"
)
def test_verify_exits_2_when_temp_dir_is_not_writable(tree, tmp_path, monkeypatch, capsys):
    scratch = tmp_path / "read-only-tmp"
    scratch.mkdir()
    scratch.chmod(0o500)
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    try:
        assert_not_checked_exit_2(capsys, tree, os.strerror(errno.EACCES))
    finally:
        scratch.chmod(0o700)


@pytest.mark.parametrize("err", [errno.ENOSPC, errno.EDQUOT], ids=["ENOSPC", "EDQUOT"])
def test_verify_exits_2_when_temp_copy_cannot_be_written(tree, monkeypatch, capsys, err):
    real_open = open

    class FullDisk:
        def __init__(self, f):
            self._f = f

        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            self._f.close()

        def write(self, data):
            raise OSError(err, os.strerror(err))

    def fake_open(path, mode="r", *args, **kwargs):
        f = real_open(path, mode, *args, **kwargs)
        return FullDisk(f) if "w" in mode else f

    # only the module's own open() calls (source reads and temp writes) are affected
    monkeypatch.setattr(audit, "open", fake_open, raising=False)
    assert_not_checked_exit_2(capsys, tree, os.strerror(err))


def test_copy_distinguishes_source_errors_from_temp_errors(tmp_path):
    make_db(tmp_path / "a.db", rows=1)
    with pytest.raises(audit._SourceError):
        audit._copy_file(str(tmp_path / "vanished.db"), str(tmp_path / "copy.db"))
    with pytest.raises(OSError) as exc:
        audit._copy_file(str(tmp_path / "a.db"), str(tmp_path / "no-such-dir" / "copy.db"))
    assert not isinstance(exc.value, audit._SourceError)


def test_source_file_vanishing_before_copy_is_a_backup_problem(tmp_path, monkeypatch, capsys):
    make_db(tmp_path / "a.db", rows=1)
    real_scan = audit.scan

    def scan_then_delete(root, warnings=None):
        entries = real_scan(root, warnings)
        (tmp_path / "a.db").unlink()
        return entries

    monkeypatch.setattr(audit, "scan", scan_then_delete)
    code, out, _ = run_cli(capsys, "verify", str(tmp_path), "--json")
    assert code == 1
    (entry,) = json.loads(out)
    assert entry["integrity"].startswith("copy failed: ")


def test_verify_exits_0_on_clean_tree(tmp_path, capsys):
    make_db(tmp_path / "a.db", rows=1)
    conn = sqlite3.connect(tmp_path / "b.sqlite")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("CREATE TABLE t (x)")
    conn.execute("INSERT INTO t VALUES (1)")
    conn.commit()
    try:
        code, out, _ = run_cli(capsys, "verify", str(tmp_path), "--json")
    finally:
        conn.close()
    assert code == 0
    assert [(e["main"], e["class"], e["integrity"]) for e in json.loads(out)] == [
        ("a.db", "standalone", "ok"),
        ("b.sqlite", "wal-family", "ok"),
    ]


@pytest.mark.parametrize(
    "setup",
    [
        lambda d: (d / "x.db").write_text("nope"),
        lambda d: (d / "x-wal").write_bytes(b"\x00"),
        lambda d: (d / "x-shm").write_bytes(b"\x00"),
    ],
    ids=["not-sqlite", "orphan-wal", "orphan-shm"],
)
def test_verify_exits_1_for_each_problem_class(tmp_path, capsys, setup):
    make_db(tmp_path / "good.db", rows=1)
    setup(tmp_path)
    code, out, _ = run_cli(capsys, "verify", str(tmp_path), "--json")
    assert code == 1
    assert len(json.loads(out)) == 2


def test_scan_exits_0_even_with_problem_entries(tree, capsys):
    code, _, _ = run_cli(capsys, "scan", str(tree), "--json")
    assert code == 0


@pytest.mark.parametrize("command", ["scan", "verify"])
def test_missing_directory_exits_2(tmp_path, capsys, command):
    code, out, err = run_cli(capsys, command, str(tmp_path / "missing"), "--json")
    assert code == 2
    assert out == ""
    assert "not a directory" in err


def test_usage_error_exits_2(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["verify"])
    assert exc.value.code == 2


@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() == 0, reason="root can read unreadable files"
)
def test_unreadable_file_is_a_warning_and_the_rest_is_audited(tmp_path, capsys):
    make_db(tmp_path / "a.db", rows=1)
    locked = tmp_path / "locked.db"
    make_db(locked, rows=1)
    locked.chmod(0)
    try:
        warnings = []
        entries = scan(str(tmp_path), warnings)
        code, out, err = run_cli(capsys, "verify", str(tmp_path), "--json")
    finally:
        locked.chmod(0o600)
    assert [e["main"] for e in entries] == ["a.db"]
    assert warnings == [f"skipped locked.db: {os.strerror(errno.EACCES)}"]
    # the readable database is still audited, but a file nobody could read was not
    assert code == 1
    assert [e["main"] for e in json.loads(out)] == ["a.db"]
    assert err == (
        "sqlite-snapshot-audit: warning: skipped locked.db: "
        f"{os.strerror(errno.EACCES)}\n"
        "sqlite-snapshot-audit: 1 path(s) could not be audited (unreadable, or a symbolic "
        "link that was not followed); the tree was not audited in full\n"
    )


@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() == 0, reason="root can read unreadable directories"
)
def test_unreadable_subdirectory_is_a_warning_and_the_rest_is_audited(tmp_path, capsys):
    """A backup volume mounted at a filesystem root has a root-only lost+found."""
    make_db(tmp_path / "a.db", rows=1)
    (tmp_path / "sub").mkdir()
    make_db(tmp_path / "sub" / "b.db", rows=1)
    locked = tmp_path / "lost+found"
    locked.mkdir()
    make_db(locked / "hidden.db", rows=1)
    locked.chmod(0)
    try:
        code, out, err = run_cli(capsys, "verify", str(tmp_path), "--json")
    finally:
        locked.chmod(0o700)
    assert code == 1  # the rest of the tree is audited, but this subtree was not
    assert [e["main"] for e in json.loads(out)] == ["a.db", "sub/b.db"]
    assert err == (
        "sqlite-snapshot-audit: warning: skipped lost+found: "
        f"{os.strerror(errno.EACCES)}\n"
        "sqlite-snapshot-audit: 1 path(s) could not be audited (unreadable, or a symbolic "
        "link that was not followed); the tree was not audited in full\n"
    )


@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() == 0, reason="root can read unreadable directories"
)
@pytest.mark.parametrize("command", ["scan", "verify"])
def test_unreadable_audited_directory_itself_exits_2(tmp_path, capsys, command):
    root = tmp_path / "root"
    root.mkdir()
    make_db(root / "a.db", rows=1)
    root.chmod(0)
    try:
        code, out, err = run_cli(capsys, command, str(root), "--json")
    finally:
        root.chmod(0o700)
    assert code == 2
    assert out == ""
    assert "Permission denied" in err


def test_file_that_vanishes_during_the_walk_is_not_a_warning(tmp_path, monkeypatch):
    make_db(tmp_path / "a.db", rows=1)
    real_lstat = os.lstat

    def lstat(path, *args, **kwargs):
        if str(path).endswith("a.db"):
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), str(path))
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(audit.os, "lstat", lstat)
    warnings = []
    assert scan(str(tmp_path), warnings) == []
    assert warnings == []


def test_sidecar_next_to_non_sqlite_main_and_shm_without_wal(tmp_path):
    (tmp_path / "fake.db").write_text("text")
    (tmp_path / "fake.db-wal").write_bytes(b"\x00")
    (tmp_path / "empty.sqlite").write_bytes(b"")
    make_db(tmp_path / "real.db", rows=2)
    (tmp_path / "real.db-shm").write_bytes(b"\x00" * 32)
    make_db(tmp_path / "walonly.db", rows=2)
    (tmp_path / "walonly.db-wal").write_bytes(b"")
    assert [(e["main"], e["sidecars"], e["class"], e["reason"]) for e in scan(str(tmp_path))] == [
        ("empty.sqlite", [], "not-sqlite", "empty file"),
        ("fake.db", [], "not-sqlite", "database file name but no SQLite header"),
        (
            "fake.db",
            ["fake.db-wal"],
            "orphan-sidecar",
            "main file exists but has no SQLite header",
        ),
        ("real.db", ["real.db-shm"], "wal-family", "SQLite database with -shm sidecar but no -wal"),
        ("walonly.db", ["walonly.db-wal"], "wal-family", "SQLite database with -wal sidecar, no -shm"),
    ]
    entries = by_main(verify(str(tmp_path)))
    assert entries["real.db"]["integrity"] == "ok"
    assert entries["real.db"]["tables"] == {"items": 2}
    # the -shm is there without a -wal: SQLite never leaves that pair, so the -wal was lost
    assert entries["real.db"]["wal"].startswith("missing: real.db-wal is absent")
    assert entries["walonly.db"]["tables"] == {"items": 2}
    assert entries["walonly.db"]["wal"] == "empty"


def test_file_named_exactly_like_a_suffix_is_not_a_sidecar(tmp_path):
    """`-wal` on its own has no main file name in front of it, so it is just a file."""
    (tmp_path / "-wal").write_bytes(b"\x00")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "-shm").write_bytes(b"\x00")
    make_db(tmp_path / "a.db", rows=1)
    assert [(e["main"], e["class"]) for e in scan(str(tmp_path))] == [("a.db", "standalone")]


def test_header_detection_ignores_extension_and_sidecar_names(tmp_path):
    make_db(tmp_path / "no_extension", rows=1)
    make_db(tmp_path / "UPPER.DB", rows=1)
    (tmp_path / "LOWER.SQLITE3").write_text("text")
    assert [(e["main"], e["class"]) for e in scan(str(tmp_path))] == [
        ("LOWER.SQLITE3", "not-sqlite"),
        ("UPPER.DB", "standalone"),
        ("no_extension", "standalone"),
    ]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs FIFOs and symlinks")
def test_special_files_and_symlinked_dirs_are_skipped(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    make_db(outside / "elsewhere.db", rows=1)
    os.mkfifo(root / "pipe.db")  # reading it would block forever
    (root / "linked-dir").symlink_to(outside, target_is_directory=True)
    (root / "dangling.db").symlink_to(tmp_path / "does-not-exist")
    make_db(root / "real.db", rows=1)
    warnings = []
    # the FIFO is not read, but the dangling link is still a file in the tree and is reported
    assert [e["main"] for e in scan(str(root), warnings)] == ["dangling.db", "real.db"]
    assert warnings == [
        "symlinked directory not followed: linked-dir",
        "symbolic link not followed: dangling.db (target is missing)",
    ]


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
def test_symlinked_directory_is_warned_about_not_silently_skipped(tmp_path, capsys):
    """A linked subtree is not walked, so its databases are missing from the report."""
    root = tmp_path / "root"
    (root / "sub").mkdir(parents=True)
    outside = tmp_path / "outside"
    (outside / "deep").mkdir(parents=True)
    make_db(outside / "hidden.db", rows=1)
    make_db(outside / "deep" / "deeper.db", rows=1)
    make_db(root / "real.db", rows=1)
    (root / "linked-dir").symlink_to(outside, target_is_directory=True)
    (root / "sub" / "nested-link").symlink_to(outside / "deep", target_is_directory=True)

    warnings = []
    entries = scan(str(root), warnings)
    assert [e["main"] for e in entries] == ["real.db"]
    assert sorted(warnings) == [
        "symlinked directory not followed: linked-dir",
        "symlinked directory not followed: sub/nested-link",
    ]

    code, out, err = run_cli(capsys, "verify", str(root), "--json")
    assert code == 1  # two subtrees were never looked at, so the tree was not cleared
    assert [e["main"] for e in json.loads(out)] == ["real.db"]
    assert err == (
        "sqlite-snapshot-audit: warning: symlinked directory not followed: linked-dir\n"
        "sqlite-snapshot-audit: warning: symlinked directory not followed: sub/nested-link\n"
        "sqlite-snapshot-audit: 2 path(s) could not be audited (unreadable, or a symbolic "
        "link that was not followed); the tree was not audited in full\n"
    )


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
def test_symlinked_directory_pointing_inside_the_tree_is_not_a_missed_subtree(tmp_path, capsys):
    """Its files are walked under their real path, so nothing is missing from the audit."""
    root = tmp_path / "root"
    (root / "sub").mkdir(parents=True)
    make_db(root / "sub" / "real.db", rows=1)
    (root / "same-again").symlink_to(root / "sub", target_is_directory=True)

    code, out, err = run_cli(capsys, "verify", str(root), "--json")
    assert [e["main"] for e in json.loads(out)] == ["sub/real.db"]
    assert err == (
        "sqlite-snapshot-audit: warning: symlinked directory not followed: same-again "
        "(its target is inside the audited directory and is audited there)\n"
    )
    assert code == 0  # not counted as skipped: every file behind the link was audited


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
def test_file_symlinks_are_reported_not_followed(tmp_path, monkeypatch, capsys):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    make_db(outside / "elsewhere.db", rows=1)
    (outside / "elsewhere.db-wal").write_bytes(b"\x00")
    make_db(root / "real.db", rows=2)
    (root / "link.db").symlink_to(outside / "elsewhere.db")
    (root / "real.db-wal").symlink_to(outside / "elsewhere.db-wal")
    (root / "sub").mkdir()
    (root / "sub" / "inside.sqlite").symlink_to(root / "real.db")
    (root / "sub" / "notes.txt").symlink_to(outside / "elsewhere.db")
    outside_before = tree_hashes(outside)
    opened = []
    real_open = open

    def recording_open(path, *args, **kwargs):
        opened.append(os.path.realpath(path))
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(audit, "open", recording_open, raising=False)

    expected = [
        ("link.db", "not-sqlite"),
        # the symlinked -wal is grouped by name, so the database is not called standalone
        ("real.db", "wal-family"),
        # this one resolves inside the audited tree: read and classified like any file
        ("sub/inside.sqlite", "standalone"),
        ("sub/notes.txt", "not-sqlite"),
    ]
    warnings = []
    entries = scan(str(root), warnings)
    assert [(e["main"], e["class"]) for e in entries] == expected
    assert [e["main"] for e in entries if e.get("skipped")] == ["link.db", "sub/notes.txt"]
    for entry in entries:
        if entry.get("skipped"):
            assert entry["skipped"] == "symlink-outside"
            assert entry["sidecars"] == []
            assert entry["reason"] == (
                "symbolic link to a file outside the audited directory; "
                "not followed, so no SQLite header was read"
            )
    assert sorted(warnings) == [
        "symbolic link not followed: link.db (target is outside the audited directory)",
        "symbolic link not followed: real.db-wal (target is outside the audited directory)",
        "symbolic link not followed: sub/notes.txt (target is outside the audited directory)",
    ]
    assert by_main(entries)["real.db"]["sidecars"] == ["real.db-wal"]
    assert by_main(entries)["real.db"]["reason"] == (
        "SQLite database with -wal sidecar, no -shm; symbolic link not followed: real.db-wal"
    )

    code, out, _ = run_cli(capsys, "verify", str(root), "--json")
    assert code == 1  # the -wal that would be replayed was not checked
    entries = json.loads(out)
    assert [(e["main"], e["class"]) for e in entries] == expected
    assert [e["main"] for e in entries if "integrity" in e] == ["real.db", "sub/inside.sqlite"]
    assert by_main(entries)["real.db"]["wal"] == "symlink-outside"
    assert by_main(entries)["sub/inside.sqlite"]["tables"] == {"items": 2}
    assert all(e["class"] in CONTRACT_CLASSES for e in entries)
    assert "elsewhere" not in out and str(outside) not in out
    assert tree_hashes(outside) == outside_before
    assert opened and not [p for p in opened if p.startswith(str(outside.resolve()))]


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
def test_symlinked_wal_does_not_make_a_live_database_look_standalone(tmp_path, capsys, live_wal_db):
    """The reported repro: a real database whose -wal is a symlink to rows outside the tree."""
    root = tmp_path / "root"
    root.mkdir()
    shutil.copyfile(live_wal_db, root / "app.db")
    (root / "app.db-wal").symlink_to(str(live_wal_db) + "-wal")
    code, out, _ = run_cli(capsys, "verify", str(root), "--json")
    (entry,) = json.loads(out)
    assert entry["class"] == "wal-family"
    assert entry["sidecars"] == ["app.db-wal"]
    assert entry["wal"] == "symlink-outside"
    # without its -wal the copy misses the uncheckpointed rows, and that must not pass
    assert entry["integrity"] == "ok"
    assert entry["tables"] == {"events": LIVE_ROWS_COMMITTED_BEFORE_WAL}
    assert code == 1

    code, out, _ = run_cli(capsys, "verify", str(root))
    assert code == 1
    assert "wal: symlink-outside" in out


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
def test_symlinked_shm_does_not_fail_a_healthy_family_or_mute_the_wal_check(
    tmp_path, capsys, live_wal_db
):
    """A -shm holds no rows: SQLite rebuilds it from the -wal, so the unit is still checked."""
    root = tmp_path / "root"
    root.mkdir()
    shutil.copyfile(live_wal_db, root / "app.db")
    shutil.copyfile(str(live_wal_db) + "-wal", root / "app.db-wal")
    (root / "app.db-shm").symlink_to(str(live_wal_db) + "-shm")
    code, out, err = run_cli(capsys, "verify", str(root), "--json")
    (entry,) = json.loads(out)
    assert entry["sidecars"] == ["app.db-shm", "app.db-wal"]
    assert entry["shm"] == "symlink-outside"  # reported, but it costs the audit nothing
    assert entry["wal"].startswith("ok (")  # the -wal was still checked, not muted
    assert entry["integrity"] == "ok"
    assert entry["tables"] == {
        "events": LIVE_ROWS_COMMITTED_BEFORE_WAL + LIVE_ROWS_IN_WAL
    }
    assert err == (
        "sqlite-snapshot-audit: warning: symbolic link not followed: app.db-shm "
        "(target is outside the audited directory) "
        "(a -shm holds no data; its unit is still checked)\n"
    )
    assert code == 0

    code, text_out, _ = run_cli(capsys, "verify", str(root))
    assert code == 0
    assert "shm: symlink-outside" in text_out


@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() == 0, reason="root can read unreadable files"
)
def test_unreadable_wal_does_not_make_a_live_database_look_standalone(
    tmp_path, capsys, live_wal_db
):
    """A -wal whose permissions deny reading it (root-owned dump, restore under another uid)."""
    root = tmp_path / "root"
    root.mkdir()
    shutil.copyfile(live_wal_db, root / "app.db")
    shutil.copyfile(str(live_wal_db) + "-wal", root / "app.db-wal")
    (root / "app.db-wal").chmod(0)
    try:
        warnings = []
        entries = scan(str(root), warnings)
        code, out, err = run_cli(capsys, "verify", str(root), "--json")
        text_code, text_out, _ = run_cli(capsys, "verify", str(root))
    finally:
        (root / "app.db-wal").chmod(0o600)
    # the sidecar is grouped by name, before and independently of any read
    assert [(e["main"], e["sidecars"], e["class"]) for e in entries] == [
        ("app.db", ["app.db-wal"], "wal-family")
    ]
    assert warnings == []  # scan never reads a sidecar, so nothing failed there
    (entry,) = json.loads(out)
    assert entry["class"] == "wal-family"
    assert entry["wal"] == f"unreadable: app.db-wal: {os.strerror(errno.EACCES)}"
    # the copy is the main file alone, so its row count misses the uncheckpointed rows
    assert entry["integrity"] == "ok"
    assert entry["tables"] == {"events": LIVE_ROWS_COMMITTED_BEFORE_WAL}
    assert code == 1
    assert err == (
        f"sqlite-snapshot-audit: warning: skipped app.db-wal: {os.strerror(errno.EACCES)}\n"
        "sqlite-snapshot-audit: 1 path(s) could not be audited (unreadable, or a symbolic "
        "link that was not followed); the tree was not audited in full\n"
    )
    assert text_code == 1
    assert "wal: unreadable: app.db-wal" in text_out


@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() == 0, reason="root can read unreadable files"
)
def test_unreadable_shm_does_not_fail_a_healthy_family_or_mute_the_wal_check(
    tmp_path, capsys, live_wal_db
):
    root = tmp_path / "root"
    root.mkdir()
    shutil.copyfile(live_wal_db, root / "app.db")
    shutil.copyfile(str(live_wal_db) + "-wal", root / "app.db-wal")
    (root / "app.db-shm").write_bytes(b"\x00" * 32)
    (root / "app.db-shm").chmod(0)
    try:
        code, out, err = run_cli(capsys, "verify", str(root), "--json")
    finally:
        (root / "app.db-shm").chmod(0o600)
    (entry,) = json.loads(out)
    assert entry["sidecars"] == ["app.db-shm", "app.db-wal"]
    assert entry["shm"] == f"unreadable: app.db-shm: {os.strerror(errno.EACCES)}"
    assert entry["wal"].startswith("ok (")  # the -wal was read and replayed as it stands
    assert entry["tables"] == {"events": LIVE_ROWS_COMMITTED_BEFORE_WAL + LIVE_ROWS_IN_WAL}
    assert err == (
        f"sqlite-snapshot-audit: warning: skipped app.db-shm: {os.strerror(errno.EACCES)}"
        " (a -shm holds no data; its unit is still checked)\n"
    )
    # it is not counted as an unaudited path either: there was nothing in it to audit
    assert code == 0


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
def test_dangling_shm_link_does_not_fail_its_family(tmp_path, capsys, live_wal_db):
    """Same as the outward -shm: what is missing is an index, not a row."""
    root = tmp_path / "root"
    root.mkdir()
    shutil.copyfile(live_wal_db, root / "app.db")
    shutil.copyfile(str(live_wal_db) + "-wal", root / "app.db-wal")
    (root / "app.db-shm").symlink_to(tmp_path / "gone" / "app.db-shm")
    code, out, err = run_cli(capsys, "verify", str(root), "--json")
    (entry,) = json.loads(out)
    assert entry["class"] == "wal-family"
    assert entry["shm"] == "symlink-dangling"
    assert entry["wal"].startswith("ok (")
    assert entry["tables"] == {"events": LIVE_ROWS_COMMITTED_BEFORE_WAL + LIVE_ROWS_IN_WAL}
    assert "a -shm holds no data" in err
    assert code == 0


def test_a_shm_without_its_wal_fails_instead_of_passing_on_the_main_file(
    tmp_path, capsys, live_wal_db
):
    """An interrupted copy that got the -shm but not the -wal loses every row the -wal held.

    SQLite never leaves a -shm without a -wal, so the -shm proves the -wal was there. The
    main file alone still passes integrity_check, which is exactly why it must not exit 0.
    """
    root = tmp_path / "root"
    root.mkdir()
    # cp order: main, then -shm, then the -wal that never arrives
    shutil.copyfile(live_wal_db, root / "app.db")
    shutil.copyfile(str(live_wal_db) + "-shm", root / "app.db-shm")
    code, out, err = run_cli(capsys, "verify", str(root), "--json")
    (entry,) = json.loads(out)
    assert entry["class"] == "wal-family"
    assert entry["sidecars"] == ["app.db-shm"]
    assert entry["integrity"] == "ok"
    # the late rows live only in the -wal: the copy reads clean and short
    assert entry["tables"] == {"events": LIVE_ROWS_COMMITTED_BEFORE_WAL}
    assert entry["wal"] == (
        "missing: app.db-wal is absent although its -shm is present, "
        "so the -wal was lost in the copy"
    )
    assert code == 1


@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() == 0, reason="root can read unreadable paths"
)
@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
def test_verify_does_not_exit_0_when_the_tree_was_not_audited_in_full(tmp_path, capsys):
    """Exit 0 must mean "this tree was checked", not "the part I could read was fine"."""
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    make_db(outside / "hidden.db", rows=1)
    make_db(root / "good.db", rows=3)
    locked_file = root / "locked.db"
    make_db(locked_file, rows=1)
    locked_file.chmod(0)
    locked_dir = root / "lost+found"
    locked_dir.mkdir()
    make_db(locked_dir / "hidden.db", rows=1)
    locked_dir.chmod(0)
    (root / "linked-dir").symlink_to(outside, target_is_directory=True)
    try:
        code, out, err = run_cli(capsys, "verify", str(root), "--json")
        # scan says the same on stderr but does not turn it into an exit code
        scan_code, _, scan_err = run_cli(capsys, "scan", str(root), "--json")
    finally:
        locked_file.chmod(0o600)
        locked_dir.chmod(0o700)

    assert "3 path(s) could not be audited" in scan_err
    assert scan_code == 0

    # everything that was audited is still reported, in full
    assert [(e["main"], e["integrity"], e["tables"]) for e in json.loads(out)] == [
        ("good.db", "ok", {"items": 3})
    ]
    assert err.splitlines()[-1] == (
        "sqlite-snapshot-audit: 3 path(s) could not be audited (unreadable, or a symbolic "
        "link that was not followed); the tree was not audited in full"
    )
    assert code == 1


@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() == 0, reason="root can read unreadable files"
)
def test_unreadable_main_next_to_a_sidecar_is_an_orphan(tmp_path, capsys, live_wal_db):
    root = tmp_path / "root"
    root.mkdir()
    shutil.copyfile(live_wal_db, root / "app.db")
    shutil.copyfile(str(live_wal_db) + "-wal", root / "app.db-wal")
    (root / "app.db").chmod(0)
    try:
        code, out, err = run_cli(capsys, "verify", str(root), "--json")
    finally:
        (root / "app.db").chmod(0o600)
    assert code == 1
    assert [(e["main"], e["sidecars"], e["class"], e["reason"]) for e in json.loads(out)] == [
        (
            "app.db",
            ["app.db-wal"],
            "orphan-sidecar",
            f"main file could not be read: {os.strerror(errno.EACCES)}",
        )
    ]
    assert err == (
        f"sqlite-snapshot-audit: warning: skipped app.db: {os.strerror(errno.EACCES)}\n"
        "sqlite-snapshot-audit: 1 path(s) could not be audited (unreadable, or a symbolic "
        "link that was not followed); the tree was not audited in full\n"
    )


def test_sidecar_names_are_grouped_before_any_header_is_read(tmp_path):
    """The name decides the unit; a header is never read from a -wal/-shm path."""
    make_db(tmp_path / "a.db", rows=1)
    # a full database misnamed as a sidecar is still the -wal of "a.db", not a database
    make_db(tmp_path / "a.db-wal", rows=1)
    make_db(tmp_path / "lonely.db-shm", rows=1)
    assert [(e["main"], e["sidecars"], e["class"]) for e in scan(str(tmp_path))] == [
        ("a.db", ["a.db-wal"], "wal-family"),
        ("lonely.db", ["lonely.db-shm"], "orphan-sidecar"),
    ]


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
def test_symlinked_sidecar_without_a_main_file_is_an_orphan(tmp_path, capsys):
    root = tmp_path / "root"
    root.mkdir()
    (tmp_path / "elsewhere.db-wal").write_bytes(b"\x00" * 32)
    (root / "gone.db-wal").symlink_to(tmp_path / "elsewhere.db-wal")
    code, out, _ = run_cli(capsys, "verify", str(root), "--json")
    assert code == 1
    assert [(e["main"], e["sidecars"], e["class"], e["reason"]) for e in json.loads(out)] == [
        (
            "gone.db",
            ["gone.db-wal"],
            "orphan-sidecar",
            "main file is missing; symbolic link not followed: gone.db-wal",
        )
    ]


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
def test_outward_symlink_makes_verify_exit_1_like_any_not_sqlite_entry(tmp_path, capsys):
    """It is never opened, so nothing about its target was established: not a pass."""
    root = tmp_path / "root"
    root.mkdir()
    make_db(root / "a.db", rows=1)
    make_db(tmp_path / "elsewhere.db", rows=1)
    (root / "link.db").symlink_to(tmp_path / "elsewhere.db")
    code, out, _ = run_cli(capsys, "verify", str(root), "--json")
    assert code == 1
    assert [(e["main"], e["class"], e.get("skipped")) for e in json.loads(out)] == [
        ("a.db", "standalone", None),
        ("link.db", "not-sqlite", "symlink-outside"),
    ]
    code, out, _ = run_cli(capsys, "verify", str(root))
    assert code == 1
    assert "not-sqlite      link.db" in out and "skipped: symlink-outside" in out

    (root / "notes.db").write_text("text")
    code, out, _ = run_cli(capsys, "verify", str(root), "--json")
    assert code == 1
    assert len(json.loads(out)) == 3

    (root / "link.db").unlink()
    (root / "notes.db").unlink()
    code, _, _ = run_cli(capsys, "verify", str(root), "--json")
    assert code == 0  # without the link the same tree is clean


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
def test_symlink_resolving_inside_the_tree_is_audited_like_a_regular_file(
    tmp_path, capsys, live_wal_db
):
    """Its target is part of the tree that would be restored, so it is read, not skipped."""
    root = tmp_path / "root"
    (root / "store").mkdir(parents=True)
    shutil.copyfile(live_wal_db, root / "store" / "app.db")
    shutil.copyfile(str(live_wal_db) + "-wal", root / "store" / "app.db-wal")
    # the whole unit reaches the restore point through links, as a layout of hard-linked
    # or symlinked "current" snapshots does
    (root / "current.db").symlink_to(root / "store" / "app.db")
    (root / "current.db-wal").symlink_to(root / "store" / "app.db-wal")
    (root / "text.db").write_text("not a database\n")
    (root / "text-link.db").symlink_to(root / "text.db")

    warnings = []
    entries = scan(str(root), warnings)
    assert warnings == []  # nothing was skipped, so there is nothing to warn about
    assert [(e["main"], e["sidecars"], e["class"]) for e in entries] == [
        ("current.db", ["current.db-wal"], "wal-family"),
        ("store/app.db", ["store/app.db-wal"], "wal-family"),
        ("text-link.db", [], "not-sqlite"),  # classified by header, like its target
        ("text.db", [], "not-sqlite"),
    ]
    assert not [e for e in entries if e.get("skipped")]
    assert by_main(entries)["current.db"]["reason"] == (
        "SQLite database with -wal sidecar, no -shm"
    )

    code, out, err = run_cli(capsys, "verify", str(root), "--json")
    linked = by_main(json.loads(out))["current.db"]
    assert linked["wal"].startswith("ok (")
    assert linked["integrity"] == "ok"
    # read through the links, the unit holds the rows that live only in its -wal
    assert linked["tables"] == {"events": LIVE_ROWS_COMMITTED_BEFORE_WAL + LIVE_ROWS_IN_WAL}
    assert err == ""
    assert code == 1  # only because of the two text files, which are really not databases

    (root / "text.db").unlink()
    (root / "text-link.db").unlink()
    code, out, err = run_cli(capsys, "verify", str(root), "--json")
    assert (code, err) == (0, "")  # a tree reached through links is a tree that passes


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
def test_tree_of_only_symlinks_does_not_exit_0(tmp_path, capsys):
    """Nothing in this tree was opened, so verify must not report it as restorable."""
    root = tmp_path / "root"
    root.mkdir()
    make_db(tmp_path / "real.db", rows=1)
    (root / "app.db").symlink_to(tmp_path / "real.db")
    code, out, _ = run_cli(capsys, "verify", str(root), "--json")
    assert code == 1
    assert [(e["main"], e["class"], e.get("skipped")) for e in json.loads(out)] == [
        ("app.db", "not-sqlite", "symlink-outside"),
    ]


def test_dangling_symlink_is_reported_like_any_other_link(tmp_path, capsys):
    make_db(tmp_path / "a.db", rows=1)
    (tmp_path / "dangling.db").symlink_to(tmp_path / "does-not-exist")
    code, out, _ = run_cli(capsys, "verify", str(tmp_path), "--json")
    assert code == 1  # a link that is not a sidecar was never opened, so nothing is known
    assert [(e["main"], e["class"], e.get("skipped")) for e in json.loads(out)] == [
        ("a.db", "standalone", None),
        ("dangling.db", "not-sqlite", "symlink-dangling"),
    ]
    assert by_main(json.loads(out))["dangling.db"]["reason"] == (
        "dangling symbolic link (target is missing); "
        "not followed, so no SQLite header was read"
    )


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
def test_dangling_wal_symlink_does_not_make_a_live_database_look_standalone(
    tmp_path, capsys, live_wal_db
):
    """A -wal copied as a link whose target is absent (rsync -l, tar of a link, other host)."""
    root = tmp_path / "root"
    root.mkdir()
    shutil.copyfile(live_wal_db, root / "app.db")
    (root / "app.db-wal").symlink_to(tmp_path / "gone" / "app.db-wal")
    code, out, _ = run_cli(capsys, "verify", str(root), "--json")
    (entry,) = json.loads(out)
    assert entry["class"] == "wal-family"  # not standalone: the rows in the -wal are missing
    assert entry["sidecars"] == ["app.db-wal"]
    assert entry["reason"] == (
        "SQLite database with -wal sidecar, no -shm; "
        "symbolic link not followed: app.db-wal (dangling)"
    )
    assert entry["wal"] == "symlink-dangling"
    assert entry["tables"] == {"events": LIVE_ROWS_COMMITTED_BEFORE_WAL}
    assert code == 1


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
def test_tree_of_broken_links_is_not_reported_as_having_nothing_wrong(tmp_path, capsys):
    root = tmp_path / "root"
    root.mkdir()
    (root / "app.db").symlink_to(tmp_path / "gone" / "app.db")
    (root / "app.db-wal").symlink_to(tmp_path / "gone" / "app.db-wal")
    code, out, _ = run_cli(capsys, "verify", str(root), "--json")
    assert code == 1  # a directory that would restore nothing is not a clean directory
    assert [(e["main"], e["class"], e["reason"]) for e in json.loads(out)] == [
        (
            "app.db",
            "not-sqlite",
            "dangling symbolic link (target is missing); "
            "not followed, so no SQLite header was read",
        ),
        (
            "app.db",
            "orphan-sidecar",
            "main path is a symbolic link whose target is missing; "
            "not followed, so no SQLite header was read; "
            "symbolic link not followed: app.db-wal (dangling)",
        ),
    ]


def test_special_characters_in_names_survive_copy_and_uri(tmp_path):
    make_db(tmp_path / "we?ird #name%20.db", rows=5)
    (entry,) = verify(str(tmp_path))
    assert entry["integrity"] == "ok"
    assert entry["tables"] == {"items": 5}


def test_wal_mode_database_without_sidecars(tmp_path):
    conn = sqlite3.connect(tmp_path / "closed.db")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("CREATE TABLE t (x)")
    conn.execute("INSERT INTO t VALUES (1)")
    conn.commit()
    conn.close()  # clean close checkpoints and removes -wal/-shm
    assert sorted(p.name for p in tmp_path.iterdir()) == ["closed.db"]
    (entry,) = verify(str(tmp_path))
    assert (entry["class"], entry["integrity"], entry["tables"]) == ("standalone", "ok", {"t": 1})
    assert sorted(p.name for p in tmp_path.iterdir()) == ["closed.db"]


def test_non_utf8_file_name(tmp_path, capsys):
    name = os.fsdecode(b"caf\xe9.db")
    try:
        make_db(tmp_path / name, rows=1)
    except (OSError, UnicodeEncodeError, sqlite3.Error):
        pytest.skip("file system does not accept non-UTF-8 names")
    code, out, _ = run_cli(capsys, "verify", str(tmp_path), "--json")
    assert code == 0
    (entry,) = json.loads(out)
    assert entry["main"] == name
    assert entry["tables"] == {"items": 1}

    code, out, _ = run_cli(capsys, "verify", str(tmp_path))
    assert code == 0
    assert out == (
        "standalone      caf\\xe9.db - SQLite database without -wal/-shm sidecars; "
        "integrity: ok; tables: items=1\n"
    )


@pytest.mark.parametrize("encoding", ["utf-8", "ascii"])
def test_text_output_never_crashes_on_file_names(tmp_path, encoding):
    try:
        make_db(tmp_path / os.fsdecode(b"caf\xe9.db"), rows=1)
    except (OSError, UnicodeEncodeError, sqlite3.Error):
        pytest.skip("file system does not accept non-UTF-8 names")
    make_db(tmp_path / "na\u00efve.db", rows=1)
    env = dict(os.environ, PYTHONPATH=str(SRC), PYTHONIOENCODING=encoding)
    for command in ("scan", "verify"):
        result = subprocess.run(
            [sys.executable, "-m", "sqlite_snapshot_audit", command, str(tmp_path)],
            capture_output=True,
            env=env,
        )
        assert result.returncode == 0, result.stderr
        assert result.stderr == b""
        assert b"caf\\xe9.db" in result.stdout
        expected = "na\u00efve.db" if encoding == "utf-8" else "na\\xefve.db"
        assert expected.encode(encoding) in result.stdout


def live_wal_copy(src_dir, dst_dir, name="app.db", page_size=None, rows=LIVE_ROWS_IN_WAL):
    """Copy a live WAL-mode database (main + -wal, uncheckpointed rows) into dst_dir.

    Returns (main path, -wal path) of the copy.
    """
    src_dir.mkdir(parents=True, exist_ok=True)
    dst_dir.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(src_dir / name)
    try:
        if page_size:
            conn.execute(f"PRAGMA page_size={page_size}")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA wal_autocheckpoint=0")
        conn.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, body TEXT)")
        conn.commit()
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.executemany("INSERT INTO events (body) VALUES (?)", [("late",)] * rows)
        conn.commit()
        shutil.copyfile(src_dir / name, dst_dir / name)
        shutil.copyfile(src_dir / f"{name}-wal", dst_dir / f"{name}-wal")
    finally:
        conn.close()
    return dst_dir / name, dst_dir / f"{name}-wal"


def reference_wal_checksum(data, big_endian, seed=bytes(8)):
    """walChecksumBytes from SQLite's wal.c, written independently of the code under test."""
    s1 = int.from_bytes(seed[:4], "big")
    s2 = int.from_bytes(seed[4:], "big")
    order = "big" if big_endian else "little"
    for i in range(0, len(data), 8):
        s1 = (s1 + int.from_bytes(data[i : i + 4], order) + s2) % 2**32
        s2 = (s2 + int.from_bytes(data[i + 4 : i + 8], order) + s1) % 2**32
    return s1.to_bytes(4, "big") + s2.to_bytes(4, "big")


def rewrite_wal_frame_checksums(wal, page_size=4096):
    """Recompute the whole frame checksum chain, as SQLite would have written it."""
    data = bytearray(wal.read_bytes())
    big_endian = int.from_bytes(data[0:4], "big") & 1
    running = bytes(data[24:32])  # the header checksum seeds the chain
    frame_size = 24 + page_size
    offset = 32
    while offset + frame_size <= len(data):
        payload = bytes(data[offset : offset + 8]) + bytes(data[offset + 24 : offset + frame_size])
        running = reference_wal_checksum(payload, big_endian, running)
        data[offset + 16 : offset + 24] = running
        offset += frame_size
    wal.write_bytes(bytes(data))


def rewrite_wal_header(wal, magic=None, version=None, page_size=None, salts=None):
    """Change fields of a -wal header and recompute its checksum, as SQLite would write it."""
    data = bytearray(wal.read_bytes())
    for offset, value in ((0, magic), (4, version), (8, page_size)):
        if value is not None:
            data[offset : offset + 4] = value.to_bytes(4, "big")
    if salts is not None:
        data[16:24] = salts
    big_endian = int.from_bytes(data[0:4], "big") & 1
    data[24:32] = reference_wal_checksum(bytes(data[:24]), big_endian)
    wal.write_bytes(bytes(data))


def wal_frames(wal, page_size=4096):
    return (wal.stat().st_size - 32) // (24 + page_size)


def wal_generation(wal, page_size=4096):
    """(frame number, commit or not) of the -wal frames that carry its header's salts.

    Frames past those belong to an earlier generation (the file was reused after a
    checkpoint-restart): they were checkpointed into the database long ago.
    """
    data = wal.read_bytes()
    salts, frame_size, frames = data[16:24], 24 + page_size, []
    for number in range(1, (len(data) - 32) // frame_size + 1):
        head = data[32 + (number - 1) * frame_size :][:24]
        if head[8:16] != salts:
            break
        frames.append((number, head[4:8] != bytes(4)))
    return frames


def break_wal_frame(wal, number, page_size=4096):
    """Flip one byte of a frame's page, so its checksum -- and the chain after it -- fails."""
    data = bytearray(wal.read_bytes())
    data[32 + (number - 1) * (24 + page_size) + 24 + 100] ^= 0x01
    wal.write_bytes(bytes(data))


def sqlite_replay_count(main_path, wal):
    """How many frames SQLite really replays: mxFrame of the wal-index header it rebuilds.

    Works on a throw-away copy so the tree under test keeps its files.
    """
    scratch = tempfile.mkdtemp()
    copy = Path(scratch) / "oracle.db"
    shutil.copyfile(main_path, copy)
    shutil.copyfile(wal, str(copy) + "-wal")
    conn = sqlite3.connect(f"file:{copy}?mode=ro", uri=True)
    try:
        conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
        index_header = Path(str(copy) + "-shm").read_bytes()  # deleted when the last user closes
    finally:
        conn.close()
        shutil.rmtree(scratch)
    return int.from_bytes(index_header[16:20], sys.byteorder)


def verify_wal(capsys, root):
    code, out, _ = run_cli(capsys, "verify", str(root), "--json")
    (entry,) = json.loads(out)
    return code, entry


def test_valid_wal_is_ok_with_frame_count(tmp_path, capsys):
    main_path, wal = live_wal_copy(tmp_path / "live", tmp_path / "tree")
    frames = wal_frames(wal)
    assert frames >= 1
    # the reported count is what SQLite replays, not just what the file holds
    assert sqlite_replay_count(main_path, wal) == frames
    code, entry = verify_wal(capsys, tmp_path / "tree")
    assert code == 0
    assert entry["wal"] == f"ok ({frames} frames)"
    assert entry["tables"] == {"events": LIVE_ROWS_IN_WAL}


def test_wal_frame_with_altered_page_is_invalid(tmp_path, capsys):
    """One flipped byte in a frame's page breaks the checksum chain: SQLite replays nothing."""
    main_path, wal = live_wal_copy(tmp_path / "live", tmp_path / "tree")
    data = bytearray(wal.read_bytes())
    data[32 + 24 + 100] ^= 0x01  # page data of frame 1
    wal.write_bytes(bytes(data))
    assert sqlite_replay_count(main_path, wal) == 0
    code, entry = verify_wal(capsys, tmp_path / "tree")
    assert entry["wal"] == "invalid: 0 of 1 frames will be replayed (frame 1 fails its checksum)"
    assert entry["integrity"] == "ok"  # the database alone is fine; the WAL rows are gone
    assert entry["tables"] == {"events": 0}
    assert code == 1


def test_wal_cut_short_inside_a_frame_is_invalid(tmp_path, capsys):
    """A -wal copied while it was being written ends mid-frame; SQLite drops that frame."""
    main_path, wal = live_wal_copy(tmp_path / "live", tmp_path / "tree")
    frames = wal_frames(wal)
    wal.write_bytes(wal.read_bytes()[:-10])
    assert sqlite_replay_count(main_path, wal) == 0
    code, entry = verify_wal(capsys, tmp_path / "tree")
    assert entry["wal"] == (
        f"invalid: 0 of {frames} frames will be replayed "
        f"(frame {frames} stops after {24 + 4096 - 10} of {24 + 4096} bytes)"
    )
    assert entry["tables"] == {"events": 0}
    assert code == 1


def test_wal_without_a_final_commit_frame_is_ok_up_to_the_last_commit(tmp_path, capsys):
    """Frames after the last commit frame are dropped by SQLite, so nothing committed is lost."""
    src, tree = tmp_path / "live", tmp_path / "tree"
    src.mkdir()
    tree.mkdir()
    conn = sqlite3.connect(src / "app.db")
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA wal_autocheckpoint=0")
        conn.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, body TEXT)")
        conn.commit()
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.executemany("INSERT INTO events (body) VALUES (?)", [("committed",)] * 25)
        conn.commit()
        committed_frames = wal_frames(Path(str(src / "app.db") + "-wal"))
        conn.executemany("INSERT INTO events (body) VALUES (?)", [("in flight",)] * 500)
        conn.commit()
        shutil.copyfile(src / "app.db", tree / "app.db")
        wal = tree / "app.db-wal"
        # drop the second transaction's commit frame, keeping its earlier frames intact
        shutil.copyfile(str(src / "app.db") + "-wal", wal)
        wal.write_bytes(wal.read_bytes()[: -(24 + 4096)])
    finally:
        conn.close()
    frames = wal_frames(wal)
    assert frames > committed_frames
    assert sqlite_replay_count(tree / "app.db", wal) == committed_frames
    code, entry = verify_wal(capsys, tree)
    assert entry["wal"] == (
        f"ok ({committed_frames} frames; {frames - committed_frames} further frames "
        "will be dropped, as SQLite does: they were never committed)"
    )
    assert entry["integrity"] == "ok"
    assert entry["tables"] == {"events": 25}
    assert code == 0


def test_wal_with_a_torn_tail_after_a_commit_is_ok(tmp_path, capsys):
    """A cp of a live WAL database ends mid-frame; the committed prefix still restores."""
    src, tree = tmp_path / "live", tmp_path / "tree"
    src.mkdir()
    tree.mkdir()
    conn = sqlite3.connect(src / "app.db")
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA wal_autocheckpoint=0")
        conn.execute("PRAGMA cache_size=10")  # so an open transaction spills to the -wal
        conn.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, body TEXT)")
        conn.commit()
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.executemany("INSERT INTO events (body) VALUES (?)", [("committed",)] * 25)
        conn.commit()
        committed_frames = wal_frames(Path(str(src / "app.db") + "-wal"))
        conn.execute("BEGIN")
        conn.executemany("INSERT INTO events (body) VALUES (?)", [("in flight " * 40,)] * 2000)
        shutil.copyfile(src / "app.db", tree / "app.db")
        wal = tree / "app.db-wal"
        shutil.copyfile(str(src / "app.db") + "-wal", wal)
        wal.write_bytes(wal.read_bytes()[:-1000])  # the copy caught the last frame half-written
        conn.rollback()
    finally:
        conn.close()
    frames = wal_frames(wal) + 1  # the trailing partial frame
    assert frames > committed_frames
    assert sqlite_replay_count(tree / "app.db", wal) == committed_frames
    code, entry = verify_wal(capsys, tree)
    assert entry["wal"] == (
        f"ok ({committed_frames} frames; {frames - committed_frames} further frames will be "
        f"dropped, as SQLite does: frame {frames} stops after {24 + 4096 - 1000} "
        f"of {24 + 4096} bytes)"
    )
    # SQLite reads these two files exactly the same way, so the tool must not say "do not restore"
    assert entry["integrity"] == "ok"
    assert entry["tables"] == {"events": 25}
    assert code == 0


def test_dropped_frames_after_a_broken_one_are_all_counted(tmp_path, capsys):
    """The count of dropped frames covers the whole tail, not just the frame that broke."""
    src, tree = tmp_path / "live", tmp_path / "tree"
    src.mkdir()
    tree.mkdir()
    conn = sqlite3.connect(src / "app.db")
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA wal_autocheckpoint=0")
        conn.execute("PRAGMA cache_size=10")  # so an open transaction spills to the -wal
        conn.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, body TEXT)")
        conn.commit()
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.executemany("INSERT INTO events (body) VALUES (?)", [("committed",)] * 25)
        conn.commit()
        committed_frames = wal_frames(Path(str(src / "app.db") + "-wal"))
        conn.execute("BEGIN")
        conn.executemany("INSERT INTO events (body) VALUES (?)", [("in flight " * 40,)] * 2000)
        shutil.copyfile(src / "app.db", tree / "app.db")
        wal = tree / "app.db-wal"
        shutil.copyfile(str(src / "app.db") + "-wal", wal)
        conn.rollback()
    finally:
        conn.close()
    broken = committed_frames + 2  # inside the uncommitted tail, far from its end
    frames = len(wal_generation(wal))
    assert frames > broken + 10
    break_wal_frame(wal, broken)
    assert sqlite_replay_count(tree / "app.db", wal) == committed_frames
    code, entry = verify_wal(capsys, tree)
    # every frame from the break on is discarded, so all of them are reported as dropped
    assert entry["wal"] == (
        f"ok ({committed_frames} frames; {frames - committed_frames} further frames will be "
        f"dropped, as SQLite does: frame {broken} fails its checksum)"
    )
    assert entry["integrity"] == "ok"
    assert entry["tables"] == {"events": 25}
    assert code == 0


def test_wal_that_drops_a_committed_transaction_is_invalid(tmp_path, capsys):
    """A break in the middle of committed frames loses whole transactions, not a torn tail."""
    src, tree = tmp_path / "live", tmp_path / "tree"
    src.mkdir()
    tree.mkdir()
    conn = sqlite3.connect(src / "app.db")
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA wal_autocheckpoint=0")
        conn.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, body TEXT)")
        conn.commit()
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        for _ in range(3):  # three transactions, each spanning several frames
            conn.executemany("INSERT INTO events (body) VALUES (?)", [("x" * 200,)] * 30)
            conn.commit()
        shutil.copyfile(src / "app.db", tree / "app.db")
        wal = tree / "app.db-wal"
        shutil.copyfile(str(src / "app.db") + "-wal", wal)
    finally:
        conn.close()
    generation = wal_generation(wal)
    commits = [number for number, commit in generation if commit]
    assert len(commits) == 3
    broken = commits[0] + 1  # the first frame of the second transaction
    assert broken < commits[1]
    break_wal_frame(wal, broken)
    assert sqlite_replay_count(tree / "app.db", wal) == commits[0]
    code, entry = verify_wal(capsys, tree)
    assert entry["wal"] == (
        f"invalid: {commits[0]} of {len(generation)} frames will be replayed "
        f"(frame {broken} fails its checksum; dropped frame {commits[1]} is a commit frame, "
        "so a committed transaction is lost)"
    )
    # SQLite says the database is fine and quietly restores one transaction out of three
    assert entry["integrity"] == "ok"
    assert entry["tables"] == {"events": 30}
    assert code == 1


def test_frames_of_an_earlier_wal_generation_are_not_counted_as_dropped(tmp_path, capsys):
    """After a checkpoint-restart the file keeps older frames; they hold nothing to lose."""
    src, tree = tmp_path / "live", tmp_path / "tree"
    src.mkdir()
    tree.mkdir()
    conn = sqlite3.connect(src / "app.db")
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA wal_autocheckpoint=0")
        conn.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, body TEXT)")
        conn.commit()
        conn.executemany("INSERT INTO events (body) VALUES (?)", [("x" * 200,)] * 400)
        conn.commit()
        # the restart rewinds to frame 1 with new salts and leaves the old frames in the file
        conn.execute("PRAGMA wal_checkpoint(RESTART)")
        for _ in range(2):
            conn.executemany("INSERT INTO events (body) VALUES (?)", [("y" * 200,)] * 30)
            conn.commit()
        shutil.copyfile(src / "app.db", tree / "app.db")
        wal = tree / "app.db-wal"
        shutil.copyfile(str(src / "app.db") + "-wal", wal)
    finally:
        conn.close()
    generation = wal_generation(wal)
    commits = [number for number, commit in generation if commit]
    assert len(commits) == 2
    assert wal_frames(wal) > len(generation)  # the file is longer than the current generation
    broken = commits[0] + 1
    assert broken < commits[1]
    break_wal_frame(wal, broken)
    assert sqlite_replay_count(tree / "app.db", wal) == commits[0]
    code, entry = verify_wal(capsys, tree)
    assert entry["wal"] == (
        f"invalid: {commits[0]} of {len(generation)} frames will be replayed "
        f"(frame {broken} fails its checksum; dropped frame {commits[1]} is a commit frame, "
        "so a committed transaction is lost)"
    )
    assert code == 1


def test_wal_of_random_bytes_is_invalid(tmp_path, capsys):
    _, wal = live_wal_copy(tmp_path / "live", tmp_path / "tree")
    wal.write_bytes(random.Random(1).randbytes(wal.stat().st_size))
    code, entry = verify_wal(capsys, tmp_path / "tree")
    # SQLite ignores the garbage -wal: the database alone checks out, the WAL rows are lost
    assert entry["integrity"] == "ok"
    assert entry["tables"] == {"events": 0}
    assert entry["wal"].startswith("invalid: bad magic number 0x")
    assert code == 1


def test_wal_with_other_page_size_is_invalid(tmp_path, capsys):
    (tmp_path / "tree").mkdir()
    make_db(tmp_path / "tree" / "app.db", rows=1)
    _, other_wal = live_wal_copy(tmp_path / "live", tmp_path / "other", page_size=1024)
    shutil.copyfile(other_wal, tmp_path / "tree" / "app.db-wal")
    code, entry = verify_wal(capsys, tmp_path / "tree")
    assert entry["wal"] == "invalid: page size 1024 does not match database page size 4096"
    assert code == 1


def test_wal_header_page_size_65536_matches_database_header_value_1(tmp_path, capsys):
    main_path, wal = live_wal_copy(tmp_path / "live", tmp_path / "tree", page_size=65536)
    assert main_path.read_bytes()[16:18] == b"\x00\x01"
    code, entry = verify_wal(capsys, tmp_path / "tree")
    assert entry["wal"].startswith("ok (")
    assert code == 0


def test_wal_frames_from_another_database_are_invalid(tmp_path, capsys):
    # header from the database's own -wal, frames from another database's -wal
    _, wal = live_wal_copy(tmp_path / "live", tmp_path / "tree")
    _, other_wal = live_wal_copy(tmp_path / "other-live", tmp_path / "other", rows=3)
    wal.write_bytes(wal.read_bytes()[:32] + other_wal.read_bytes()[32:])
    code, entry = verify_wal(capsys, tmp_path / "tree")
    assert entry["wal"] == "invalid: first frame salt does not match header salt"
    assert code == 1


def test_whole_wal_from_another_database_with_same_page_size_is_not_detected(tmp_path, capsys):
    # A -wal header carries nothing that ties it to one database: a complete, self-consistent
    # -wal of another database with the same page size passes every check and SQLite applies it.
    _, wal = live_wal_copy(tmp_path / "live", tmp_path / "tree")
    _, other_wal = live_wal_copy(tmp_path / "other-live", tmp_path / "other", rows=3)
    shutil.copyfile(other_wal, wal)
    code, entry = verify_wal(capsys, tmp_path / "tree")
    assert entry["wal"].startswith("ok (")
    assert entry["tables"] == {"events": 3}
    assert code == 0


@pytest.mark.parametrize(
    "change, expected",
    [
        (dict(version=3007001), "invalid: unsupported format version 3007001"),
        (dict(magic=0x377F0684), "invalid: bad magic number 0x377f0684"),
    ],
    ids=["version", "magic"],
)
def test_wal_header_fields_are_checked(tmp_path, capsys, change, expected):
    _, wal = live_wal_copy(tmp_path / "live", tmp_path / "tree")
    rewrite_wal_header(wal, **change)
    code, entry = verify_wal(capsys, tmp_path / "tree")
    assert entry["wal"] == expected
    assert code == 1


def test_wal_header_checksum_is_checked(tmp_path, capsys):
    _, wal = live_wal_copy(tmp_path / "live", tmp_path / "tree")
    data = bytearray(wal.read_bytes())
    data[12] ^= 0x01  # checkpoint sequence number, covered by the header checksum
    wal.write_bytes(bytes(data))
    code, entry = verify_wal(capsys, tmp_path / "tree")
    assert entry["wal"] == "invalid: header checksum mismatch"
    assert code == 1


def test_big_endian_wal_checksum(tmp_path):
    main_path, wal = live_wal_copy(tmp_path / "live", tmp_path / "tree")
    rewrite_wal_header(wal, magic=0x377F0683)
    rewrite_wal_frame_checksums(wal)  # the frame chain uses the magic's byte order too
    assert audit._check_wal(str(wal), str(main_path)).startswith("ok (")
    data = bytearray(wal.read_bytes())
    data[0:4] = (0x377F0682).to_bytes(4, "big")  # same checksum read as little-endian
    wal.write_bytes(bytes(data))
    assert audit._check_wal(str(wal), str(main_path)) == "invalid: header checksum mismatch"


def test_wal_frame_count_stops_at_left_over_frames(tmp_path):
    main_path, wal = live_wal_copy(tmp_path / "live", tmp_path / "tree")
    data = wal.read_bytes()
    frames = (len(data) - 32) // (24 + 4096)
    stale = bytearray(data[32 : 32 + 24 + 4096])
    stale[8:16] = bytes(8)  # salts of an earlier WAL generation
    wal.write_bytes(data + bytes(stale) + b"partial frame")
    assert audit._check_wal(str(wal), str(main_path)) == f"ok ({frames} frames)"


@pytest.mark.parametrize(
    "content, expected",
    [
        (b"", "empty"),
        (b"\x37\x7f\x06\x82", "invalid: header truncated to 4 bytes"),
        (None, "ok (0 frames)"),
    ],
    ids=["empty", "truncated", "header-only"],
)
def test_wal_without_frames(tmp_path, capsys, content, expected):
    _, wal = live_wal_copy(tmp_path / "live", tmp_path / "tree")
    wal.write_bytes(wal.read_bytes()[:32] if content is None else content)
    code, entry = verify_wal(capsys, tmp_path / "tree")
    assert entry["wal"] == expected
    assert code == (1 if expected.startswith("invalid") else 0)


def test_unreadable_wal_copy_is_not_checked(tmp_path, monkeypatch, capsys):
    live_wal_copy(tmp_path / "live", tmp_path / "tree")

    def failing_check(wal_path, db_path):
        raise OSError(errno.EIO, os.strerror(errno.EIO))

    monkeypatch.setattr(audit, "_check_wal", failing_check)
    code, out, err = run_cli(capsys, "verify", str(tmp_path / "tree"), "--json")
    assert code == 2
    assert "not checked" in err
    (entry,) = json.loads(out)
    assert entry["integrity"] == "ok"
    assert entry["wal"] == f"not-checked: [Errno {errno.EIO}] {os.strerror(errno.EIO)}"


def test_wal_result_in_text_output(tmp_path, capsys):
    live_wal_copy(tmp_path / "live", tmp_path / "tree")
    (tmp_path / "tree" / "app.db-wal").write_bytes(b"junk")
    code, out, _ = run_cli(capsys, "verify", str(tmp_path / "tree"))
    assert code == 1
    assert out.endswith("; wal: invalid: header truncated to 4 bytes\n")


def test_module_entry_point_exit_codes(tree, tmp_path):
    env = dict(os.environ, PYTHONPATH=str(SRC))
    cmd = [sys.executable, "-m", "sqlite_snapshot_audit"]
    problems = subprocess.run([*cmd, "verify", str(tree), "--json"], capture_output=True, env=env)
    assert problems.returncode == 1
    assert len(json.loads(problems.stdout)) == 8
    missing = subprocess.run([*cmd, "verify", str(tmp_path / "nope")], capture_output=True, env=env)
    assert missing.returncode == 2
    usage = subprocess.run(cmd, capture_output=True, env=env)
    assert usage.returncode == 2
