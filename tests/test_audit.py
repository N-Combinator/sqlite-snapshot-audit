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
    assert code == 0
    assert [e["main"] for e in json.loads(out)] == ["a.db"]
    assert err == (
        "sqlite-snapshot-audit: warning: skipped locked.db: "
        f"{os.strerror(errno.EACCES)}\n"
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
    assert code == 0
    assert [e["main"] for e in json.loads(out)] == ["a.db", "sub/b.db"]
    assert err == (
        "sqlite-snapshot-audit: warning: skipped lost+found: "
        f"{os.strerror(errno.EACCES)}\n"
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
    assert "wal" not in entries["real.db"]
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
    assert [e["main"] for e in scan(str(root))] == ["real.db"]


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
        ("link.db", "skipped-symlink"),
        # the symlinked -wal is grouped by name, so the database is not called standalone
        ("real.db", "wal-family"),
        ("sub/inside.sqlite", "skipped-symlink"),
        ("sub/notes.txt", "skipped-symlink"),
    ]
    entries = scan(str(root))
    assert [(e["main"], e["class"]) for e in entries] == expected
    for entry in entries:
        if entry["class"] == "skipped-symlink":
            assert entry["sidecars"] == []
            assert entry["reason"] == "symbolic link to a file; not followed"
    assert by_main(entries)["real.db"]["sidecars"] == ["real.db-wal"]
    assert by_main(entries)["real.db"]["reason"] == (
        "SQLite database with -wal sidecar, no -shm; symbolic link not followed: real.db-wal"
    )

    code, out, _ = run_cli(capsys, "verify", str(root), "--json")
    assert code == 1  # the -wal that would be replayed was not checked
    entries = json.loads(out)
    assert [(e["main"], e["class"]) for e in entries] == expected
    assert [e["main"] for e in entries if "integrity" in e] == ["real.db"]
    assert by_main(entries)["real.db"]["wal"] == "symlink-skipped"
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
    assert entry["wal"] == "symlink-skipped"
    # without its -wal the copy misses the uncheckpointed rows, and that must not pass
    assert entry["integrity"] == "ok"
    assert entry["tables"] == {"events": LIVE_ROWS_COMMITTED_BEFORE_WAL}
    assert code == 1

    code, out, _ = run_cli(capsys, "verify", str(root))
    assert code == 1
    assert "wal: symlink-skipped" in out


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
def test_symlinked_shm_next_to_a_real_wal_is_also_reported(tmp_path, capsys, live_wal_db):
    root = tmp_path / "root"
    root.mkdir()
    shutil.copyfile(live_wal_db, root / "app.db")
    shutil.copyfile(str(live_wal_db) + "-wal", root / "app.db-wal")
    (root / "app.db-shm").symlink_to(str(live_wal_db) + "-shm")
    code, out, _ = run_cli(capsys, "verify", str(root), "--json")
    (entry,) = json.loads(out)
    assert entry["sidecars"] == ["app.db-shm", "app.db-wal"]
    assert entry["wal"] == "symlink-skipped"  # the unit could not be copied as it stands
    assert code == 1


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
def test_skipped_symlink_does_not_change_verify_exit_code(tmp_path, capsys):
    make_db(tmp_path / "a.db", rows=1)
    (tmp_path / "link.db").symlink_to(tmp_path / "a.db")
    code, out, _ = run_cli(capsys, "verify", str(tmp_path), "--json")
    assert code == 0
    assert [(e["main"], e["class"]) for e in json.loads(out)] == [
        ("a.db", "standalone"),
        ("link.db", "skipped-symlink"),
    ]
    code, out, _ = run_cli(capsys, "verify", str(tmp_path))
    assert code == 0
    assert "skipped-symlink link.db" in out

    (tmp_path / "notes.db").write_text("text")
    code, out, _ = run_cli(capsys, "verify", str(tmp_path), "--json")
    assert code == 1
    assert len(json.loads(out)) == 3


def test_dangling_symlink_is_ignored(tmp_path, capsys):
    make_db(tmp_path / "a.db", rows=1)
    (tmp_path / "dangling.db").symlink_to(tmp_path / "does-not-exist")
    code, out, _ = run_cli(capsys, "verify", str(tmp_path), "--json")
    assert code == 0
    assert [e["main"] for e in json.loads(out)] == ["a.db"]


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


def test_wal_without_a_final_commit_frame_is_invalid(tmp_path, capsys):
    """Frames after the last commit frame are complete and checksummed, but never replayed."""
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
        f"invalid: {committed_frames} of {frames} frames will be replayed "
        "(the last transaction has no commit frame)"
    )
    assert entry["tables"] == {"events": 25}
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
