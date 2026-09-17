import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from sqlite_snapshot_audit import scan, verify
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
    # A broken cell pointer on a leaf page: integrity_check returns an error message.
    make_db(root / "bad-cell.db", rows=60)
    corrupt_page(root / "bad-cell.db", 3, 8, b"\xff\xff\xff\xff")
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
def test_unreadable_file_exits_2(tmp_path, capsys):
    locked = tmp_path / "locked.db"
    make_db(locked, rows=1)
    locked.chmod(0)
    try:
        code, out, err = run_cli(capsys, "verify", str(tmp_path), "--json")
    finally:
        locked.chmod(0o600)
    assert code == 2
    assert out == ""
    assert "Permission denied" in err


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
    assert entries["walonly.db"]["tables"] == {"items": 2}


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


def test_special_characters_in_names_survive_copy_and_uri(tmp_path):
    make_db(tmp_path / "we?ird #name%20.db", rows=5)
    (entry,) = verify(str(tmp_path))
    assert entry["integrity"] == "ok"
    assert entry["tables"] == {"items": 5}


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
