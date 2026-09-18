# sqlite-snapshot-audit
Read-only SQLite backup-family consistency auditor

Point it at a directory of SQLite database copies (backups, snapshots, rsync targets) **before** anyone
restores from it. It finds every SQLite database by its file header, checks that each one travelled together
with its `-wal`/`-shm` sidecars, flags orphaned sidecars and files that only look like databases, and
integrity-checks a temporary copy of each database unit.

The audited tree is never modified: `scan` reads at most the first 16 bytes of each file, and `verify` opens
SQLite only on copies in a temporary directory outside the tree (it refuses to run if `TMPDIR` points inside it).
Symbolic links are followed only as far as the tree itself: one resolving inside `<dir>` is an ordinary file
here, one leaving it or leading nowhere is reported instead of read.

Requires Python 3.10+; no runtime dependencies beyond the standard library.

## Install

From a checkout:

```sh
pip install .
```

From a GitHub Release wheel (replace the version with the release you want):

```sh
pip install https://github.com/N-Combinator/sqlite-snapshot-audit/releases/download/v0.1.0/sqlite_snapshot_audit-0.1.0-py3-none-any.whl
```

Both install the `sqlite-snapshot-audit` command (`python -m sqlite_snapshot_audit` works too).

## Usage

### `scan`

```sh
sqlite-snapshot-audit scan /backups/2026-09-17 --json
```

Walks the directory recursively and prints one entry per database unit or problem:

```json
[
  {
    "main": "app/app.db",
    "sidecars": ["app/app.db-shm", "app/app.db-wal"],
    "class": "wal-family",
    "reason": "SQLite database with -wal and -shm sidecars"
  },
  {
    "main": "old/gone.db",
    "sidecars": ["old/gone.db-wal"],
    "class": "orphan-sidecar",
    "reason": "main file is missing"
  }
]
```

- Databases are detected by the 16-byte header `SQLite format 3\0`, whatever their extension.
- Paths are relative to the scanned directory, `/`-separated. The list is sorted by `main` (then `class`) and
  contains no timestamps or hostnames, so two runs over the same tree produce byte-identical output.
- Only regular files are read: FIFOs, sockets and devices are skipped.
- **Symbolic links** are followed exactly as far as the audited tree goes:
  - a link resolving to a regular file **inside `<dir>`** is an ordinary file here: it is read, classified by
    its header, grouped into a family and verified like the file it points at — what it points at is part of
    the tree that would be restored. (A backup laid out as `store/app.db` plus a `current.db` link therefore
    audits cleanly, and a whole `current.db` + `current.db-wal` unit is verified through its links.)
  - a link whose target lies **outside `<dir>`**, or that **does not resolve**, is not followed: its target is
    not part of what would be restored, and reading it could reach anywhere on the host. It is still reported,
    with `"skipped": "symlink-outside"` or `"skipped": "symlink-dangling"` saying which, plus a
    `warning: symbolic link not followed: <path> (<why>)` line on stderr. Its `class` is `not-sqlite`, because
    no header was read to classify it — the `skipped` key, not the class, says why.
  - such a link named `<name>-wal` or `<name>-shm` is grouped with its database by name anyway (otherwise the
    database would look `standalone` and be verified without its WAL); the link is named in the entry's
    `reason`, and for a `-wal` the unit fails `verify` (`wal: symlink-outside` / `symlink-dangling` below).
    This holds for a dangling `-wal` too — a `-wal` that arrived as a link to a path that does not exist on
    this host is the case where dropping it would be most expensive, since the rows it holds are in no other
    file. A `-shm` in the same state does **not** fail the unit: see `shm` below.
  - a **symlinked directory** is not descended into (a link back up the tree would loop forever), and each one
    is reported on stderr as `warning: symlinked directory not followed: <path>`. If its target is inside
    `<dir>`, the warning says so and nothing is missing from the audit — those files are walked under their
    real path. If it leads outside, whatever it holds is not part of the audit.
- A path that cannot be read — an unreadable subdirectory such as a root-only `lost+found`, or a file whose
  permissions deny it — is skipped with a `warning: skipped <path>: <error>` line on stderr, and the rest of
  the tree is still audited. Sidecars are the exception: they are grouped with their database **by name**,
  before and independently of any read, so a `-wal` that cannot be read never drops out of its family — the
  unit stays `wal-family` and `verify` reports `wal: "unreadable: <path>: <error>"` and exits 1 instead of
  passing the database with a row count taken from the main file alone. A main file that cannot be read and
  has a sidecar is reported as `orphan-sidecar` (`main file could not be read: <error>`). Only `<dir>` itself
  being unreadable is an error (exit 2).
- Anything that was **not** audited — an unreadable file or directory, a link that was not followed, a
  symlinked directory leading out of the tree — is counted, and the count is printed last on stderr:
  `N path(s) could not be audited (unreadable, or a symbolic link that was not followed); the tree was not
  audited in full`. `verify` exits 1 when that count is not zero, because "nothing wrong was found in what I
  could read" is not the same claim as "this tree was checked". Unreadable `-shm` sidecars are the one
  exception (they hold no data; see below). Warnings and the count go to stderr, so the entries on stdout stay
  a plain list.
- Without `--json`, the same entries are printed one per line; bytes in file names that are not valid UTF-8
  are shown as `\xNN` escapes.

### `verify`

```sh
sqlite-snapshot-audit verify /backups/2026-09-17 --json
```

Runs `scan`, then for each `standalone` or `wal-family` entry:

1. copies the main file **and its sidecars together** into a fresh temporary directory,
2. opens the copy with `sqlite3.connect("file:<copy>?mode=ro", uri=True)` and runs `PRAGMA integrity_check`,
3. counts the rows of every table in the copy (so rows still sitting in an uncheckpointed `-wal` are included),
4. deletes the temporary copy.

Those entries gain two keys:

```json
{
  "main": "app/app.db",
  "sidecars": ["app/app.db-shm", "app/app.db-wal"],
  "class": "wal-family",
  "reason": "SQLite database with -wal and -shm sidecars",
  "integrity": "ok",
  "tables": {"events": 27, "users": 3}
}
```

`integrity` is `"ok"`, the first row returned by `PRAGMA integrity_check`, or the error text if SQLite could
not open or check the copy (e.g. `"database disk image is malformed"`). If the main file cannot be read
from the audited tree (e.g. it vanished after the scan), `integrity` is `"copy failed: <error>"`; if one of its
sidecars cannot be read, the main file is still checked and `wal` (or, for a `-shm`, `shm`) carries the error
(see below). If the copy
fails on the tool's side — the temporary directory is missing, full (`ENOSPC`), over quota (`EDQUOT`) or not
writable (`EACCES`) — nothing is known about the backup, so `integrity` is `"not-checked: <error>"` and
`verify` exits 2.

Entries whose unit includes a `-wal` sidecar — or a `-shm` that arrived without one — also gain a `wal` key. SQLite silently ignores `-wal` content it
cannot replay — the database then passes `integrity_check` while the transactions in the `-wal` are lost — so
`verify` reads the copied `-wal` itself, repeating the checks SQLite's recovery makes: the header, then each
frame's salt and its link in the running checksum chain, up to the last commit frame:

| `wal`                   | meaning                                                                                    |
|-------------------------|--------------------------------------------------------------------------------------------|
| `"empty"`               | the `-wal` is 0 bytes (nothing to replay)                                                  |
| `"ok (<N> frames)"`     | every frame of this WAL generation is replayed; `N` is SQLite’s `mxFrame`. Frames after them carry an older generation’s salt and are ignored by SQLite, as they are here |
| `"ok (<N> frames; <M> further frames will be dropped, as SQLite does: <reason>)"` | the `-wal` ends after its last commit frame in a tail SQLite discards on recovery — an uncommitted transaction, a frame the copy caught half-written, or a frame whose checksum does not chain. Normal for any `cp`/rsync of a live WAL database: the `N` replayed frames hold every committed transaction, so this is **not** a failure. `N` is 0 when the whole generation is one transaction that never committed (a copy taken after a checkpoint-restart, while a long write was in flight) — SQLite replays nothing there either, and nothing committed was lost |
| `"invalid: <reason>"`   | the header is unusable, so SQLite throws the whole `-wal` away — truncated, wrong magic number (`0x377f0682`/`0x377f0683`) or format version (3007000), failing checksum, a page size different from the database’s (header bytes 16–17), or a first frame whose salt differs from the header’s |
| `"invalid: 0 of <M> frames will be replayed (<reason>)"` | the header is fine, but a frame does not decode — torn or failing its checksum — and nothing at all is replayed: the `-wal` holds frames, every one of them is lost, and the break can hide a commit the main file does not have |
| `"invalid: <N> of <M> frames will be replayed (<reason>; dropped frame <K> is a commit frame, so a committed transaction is lost)"` | the dropped frames are not an uncommitted tail: frame `K` past the break commits a transaction that was written in full, so the restore silently loses it (and everything committed after it) |
| `"symlink-outside"` / `"symlink-dangling"` | the unit's `-wal` is a symbolic link leading out of the audited directory, or nowhere: it is not followed, so the unit could not be copied as it stands and what its `-wal` holds is unknown |
| `"unreadable: <path>: <error>"` | the unit's `-wal` could not be read from the audited tree (permissions, IO error): it is not copied either, so again the unit is not the one that would be restored |
| `"missing: <name>-wal is absent although its -shm is present, so the -wal was lost in the copy"` | the unit has a `-shm` and no `-wal` at all. SQLite never leaves that pair behind — a clean close deletes both, a live database has both, and `wal_checkpoint(TRUNCATE)` leaves a 0-byte `-wal` that is still there — so the `-shm` proves a `-wal` stood beside it and did not reach the backup, taking every transaction that lived only in it |

`M` counts the frames the `-wal` really holds, from the first one to the last of its generation — not just the
frames up to the break. A frame the file cuts short counts as one; frames carrying an older generation’s salts
do not count at all, as they were checkpointed into the database long ago.

An `invalid`, `symlink-outside`, `symlink-dangling`, `unreadable` or `missing` `wal` makes `verify` exit 1 even when
`integrity` is `ok`; an `ok` one never does, however many frames its tail drops — even when the tail is the
whole `-wal` — because discarding an uncommitted tail *is* SQLite’s crash recovery, and no transaction that
was ever reported committed is lost. The frame accounting is reported either way, so a caller
that wants to know how much of a `-wal` survived the copy can read it. These checks catch garbage, truncated,
damaged, half-written and mismatched `-wal` files, but not a complete, self-consistent `-wal` of a *different*
database with the same page size: nothing in the WAL format ties a `-wal` to its database, and SQLite would
replay it. Past a broken checksum the frames can only be read as bytes, not verified, so a dropped tail of
frames that none of them commits is taken at face value: a `-wal` corrupted inside a transaction that was
never committed is reported as the ordinary tail of a live copy.

A `-shm` sidecar that could not be copied — a link leading out of the tree or nowhere, or a file whose
permissions deny reading it — is reported in a separate `shm` key (`"symlink-outside"`,
`"symlink-dangling"` or `"unreadable: <path>: <error>"`) and as a warning on stderr, but it does **not**
fail the unit and does not stop the `-wal` from being checked: a `-shm` is a wal-index that SQLite rebuilds
from the `-wal`, so it holds no row that the copy could lose. Its unit is copied and checked as usual,
row counts included, and `verify` can still exit 0. A `-shm` that is *present and readable* next to a database
with no `-wal` at all is the opposite case and fails the unit — see the `missing` row above: there the `-shm`
is the evidence that a `-wal` was left behind.

A table whose rows cannot be counted (corrupt pages, unavailable virtual-table module) is reported with a count
of `null`. `orphan-sidecar` and `not-sqlite` entries (including the links that were not followed) are reported
unchanged, without `integrity`/`tables`/`wal`.

## Classes

| class            | meaning                                                                                              | `main` is                         |
|------------------|------------------------------------------------------------------------------------------------------|-----------------------------------|
| `standalone`     | SQLite database with no `-wal`/`-shm` sidecars                                                       | the database                      |
| `wal-family`     | SQLite database with its `-wal` (`-shm` optional; a lone `-shm` next to a database is also grouped here, and fails `verify` — its `-wal` is missing) | the database                      |
| `orphan-sidecar` | a `-wal` and/or `-shm` whose main file is missing or is not SQLite                                   | the expected (missing) main path  |
| `not-sqlite`     | a file named `*.db`, `*.sqlite` or `*.sqlite3` (any case) without the SQLite header, including empty files | the file                          |

These four are the only values of `class`. An entry may also carry `"skipped"`, with the value
`"symlink-outside"` or `"symlink-dangling"`: its `main` is a symbolic link that is not a sidecar of a
database and that leads out of the audited directory or nowhere, so it was not followed and its target was
neither read nor checked. Such an entry is classed `not-sqlite` because no SQLite header was read from it —
`skipped` is there so that a consumer can tell "the header says this is not a database" from "the file was
never opened". Like any other `not-sqlite` entry it makes `verify` exit 1: a tree in which nothing was opened
is not a tree that was checked. A link resolving inside the directory carries no `skipped` key at all — it was
read, and is classified by what its target holds.

A name ending in `-wal` or `-shm` makes a file a sidecar of the name in front of the suffix, whatever it
contains and whether or not it can be read — that grouping happens before any header is read. When
a non-SQLite `name.db` has a `name.db-wal`, both a `not-sqlite` and an `orphan-sidecar` entry are reported. A
file named exactly `-wal` or `-shm` has no main file name in front of the suffix and is not a sidecar.

## Exit codes

| code | `scan`                             | `verify`                                                                                  |
|------|------------------------------------|-------------------------------------------------------------------------------------------|
| 0    | tree scanned (unreadable paths and symlinked directories warned about on stderr) | the whole tree was audited, every `standalone`/`wal-family` entry has `integrity: "ok"` and a `wal` that is `empty` or `ok (…)` (including one with a dropped uncommitted tail), and there are no `orphan-sidecar`/`not-sqlite` entries |
| 1    | —                                  | any path could not be audited (unreadable file or directory, unfollowed link, symlinked directory leading out of the tree; a `-shm` does not count), any `orphan-sidecar` or `not-sqlite` entry (including one with a `"skipped"` key), any integrity other than `ok`, or any `invalid`/`symlink-outside`/`symlink-dangling`/`unreadable`/`missing` `wal` (all entries are still printed) |
| 2    | usage or IO error: `<dir>` does not exist or cannot be read | same; also when `TMPDIR` is inside `<dir>`, or when any unit (or its `wal`) is `not-checked` because its temporary copy failed (all entries are still printed; takes precedence over 1) |

## Similar tools

- **`.backup` / `VACUUM INTO`** (sqlite3 shell, online backup API): *take* a consistent single-file copy from a
  live database. sqlite-snapshot-audit does not take backups; it checks copies that already exist — including
  ones made by `cp`/rsync/filesystem snapshots that may have split a database from its `-wal`.
- **[Litestream](https://litestream.io/)**: continuously replicates a live database's WAL to object storage and
  restores from it. sqlite-snapshot-audit is a one-shot, offline check of a directory of plain files and needs
  no running process or replica format.
- **`sqlite3_rsync`**: efficiently synchronises a live database to a replica. sqlite-snapshot-audit does not copy
  or sync anything back; it audits whatever ended up in the backup directory, without ever writing to it.

## Development

```sh
pip install -e ".[dev]"
pytest -q
```

Releases: bump `version` in `pyproject.toml`, then push a matching `vX.Y.Z` tag; the release workflow runs the
tests, checks the tag against the version, and attaches the sdist and wheel to a GitHub Release.

## License

MIT
