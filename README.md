# sqlite-snapshot-audit
Read-only SQLite backup-family consistency auditor

Point it at a directory of SQLite database copies (backups, snapshots, rsync targets) **before** anyone
restores from it. It finds every SQLite database by its file header, checks that each one travelled together
with its `-wal`/`-shm` sidecars, flags orphaned sidecars and files that only look like databases, and
integrity-checks a temporary copy of each database unit.

The audited tree is never modified: `scan` reads at most the first 16 bytes of each file, and `verify` opens
SQLite only on copies in a temporary directory outside the tree (it refuses to run if `TMPDIR` points inside it).

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
- Only regular files are read: FIFOs, sockets and devices are skipped, symlinked directories are not
  followed, and dangling symlinks are ignored. Symlinks to files are never followed (their target may lie
  outside the directory): each one is reported as a `skipped-symlink` entry and is neither checked nor grouped
  as a sidecar. A symlink is not a problem with the backup itself, so it does not make `verify` exit 1.
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
not open or check the copy (e.g. `"database disk image is malformed"`). If a file of the unit cannot be read
from the audited tree (e.g. it vanished after the scan), `integrity` is `"copy failed: <error>"`. If the copy
fails on the tool's side — the temporary directory is missing, full (`ENOSPC`), over quota (`EDQUOT`) or not
writable (`EACCES`) — nothing is known about the backup, so `integrity` is `"not-checked: <error>"` and
`verify` exits 2.

Entries whose unit includes a `-wal` sidecar also gain a `wal` key. SQLite silently ignores `-wal` content it
cannot replay — the database then passes `integrity_check` while the transactions in the `-wal` are lost — so
`verify` reads the copied `-wal` itself, repeating the checks SQLite's recovery makes: the header, then each
frame's salt and its link in the running checksum chain, up to the last commit frame:

| `wal`                   | meaning                                                                                    |
|-------------------------|--------------------------------------------------------------------------------------------|
| `"empty"`               | the `-wal` is 0 bytes (nothing to replay)                                                  |
| `"ok (<N> frames)"`     | `N` is the number of frames SQLite would replay (up to the last commit frame); frames after them carry an older WAL generation's salt and are ignored by SQLite, as they are here |
| `"invalid: <reason>"`   | the header is unusable — truncated, wrong magic number (`0x377f0682`/`0x377f0683`) or format version (3007000), failing checksum, a page size different from the database's (header bytes 16–17), or a first frame whose salt differs from the header's |
| `"invalid: <N> of <M> frames will be replayed (<reason>)"` | the header is fine but frames of this WAL generation would be dropped: a frame fails its checksum (altered or torn page), the file stops in the middle of a frame, or the last transaction has no commit frame |

An `invalid` `wal` makes `verify` exit 1 even when `integrity` is `ok`. These checks catch garbage, truncated,
damaged, half-written and mismatched `-wal` files, but not a complete, self-consistent `-wal` of a *different*
database with the same page size: nothing in the WAL format ties a `-wal` to its database, and SQLite would
replay it.

A table whose rows cannot be counted (corrupt pages, unavailable virtual-table module) is reported with a count
of `null`. `orphan-sidecar`, `not-sqlite` and `skipped-symlink` entries are reported unchanged, without
`integrity`/`tables`/`wal`.

## Classes

| class            | meaning                                                                                              | `main` is                         |
|------------------|------------------------------------------------------------------------------------------------------|-----------------------------------|
| `standalone`     | SQLite database with no `-wal`/`-shm` sidecars                                                       | the database                      |
| `wal-family`     | SQLite database with its `-wal` (`-shm` optional; a lone `-shm` next to a database is also grouped here) | the database                      |
| `orphan-sidecar` | a `-wal` and/or `-shm` whose main file is missing or is not SQLite                                   | the expected (missing) main path  |
| `not-sqlite`     | a file named `*.db`, `*.sqlite` or `*.sqlite3` (any case) without the SQLite header, including empty files | the file                          |
| `skipped-symlink` | a symbolic link to a file (any name); not followed, so its target is neither read nor checked       | the link                          |

A file with the SQLite header is always treated as a database, even if its name ends in `-wal` or `-shm`. When
a non-SQLite `name.db` has a `name.db-wal`, both a `not-sqlite` and an `orphan-sidecar` entry are reported.

## Exit codes

| code | `scan`                             | `verify`                                                                                  |
|------|------------------------------------|-------------------------------------------------------------------------------------------|
| 0    | tree scanned                       | every `standalone`/`wal-family` entry has `integrity: "ok"` and no `invalid` `wal`, and there are no `orphan-sidecar`/`not-sqlite` entries (`skipped-symlink` entries are printed but do not affect the exit code) |
| 1    | —                                  | any `orphan-sidecar` or `not-sqlite` entry, any integrity other than `ok`, or any `invalid` `wal` (all entries are still printed) |
| 2    | usage or IO error (e.g. `<dir>` does not exist, unreadable file) | same; also when `TMPDIR` is inside `<dir>`, or when any unit (or its `wal`) is `not-checked` because its temporary copy failed (all entries are still printed; takes precedence over 1) |

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
