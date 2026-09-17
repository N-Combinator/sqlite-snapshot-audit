"""Read-only SQLite backup-family consistency auditor."""

from .audit import scan, verify

__all__ = ["scan", "verify"]
