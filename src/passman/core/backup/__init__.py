"""Encrypted vault backup/restore (spec section 15)."""

from __future__ import annotations

from .archive import (
    ARCHIVE_SUFFIX,
    BackupCorruptError,
    BackupError,
    BackupWrongPassphraseError,
    backup_filename,
    create_backup,
    restore_backup,
    verify_backup,
)

__all__ = [
    "ARCHIVE_SUFFIX",
    "BackupCorruptError",
    "BackupError",
    "BackupWrongPassphraseError",
    "backup_filename",
    "create_backup",
    "restore_backup",
    "verify_backup",
]
