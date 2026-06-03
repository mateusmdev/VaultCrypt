"""
Shared type definitions and custom exceptions for VaultCrypt.

All domain types and exception hierarchy live here to avoid circular imports
across the other modules.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal


# ---------------------------------------------------------------------------
# Domain types
# ---------------------------------------------------------------------------

Operation = Literal["encrypt", "decrypt"]


@dataclass
class FileTask:
    """Represents a single file operation (encrypt or decrypt)."""

    source: Path
    destination: Path
    operation: Operation
    password: str


@dataclass
class TaskResult:
    """Result of a single file operation."""

    task: FileTask
    success: bool
    error: Exception | None = None

    # Convenience aliases so callers don't have to access task.*

    @property
    def source(self) -> Path:
        """Source file path."""
        return self.task.source

    @property
    def destination(self) -> Path:
        """Destination file path."""
        return self.task.destination

    @property
    def operation(self) -> Operation:
        """Operation that was performed."""
        return self.task.operation


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


class VaultError(Exception):
    """Base class for all VaultCrypt errors."""


class InvalidMagicError(VaultError):
    """File does not begin with the expected VaultCrypt magic bytes."""


class UnsupportedVersionError(VaultError):
    """File was created by an unsupported version of VaultCrypt."""


class InvalidKeyError(VaultError):
    """
    Authentication tag verification failed.

    This is raised when the provided key is incorrect or the file is
    corrupted.  The two cases are intentionally indistinguishable to
    prevent oracle attacks.
    """


class CorruptedFileError(VaultError):
    """File structure is incomplete or malformed."""


class DestinationExistsError(VaultError):
    """Destination file already exists; will not overwrite."""


class ShutdownRequestedError(VaultError):
    """Processing was interrupted by a user-requested shutdown (SIGINT)."""


class ValidationError(VaultError):
    """A CLI argument failed validation."""
