"""
Transactional file operations: commit and rollback.

Security design
---------------
All processing happens in an in-memory ``io.BytesIO`` buffer.  The source
file is **never** modified during processing.  Only two moments touch the
filesystem:

  commit  — write buffer → destination, then unlink source.
  rollback — discard buffer (memory only); remove any partial destination.

This approach minimises the forensic footprint:

  * No intermediate files are written to disk during encryption or decryption.
  * Sensitive plaintext never exists as a temporary disk file.
  * If a crash occurs during commit, the source file remains intact and any
    partial destination is cleaned up on the next run (or reported to the
    user via the rollback result).
"""

from __future__ import annotations

import io
from dataclasses import dataclass
from pathlib import Path

from src.utils.types import DestinationExistsError


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------


def get_destination(source: Path, operation: str) -> Path:
    """
    Derive the destination path for *source* given *operation*.

    Encrypt:  ``file.txt``    → ``file.txt.vt``
              ``file.md``     → ``file.md.vt``
    Decrypt:  ``file.txt.vt`` → ``file.txt``
              ``file.md.vt``  → ``file.md``

    Args:
        source:    Validated source file path.
        operation: ``"encrypt"`` or ``"decrypt"``.

    Returns:
        Computed destination Path (not yet created).
    """
    if operation == "encrypt":
        # Append '.vt' to the full filename string
        return source.parent / (source.name + ".vt")

    # Decrypt: Path('file.txt.vt').stem == 'file.txt'  (strips last suffix)
    return source.parent / source.stem


# ---------------------------------------------------------------------------
# Commit
# ---------------------------------------------------------------------------


def commit(buf: io.BytesIO, destination: Path, source: Path) -> None:
    """
    Atomically finalise a successful operation.

    Steps:
      1. Verify *destination* does not already exist.
      2. Write the buffer contents to *destination*.
      3. Unlink *source*.

    If the write fails partway through, the partial destination file is
    removed and the original exception is re-raised.  The source file is
    never deleted unless the write succeeds.

    Args:
        buf:         In-memory buffer containing the processed result (will
                     be seeked to 0 before reading).
        destination: Target path to create.
        source:      Original file to remove after a successful write.

    Raises:
        DestinationExistsError: *destination* already exists.
        OSError:                Write or unlink failure.
    """
    if destination.exists():
        raise DestinationExistsError(
            f"Destination already exists: '{destination.name}'. "
            "Remove or rename it manually before proceeding."
        )

    try:
        buf.seek(0)
        destination.write_bytes(buf.read())
        source.unlink()
    except Exception:
        _safe_unlink(destination)
        raise


# ---------------------------------------------------------------------------
# Rollback
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RollbackResult:
    """Outcome of a rollback attempt."""

    buffer_closed: bool
    dest_was_present: bool
    dest_cleaned: bool

    @property
    def fully_clean(self) -> bool:
        """True when no leftover artefacts remain."""
        return self.buffer_closed and (
            not self.dest_was_present or self.dest_cleaned
        )


def rollback(buf: io.BytesIO, destination: Path) -> RollbackResult:
    """
    Roll back a failed operation.

    * Closes and discards the in-memory buffer (no disk write).
    * Removes *destination* if it was partially written.
    * The source file is **always** left intact; this function never touches it.

    Args:
        buf:         Buffer to discard.
        destination: Potential partial output file to clean up.

    Returns:
        RollbackResult describing what was cleaned up.
    """
    buf_ok = True
    dest_present = destination.exists()
    dest_ok = True

    try:
        buf.close()
    except Exception:
        buf_ok = False

    if dest_present:
        dest_ok = _safe_unlink(destination)

    return RollbackResult(
        buffer_closed=buf_ok,
        dest_was_present=dest_present,
        dest_cleaned=dest_ok,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _safe_unlink(path: Path) -> bool:
    """Attempt to delete *path*, returning True on success."""
    try:
        if path.exists():
            path.unlink()
        return True
    except OSError:
        return False
