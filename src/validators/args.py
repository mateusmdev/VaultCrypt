"""
CLI argument validation.

All validation raises ValidationError with a clear, human-readable message
so the caller can display it and exit without a traceback.
"""

from __future__ import annotations

from pathlib import Path

from src.crypto.constants import (
    ALL_VALID_SUFFIXES,
    ENCRYPTED_COMPOUND_SUFFIXES,
    KEY_MAX_LENGTH,
    KEY_MIN_LENGTH,
)
from src.utils.types import ValidationError


# ---------------------------------------------------------------------------
# Key validation
# ---------------------------------------------------------------------------


def validate_key(key: str) -> None:
    """
    Validate the user-supplied encryption/decryption key.

    Rules:
      - Must not be empty or consist entirely of whitespace.
      - Length must be within [KEY_MIN_LENGTH, KEY_MAX_LENGTH].
      - Any character is accepted (Unicode, punctuation, spaces within
        the length bounds).

    Args:
        key: Raw string from the ``--key`` argument.

    Raises:
        ValidationError: If any rule is violated.
    """
    if not key or not key.strip():
        raise ValidationError(
            "Key must not be empty or consist entirely of whitespace characters."
        )

    length = len(key)

    if length < KEY_MIN_LENGTH:
        raise ValidationError(
            f"Key is too short: minimum is {KEY_MIN_LENGTH} character(s), "
            f"got {length}."
        )

    if length > KEY_MAX_LENGTH:
        raise ValidationError(
            f"Key is too long: maximum is {KEY_MAX_LENGTH} characters, "
            f"got {length}. Please use a shorter key."
        )


# ---------------------------------------------------------------------------
# Workers validation
# ---------------------------------------------------------------------------


def validate_workers(workers: int) -> None:
    """
    Validate the requested worker count.

    Args:
        workers: Value from the ``--workers`` argument.

    Raises:
        ValidationError: If *workers* is not a positive integer.
    """
    if workers < 1:
        raise ValidationError(
            f"--workers must be a positive integer (≥ 1). Got: {workers}."
        )


# ---------------------------------------------------------------------------
# Path validation
# ---------------------------------------------------------------------------


def validate_path(path_str: str, operation: str) -> Path:
    """
    Validate the target path and its compatibility with *operation*.

    - The path must exist.
    - It must be a regular file or a directory.
    - If it is a file, its extension must be valid for *operation*.

    Args:
        path_str:  Raw string from the ``--path`` argument.
        operation: ``"encrypt"`` or ``"decrypt"``.

    Returns:
        Resolved Path object.

    Raises:
        ValidationError: On any validation failure.
    """
    path = Path(path_str)

    if not path.exists():
        raise ValidationError(f"Path does not exist: '{path_str}'.")

    if path.is_file():
        _validate_file_for_operation(path, operation)
    elif not path.is_dir():
        raise ValidationError(
            f"Path is neither a regular file nor a directory: '{path_str}'."
        )

    return path


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _is_encrypted_file(name: str) -> bool:
    """Return True if *name* ends with a VaultCrypt compound suffix."""
    return any(name.endswith(s) for s in ENCRYPTED_COMPOUND_SUFFIXES)


def _validate_file_for_operation(path: Path, operation: str) -> None:
    """
    Ensure a single-file target is compatible with *operation*.

    Raises:
        ValidationError: Extension mismatch or unsupported extension.
    """
    name = path.name

    if not any(name.endswith(s) for s in ALL_VALID_SUFFIXES):
        raise ValidationError(
            f"Unsupported file type: '{name}'. "
            f"Accepted: {', '.join(ALL_VALID_SUFFIXES)}."
        )

    if operation == "encrypt" and _is_encrypted_file(name):
        raise ValidationError(
            f"File is already encrypted: '{name}'. "
            "Cannot encrypt a file that is already encrypted."
        )

    if operation == "decrypt" and not _is_encrypted_file(name):
        raise ValidationError(
            f"File is not encrypted: '{name}'. "
            "Cannot decrypt a file that was not encrypted by VaultCrypt."
        )
