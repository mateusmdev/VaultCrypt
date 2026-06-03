"""
File discovery and scanning utilities.

Provides functions to locate eligible files within a directory tree,
filtering by extension according to the requested operation.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from src.crypto.constants import ENCRYPTED_COMPOUND_SUFFIXES, PLAINTEXT_SUFFIXES


def scan_files(path: Path, operation: str, recursive: bool) -> list[Path]:
    """
    Discover all files eligible for *operation* under *path*.

    - ``encrypt``: returns ``.txt`` and ``.md`` files (excludes ``.txt.vt``
      and ``.md.vt``).
    - ``decrypt``: returns ``.txt.vt`` and ``.md.vt`` files only.

    When *path* is a single file it is returned as-is (already validated by
    the caller).  When *path* is a directory, the tree is walked shallowly
    unless *recursive* is True.

    Args:
        path:      Validated Path object (file or directory).
        operation: ``"encrypt"`` or ``"decrypt"``.
        recursive: Walk subdirectories when True.

    Returns:
        Sorted list of matching Path objects.
    """
    if path.is_file():
        return [path]

    glob = path.rglob if recursive else path.glob
    results: list[Path] = []

    if operation == "encrypt":
        for candidate in glob("*"):
            if candidate.is_file() and _is_plaintext(candidate.name):
                results.append(candidate)
    else:
        for candidate in glob("*"):
            if candidate.is_file() and _is_encrypted(candidate.name):
                results.append(candidate)

    return sorted(results)


def group_by_directory(files: list[Path]) -> dict[Path, list[Path]]:
    """
    Group file paths by their parent directory.

    Args:
        files: Flat list of file paths.

    Returns:
        Mapping of ``directory → [files in that directory]``.
    """
    grouped: dict[Path, list[Path]] = defaultdict(list)
    for f in files:
        grouped[f.parent].append(f)
    return dict(grouped)


# ---------------------------------------------------------------------------
# Extension predicates
# ---------------------------------------------------------------------------


def _is_plaintext(name: str) -> bool:
    """
    True if *name* is a plaintext file eligible for encryption.

    A filename like ``document.txt`` qualifies; ``document.txt.vt`` does not,
    even though it ends in ``.txt`` when the compound suffix is stripped.
    """
    # Reject compound encrypted suffixes first
    for enc in ENCRYPTED_COMPOUND_SUFFIXES:
        if name.endswith(enc):
            return False
    return any(name.endswith(s) for s in PLAINTEXT_SUFFIXES)


def _is_encrypted(name: str) -> bool:
    """True if *name* is a VaultCrypt-encrypted file eligible for decryption."""
    return any(name.endswith(s) for s in ENCRYPTED_COMPOUND_SUFFIXES)
