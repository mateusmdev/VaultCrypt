"""
Shared pytest fixtures and configuration for VaultCrypt tests.

Fast-KDF fixture
----------------
Argon2id with production parameters (~64 MiB memory, 3 iterations) would
make each test that involves encryption/decryption take ~0.5–1 s.  For the
test suite we patch the module-level constants inside kdf.py so the KDF uses
minimal resources while preserving identical code paths.

The fixture is applied automatically (autouse=True) to all tests in this
package; individual tests that verify KDF properties explicitly un-apply it
or use their own parameters.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Fast KDF (autouse for all tests)
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def fast_argon2(monkeypatch: pytest.MonkeyPatch) -> None:
    """Patch Argon2id parameters to be fast for testing."""
    monkeypatch.setattr("src.crypto.kdf.ARGON2_TIME_COST", 1)
    monkeypatch.setattr("src.crypto.kdf.ARGON2_MEMORY_COST", 8192)   # 8 MiB
    monkeypatch.setattr("src.crypto.kdf.ARGON2_PARALLELISM", 1)


# ---------------------------------------------------------------------------
# Common test data
# ---------------------------------------------------------------------------


@pytest.fixture
def password() -> str:
    """Default valid password for tests."""
    return "test-passphrase-42!"


@pytest.fixture
def wrong_password() -> str:
    """An intentionally incorrect password for negative tests."""
    return "completely-wrong-key"


@pytest.fixture
def sample_txt(tmp_path: Path) -> Path:
    """A small .txt file with known content."""
    f = tmp_path / "sample.txt"
    f.write_text(
        "Hello, VaultCrypt!\nThis is a test file with some content.\n",
        encoding="utf-8",
    )
    return f


@pytest.fixture
def sample_md(tmp_path: Path) -> Path:
    """A small .md file with known content."""
    f = tmp_path / "sample.md"
    f.write_text(
        "# Test Document\n\nThis is **markdown** content.\n",
        encoding="utf-8",
    )
    return f


@pytest.fixture
def large_file(tmp_path: Path) -> Path:
    """
    A file large enough to produce multiple 64 KiB chunks (~320 KiB).

    Uses deterministic random bytes so tests are reproducible.
    """
    rng = os.urandom  # CSRNG is fine; not seeded for reproducibility in size tests
    f = tmp_path / "large.txt"
    f.write_bytes(rng(5 * 64 * 1024))  # 5 chunks × 64 KiB = 320 KiB
    return f
