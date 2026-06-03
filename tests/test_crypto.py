"""Tests for src.crypto.cipher — ChaCha20-Poly1305 streaming encrypt/decrypt."""

from __future__ import annotations

import io
import os
import threading
from pathlib import Path

import pytest

from src.crypto.cipher import decrypt_file, encrypt_file
from src.crypto.constants import CHUNK_SIZE, FILE_MAGIC, FILE_VERSION, HEADER_SIZE
from src.utils.types import (
    CorruptedFileError,
    InvalidKeyError,
    InvalidMagicError,
    ShutdownRequestedError,
    UnsupportedVersionError,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_encrypted(source: Path, password: str, dest: Path) -> None:
    """Encrypt *source* and write the result to *dest*."""
    buf = encrypt_file(source, password)
    buf.seek(0)
    dest.write_bytes(buf.read())


# ---------------------------------------------------------------------------
# Encrypt
# ---------------------------------------------------------------------------


class TestEncryptFile:
    def test_returns_bytesio(self, sample_txt: Path, password: str) -> None:
        result = encrypt_file(sample_txt, password)
        assert isinstance(result, io.BytesIO)

    def test_buffer_positioned_at_zero(self, sample_txt: Path, password: str) -> None:
        result = encrypt_file(sample_txt, password)
        assert result.tell() == 0

    def test_output_starts_with_magic(self, sample_txt: Path, password: str) -> None:
        data = encrypt_file(sample_txt, password).read()
        assert data[:len(FILE_MAGIC)] == FILE_MAGIC

    def test_output_contains_version_byte(self, sample_txt: Path, password: str) -> None:
        data = encrypt_file(sample_txt, password).read()
        version_offset = len(FILE_MAGIC)
        assert data[version_offset : version_offset + 1] == FILE_VERSION

    def test_output_larger_than_input(self, sample_txt: Path, password: str) -> None:
        """Encrypted file is larger than the original (header + tag overhead)."""
        original_size = sample_txt.stat().st_size
        encrypted_size = len(encrypt_file(sample_txt, password).read())
        assert encrypted_size > original_size

    def test_two_encryptions_differ(self, sample_txt: Path, password: str) -> None:
        """Each encryption uses a fresh salt and nonces — output is never identical."""
        buf_a = encrypt_file(sample_txt, password).read()
        buf_b = encrypt_file(sample_txt, password).read()
        assert buf_a != buf_b

    def test_progress_callback_called(self, sample_txt: Path, password: str) -> None:
        received: list[int] = []
        encrypt_file(sample_txt, password, progress=received.append)
        assert sum(received) == sample_txt.stat().st_size

    def test_empty_file(self, tmp_path: Path, password: str) -> None:
        """Empty source file must produce a valid (header-only) .vt buffer."""
        empty = tmp_path / "empty.txt"
        empty.write_bytes(b"")
        buf = encrypt_file(empty, password)
        data = buf.read()
        # At minimum: MAGIC + VERSION + SALT
        assert len(data) >= HEADER_SIZE
        assert data[:len(FILE_MAGIC)] == FILE_MAGIC

    def test_large_file_multiple_chunks(self, large_file: Path, password: str) -> None:
        """A file larger than CHUNK_SIZE must be split across multiple chunks."""
        assert large_file.stat().st_size > CHUNK_SIZE
        buf = encrypt_file(large_file, password)
        assert buf.read(len(FILE_MAGIC)) == FILE_MAGIC  # sanity: valid header

    def test_shutdown_event_raises(self, sample_txt: Path, password: str) -> None:
        """Setting the shutdown event before calling must raise immediately."""
        ev = threading.Event()
        ev.set()
        with pytest.raises(ShutdownRequestedError):
            encrypt_file(sample_txt, password, shutdown=ev)


# ---------------------------------------------------------------------------
# Decrypt
# ---------------------------------------------------------------------------


class TestDecryptFile:
    def test_roundtrip_txt(self, sample_txt: Path, password: str, tmp_path: Path) -> None:
        """Encrypt → decrypt must reproduce the original bytes exactly."""
        original = sample_txt.read_bytes()
        vt = tmp_path / "sample.txt.vt"
        _write_encrypted(sample_txt, password, vt)
        recovered = decrypt_file(vt, password).read()
        assert recovered == original

    def test_roundtrip_md(self, sample_md: Path, password: str, tmp_path: Path) -> None:
        original = sample_md.read_bytes()
        vt = tmp_path / "sample.md.vt"
        _write_encrypted(sample_md, password, vt)
        assert decrypt_file(vt, password).read() == original

    def test_roundtrip_large_file(
        self, large_file: Path, password: str, tmp_path: Path
    ) -> None:
        original = large_file.read_bytes()
        vt = tmp_path / "large.txt.vt"
        _write_encrypted(large_file, password, vt)
        assert decrypt_file(vt, password).read() == original

    def test_roundtrip_empty_file(
        self, tmp_path: Path, password: str
    ) -> None:
        empty = tmp_path / "empty.txt"
        empty.write_bytes(b"")
        vt = tmp_path / "empty.txt.vt"
        _write_encrypted(empty, password, vt)
        assert decrypt_file(vt, password).read() == b""

    def test_wrong_key_raises_invalid_key_error(
        self, sample_txt: Path, password: str, wrong_password: str, tmp_path: Path
    ) -> None:
        vt = tmp_path / "sample.txt.vt"
        _write_encrypted(sample_txt, password, vt)
        with pytest.raises(InvalidKeyError):
            decrypt_file(vt, wrong_password)

    def test_invalid_magic_raises(self, tmp_path: Path, password: str) -> None:
        bad = tmp_path / "bad.txt.vt"
        bad.write_bytes(b"JUNK" + b"\x00" * 50)
        with pytest.raises(InvalidMagicError):
            decrypt_file(bad, password)

    def test_unsupported_version_raises(self, tmp_path: Path, password: str) -> None:
        bad = tmp_path / "bad.txt.vt"
        # Correct magic but wrong version byte
        bad.write_bytes(FILE_MAGIC + b"\xff" + b"\x00" * 32)
        with pytest.raises(UnsupportedVersionError):
            decrypt_file(bad, password)

    def test_truncated_header_raises(self, tmp_path: Path, password: str) -> None:
        bad = tmp_path / "truncated.txt.vt"
        bad.write_bytes(FILE_MAGIC + FILE_VERSION + b"\x00" * 10)  # salt too short
        with pytest.raises(CorruptedFileError):
            decrypt_file(bad, password)

    def test_corrupted_chunk_raises(
        self, sample_txt: Path, password: str, tmp_path: Path
    ) -> None:
        vt = tmp_path / "sample.txt.vt"
        _write_encrypted(sample_txt, password, vt)
        data = bytearray(vt.read_bytes())
        # Flip a byte in the ciphertext area (after the header)
        if len(data) > HEADER_SIZE + 20:
            data[HEADER_SIZE + 20] ^= 0xFF
        vt.write_bytes(bytes(data))
        with pytest.raises((InvalidKeyError, CorruptedFileError)):
            decrypt_file(vt, password)

    def test_shutdown_event_raises(
        self, sample_txt: Path, password: str, tmp_path: Path
    ) -> None:
        vt = tmp_path / "sample.txt.vt"
        _write_encrypted(sample_txt, password, vt)
        ev = threading.Event()
        ev.set()
        with pytest.raises(ShutdownRequestedError):
            decrypt_file(vt, password, shutdown=ev)

    def test_progress_callback_called(
        self, sample_txt: Path, password: str, tmp_path: Path
    ) -> None:
        vt = tmp_path / "sample.txt.vt"
        _write_encrypted(sample_txt, password, vt)
        received: list[int] = []
        decrypt_file(vt, password, progress=received.append)
        assert sum(received) > 0
