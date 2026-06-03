"""Tests for src.transactions.manager — commit, rollback, and path helpers."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from src.transactions.manager import RollbackResult, commit, get_destination, rollback
from src.utils.types import DestinationExistsError


# ---------------------------------------------------------------------------
# get_destination
# ---------------------------------------------------------------------------


class TestGetDestination:
    def test_encrypt_txt(self, tmp_path: Path) -> None:
        src = tmp_path / "notes.txt"
        assert get_destination(src, "encrypt") == tmp_path / "notes.txt.vt"

    def test_encrypt_md(self, tmp_path: Path) -> None:
        src = tmp_path / "readme.md"
        assert get_destination(src, "encrypt") == tmp_path / "readme.md.vt"

    def test_decrypt_txt_vt(self, tmp_path: Path) -> None:
        src = tmp_path / "notes.txt.vt"
        assert get_destination(src, "decrypt") == tmp_path / "notes.txt"

    def test_decrypt_md_vt(self, tmp_path: Path) -> None:
        src = tmp_path / "readme.md.vt"
        assert get_destination(src, "decrypt") == tmp_path / "readme.md"

    def test_preserves_parent_directory(self, tmp_path: Path) -> None:
        sub = tmp_path / "sub"
        sub.mkdir()
        src = sub / "file.txt"
        dest = get_destination(src, "encrypt")
        assert dest.parent == sub


# ---------------------------------------------------------------------------
# commit
# ---------------------------------------------------------------------------


class TestCommit:
    def test_writes_buffer_to_destination(self, tmp_path: Path) -> None:
        src = tmp_path / "source.txt"
        src.write_bytes(b"original")
        dest = tmp_path / "source.txt.vt"
        payload = b"encrypted-payload"
        buf = io.BytesIO(payload)
        commit(buf, dest, src)
        assert dest.read_bytes() == payload

    def test_removes_source_on_success(self, tmp_path: Path) -> None:
        src = tmp_path / "source.txt"
        src.write_bytes(b"data")
        dest = tmp_path / "source.txt.vt"
        commit(io.BytesIO(b"enc"), dest, src)
        assert not src.exists()

    def test_destination_exists_raises(self, tmp_path: Path) -> None:
        src = tmp_path / "source.txt"
        src.write_bytes(b"data")
        dest = tmp_path / "source.txt.vt"
        dest.write_bytes(b"already here")
        with pytest.raises(DestinationExistsError):
            commit(io.BytesIO(b"enc"), dest, src)

    def test_source_preserved_when_destination_exists(self, tmp_path: Path) -> None:
        src = tmp_path / "source.txt"
        src.write_bytes(b"data")
        dest = tmp_path / "source.txt.vt"
        dest.write_bytes(b"already here")
        with pytest.raises(DestinationExistsError):
            commit(io.BytesIO(b"enc"), dest, src)
        # Source must still be intact
        assert src.exists()
        assert src.read_bytes() == b"data"

    def test_buffer_seeked_to_zero_before_read(self, tmp_path: Path) -> None:
        src = tmp_path / "source.txt"
        src.write_bytes(b"data")
        dest = tmp_path / "source.txt.vt"
        payload = b"payload"
        buf = io.BytesIO(payload)
        buf.seek(len(payload))  # Intentionally at end
        commit(buf, dest, src)
        assert dest.read_bytes() == payload


# ---------------------------------------------------------------------------
# rollback
# ---------------------------------------------------------------------------


class TestRollback:
    def test_returns_rollback_result(self, tmp_path: Path) -> None:
        dest = tmp_path / "dest.vt"
        buf = io.BytesIO(b"data")
        result = rollback(buf, dest)
        assert isinstance(result, RollbackResult)

    def test_source_is_never_touched(self, tmp_path: Path) -> None:
        src = tmp_path / "source.txt"
        src.write_bytes(b"original content")
        dest = tmp_path / "source.txt.vt"
        rollback(io.BytesIO(b"partial"), dest)
        # rollback never touches src
        assert src.exists()
        assert src.read_bytes() == b"original content"

    def test_removes_partial_destination(self, tmp_path: Path) -> None:
        dest = tmp_path / "partial.vt"
        dest.write_bytes(b"partial write")
        result = rollback(io.BytesIO(b""), dest)
        assert not dest.exists()
        assert result.dest_cleaned is True

    def test_no_destination_fully_clean(self, tmp_path: Path) -> None:
        dest = tmp_path / "nonexistent.vt"
        result = rollback(io.BytesIO(b""), dest)
        assert result.fully_clean is True
        assert result.dest_was_present is False
