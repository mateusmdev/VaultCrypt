"""Tests for src.pipeline.tasks — execute_task() with commit/rollback."""

from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest

from src.pipeline.tasks import execute_task
from src.transactions.manager import get_destination
from src.utils.types import (
    DestinationExistsError,
    FileTask,
    InvalidKeyError,
    ShutdownRequestedError,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_task(
    source: Path,
    operation: str,
    password: str,
) -> FileTask:
    return FileTask(
        source=source,
        destination=get_destination(source, operation),
        operation=operation,  # type: ignore[arg-type]
        password=password,
    )


def _no_shutdown() -> threading.Event:
    return threading.Event()  # not set


# ---------------------------------------------------------------------------
# Encrypt tasks
# ---------------------------------------------------------------------------


class TestExecuteTaskEncrypt:
    def test_success_produces_destination(
        self, sample_txt: Path, password: str
    ) -> None:
        task = _make_task(sample_txt, "encrypt", password)
        result = execute_task(task, shutdown=_no_shutdown(), on_progress=lambda _: None)
        assert result.success is True
        assert task.destination.exists()

    def test_success_removes_source(self, sample_txt: Path, password: str) -> None:
        task = _make_task(sample_txt, "encrypt", password)
        execute_task(task, shutdown=_no_shutdown(), on_progress=lambda _: None)
        assert not sample_txt.exists()

    def test_destination_has_vt_extension(
        self, sample_txt: Path, password: str
    ) -> None:
        task = _make_task(sample_txt, "encrypt", password)
        execute_task(task, shutdown=_no_shutdown(), on_progress=lambda _: None)
        assert task.destination.name.endswith(".vt")

    def test_destination_exists_returns_failure(
        self, sample_txt: Path, password: str, tmp_path: Path
    ) -> None:
        task = _make_task(sample_txt, "encrypt", password)
        task.destination.write_bytes(b"already here")
        result = execute_task(task, shutdown=_no_shutdown(), on_progress=lambda _: None)
        assert result.success is False
        assert isinstance(result.error, DestinationExistsError)

    def test_source_preserved_on_destination_conflict(
        self, sample_txt: Path, password: str
    ) -> None:
        original_content = sample_txt.read_bytes()
        task = _make_task(sample_txt, "encrypt", password)
        task.destination.write_bytes(b"conflict")
        execute_task(task, shutdown=_no_shutdown(), on_progress=lambda _: None)
        assert sample_txt.exists()
        assert sample_txt.read_bytes() == original_content

    def test_progress_callback_called(self, sample_txt: Path, password: str) -> None:
        original_size = sample_txt.stat().st_size  # capture before source is deleted
        received: list[int] = []
        task = _make_task(sample_txt, "encrypt", password)
        execute_task(task, shutdown=_no_shutdown(), on_progress=received.append)
        assert len(received) >= 1
        assert sum(received) == original_size

    def test_shutdown_returns_failure_and_preserves_source(
        self, sample_txt: Path, password: str
    ) -> None:
        ev = threading.Event()
        ev.set()
        original = sample_txt.read_bytes()
        task = _make_task(sample_txt, "encrypt", password)
        result = execute_task(task, shutdown=ev, on_progress=lambda _: None)
        assert result.success is False
        assert isinstance(result.error, ShutdownRequestedError)
        assert sample_txt.exists()
        assert sample_txt.read_bytes() == original


# ---------------------------------------------------------------------------
# Decrypt tasks
# ---------------------------------------------------------------------------


class TestExecuteTaskDecrypt:
    def _encrypt_first(
        self, source: Path, password: str
    ) -> Path:
        """Encrypt *source* and return the .vt path."""
        encrypt_task = _make_task(source, "encrypt", password)
        result = execute_task(
            encrypt_task, shutdown=_no_shutdown(), on_progress=lambda _: None
        )
        assert result.success
        return encrypt_task.destination

    def test_decrypt_roundtrip(
        self, sample_txt: Path, password: str, tmp_path: Path
    ) -> None:
        original = sample_txt.read_bytes()
        vt = self._encrypt_first(sample_txt, password)
        task = _make_task(vt, "decrypt", password)
        result = execute_task(task, shutdown=_no_shutdown(), on_progress=lambda _: None)
        assert result.success is True
        assert task.destination.read_bytes() == original

    def test_decrypt_removes_vt_source(
        self, sample_txt: Path, password: str
    ) -> None:
        vt = self._encrypt_first(sample_txt, password)
        task = _make_task(vt, "decrypt", password)
        execute_task(task, shutdown=_no_shutdown(), on_progress=lambda _: None)
        assert not vt.exists()

    def test_wrong_key_returns_failure_and_preserves_vt(
        self, sample_txt: Path, password: str, wrong_password: str
    ) -> None:
        vt = self._encrypt_first(sample_txt, password)
        vt_content = vt.read_bytes()
        task = _make_task(vt, "decrypt", wrong_password)
        result = execute_task(task, shutdown=_no_shutdown(), on_progress=lambda _: None)
        assert result.success is False
        assert isinstance(result.error, InvalidKeyError)
        # Source (.vt file) must be intact
        assert vt.exists()
        assert vt.read_bytes() == vt_content

    def test_corrupted_file_returns_failure_and_preserves_source(
        self, sample_txt: Path, password: str
    ) -> None:
        vt = self._encrypt_first(sample_txt, password)
        data = bytearray(vt.read_bytes())
        data[-10] ^= 0xFF  # Corrupt last chunk
        vt.write_bytes(bytes(data))
        task = _make_task(vt, "decrypt", password)
        result = execute_task(task, shutdown=_no_shutdown(), on_progress=lambda _: None)
        assert result.success is False
        assert vt.exists()


# ---------------------------------------------------------------------------
# Isolation: one file's failure must not affect others
# ---------------------------------------------------------------------------


class TestIsolation:
    def test_failure_leaves_no_partial_destination(
        self, sample_txt: Path, password: str
    ) -> None:
        task = _make_task(sample_txt, "encrypt", password)
        # Pre-create destination to cause DestinationExistsError
        task.destination.write_bytes(b"existing")
        execute_task(task, shutdown=_no_shutdown(), on_progress=lambda _: None)
        # Destination still has the original content (not overwritten)
        assert task.destination.read_bytes() == b"existing"
