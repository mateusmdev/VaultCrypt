"""
Integration tests for VaultCrypt.

These tests exercise the full pipeline: encrypt → decrypt roundtrips,
directory processing, recursive traversal, error isolation, and
permission handling.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

from src.pipeline.tasks import execute_task
from src.transactions.manager import get_destination
from src.utils.types import FileTask, InvalidKeyError
from src.workers.executor import run_parallel


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_task(source: Path, op: str, password: str) -> FileTask:
    return FileTask(
        source=source,
        destination=get_destination(source, op),
        operation=op,  # type: ignore[arg-type]
        password=password,
    )


def _noop_callbacks():
    return dict(
        on_start=lambda *_: None,
        on_advance=lambda *_: None,
        on_done=lambda *_: None,
    )


def _shutdown():
    import threading
    return threading.Event()


def _encrypt(source: Path, password: str) -> Path:
    task = _make_task(source, "encrypt", password)
    result = execute_task(task, shutdown=_shutdown(), on_progress=lambda _: None)
    assert result.success, f"Encrypt failed: {result.error}"
    return task.destination


def _decrypt(source: Path, password: str) -> Path:
    task = _make_task(source, "decrypt", password)
    result = execute_task(task, shutdown=_shutdown(), on_progress=lambda _: None)
    assert result.success, f"Decrypt failed: {result.error}"
    return task.destination


# ---------------------------------------------------------------------------
# Full roundtrip
# ---------------------------------------------------------------------------


class TestFullRoundtrip:
    def test_encrypt_decrypt_txt(self, sample_txt: Path, password: str) -> None:
        original = sample_txt.read_bytes()
        vt = _encrypt(sample_txt, password)
        assert vt.suffix == ".vt"

        plaintext = _decrypt(vt, password)
        assert plaintext.name == "sample.txt"
        assert plaintext.read_bytes() == original

    def test_encrypt_decrypt_md(self, sample_md: Path, password: str) -> None:
        original = sample_md.read_bytes()
        vt = _encrypt(sample_md, password)
        plaintext = _decrypt(vt, password)
        assert plaintext.read_bytes() == original

    def test_large_file_roundtrip(self, large_file: Path, password: str) -> None:
        """File spanning multiple 64 KiB chunks must survive roundtrip intact."""
        original = large_file.read_bytes()
        vt = _encrypt(large_file, password)
        recovered = _decrypt(vt, password)
        assert recovered.read_bytes() == original

    def test_empty_file_roundtrip(self, tmp_path: Path, password: str) -> None:
        empty = tmp_path / "empty.txt"
        empty.write_bytes(b"")
        vt = _encrypt(empty, password)
        recovered = _decrypt(vt, password)
        assert recovered.read_bytes() == b""


# ---------------------------------------------------------------------------
# Directory processing
# ---------------------------------------------------------------------------


class TestDirectoryProcessing:
    def test_encrypt_whole_directory(
        self, tmp_path: Path, password: str
    ) -> None:
        from src.storage.scanner import scan_files

        for name in ["a.txt", "b.md", "c.txt"]:
            (tmp_path / name).write_text(f"content of {name}", encoding="utf-8")

        files = scan_files(tmp_path, "encrypt", recursive=False)
        tasks = [_make_task(f, "encrypt", password) for f in files]
        results = run_parallel(tasks, max_workers=2, **_noop_callbacks())

        assert all(r.success for r in results)
        assert all(t.destination.exists() for t in tasks)

    def test_recursive_encrypt(self, tmp_path: Path, password: str) -> None:
        from src.storage.scanner import scan_files

        sub = tmp_path / "sub"
        sub.mkdir()
        (tmp_path / "root.txt").write_text("root", encoding="utf-8")
        (sub / "nested.md").write_text("nested", encoding="utf-8")

        files = scan_files(tmp_path, "encrypt", recursive=True)
        assert len(files) == 2

        tasks = [_make_task(f, "encrypt", password) for f in files]
        results = run_parallel(tasks, max_workers=2, **_noop_callbacks())
        assert all(r.success for r in results)

    def test_non_recursive_skips_subdirs(
        self, tmp_path: Path, password: str
    ) -> None:
        from src.storage.scanner import scan_files

        sub = tmp_path / "sub"
        sub.mkdir()
        (tmp_path / "root.txt").write_text("root", encoding="utf-8")
        (sub / "nested.txt").write_text("nested", encoding="utf-8")

        files = scan_files(tmp_path, "encrypt", recursive=False)
        assert len(files) == 1
        assert files[0].name == "root.txt"


# ---------------------------------------------------------------------------
# Key errors
# ---------------------------------------------------------------------------


class TestKeyErrors:
    def test_wrong_key_fails(
        self, sample_txt: Path, password: str, wrong_password: str
    ) -> None:
        vt = _encrypt(sample_txt, password)
        task = _make_task(vt, "decrypt", wrong_password)
        result = execute_task(task, shutdown=_shutdown(), on_progress=lambda _: None)
        assert result.success is False
        assert isinstance(result.error, InvalidKeyError)

    def test_wrong_key_preserves_vt_file(
        self, sample_txt: Path, password: str, wrong_password: str
    ) -> None:
        vt = _encrypt(sample_txt, password)
        vt_content = vt.read_bytes()
        task = _make_task(vt, "decrypt", wrong_password)
        execute_task(task, shutdown=_shutdown(), on_progress=lambda _: None)
        assert vt.exists()
        assert vt.read_bytes() == vt_content


# ---------------------------------------------------------------------------
# Corrupted files
# ---------------------------------------------------------------------------


class TestCorruptedFiles:
    def test_corrupted_vt_fails_gracefully(
        self, sample_txt: Path, password: str
    ) -> None:
        vt = _encrypt(sample_txt, password)
        data = bytearray(vt.read_bytes())
        data[len(data) // 2] ^= 0xFF
        vt.write_bytes(bytes(data))

        task = _make_task(vt, "decrypt", password)
        result = execute_task(task, shutdown=_shutdown(), on_progress=lambda _: None)
        assert result.success is False

    def test_corrupted_vt_source_preserved(
        self, sample_txt: Path, password: str
    ) -> None:
        vt = _encrypt(sample_txt, password)
        original_vt = vt.read_bytes()
        data = bytearray(original_vt)
        data[-5] ^= 0xFF
        vt.write_bytes(bytes(data))

        task = _make_task(vt, "decrypt", password)
        execute_task(task, shutdown=_shutdown(), on_progress=lambda _: None)
        assert vt.exists()


# ---------------------------------------------------------------------------
# Error isolation
# ---------------------------------------------------------------------------


class TestErrorIsolation:
    def test_one_failure_does_not_stop_others(
        self, tmp_path: Path, password: str
    ) -> None:
        """Three tasks: one has a pre-existing destination → only that one fails."""
        tasks: list[FileTask] = []
        for name in ["a.txt", "b.txt", "c.txt"]:
            f = tmp_path / name
            f.write_text(f"content {name}", encoding="utf-8")
            tasks.append(_make_task(f, "encrypt", password))

        # Force first task to fail
        tasks[0].destination.write_bytes(b"already here")

        results = run_parallel(tasks, max_workers=2, **_noop_callbacks())
        successes = [r for r in results if r.success]
        failures = [r for r in results if not r.success]

        assert len(failures) == 1
        assert len(successes) == 2

    def test_failed_task_source_remains(
        self, tmp_path: Path, password: str
    ) -> None:
        f = tmp_path / "file.txt"
        f.write_text("data", encoding="utf-8")
        task = _make_task(f, "encrypt", password)
        task.destination.write_bytes(b"conflict")

        execute_task(task, shutdown=_shutdown(), on_progress=lambda _: None)
        assert f.exists()


# ---------------------------------------------------------------------------
# Permission errors
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    sys.platform == "win32" or os.getuid() == 0,
    reason="Permission tests require a non-root Unix environment",
)
class TestPermissions:
    def test_unreadable_source_returns_failure(
        self, sample_txt: Path, password: str
    ) -> None:
        sample_txt.chmod(0o000)
        try:
            task = _make_task(sample_txt, "encrypt", password)
            result = execute_task(
                task, shutdown=_shutdown(), on_progress=lambda _: None
            )
            assert result.success is False
        finally:
            sample_txt.chmod(0o644)

    def test_unreadable_source_preserves_original(
        self, sample_txt: Path, password: str
    ) -> None:
        sample_txt.chmod(0o000)
        try:
            task = _make_task(sample_txt, "encrypt", password)
            execute_task(task, shutdown=_shutdown(), on_progress=lambda _: None)
            assert task.destination.exists() is False
        finally:
            sample_txt.chmod(0o644)
