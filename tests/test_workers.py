"""Tests for src.workers.executor — parallel task execution."""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from src.pipeline.tasks import execute_task
from src.transactions.manager import get_destination
from src.utils.types import FileTask, TaskResult
from src.workers.executor import run_parallel


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _noop(*_: object) -> None:
    pass


def _make_tasks(tmp_path: Path, count: int, password: str) -> list[FileTask]:
    """Create *count* .txt source files and corresponding FileTask objects."""
    tasks = []
    for i in range(count):
        src = tmp_path / f"file_{i}.txt"
        src.write_text(f"content of file {i}", encoding="utf-8")
        tasks.append(
            FileTask(
                source=src,
                destination=get_destination(src, "encrypt"),
                operation="encrypt",
                password=password,
            )
        )
    return tasks


# ---------------------------------------------------------------------------
# Basic correctness
# ---------------------------------------------------------------------------


class TestRunParallel:
    def test_all_succeed(self, tmp_path: Path, password: str) -> None:
        tasks = _make_tasks(tmp_path, 3, password)
        results = run_parallel(
            tasks,
            max_workers=2,
            on_start=lambda *_: None,
            on_advance=lambda *_: None,
            on_done=lambda *_: None,
        )
        assert len(results) == 3
        assert all(r.success for r in results)

    def test_all_destinations_created(self, tmp_path: Path, password: str) -> None:
        tasks = _make_tasks(tmp_path, 3, password)
        run_parallel(
            tasks,
            max_workers=2,
            on_start=lambda *_: None,
            on_advance=lambda *_: None,
            on_done=lambda *_: None,
        )
        for task in tasks:
            assert task.destination.exists()

    def test_partial_failure_others_continue(
        self, tmp_path: Path, password: str
    ) -> None:
        """One failing task must not stop the remaining tasks."""
        tasks = _make_tasks(tmp_path, 3, password)
        # Pre-create destination of first task to force a failure
        tasks[0].destination.write_bytes(b"already here")

        results = run_parallel(
            tasks,
            max_workers=2,
            on_start=lambda *_: None,
            on_advance=lambda *_: None,
            on_done=lambda *_: None,
        )
        successes = [r for r in results if r.success]
        failures = [r for r in results if not r.success]
        assert len(failures) == 1
        assert len(successes) == 2

    def test_returns_result_for_every_task(
        self, tmp_path: Path, password: str
    ) -> None:
        tasks = _make_tasks(tmp_path, 5, password)
        results = run_parallel(
            tasks,
            max_workers=4,
            on_start=lambda *_: None,
            on_advance=lambda *_: None,
            on_done=lambda *_: None,
        )
        assert len(results) == len(tasks)

    def test_on_start_called_for_each_task(
        self, tmp_path: Path, password: str
    ) -> None:
        tasks = _make_tasks(tmp_path, 3, password)
        started: list[Path] = []
        run_parallel(
            tasks,
            max_workers=2,
            on_start=lambda src, _: started.append(src),
            on_advance=lambda *_: None,
            on_done=lambda *_: None,
        )
        assert len(started) == 3

    def test_on_done_called_for_each_task(
        self, tmp_path: Path, password: str
    ) -> None:
        tasks = _make_tasks(tmp_path, 3, password)
        done_count = [0]
        run_parallel(
            tasks,
            max_workers=2,
            on_start=lambda *_: None,
            on_advance=lambda *_: None,
            on_done=lambda r, _: done_count.__setitem__(0, done_count[0] + 1),
        )
        assert done_count[0] == 3

    def test_single_worker_processes_sequentially(
        self, tmp_path: Path, password: str
    ) -> None:
        tasks = _make_tasks(tmp_path, 3, password)
        results = run_parallel(
            tasks,
            max_workers=1,
            on_start=lambda *_: None,
            on_advance=lambda *_: None,
            on_done=lambda *_: None,
        )
        assert all(r.success for r in results)
