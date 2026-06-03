"""
Parallel task execution via ThreadPoolExecutor.

Each FileTask is submitted as an independent unit of work.  Workers pull
tasks from the executor's internal queue, processing up to *max_workers*
files concurrently.

SIGINT / shutdown handling
--------------------------
A threading.Event is shared with every worker thread.  When SIGINT is
received, the event is set.  Worker threads check the event between chunks
and raise ShutdownRequestedError, which triggers a rollback inside
execute_task().  Pending (not-yet-started) futures are cancelled.

Callback protocol
-----------------
Three callbacks bridge the executor with the progress display:

  on_start(source, exec_id)
      Called from the worker thread when a task begins processing.
      Use this to create the file's progress bar.

  on_advance(exec_id, bytes_done)
      Called from the worker thread after each encrypted/decrypted chunk.
      Use this to update the progress bar.

  on_done(result, exec_id)
      Called from the main thread when a future completes (success or failure).
      Use this to log the result, remove the progress bar, and tick the
      overall counter.
"""

from __future__ import annotations

import signal
import threading
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from pathlib import Path

from src.pipeline.tasks import execute_task
from src.utils.types import FileTask, TaskResult

# Callback type aliases
StartCallback = Callable[[Path, int], None]
AdvanceCallback = Callable[[int, int], None]
DoneCallback = Callable[[TaskResult, int], None]


def run_parallel(
    tasks: list[FileTask],
    max_workers: int,
    *,
    on_start: StartCallback,
    on_advance: AdvanceCallback,
    on_done: DoneCallback,
) -> list[TaskResult]:
    """
    Process all *tasks* in parallel, up to *max_workers* at a time.

    Args:
        tasks:       File tasks to execute.
        max_workers: Maximum concurrent worker threads.
        on_start:    Called in the worker thread at task start.
        on_advance:  Called in the worker thread after each chunk.
        on_done:     Called in the main thread when a future settles.

    Returns:
        List of TaskResult objects in completion order (not submission order).
    """
    shutdown_event = threading.Event()
    results: list[TaskResult] = []

    original_handler = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, _make_sigint_handler(shutdown_event))

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map: dict[Future[tuple[TaskResult, int]], tuple[FileTask, int]] = {}

            for exec_id, task in enumerate(tasks):
                future = executor.submit(
                    _worker,
                    task,
                    exec_id,
                    shutdown_event,
                    on_start,
                    on_advance,
                )
                future_map[future] = (task, exec_id)

            for future in as_completed(future_map):
                original_task, exec_id = future_map[future]
                try:
                    result, tid = future.result()
                except Exception as exc:
                    # Unexpected exception not captured inside execute_task
                    result = TaskResult(
                        task=original_task,
                        success=False,
                        error=exc,
                    )
                    tid = exec_id

                on_done(result, tid)
                results.append(result)

    finally:
        signal.signal(signal.SIGINT, original_handler)

    return results


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _worker(
    task: FileTask,
    exec_id: int,
    shutdown: threading.Event,
    on_start: StartCallback,
    on_advance: AdvanceCallback,
) -> tuple[TaskResult, int]:
    """Worker function executed inside a thread."""
    on_start(task.source, exec_id)
    result = execute_task(
        task,
        shutdown=shutdown,
        on_progress=lambda n: on_advance(exec_id, n),
    )
    return result, exec_id


def _make_sigint_handler(shutdown_event: threading.Event) -> Callable:
    """Return a SIGINT handler that sets the shutdown event."""

    def _handler(signum: int, frame: object) -> None:  # noqa: ARG001
        shutdown_event.set()

    return _handler
