"""
VaultCrypt main orchestration.

Flow
----
1. Parse CLI arguments.
2. Validate key, workers, and path.
3. Discover eligible files.
4. Display the discovery summary.
5. Build FileTask objects.
6. Run tasks in parallel with live progress display.
7. Print the run summary.
8. Return exit code (0 = all OK, 1 = one or more failures).
"""

from __future__ import annotations

import threading
from pathlib import Path

from rich.progress import TaskID

from src.cli.parser import parse_args, resolve_operation
from src.progress.display import (
    ProgressManager,
    console,
    show_banner,
    show_discovery,
    show_interrupted,
    show_summary,
)
from src.storage.scanner import group_by_directory, scan_files
from src.transactions.manager import get_destination
from src.utils.types import FileTask, ShutdownRequestedError, TaskResult
from src.validators.args import validate_key, validate_path, validate_workers
from src.workers.executor import run_parallel


def main() -> int:
    """
    Application entry point.

    Returns:
        0 if every file was processed successfully, 1 otherwise.
    """
    # ------------------------------------------------------------------ #
    # 1. Parse
    # ------------------------------------------------------------------ #
    args = parse_args()
    operation = resolve_operation(args)

    # ------------------------------------------------------------------ #
    # 2. Validate
    # ------------------------------------------------------------------ #
    try:
        validate_key(args.key)
        validate_workers(args.workers)
        target = validate_path(args.path, operation)
    except Exception as exc:
        console.print(f"\n[bold red]Error:[/bold red] {exc}\n")
        return 1

    # ------------------------------------------------------------------ #
    # 3. Discover
    # ------------------------------------------------------------------ #
    is_single_file = target.is_file()
    files = scan_files(target, operation, args.recursive)
    files_by_dir = group_by_directory(files)

    # ------------------------------------------------------------------ #
    # 4. Display discovery
    # ------------------------------------------------------------------ #
    show_banner(operation)
    show_discovery(files_by_dir, target, operation, total=len(files))

    if not files:
        return 0  # Nothing to do — clean exit

    # ------------------------------------------------------------------ #
    # 5. Build tasks
    # ------------------------------------------------------------------ #
    tasks: list[FileTask] = [
        FileTask(
            source=f,
            destination=get_destination(f, operation),
            operation=operation,   # type: ignore[arg-type]
            password=args.key,
        )
        for f in files
    ]

    # ------------------------------------------------------------------ #
    # 6. Process
    # ------------------------------------------------------------------ #
    # --workers is silently ignored for single-file targets.
    effective_workers = 1 if is_single_file else args.workers

    results, interrupted = _run(tasks, effective_workers)

    # ------------------------------------------------------------------ #
    # 7. Summary
    # ------------------------------------------------------------------ #
    if interrupted:
        show_interrupted()

    show_summary(results, operation)

    # ------------------------------------------------------------------ #
    # 8. Exit code
    # ------------------------------------------------------------------ #
    return 1 if any(not r.success for r in results) else 0


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _run(
    tasks: list[FileTask],
    workers: int,
) -> tuple[list[TaskResult], bool]:
    """
    Execute all tasks with the live progress display.

    Returns:
        (results, interrupted) where *interrupted* is True if the user
        sent SIGINT during the run.
    """
    # Maps executor task IDs → Rich progress TaskIDs.
    # Written from worker threads (on_start), read from main (on_advance, on_done).
    prog_id_map: dict[int, TaskID] = {}
    map_lock = threading.Lock()

    with ProgressManager(total_files=len(tasks)) as prog:

        def on_start(source: Path, exec_id: int) -> None:
            """Called from the worker thread when a task begins."""
            try:
                size = max(1, source.stat().st_size)
            except OSError:
                size = 1
            tid = prog.start_file(source.name, size)
            with map_lock:
                prog_id_map[exec_id] = tid

        def on_advance(exec_id: int, bytes_done: int) -> None:
            """Called from the worker thread after each chunk."""
            with map_lock:
                tid = prog_id_map.get(exec_id)
            if tid is not None:
                prog.advance(tid, bytes_done)

        def on_done(result: TaskResult, exec_id: int) -> None:
            """Called from the main thread when a future settles."""
            with map_lock:
                tid = prog_id_map.pop(exec_id, None)

            if tid is not None:
                prog.finish(
                    tid,
                    success=result.success,
                    source=result.source,
                    destination=result.destination,
                    error=str(result.error) if result.error else "",
                )

            prog.tick_overall()

        results = run_parallel(
            tasks,
            max_workers=workers,
            on_start=on_start,
            on_advance=on_advance,
            on_done=on_done,
        )

    interrupted = any(
        isinstance(r.error, ShutdownRequestedError)
        for r in results
        if r.error is not None
    )

    return results, interrupted
