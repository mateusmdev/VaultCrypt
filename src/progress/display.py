"""
Terminal progress display using Rich.

Three display phases
--------------------
1. Discovery
   A panel listing all found files grouped by their parent directory,
   with the total count at the bottom.

2. Processing (live)
   - An overall bar showing how many files have been completed (N / total).
   - Per-file bars — one per *actively running* worker — showing byte-level
     progress, transfer speed, and estimated time remaining.
   - Each completed or failed file is logged as a static line *above* the
     live panel (Rich's console.log() handles this correctly within Live).
   - The live panel therefore stays compact: at most max_workers + 1 rows.

3. Summary
   A Rich table listing every processed file, its status, and destination
   (or error message on failure).

Thread safety
-------------
Rich's Progress is internally thread-safe.  The only additional lock used
here protects the exec_id → TaskID mapping dictionary against concurrent
reads and writes from worker threads.
"""

from __future__ import annotations

import threading
from pathlib import Path

from rich import box
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TaskProgressColumn,
    TextColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)
from rich.table import Table

from src.utils.types import TaskResult

# Single shared console (stdout).
console = Console()


# ---------------------------------------------------------------------------
# Phase 1 — Discovery
# ---------------------------------------------------------------------------


def show_banner(operation: str) -> None:
    """Print the VaultCrypt banner with the active operation label."""
    if operation == "encrypt":
        label = "[bold green]🔒  ENCRYPT[/bold green]"
    else:
        label = "[bold yellow]🔓  DECRYPT[/bold yellow]"

    console.print(
        Panel(
            f"[bold cyan]VaultCrypt[/bold cyan]   ·   {label}",
            box=box.ROUNDED,
            padding=(0, 2),
        )
    )
    console.print()


def show_discovery(
    files_by_dir: dict[Path, list[Path]],
    root: Path,
    operation: str,
    total: int,
) -> None:
    """
    Print discovered files grouped by directory.

    Args:
        files_by_dir: Mapping of directory → files (from scanner.group_by_directory).
        root:         The path the user passed on the CLI.
        operation:    ``"encrypt"`` or ``"decrypt"``.
        total:        Total number of eligible files found.
    """
    if total == 0:
        ext_hint = (
            ".txt / .md" if operation == "encrypt" else ".txt.vt / .md.vt"
        )
        console.print(
            Panel(
                f"[yellow]⚠  No eligible files found.[/yellow]\n\n"
                f"Path scanned : [dim]{root}[/dim]\n"
                f"Looking for  : [dim]{ext_hint}[/dim]\n\n"
                "[green]Process completed successfully — nothing to do.[/green]",
                title="[bold]Discovery[/bold]",
                box=box.ROUNDED,
            )
        )
        return

    lines: list[str] = []
    for directory in sorted(files_by_dir):
        dir_files = sorted(files_by_dir[directory], key=lambda f: f.name)
        lines.append(f"[bold blue]📁  {directory}[/bold blue]")
        for idx, f in enumerate(dir_files):
            connector = "└──" if idx == len(dir_files) - 1 else "├──"
            lines.append(f"   {connector} [white]{f.name}[/white]")
        lines.append("")

    lines.append(
        f"[bold green]✓  {total} file(s) ready for processing[/bold green]"
    )

    console.print(
        Panel(
            "\n".join(lines),
            title="[bold]Discovered Files[/bold]",
            box=box.ROUNDED,
        )
    )
    console.print()


# ---------------------------------------------------------------------------
# Phase 2 — Live processing progress
# ---------------------------------------------------------------------------


class ProgressManager:
    """
    Context manager that owns the Rich Live display during processing.

    Usage::

        with ProgressManager(total_files=n) as prog:
            tid = prog.start_file(filename, file_size_bytes)
            prog.advance(tid, chunk_bytes)
            prog.finish(tid, success=True, source=..., destination=...)
            prog.tick_overall()

    All public methods are thread-safe.
    """

    def __init__(self, total_files: int) -> None:
        self._total = total_files
        self._lock = threading.Lock()

        # --- Overall progress (file count) ---
        self._overall = Progress(
            TextColumn("[bold]Overall"),
            BarColumn(bar_width=38),
            MofNCompleteColumn(),
            TextColumn("file(s)"),
            console=console,
        )
        self._overall_task: TaskID = self._overall.add_task(
            "", total=total_files
        )

        # --- Per-file progress (bytes) ---
        self._files = Progress(
            SpinnerColumn(),
            TextColumn("[cyan]{task.fields[name]:<40}"),
            BarColumn(bar_width=18),
            TaskProgressColumn(),
            TransferSpeedColumn(),
            TimeRemainingColumn(),
            console=console,
        )

        group = Group(
            Panel(
                self._overall,
                box=box.ROUNDED,
                padding=(0, 1),
                title="[bold dim]Progress[/bold dim]",
            ),
            self._files,
        )
        self._live = Live(
            group,
            console=console,
            refresh_per_second=15,
        )

    # --- Context manager ---

    def __enter__(self) -> "ProgressManager":
        self._live.__enter__()
        return self

    def __exit__(self, *args: object) -> None:
        self._live.__exit__(*args)

    # --- Per-file lifecycle ---

    def start_file(self, filename: str, total_bytes: int) -> TaskID:
        """
        Register a new active file and return its TaskID.

        Called from a worker thread when the task begins execution.
        """
        name = _truncate(filename, 39)
        with self._lock:
            return self._files.add_task(
                "",
                name=name,
                total=max(1, total_bytes),
            )

    def advance(self, task_id: TaskID, bytes_done: int) -> None:
        """Advance a file's byte-level progress bar. Thread-safe."""
        self._files.advance(task_id, bytes_done)

    def finish(
        self,
        task_id: TaskID,
        *,
        success: bool,
        source: Path,
        destination: Path,
        error: str = "",
    ) -> None:
        """
        Log the file result and remove its progress bar.

        The log line appears above the live panel (Rich handles ordering).
        Called from the main thread after the future settles.
        """
        if success:
            console.log(
                f"[green]✓[/green]  [white]{source.name}[/white]"
                f"  [dim]→ {destination.name}[/dim]"
            )
        else:
            short_err = _truncate(error, 72)
            console.log(
                f"[red]✗[/red]  [white]{source.name}[/white]"
                f"  [red]{short_err}[/red]"
            )

        with self._lock:
            self._files.remove_task(task_id)

    def tick_overall(self) -> None:
        """Advance the overall file counter by one. Thread-safe."""
        self._overall.advance(self._overall_task, 1)


# ---------------------------------------------------------------------------
# Phase 3 — Summary
# ---------------------------------------------------------------------------


def show_summary(results: list[TaskResult], operation: str) -> None:
    """
    Print a tabular summary of all processed files.

    Args:
        results:   All TaskResult objects from the run.
        operation: ``"encrypt"`` or ``"decrypt"``.
    """
    successes = [r for r in results if r.success]
    failures = [r for r in results if not r.success]

    console.print()

    table = Table(
        title="[bold]Run Summary[/bold]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold dim",
        show_lines=False,
    )
    table.add_column("", justify="center", width=3, no_wrap=True)
    table.add_column("Source file", style="white", min_width=24)
    table.add_column("Result / Error", style="dim", min_width=28)

    for r in successes:
        table.add_row(
            "[green]✓[/green]",
            r.source.name,
            f"[dim]→ {r.destination.name}[/dim]",
        )

    for r in failures:
        msg = str(r.error) if r.error else "Unknown error"
        table.add_row(
            "[red]✗[/red]",
            r.source.name,
            f"[red]{_truncate(msg, 60)}[/red]",
        )

    console.print(table)
    console.print()

    if failures:
        console.print(
            f"[bold red]✗  {len(failures)} failed[/bold red]    "
            f"[bold green]✓  {len(successes)} succeeded[/bold green]"
        )
    else:
        word = "encrypted" if operation == "encrypt" else "decrypted"
        console.print(
            f"[bold green]✓  All {len(successes)} file(s) {word} successfully.[/bold green]"
        )


def show_interrupted() -> None:
    """Print a shutdown notice after the Live context has closed."""
    console.print(
        "\n[bold yellow]⚠  Operation interrupted by user. "
        "In-progress files were rolled back and left unchanged.[/bold yellow]"
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _truncate(text: str, max_len: int) -> str:
    """Truncate *text* to *max_len* characters, appending '…' if needed."""
    if len(text) <= max_len:
        return text
    return text[: max_len - 1] + "…"
