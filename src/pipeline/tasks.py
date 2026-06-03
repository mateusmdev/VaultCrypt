"""
Single-file task execution.

Each call to execute_task() processes exactly one file end-to-end:

  1. Pre-flight check — abort immediately if the destination already exists.
  2. Process         — encrypt or decrypt source into an in-memory buffer.
                       The source file is NOT touched during this step.
  3. Commit          — write buffer → destination, then unlink source.
     or
     Discard         — close the in-memory buffer, leave source intact.

On failure the source file is ALWAYS preserved.  The destination is only
ever touched by commit(), which self-cleans any partial write it creates.

Errors are fully isolated: an exception in one task never affects others.
"""

from __future__ import annotations

import io
import threading
from collections.abc import Callable

from src.crypto.cipher import decrypt_file, encrypt_file
from src.transactions.manager import commit
from src.utils.types import (
    DestinationExistsError,
    FileTask,
    TaskResult,
)

ProgressCallback = Callable[[int], None]


def execute_task(
    task: FileTask,
    *,
    shutdown: threading.Event,
    on_progress: ProgressCallback,
) -> TaskResult:
    """
    Execute a single file task with transactional guarantees.

    Args:
        task:        Describes the source, destination, operation, and password.
        shutdown:    Event monitored between chunks; when set the operation
                     stops and a failed TaskResult is returned.
        on_progress: Callback receiving source bytes processed after each chunk.

    Returns:
        TaskResult with ``success=True`` on commit, or ``success=False`` with
        the causing exception on any failure.
    """
    buf: io.BytesIO = io.BytesIO()

    try:
        # --- Pre-flight: destination must not already exist ---
        if task.destination.exists():
            raise DestinationExistsError(
                f"Destination already exists: '{task.destination.name}'. "
                "Remove or rename it manually before proceeding."
            )

        # --- Process source into an in-memory buffer ---
        if task.operation == "encrypt":
            buf = encrypt_file(
                task.source,
                task.password,
                progress=on_progress,
                shutdown=shutdown,
            )
        else:
            buf = decrypt_file(
                task.source,
                task.password,
                progress=on_progress,
                shutdown=shutdown,
            )

        # --- Commit: write buffer to destination, then unlink source ---
        # commit() cleans up any partial destination write on its own failure.
        commit(buf, task.destination, task.source)
        return TaskResult(task=task, success=True)

    except Exception as exc:
        # Discard the in-memory buffer.  The source file is always untouched.
        #
        # We intentionally do NOT call rollback() here because:
        #   • Pre-flight failure  → destination was pre-existing; must NOT delete it.
        #   • Processing failure  → destination was never created; nothing to clean.
        #   • Commit write error  → commit() already cleaned its own partial write.
        try:
            buf.close()
        except Exception:
            pass
        return TaskResult(task=task, success=False, error=exc)
