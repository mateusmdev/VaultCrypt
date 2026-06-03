"""
CLI argument parser for VaultCrypt.

Defines all supported arguments and returns parsed Namespace objects.
Validation of argument *values* is handled separately by src.validators.
"""

from __future__ import annotations

import argparse
from argparse import ArgumentParser, Namespace

from src.crypto.constants import DEFAULT_WORKERS


def build_parser() -> ArgumentParser:
    """
    Construct and return the ArgumentParser for VaultCrypt.

    Returns:
        Fully configured ArgumentParser instance.
    """
    parser = ArgumentParser(
        prog="vault",
        description=(
            "VaultCrypt — Secure file encryption and decryption.\n"
            "Algorithm : ChaCha20-Poly1305 (authenticated encryption)\n"
            "KDF       : Argon2id  (per-file random salt, 64 MiB memory cost)\n"
            "Format    : Chunked (.vt) — each 64 KiB block is independently verified"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_EXAMPLES,
    )

    # --- Target path (required) ---
    parser.add_argument(
        "--path", "-p",
        required=True,
        metavar="PATH",
        help="Path to a file or directory to process.",
    )

    # --- Encryption key (required) ---
    parser.add_argument(
        "--key", "-k",
        required=True,
        metavar="KEY",
        help="Encryption/decryption key (1–100 characters). Never stored.",
    )

    # --- Operation (mutually exclusive, one required) ---
    ops = parser.add_mutually_exclusive_group(required=True)
    ops.add_argument(
        "--encrypt",
        action="store_true",
        help="Encrypt .txt and .md files → .txt.vt / .md.vt.",
    )
    ops.add_argument(
        "--decrypt",
        action="store_true",
        help="Decrypt .txt.vt and .md.vt files → .txt / .md.",
    )

    # --- Recursive flag (optional) ---
    parser.add_argument(
        "--recursive", "-r",
        action="store_true",
        default=False,
        help="Process subdirectories recursively. Silently ignored for single files.",
    )

    # --- Worker count (optional) ---
    parser.add_argument(
        "--workers", "-w",
        type=int,
        default=DEFAULT_WORKERS,
        metavar="N",
        help=(
            f"Number of parallel workers (default: {DEFAULT_WORKERS}). "
            "Must be a positive integer. Silently ignored for single files."
        ),
    )

    return parser


def parse_args() -> Namespace:
    """Parse sys.argv and return the Namespace."""
    return build_parser().parse_args()


def resolve_operation(args: Namespace) -> str:
    """
    Derive the operation string from parsed arguments.

    Returns:
        ``"encrypt"`` or ``"decrypt"``.
    """
    return "encrypt" if args.encrypt else "decrypt"


# ---------------------------------------------------------------------------
# Help text
# ---------------------------------------------------------------------------

_EXAMPLES = """
examples:
  Encrypt a single file:
    python vault.py -p notes.txt -k "my passphrase" --encrypt

  Decrypt a single file:
    python vault.py -p notes.txt.vt -k "my passphrase" --decrypt

  Encrypt an entire directory:
    python vault.py -p ./docs -k "my passphrase" --encrypt

  Encrypt recursively with 8 workers:
    python vault.py -p ./docs -k "my passphrase" --encrypt -r -w 8

security note:
  The key is NEVER stored by the tool.
  Loss of the key means permanent, irreversible loss of access to encrypted data.
  There is no recovery mechanism, no backdoor, and no master key.
"""
