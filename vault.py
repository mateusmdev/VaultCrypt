#!/usr/bin/env python3
"""
VaultCrypt — Secure file encryption and decryption tool.

Usage:
    python vault.py --path <path> --key <key> --encrypt [--recursive] [--workers N]
    python vault.py --path <path> --key <key> --decrypt [--recursive] [--workers N]

Run 'python vault.py --help' for full documentation.
"""

import sys
from pathlib import Path

# Ensure the project root is in sys.path when invoked directly
sys.path.insert(0, str(Path(__file__).parent))

from src.main import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
