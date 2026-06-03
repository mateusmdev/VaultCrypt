"""
Chunked authenticated encryption using ChaCha20-Poly1305.

Why ChaCha20-Poly1305?
  - IETF-standardised authenticated cipher (RFC 8439).
  - Provides confidentiality AND integrity in one primitive.
  - No timing side-channels (constant-time by design; no AES S-box).
  - Excellent performance on hardware without AES acceleration (ARM, embedded).
  - On x86 with AES-NI, performance is comparable to AES-256-GCM.
  - Nonce size (96 bits / 12 bytes) is safe for random nonces per chunk.

Chunked design
--------------
Files are split into 64 KiB plaintext blocks.  Each block is independently
encrypted and authenticated with a fresh random nonce.  This means:

  1. The authentication tag of each chunk is verified *before* any plaintext
     is written, regardless of file size.
  2. A wrong key or any single-byte corruption is detected on the very first
     chunk, with an immediate, clear error.
  3. Memory usage is bounded to ~64 KiB of plaintext at any time; files of
     any size can be processed without loading them entirely into RAM.
  4. All intermediate data lives in an in-memory BytesIO buffer.  Nothing
     sensitive is written to disk until the caller calls commit().

Output format
-------------
The buffer returned by encrypt_file() starts with a 37-byte header
(magic + version + salt) followed by the encrypted chunks.  See
src/crypto/constants.py for the full layout.
"""

from __future__ import annotations

import io
import os
import threading
from collections.abc import Callable
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from src.crypto.constants import (
    CHUNK_LEN_FIELD,
    CHUNK_SIZE,
    FILE_MAGIC,
    FILE_VERSION,
    NONCE_SIZE,
    SALT_SIZE,
)
from src.crypto.kdf import derive_key
from src.utils.types import (
    CorruptedFileError,
    InvalidKeyError,
    InvalidMagicError,
    ShutdownRequestedError,
    UnsupportedVersionError,
)

# Callable that receives the number of bytes processed in each chunk.
ProgressCallback = Callable[[int], None]

_NOOP: ProgressCallback = lambda _: None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def encrypt_file(
    source: Path,
    password: str,
    *,
    progress: ProgressCallback = _NOOP,
    shutdown: threading.Event | None = None,
) -> io.BytesIO:
    """
    Encrypt *source* into an in-memory buffer using ChaCha20-Poly1305.

    The source file is read in CHUNK_SIZE blocks.  Each block receives
    a fresh random nonce and is independently authenticated.  The result
    is a BytesIO buffer ready to be committed to disk.

    Args:
        source:   Path to the plaintext file to encrypt.
        password: User-provided password; key is derived with Argon2id.
        progress: Optional callback called with plaintext bytes per chunk.
        shutdown: Optional event; if set between chunks, raises
                  ShutdownRequestedError and the partial buffer is discarded
                  by the caller's rollback logic.

    Returns:
        A BytesIO positioned at offset 0 containing the full .vt payload.

    Raises:
        ShutdownRequestedError: If *shutdown* is set between chunks.
        OSError:                On read errors.
    """
    _check_shutdown(shutdown)

    salt: bytes = os.urandom(SALT_SIZE)
    key: bytes = derive_key(password, salt)
    cipher = ChaCha20Poly1305(key)

    buf = io.BytesIO()

    # --- Write header ---
    buf.write(FILE_MAGIC)
    buf.write(FILE_VERSION)
    buf.write(salt)

    # --- Encrypt chunks ---
    with source.open("rb") as fh:
        while True:
            _check_shutdown(shutdown)

            chunk = fh.read(CHUNK_SIZE)
            if not chunk:
                break

            nonce: bytes = os.urandom(NONCE_SIZE)
            ciphertext: bytes = cipher.encrypt(nonce, chunk, None)

            buf.write(nonce)
            buf.write(len(ciphertext).to_bytes(CHUNK_LEN_FIELD, "big"))
            buf.write(ciphertext)

            progress(len(chunk))

    buf.seek(0)
    return buf


def decrypt_file(
    source: Path,
    password: str,
    *,
    progress: ProgressCallback = _NOOP,
    shutdown: threading.Event | None = None,
) -> io.BytesIO:
    """
    Decrypt a .vt file into an in-memory buffer using ChaCha20-Poly1305.

    Each chunk is authenticated *before* its plaintext is appended to the
    buffer, so a wrong key is detected on the first chunk without writing
    any plaintext to disk.

    Args:
        source:   Path to the .vt encrypted file.
        password: User-provided password; key is re-derived from the file's
                  embedded salt with Argon2id.
        progress: Optional callback called with source bytes consumed per chunk.
        shutdown: Optional shutdown event (checked between chunks).

    Returns:
        A BytesIO positioned at offset 0 containing the recovered plaintext.

    Raises:
        InvalidMagicError:      File is not a VaultCrypt-encrypted file.
        UnsupportedVersionError: File was created by a newer format version.
        InvalidKeyError:        Authentication failed (wrong key or corruption).
        CorruptedFileError:     File structure is incomplete or malformed.
        ShutdownRequestedError: If *shutdown* is set between chunks.
        OSError:                On read errors.
    """
    _check_shutdown(shutdown)

    buf = io.BytesIO()

    with source.open("rb") as fh:

        # --- Validate header ---
        magic = fh.read(MAGIC_SIZE := len(FILE_MAGIC))
        if magic != FILE_MAGIC:
            raise InvalidMagicError(
                f"'{source.name}' is not a valid VaultCrypt file "
                f"(unexpected magic bytes: {magic!r})."
            )

        version = fh.read(len(FILE_VERSION))
        if version != FILE_VERSION:
            ver = version[0] if version else "?"
            raise UnsupportedVersionError(
                f"Unsupported format version {ver!r} in '{source.name}'. "
                f"Expected version {FILE_VERSION[0]}."
            )

        salt = fh.read(SALT_SIZE)
        if len(salt) != SALT_SIZE:
            raise CorruptedFileError(
                f"'{source.name}' has a truncated header (incomplete salt field)."
            )

        key: bytes = derive_key(password, salt)
        cipher = ChaCha20Poly1305(key)

        # --- Decrypt chunks ---
        while True:
            _check_shutdown(shutdown)

            nonce = fh.read(NONCE_SIZE)
            if not nonce:
                break  # Clean EOF after last chunk

            if len(nonce) < NONCE_SIZE:
                raise CorruptedFileError(
                    f"'{source.name}': truncated chunk — expected {NONCE_SIZE}-byte "
                    f"nonce, got {len(nonce)} bytes."
                )

            len_field = fh.read(CHUNK_LEN_FIELD)
            if len(len_field) < CHUNK_LEN_FIELD:
                raise CorruptedFileError(
                    f"'{source.name}': truncated chunk — incomplete length field."
                )

            ct_len = int.from_bytes(len_field, "big")
            ciphertext = fh.read(ct_len)
            if len(ciphertext) < ct_len:
                raise CorruptedFileError(
                    f"'{source.name}': truncated chunk — expected {ct_len} "
                    f"ciphertext bytes, got {len(ciphertext)}."
                )

            try:
                plaintext: bytes = cipher.decrypt(nonce, ciphertext, None)
            except InvalidTag as exc:
                raise InvalidKeyError(
                    f"Authentication failed for '{source.name}'. "
                    "The key is incorrect or the file has been tampered with."
                ) from exc

            buf.write(plaintext)

            # Progress tracks bytes consumed from the source file
            progress(NONCE_SIZE + CHUNK_LEN_FIELD + ct_len)

    buf.seek(0)
    return buf


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _check_shutdown(event: threading.Event | None) -> None:
    """Raise ShutdownRequestedError if the shutdown event is set."""
    if event is not None and event.is_set():
        raise ShutdownRequestedError(
            "Operation interrupted by user request (SIGINT)."
        )
