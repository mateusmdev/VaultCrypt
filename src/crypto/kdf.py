"""
Key derivation via Argon2id.

Why Argon2id?
  - Winner of the Password Hashing Competition (2015).
  - Memory-hard: forces attackers to use large amounts of RAM, making GPU
    and ASIC attacks orders of magnitude more expensive than PBKDF2.
  - Hybrid design (Argon2i + Argon2d): resistant to both side-channel
    attacks and time–memory trade-off attacks.
  - Recommended as the first choice for new projects by OWASP (2023).

A fresh random 32-byte salt is generated for every file, so two files
encrypted with the same password produce different keys.  This means
compromising one file's key reveals nothing about the others.
"""

from __future__ import annotations

from argon2.low_level import Type, hash_secret_raw

from src.crypto.constants import (
    ARGON2_HASH_LEN,
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    ARGON2_TIME_COST,
    SALT_SIZE,
)


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 32-byte cryptographic key from a password and a per-file salt.

    Args:
        password: The user-supplied password/passphrase (UTF-8 encoded).
        salt:     A cryptographically random, per-file salt (must be exactly
                  SALT_SIZE bytes).

    Returns:
        A 32-byte (256-bit) key ready for use with ChaCha20-Poly1305.

    Raises:
        ValueError: If *salt* is not exactly ``SALT_SIZE`` bytes long.
    """
    if len(salt) != SALT_SIZE:
        raise ValueError(
            f"Salt must be exactly {SALT_SIZE} bytes; received {len(salt)}."
        )

    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID,
    )
