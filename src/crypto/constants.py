"""
Cryptographic constants and .vt file format specification.

File format (.vt) — binary layout
==================================

Header (37 bytes):
  Offset  Size  Field
  ------  ----  -----
    0       4   MAGIC    — b"VTF\\x01"  (identifies the file type)
    4       1   VERSION  — b"\\x01"    (format version for forward-compat)
    5      32   SALT     — random bytes (per-file Argon2id salt)

Followed by N chunks (until EOF):
  Offset  Size           Field
  ------  ----           -----
    0      12            NONCE          — random bytes per chunk
   12       4            CIPHERTEXT_LEN — uint32 big-endian
   16  CIPHERTEXT_LEN   CIPHERTEXT     — plaintext + 16-byte Poly1305 tag

Key derivation
==============
Argon2id is used to derive the 256-bit ChaCha20-Poly1305 key from the
user-provided password and the per-file random salt.

Parameters:
  time_cost   = 3       iterations
  memory_cost = 64 MiB  (65 536 KiB) — memory-hard, resists GPU/ASIC attacks
  parallelism = 1       threads per KDF call (predictable resource usage)
  hash_len    = 32      bytes (256-bit output key)

These parameters satisfy the OWASP minimum recommendations while keeping
KDF time under ~1 s on typical hardware, which is acceptable for a
file-encryption tool (KDF runs once per file, not per request).
"""

# ---------------------------------------------------------------------------
# File format
# ---------------------------------------------------------------------------

#: Identifies a VaultCrypt-encrypted file.  "VTF" + 0x01 version marker.
FILE_MAGIC: bytes = b"VTF\x01"

#: Format version byte stored in every .vt file header.
FILE_VERSION: bytes = b"\x01"

MAGIC_SIZE: int = len(FILE_MAGIC)       # 4
VERSION_SIZE: int = len(FILE_VERSION)   # 1
SALT_SIZE: int = 32
HEADER_SIZE: int = MAGIC_SIZE + VERSION_SIZE + SALT_SIZE  # 37

#: Per-chunk nonce size for ChaCha20-Poly1305.
NONCE_SIZE: int = 12

#: Bytes used to encode the ciphertext length field within each chunk.
CHUNK_LEN_FIELD: int = 4  # uint32

#: Poly1305 authentication tag appended to ciphertext by the library.
TAG_SIZE: int = 16

#: Plaintext chunk size (64 KiB).  Large enough for efficient I/O,
#: small enough to verify each chunk before writing any plaintext.
CHUNK_SIZE: int = 64 * 1024  # 65 536 bytes

# ---------------------------------------------------------------------------
# Argon2id parameters
# ---------------------------------------------------------------------------

ARGON2_TIME_COST: int = 3
ARGON2_MEMORY_COST: int = 65_536   # KiB → 64 MiB
ARGON2_PARALLELISM: int = 1
ARGON2_HASH_LEN: int = 32          # bytes → 256-bit key

# ---------------------------------------------------------------------------
# Key / password constraints
# ---------------------------------------------------------------------------

KEY_MIN_LENGTH: int = 1
KEY_MAX_LENGTH: int = 100

# ---------------------------------------------------------------------------
# Recognised file extensions
# ---------------------------------------------------------------------------

#: Extensions eligible for encryption.
PLAINTEXT_SUFFIXES: frozenset[str] = frozenset({".txt", ".md"})

#: Compound extensions produced by encryption (and consumed by decryption).
ENCRYPTED_COMPOUND_SUFFIXES: tuple[str, ...] = (".txt.vt", ".md.vt")

#: All extensions accepted as CLI --path targets (single-file mode).
ALL_VALID_SUFFIXES: tuple[str, ...] = (".txt", ".md", ".txt.vt", ".md.vt")

# ---------------------------------------------------------------------------
# Parallelism defaults
# ---------------------------------------------------------------------------

DEFAULT_WORKERS: int = 4
