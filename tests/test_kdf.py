"""Tests for src.crypto.kdf — Argon2id key derivation."""

from __future__ import annotations

import os

import pytest

from src.crypto.constants import ARGON2_HASH_LEN, SALT_SIZE
from src.crypto.kdf import derive_key


class TestDeriveKey:
    """Unit tests for derive_key()."""

    def test_returns_correct_length(self, password: str) -> None:
        """Output must be exactly ARGON2_HASH_LEN bytes (32)."""
        salt = os.urandom(SALT_SIZE)
        key = derive_key(password, salt)
        assert len(key) == ARGON2_HASH_LEN

    def test_returns_bytes(self, password: str) -> None:
        """Output must be a bytes object."""
        salt = os.urandom(SALT_SIZE)
        assert isinstance(derive_key(password, salt), bytes)

    def test_deterministic_same_inputs(self, password: str) -> None:
        """Same password + same salt → same key (deterministic KDF)."""
        salt = os.urandom(SALT_SIZE)
        key_a = derive_key(password, salt)
        key_b = derive_key(password, salt)
        assert key_a == key_b

    def test_different_salts_produce_different_keys(self, password: str) -> None:
        """Different salts → different keys, even with the same password."""
        salt_a = os.urandom(SALT_SIZE)
        salt_b = os.urandom(SALT_SIZE)
        assert derive_key(password, salt_a) != derive_key(password, salt_b)

    def test_different_passwords_produce_different_keys(self) -> None:
        """Different passwords → different keys with the same salt."""
        salt = os.urandom(SALT_SIZE)
        key_a = derive_key("password-one", salt)
        key_b = derive_key("password-two", salt)
        assert key_a != key_b

    def test_wrong_salt_size_raises_value_error(self, password: str) -> None:
        """Salt that is not exactly SALT_SIZE bytes must raise ValueError."""
        with pytest.raises(ValueError, match="Salt must be exactly"):
            derive_key(password, b"too-short")

    def test_empty_salt_raises_value_error(self, password: str) -> None:
        """Empty salt must raise ValueError."""
        with pytest.raises(ValueError):
            derive_key(password, b"")

    def test_unicode_password_works(self) -> None:
        """Unicode characters in the password must be handled correctly."""
        salt = os.urandom(SALT_SIZE)
        key = derive_key("пароль-🔑-密码", salt)
        assert len(key) == ARGON2_HASH_LEN
