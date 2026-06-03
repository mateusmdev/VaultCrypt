"""Tests for src.cli.parser and src.validators.args."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.cli.parser import build_parser, resolve_operation
from src.validators.args import validate_key, validate_path, validate_workers
from src.utils.types import ValidationError


# ---------------------------------------------------------------------------
# Parser — argument parsing
# ---------------------------------------------------------------------------


class TestParser:
    def _parse(self, args: list[str]):
        return build_parser().parse_args(args)

    def test_encrypt_flag(self, tmp_path: Path) -> None:
        f = tmp_path / "f.txt"
        f.write_text("x")
        ns = self._parse(["--path", str(f), "--key", "k", "--encrypt"])
        assert ns.encrypt is True
        assert ns.decrypt is False

    def test_decrypt_flag(self, tmp_path: Path) -> None:
        f = tmp_path / "f.txt.vt"
        f.write_text("x")
        ns = self._parse(["--path", str(f), "--key", "k", "--decrypt"])
        assert ns.decrypt is True
        assert ns.encrypt is False

    def test_short_flags(self, tmp_path: Path) -> None:
        f = tmp_path / "f.txt"
        f.write_text("x")
        ns = self._parse(["-p", str(f), "-k", "k", "--encrypt"])
        assert ns.encrypt is True

    def test_default_workers(self, tmp_path: Path) -> None:
        from src.crypto.constants import DEFAULT_WORKERS
        f = tmp_path / "f.txt"
        f.write_text("x")
        ns = self._parse(["--path", str(f), "--key", "k", "--encrypt"])
        assert ns.workers == DEFAULT_WORKERS

    def test_custom_workers(self, tmp_path: Path) -> None:
        f = tmp_path / "f.txt"
        f.write_text("x")
        ns = self._parse(["--path", str(f), "--key", "k", "--encrypt", "--workers", "8"])
        assert ns.workers == 8

    def test_recursive_default_false(self, tmp_path: Path) -> None:
        f = tmp_path / "f.txt"
        f.write_text("x")
        ns = self._parse(["--path", str(f), "--key", "k", "--encrypt"])
        assert ns.recursive is False

    def test_recursive_flag(self, tmp_path: Path) -> None:
        ns = self._parse(["--path", str(tmp_path), "--key", "k", "--encrypt", "-r"])
        assert ns.recursive is True

    def test_both_operations_mutually_exclusive(self, tmp_path: Path) -> None:
        f = tmp_path / "f.txt"
        f.write_text("x")
        with pytest.raises(SystemExit):
            self._parse(["--path", str(f), "--key", "k", "--encrypt", "--decrypt"])

    def test_missing_path_exits(self) -> None:
        with pytest.raises(SystemExit):
            self._parse(["--key", "k", "--encrypt"])

    def test_missing_key_exits(self, tmp_path: Path) -> None:
        f = tmp_path / "f.txt"
        f.write_text("x")
        with pytest.raises(SystemExit):
            self._parse(["--path", str(f), "--encrypt"])

    def test_missing_operation_exits(self, tmp_path: Path) -> None:
        f = tmp_path / "f.txt"
        f.write_text("x")
        with pytest.raises(SystemExit):
            self._parse(["--path", str(f), "--key", "k"])

    def test_resolve_operation_encrypt(self, tmp_path: Path) -> None:
        f = tmp_path / "f.txt"
        f.write_text("x")
        ns = self._parse(["--path", str(f), "--key", "k", "--encrypt"])
        assert resolve_operation(ns) == "encrypt"

    def test_resolve_operation_decrypt(self, tmp_path: Path) -> None:
        f = tmp_path / "f.txt.vt"
        f.write_text("x")
        ns = self._parse(["--path", str(f), "--key", "k", "--decrypt"])
        assert resolve_operation(ns) == "decrypt"


# ---------------------------------------------------------------------------
# validate_key
# ---------------------------------------------------------------------------


class TestValidateKey:
    def test_valid_key(self) -> None:
        validate_key("valid-key")  # Must not raise

    def test_empty_string_raises(self) -> None:
        with pytest.raises(ValidationError):
            validate_key("")

    def test_whitespace_only_raises(self) -> None:
        with pytest.raises(ValidationError):
            validate_key("   ")

    def test_tab_only_raises(self) -> None:
        with pytest.raises(ValidationError):
            validate_key("\t\n")

    def test_exceeds_max_length_raises(self) -> None:
        from src.crypto.constants import KEY_MAX_LENGTH
        with pytest.raises(ValidationError, match="too long"):
            validate_key("a" * (KEY_MAX_LENGTH + 1))

    def test_exactly_max_length_valid(self) -> None:
        from src.crypto.constants import KEY_MAX_LENGTH
        validate_key("a" * KEY_MAX_LENGTH)  # Must not raise

    def test_single_character_valid(self) -> None:
        validate_key("x")

    def test_unicode_key_valid(self) -> None:
        validate_key("пароль-🔑-密码-عربي")

    def test_key_with_spaces_valid(self) -> None:
        validate_key("a key with spaces inside")


# ---------------------------------------------------------------------------
# validate_workers
# ---------------------------------------------------------------------------


class TestValidateWorkers:
    def test_positive_integer_valid(self) -> None:
        validate_workers(1)
        validate_workers(4)
        validate_workers(100)

    def test_zero_raises(self) -> None:
        with pytest.raises(ValidationError):
            validate_workers(0)

    def test_negative_raises(self) -> None:
        with pytest.raises(ValidationError):
            validate_workers(-1)


# ---------------------------------------------------------------------------
# validate_path
# ---------------------------------------------------------------------------


class TestValidatePath:
    def test_valid_txt_encrypt(self, sample_txt: Path) -> None:
        result = validate_path(str(sample_txt), "encrypt")
        assert result == sample_txt

    def test_valid_md_encrypt(self, sample_md: Path) -> None:
        result = validate_path(str(sample_md), "encrypt")
        assert result == sample_md

    def test_valid_directory(self, tmp_path: Path) -> None:
        result = validate_path(str(tmp_path), "encrypt")
        assert result == tmp_path

    def test_nonexistent_path_raises(self) -> None:
        with pytest.raises(ValidationError, match="does not exist"):
            validate_path("/nonexistent/path/file.txt", "encrypt")

    def test_unsupported_extension_raises(self, tmp_path: Path) -> None:
        f = tmp_path / "image.jpg"
        f.write_bytes(b"data")
        with pytest.raises(ValidationError, match="Unsupported"):
            validate_path(str(f), "encrypt")

    def test_encrypted_file_for_encrypt_raises(self, tmp_path: Path) -> None:
        f = tmp_path / "notes.txt.vt"
        f.write_bytes(b"data")
        with pytest.raises(ValidationError, match="already encrypted"):
            validate_path(str(f), "encrypt")

    def test_plaintext_file_for_decrypt_raises(self, sample_txt: Path) -> None:
        with pytest.raises(ValidationError, match="not encrypted"):
            validate_path(str(sample_txt), "decrypt")

    def test_vt_file_for_decrypt_valid(self, tmp_path: Path) -> None:
        f = tmp_path / "notes.txt.vt"
        f.write_bytes(b"data")
        result = validate_path(str(f), "decrypt")
        assert result == f
