"""Tests for src.storage.scanner — file discovery and grouping."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.storage.scanner import group_by_directory, scan_files


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_files(base: Path, names: list[str]) -> list[Path]:
    files = []
    for name in names:
        f = base / name
        f.write_text("content", encoding="utf-8")
        files.append(f)
    return files


# ---------------------------------------------------------------------------
# scan_files — encrypt mode
# ---------------------------------------------------------------------------


class TestScanEncrypt:
    def test_finds_txt_and_md(self, tmp_path: Path) -> None:
        _make_files(tmp_path, ["a.txt", "b.md", "c.txt", "d.md"])
        result = scan_files(tmp_path, "encrypt", recursive=False)
        names = {f.name for f in result}
        assert names == {"a.txt", "b.md", "c.txt", "d.md"}

    def test_ignores_vt_files(self, tmp_path: Path) -> None:
        _make_files(tmp_path, ["a.txt", "a.txt.vt", "b.md", "b.md.vt"])
        result = scan_files(tmp_path, "encrypt", recursive=False)
        names = {f.name for f in result}
        assert "a.txt.vt" not in names
        assert "b.md.vt" not in names

    def test_ignores_other_extensions(self, tmp_path: Path) -> None:
        _make_files(tmp_path, ["image.png", "doc.pdf", "notes.txt"])
        result = scan_files(tmp_path, "encrypt", recursive=False)
        names = {f.name for f in result}
        assert names == {"notes.txt"}

    def test_empty_directory_returns_empty(self, tmp_path: Path) -> None:
        assert scan_files(tmp_path, "encrypt", recursive=False) == []

    def test_returns_sorted(self, tmp_path: Path) -> None:
        _make_files(tmp_path, ["z.txt", "a.txt", "m.md"])
        result = scan_files(tmp_path, "encrypt", recursive=False)
        assert result == sorted(result)


# ---------------------------------------------------------------------------
# scan_files — decrypt mode
# ---------------------------------------------------------------------------


class TestScanDecrypt:
    def test_finds_txt_vt_and_md_vt(self, tmp_path: Path) -> None:
        _make_files(tmp_path, ["a.txt.vt", "b.md.vt", "other.txt"])
        result = scan_files(tmp_path, "decrypt", recursive=False)
        names = {f.name for f in result}
        assert names == {"a.txt.vt", "b.md.vt"}

    def test_ignores_plaintext_files(self, tmp_path: Path) -> None:
        _make_files(tmp_path, ["a.txt", "b.md"])
        assert scan_files(tmp_path, "decrypt", recursive=False) == []


# ---------------------------------------------------------------------------
# Recursive behaviour
# ---------------------------------------------------------------------------


class TestRecursive:
    def test_recursive_finds_nested_files(self, tmp_path: Path) -> None:
        sub = tmp_path / "sub"
        sub.mkdir()
        _make_files(tmp_path, ["root.txt"])
        _make_files(sub, ["nested.md"])
        result = scan_files(tmp_path, "encrypt", recursive=True)
        names = {f.name for f in result}
        assert names == {"root.txt", "nested.md"}

    def test_non_recursive_ignores_subdirs(self, tmp_path: Path) -> None:
        sub = tmp_path / "sub"
        sub.mkdir()
        _make_files(tmp_path, ["root.txt"])
        _make_files(sub, ["nested.txt"])
        result = scan_files(tmp_path, "encrypt", recursive=False)
        names = {f.name for f in result}
        assert names == {"root.txt"}

    def test_deeply_nested_recursive(self, tmp_path: Path) -> None:
        deep = tmp_path / "a" / "b" / "c"
        deep.mkdir(parents=True)
        _make_files(deep, ["deep.txt"])
        result = scan_files(tmp_path, "encrypt", recursive=True)
        assert len(result) == 1 and result[0].name == "deep.txt"


# ---------------------------------------------------------------------------
# Single file passthrough
# ---------------------------------------------------------------------------


class TestSingleFile:
    def test_single_file_returned_as_is(self, sample_txt: Path) -> None:
        result = scan_files(sample_txt, "encrypt", recursive=False)
        assert result == [sample_txt]

    def test_single_file_recursive_ignored(self, sample_txt: Path) -> None:
        """--recursive is silently ignored for single-file paths."""
        assert scan_files(sample_txt, "encrypt", recursive=True) == [sample_txt]


# ---------------------------------------------------------------------------
# group_by_directory
# ---------------------------------------------------------------------------


class TestGroupByDirectory:
    def test_groups_correctly(self, tmp_path: Path) -> None:
        sub = tmp_path / "sub"
        sub.mkdir()
        files = _make_files(tmp_path, ["a.txt"]) + _make_files(sub, ["b.txt"])
        grouped = group_by_directory(files)
        assert set(grouped.keys()) == {tmp_path, sub}
        assert any(f.name == "a.txt" for f in grouped[tmp_path])
        assert any(f.name == "b.txt" for f in grouped[sub])

    def test_empty_list_returns_empty_dict(self) -> None:
        assert group_by_directory([]) == {}
