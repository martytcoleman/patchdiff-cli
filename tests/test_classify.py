"""Tests for binary pre-scan classification and adaptive behavior."""

from __future__ import annotations

from pathlib import Path

from patchtriage.classify import classify_binary


def test_classify_go_like_binary_prefers_fast(tmp_path):
    binary = tmp_path / "go.bin"
    binary.write_bytes(b"\xfe\xed\xfa\xcf" + b"\x00" * 32 + b"Go buildinf: runtime.")
    info = classify_binary(str(binary))
    assert info["format"] == "macho"
    assert info["language"] == "go"
    assert info["recommended_profile"] == "fast"


def test_classify_small_unknown_binary_prefers_full(tmp_path):
    binary = tmp_path / "tiny.bin"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 128)
    info = classify_binary(str(binary))
    assert info["format"] == "elf"
    assert info["recommended_profile"] == "full"
