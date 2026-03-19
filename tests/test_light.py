"""Tests for the light extraction backend."""

from __future__ import annotations

from patchtriage.light import (
    _group_import_families,
    _parse_mnemonic,
    run_light_extract,
)


def test_light_extract_produces_coarse_feature_file(tmp_path):
    binary = tmp_path / "mini.bin"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 128 + b"hello world error invalid path")
    output = tmp_path / "mini_features.json"
    data = run_light_extract(str(binary), str(output), reuse_cached=False)
    assert output.exists()
    assert data["backend"] == "light"
    assert data["analysis_profile"] == "light"
    assert any(func["name"] == "__binary__" for func in data["functions"])


def test_parse_mnemonic_handles_objdump_line():
    assert _parse_mnemonic("   100003f54:\td10043ff \tsub\tsp, sp, #0x10") == "sub"
    assert _parse_mnemonic("not an instruction line") is None


def test_group_import_families_buckets_useful_symbols():
    grouped = _group_import_families(["strcpy", "malloc", "fopen", "custom_helper"])
    assert "string" in grouped
    assert "memory" in grouped
    assert "file" in grouped
    assert "other" in grouped
