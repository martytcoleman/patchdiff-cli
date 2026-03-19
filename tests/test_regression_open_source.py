"""Regression tests for the checked-in open-source sample corpus."""

from __future__ import annotations

import json
from pathlib import Path

from patchtriage.analyzer import analyze_diff
from patchtriage.matcher import match_functions
from patchtriage.triage import triage_diff


TARGETS = Path("targets/open_source")


def _load(name: str) -> dict:
    with open(TARGETS / name) as f:
        return json.load(f)


def test_open_source_sample_pipeline_regression():
    features_a = _load("features_v1.json")
    features_b = _load("features_v2.json")

    match_data = match_functions(features_a, features_b)
    diff_data = analyze_diff(features_a, features_b, match_data)
    triaged = triage_diff(diff_data)

    assert match_data["num_matches"] == 8
    assert match_data["num_unmatched_a"] == 1
    assert match_data["num_unmatched_b"] == 2
    assert triaged["unmatched_b"] == ["_parse_content_length", "_validate_path"]
    assert triaged["unmatched_a"] == ["_log_request"]

    top_names = [func["name_a"] for func in triaged["functions"][:3]]
    assert top_names == ["_parse_http_request", "_parse_request_line", "_url_decode"]
    assert all(func["triage_label"] == "security_fix_likely" for func in triaged["functions"][:3])


def test_open_source_sample_stripped_mode_still_finds_matches():
    features_a = _load("features_v1.json")
    features_b = _load("features_v2.json")

    for idx, func in enumerate(features_a["functions"]):
        func["name"] = f"FUN_A_{idx:04d}"
    for idx, func in enumerate(features_b["functions"]):
        func["name"] = f"FUN_B_{idx:04d}"

    match_data = match_functions(features_a, features_b, stripped=True)

    assert match_data["num_matches"] == 8
    assert match_data["num_unmatched_a"] == 1
    assert match_data["num_unmatched_b"] == 2
    assert all(match["method"] == "similarity_bipartite" for match in match_data["matches"])
