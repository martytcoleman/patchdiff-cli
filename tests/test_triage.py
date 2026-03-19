"""Tests for triage heuristics."""

from patchtriage.analyzer import analyze_match
from patchtriage.triage import triage_function


def test_unsafe_api_swap():
    func_diff = {
        "interestingness": 5.0,
        "signals": {
            "ext_calls_added": ["snprintf"],
            "ext_calls_removed": ["sprintf"],
            "calls_added": ["snprintf"],
            "calls_removed": ["sprintf"],
            "strings_added": [],
            "strings_removed": [],
            "constants_added": [],
            "size_delta_pct": 5.0,
            "blocks_delta": 1,
            "compare_delta": 0,
            "branch_delta": 0,
        },
    }
    result = triage_function(func_diff)
    assert result["triage_label"] in ("security_fix_likely", "security_fix_possible")
    assert any("sprintf" in r for r in result["rationale"])


def test_stack_protection_added():
    func_diff = {
        "interestingness": 3.0,
        "signals": {
            "ext_calls_added": [],
            "ext_calls_removed": [],
            "calls_added": ["__stack_chk_fail"],
            "calls_removed": [],
            "strings_added": [],
            "strings_removed": [],
            "constants_added": [],
            "size_delta_pct": 2.0,
            "blocks_delta": 1,
            "compare_delta": 0,
            "branch_delta": 0,
        },
    }
    result = triage_function(func_diff)
    assert "security" in result["triage_label"]
    assert any("stack" in r.lower() for r in result["rationale"])


def test_no_signals_unchanged():
    func_diff = {
        "interestingness": 0.0,
        "signals": {
            "ext_calls_added": [],
            "ext_calls_removed": [],
            "calls_added": [],
            "calls_removed": [],
            "strings_added": [],
            "strings_removed": [],
            "constants_added": [],
            "size_delta_pct": 0,
            "blocks_delta": 0,
            "compare_delta": 0,
            "branch_delta": 0,
        },
    }
    result = triage_function(func_diff)
    assert result["triage_label"] == "unchanged"
    assert result["confidence"] == 0.0


def test_error_strings_detected():
    func_diff = {
        "interestingness": 3.0,
        "signals": {
            "ext_calls_added": [],
            "ext_calls_removed": [],
            "calls_added": [],
            "calls_removed": [],
            "strings_added": ["buffer overflow detected", "invalid input"],
            "strings_removed": [],
            "constants_added": [],
            "size_delta_pct": 10.0,
            "blocks_delta": 0,
            "compare_delta": 0,
            "branch_delta": 0,
        },
    }
    result = triage_function(func_diff)
    assert any("error" in r.lower() or "string" in r.lower() for r in result["rationale"])


def test_behavior_change_used_for_non_security_structural_change():
    func_diff = {
        "interestingness": 3.0,
        "signals": {
            "ext_calls_added": [],
            "ext_calls_removed": [],
            "calls_added": ["matched:FUN_2000"],
            "calls_removed": [],
            "strings_added": [],
            "strings_removed": [],
            "constants_added": [],
            "size_delta_pct": 10.0,
            "blocks_delta": 1,
            "instr_delta": 8,
            "compare_delta": 0,
            "branch_delta": 0,
        },
    }
    result = triage_function(func_diff)
    assert result["triage_label"] == "behavior_change"


def test_validation_style_growth_can_be_security_possible():
    func_diff = {
        "interestingness": 6.0,
        "signals": {
            "ext_calls_added": [],
            "ext_calls_removed": [],
            "calls_added": [],
            "calls_removed": [],
            "strings_added": ["invalid path"],
            "strings_removed": [],
            "constants_added": [],
            "size_delta_pct": 12.0,
            "blocks_delta": 3,
            "instr_delta": 10,
            "compare_delta": 2,
            "branch_delta": 3,
            "api_families_added": ["validation"],
            "string_categories_added": ["error", "path"],
        },
    }
    result = triage_function(func_diff)
    assert result["triage_label"] in ("security_fix_possible", "security_fix_likely")


def test_synthetic_light_backend_scope_uses_behavior_label():
    func_diff = {
        "name_a": "section:__TEXT:__text",
        "name_b": "section:__TEXT:__text",
        "interestingness": 1.2,
        "signals": {
            "ext_calls_added": [],
            "ext_calls_removed": [],
            "calls_added": [],
            "calls_removed": [],
            "strings_added": ["executable section"],
            "strings_removed": [],
            "constants_added": [],
            "size_delta_pct": 0.1,
            "blocks_delta": 0,
            "instr_delta": 0,
            "compare_delta": 0,
            "branch_delta": 0,
        },
    }
    result = triage_function(func_diff)
    assert result["triage_label"] == "behavior_change"


def test_analyze_match_ignores_auto_internal_call_address_churn():
    func_a = {
        "called_functions": [
            {"name": "FUN_1000", "entry": "0x1000", "is_external": False},
            {"name": "printf", "entry": None, "is_external": True},
        ],
        "strings": [],
        "constants": [],
        "constant_buckets": [],
        "api_families": [],
        "string_categories": [],
        "mnemonic_hist": {},
        "size": 100,
        "block_count": 10,
        "instr_count": 20,
    }
    func_b = {
        "called_functions": [
            {"name": "FUN_2000", "entry": "0x2000", "is_external": False},
            {"name": "printf", "entry": None, "is_external": True},
        ],
        "strings": [],
        "constants": [],
        "constant_buckets": [],
        "api_families": [],
        "string_categories": [],
        "mnemonic_hist": {},
        "size": 100,
        "block_count": 10,
        "instr_count": 20,
    }
    signals = analyze_match(
        func_a,
        func_b,
        map_entry_a_to_b={"0x1000": "0x2000"},
        map_entry_b_to_a={"0x2000": "0x1000"},
        map_a_to_b={"FUN_1000": "FUN_2000"},
        map_b_to_a={"FUN_2000": "FUN_1000"},
    )
    assert signals["calls_added"] == []
    assert signals["calls_removed"] == []
