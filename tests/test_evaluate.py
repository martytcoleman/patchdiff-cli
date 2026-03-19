"""Tests for fixture-driven evaluation."""

from patchtriage.evaluate import evaluate_corpus


def _make_func(name, entry, size, strings=None, calls=None, hist=None):
    return {
        "name": name,
        "entry": entry,
        "size": size,
        "instr_count": max(size // 2, 1),
        "block_count": max(size // 10, 1),
        "mnemonic_hist": hist or {"mov": 10, "call": 3, "cmp": 2, "je": 1},
        "mnemonic_bigrams": {"cmp,je": 1},
        "strings": strings or [],
        "constants": [64],
        "called_functions": [{"name": c, "is_external": True} for c in (calls or [])],
        "callers": ["main"],
    }


def test_evaluate_corpus_reports_match_and_top3_metrics():
    corpus = {
        "cases": [
            {
                "name": "patched_http_parser",
                "stripped": True,
                "features_a": {
                    "binary": "a",
                    "functions": [
                        _make_func("FUN_1000", "0x1000", 120, strings=["bad request"], calls=["strcpy"]),
                        _make_func("FUN_2000", "0x2000", 80, strings=["ok"], calls=["write"]),
                    ],
                },
                "features_b": {
                    "binary": "b",
                    "functions": [
                        _make_func("FUN_3000", "0x3000", 150, strings=["invalid header", "bad request"], calls=["strncpy", "validate_header"]),
                        _make_func("FUN_4000", "0x4000", 82, strings=["ok"], calls=["write"]),
                    ],
                },
                "expected_matches": [["FUN_1000", "FUN_3000"], ["FUN_2000", "FUN_4000"]],
                "security_targets": ["FUN_1000", "FUN_3000"],
            }
        ]
    }

    result = evaluate_corpus(corpus)
    assert result["summary"]["cases"] == 1
    assert result["summary"]["match_recall"] == 1.0
    assert result["summary"]["top3_security_hit_rate"] == 1.0
