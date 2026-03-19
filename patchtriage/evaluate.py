"""Minimal evaluation harness for PatchTriage fixture corpora."""

from __future__ import annotations

import json

from .analyzer import analyze_diff
from .matcher import match_functions
from .triage import triage_diff


def evaluate_corpus(corpus: dict) -> dict:
    """Evaluate one or more fixture-driven binary-pair cases."""
    cases_out = []
    total_expected = 0
    total_correct = 0
    top3_hits = 0
    total_security_targets = 0

    for case in corpus.get("cases", []):
        features_a = case["features_a"]
        features_b = case["features_b"]
        stripped = case.get("stripped", False)

        match_data = match_functions(features_a, features_b, threshold=case.get("threshold", 0.3), stripped=stripped)
        diff_data = triage_diff(analyze_diff(features_a, features_b, match_data))

        matched_pairs = {(m["name_a"], m["name_b"]) for m in match_data["matches"]}
        expected_pairs = {tuple(pair) for pair in case.get("expected_matches", [])}
        correct = len(matched_pairs & expected_pairs)
        expected = len(expected_pairs)

        top_funcs = diff_data.get("functions", [])[:3]
        top_names = {f["name_a"] for f in top_funcs} | {f["name_b"] for f in top_funcs}
        security_targets = set(case.get("security_targets", []))
        hit = bool(top_names & security_targets)

        cases_out.append({
            "name": case.get("name", "unnamed"),
            "stripped": stripped,
            "expected_matches": expected,
            "correct_matches": correct,
            "match_precision": round(correct / len(matched_pairs), 3) if matched_pairs else 0.0,
            "match_recall": round(correct / expected, 3) if expected else 0.0,
            "top3_security_hit": hit,
        })

        total_expected += expected
        total_correct += correct
        total_security_targets += 1 if security_targets else 0
        top3_hits += 1 if hit and security_targets else 0

    return {
        "summary": {
            "cases": len(cases_out),
            "match_recall": round(total_correct / total_expected, 3) if total_expected else 0.0,
            "top3_security_hit_rate": round(top3_hits / total_security_targets, 3) if total_security_targets else 0.0,
        },
        "cases": cases_out,
    }


def load_corpus(path: str) -> dict:
    with open(path) as f:
        return json.load(f)
