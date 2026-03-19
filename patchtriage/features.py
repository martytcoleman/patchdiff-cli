"""Feature-set helpers shared across extraction, matching, and evaluation."""

from __future__ import annotations

from .normalize import enrich_function_features


def enrich_feature_set(feature_data: dict) -> dict:
    """Return a copy of feature_data with derived features on every function."""
    enriched = dict(feature_data)
    enriched["functions"] = [enrich_function_features(func) for func in feature_data.get("functions", [])]
    enriched["feature_schema"] = "patchtriage.v2"
    return enriched
