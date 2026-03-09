"""
sanitizer/risk_scorer.py
-------------------------
Computes a privacy risk score (0.0 – 1.0) for a piece of text or
a set of detected entity types.

Higher weight = higher privacy risk. Score is capped at 1.0.

Used in the API response so downstream systems can decide how
urgently to handle a piece of data.
"""

from __future__ import annotations

from detector.entity_detector import detect, DetectedEntity

# Weight per entity type (higher = more sensitive)
_WEIGHTS: dict[str, float] = {
    "SSN":          1.0,
    "CREDIT_CARD":  1.0,
    "PHONE":        0.7,
    "EMAIL":        0.6,
    "PERSON":       0.5,
    "IP_ADDRESS":   0.4,
    "USERNAME":     0.4,
    "CUSTOMER_ID":  0.4,
    "ORGANIZATION": 0.1,
    "LOCATION":     0.1,
    "URL":          0.05,
}
_DEFAULT_WEIGHT = 0.2


def score_text(text: str) -> tuple[float, list[str]]:
    """
    Detect PII in *text* and return (risk_score, list_of_entity_types).
    """
    entities = detect(text)
    return score_entities([e.entity_type for e in entities])


def score_entities(entity_types: list[str]) -> tuple[float, list[str]]:
    """
    Compute risk score from a list of entity type strings.
    Returns (score, deduplicated_entity_types).
    """
    unique_types = list(set(entity_types))
    total = sum(_WEIGHTS.get(et, _DEFAULT_WEIGHT) for et in unique_types)
    score = min(total, 1.0)
    return round(score, 3), unique_types


def risk_label(score: float) -> str:
    """Human-readable label for a numeric risk score."""
    if score >= 0.8:
        return "CRITICAL"
    elif score >= 0.5:
        return "HIGH"
    elif score >= 0.25:
        return "MEDIUM"
    elif score > 0.0:
        return "LOW"
    return "NONE"
