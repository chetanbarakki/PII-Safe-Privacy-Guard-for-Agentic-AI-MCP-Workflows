"""
sanitizer/redactor.py
----------------------
Replaces detected PII spans with [REDACTED] placeholders.
Works on both free text (string) and JSON/dict structures.
"""

from __future__ import annotations
from typing import Any

from detector.entity_detector import detect, DetectedEntity


REDACT_PLACEHOLDER = "[REDACTED]"


def redact_text(text: str, entities: list[DetectedEntity] | None = None) -> str:
    """
    Replace all PII spans in *text* with [REDACTED].

    If *entities* is provided, uses those instead of re-running detection.
    Processes spans in reverse order to preserve character offsets.
    """
    if entities is None:
        entities = detect(text)

    if not entities:
        return text

    # Sort by start descending so replacements don't shift earlier offsets
    sorted_entities = sorted(entities, key=lambda e: e.start, reverse=True)

    result = text
    for entity in sorted_entities:
        result = result[: entity.start] + REDACT_PLACEHOLDER + result[entity.end :]

    return result


def redact_value(value: str) -> str:
    """Redact a single known-PII string value entirely."""
    return REDACT_PLACEHOLDER


def redact_schema(data: Any, fields_to_redact: set[str] | None = None) -> Any:
    """
    Recursively walk a dict/list and redact:
      - String values in keys listed in *fields_to_redact*
      - All detected PII in any string value (if fields_to_redact is None)

    Returns a new structure (does not mutate the original).
    """
    if isinstance(data, dict):
        return {
            key: _redact_dict_value(key, value, fields_to_redact)
            for key, value in data.items()
        }
    elif isinstance(data, list):
        return [redact_schema(item, fields_to_redact) for item in data]
    else:
        return data


def _redact_dict_value(key: str, value: Any, fields_to_redact: set[str] | None) -> Any:
    if isinstance(value, str):
        if fields_to_redact is not None and key in fields_to_redact:
            return REDACT_PLACEHOLDER
        elif fields_to_redact is None:
            return redact_text(value)
        return value
    elif isinstance(value, (dict, list)):
        return redact_schema(value, fields_to_redact)
    return value
