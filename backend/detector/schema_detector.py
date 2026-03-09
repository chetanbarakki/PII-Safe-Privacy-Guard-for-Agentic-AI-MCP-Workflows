"""
detector/schema_detector.py
----------------------------
Walks a JSON/dict structure recursively and detects PII at the field level.

Combines two signals:
  1. Field-name heuristics  – "email", "ip", "phone" in the key name
  2. Value-level detection  – runs entity_detector.detect() on string values

Returns a list of SchemaEntity objects describing where PII was found.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Any, List

from detector.entity_detector import detect, DetectedEntity


# ── Field-name heuristics ────────────────────────────────────────────────────
# Maps lowercase substrings found in key names → assumed entity type
_FIELD_HINTS: dict[str, str] = {
    "email":    "EMAIL",
    "mail":     "EMAIL",
    "phone":    "PHONE",
    "mobile":   "PHONE",
    "cell":     "PHONE",
    "ip":       "IP_ADDRESS",
    "address":  "IP_ADDRESS",   # will be overridden if value doesn't look like IP
    "ssn":      "SSN",
    "social":   "SSN",
    "card":     "CREDIT_CARD",
    "credit":   "CREDIT_CARD",
    "user":     "USERNAME",
    "username": "USERNAME",
    "name":     "PERSON",
    "customer": "CUSTOMER_ID",
    "cust":     "CUSTOMER_ID",
    "url":      "URL",
    "link":     "URL",
    "href":     "URL",
}

# Field names that should not be treated as PII carriers by heuristics/value scan.
_FIELD_BLOCKLIST: set[str] = {
    "user_agent",
    "useragent",
}


@dataclass
class SchemaEntity:
    json_path: str          # e.g. "user.contact.email"
    field_name: str         # e.g. "email"
    value: str              # raw value
    entity_type: str        # e.g. EMAIL
    detection_method: str   # "field_hint" | "value_scan" | "both"
    sub_entities: List[DetectedEntity] = None  # from value-level scan

    def to_dict(self) -> dict:
        return {
            "json_path": self.json_path,
            "field_name": self.field_name,
            "value": self.value,
            "entity_type": self.entity_type,
            "detection_method": self.detection_method,
            "sub_entities": [e.to_dict() for e in (self.sub_entities or [])],
        }


# ── Main function ────────────────────────────────────────────────────────────
def detect_in_schema(data: Any, path: str = "") -> List[SchemaEntity]:
    """
    Recursively walk *data* (dict, list, or scalar) and return all
    SchemaEntity objects found.
    """
    results: List[SchemaEntity] = []

    if isinstance(data, dict):
        for key, value in data.items():
            current_path = f"{path}.{key}" if path else key
            results.extend(_process_field(key, value, current_path))
            # Recurse into nested structures
            if isinstance(value, (dict, list)):
                results.extend(detect_in_schema(value, current_path))

    elif isinstance(data, list):
        for idx, item in enumerate(data):
            results.extend(detect_in_schema(item, f"{path}[{idx}]"))

    return results


# ── Internal helpers ─────────────────────────────────────────────────────────
def _process_field(key: str, value: Any, path: str) -> List[SchemaEntity]:
    if not isinstance(value, str):
        return []

    results = []
    key_lower = key.lower()
    if key_lower in _FIELD_BLOCKLIST:
        return []

    # --- signal 1: field-name hint ---
    hint_type: str | None = None
    for hint_key, etype in _FIELD_HINTS.items():
        if hint_key in key_lower:
            hint_type = etype
            break

    # --- signal 2: value-level scan ---
    sub_entities = detect(value)
    scan_types = {e.entity_type for e in sub_entities}

    if hint_type and scan_types:
        method = "both"
        entity_type = hint_type  # field hint takes precedence
    elif hint_type:
        method = "field_hint"
        entity_type = hint_type
    elif scan_types:
        method = "value_scan"
        entity_type = next(iter(scan_types))  # first detected type
    else:
        return []  # nothing found

    results.append(
        SchemaEntity(
            json_path=path,
            field_name=key,
            value=value,
            entity_type=entity_type,
            detection_method=method,
            sub_entities=sub_entities,
        )
    )
    return results
