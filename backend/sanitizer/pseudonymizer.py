"""
sanitizer/pseudonymizer.py
---------------------------
Replaces PII values with CONSISTENT fake tokens within a session.

Key property: the same raw value ALWAYS maps to the same token
within one PseudonymSession. This lets an AI reason:
  "USER_01 failed login 3 times" 
without ever knowing USER_01 is john@company.com.

Token formats by entity type:
  EMAIL       →  USER_01, USER_02, ...
  IP_ADDRESS  →  IP_01, IP_02, ...
  PERSON      →  PERSON_01, PERSON_02, ...
  PHONE       →  PHONE_01, PHONE_02, ...
  USERNAME    →  USER_01, USER_02, ...  (shared with EMAIL counter)
  CUSTOMER_ID →  CUSTOMER_01, ...
  ORGANIZATION→  ORG_01, ...
  LOCATION    →  LOC_01, ...
  (default)   →  ENTITY_01, ...

A PseudonymSession can be serialised to / restored from a dict so that
mappings survive across API requests for the same "case" or "incident".
"""

from __future__ import annotations
from collections import defaultdict
from typing import Any

from detector.entity_detector import detect, DetectedEntity


# Maps entity_type → token prefix
_PREFIX_MAP: dict[str, str] = {
    "EMAIL":        "USER",
    "USERNAME":     "USER",
    "IP_ADDRESS":   "IP",
    "PERSON":       "PERSON",
    "PHONE":        "PHONE",
    "CUSTOMER_ID":  "CUSTOMER",
    "ORGANIZATION": "ORG",
    "LOCATION":     "LOC",
    "CREDIT_CARD":  "CARD",
    "SSN":          "SSN",
    "URL":          "URL",
}
_DEFAULT_PREFIX = "ENTITY"


class PseudonymSession:
    """
    Holds the value→token mapping for one session / incident.

    Thread-safety: not thread-safe by design (single-request use).
    For concurrent use, create one session per request or add locking.
    """

    def __init__(self, existing_mapping: dict | None = None):
        # value → token  (e.g.  "john@x.com" → "USER_01")
        self._map: dict[str, str] = {}
        # prefix → current counter  (e.g.  "USER" → 2)
        self._counters: dict[str, int] = defaultdict(int)

        if existing_mapping:
            self._restore(existing_mapping)

    # ── Public API ────────────────────────────────────────────────────────────
    def pseudonymize_text(
        self,
        text: str,
        entities: list[DetectedEntity] | None = None,
        only_types: set[str] | None = None,
    ) -> str:
        """
        Replace PII spans in *text* with consistent tokens.

        *only_types*: if provided, only pseudonymize entities of those types.
        Other entity types are left untouched (caller handles them separately).
        """
        if entities is None:
            entities = detect(text)

        if not entities:
            return text

        filtered = entities
        if only_types:
            filtered = [e for e in entities if e.entity_type in only_types]

        # Process in reverse to keep offsets valid
        sorted_entities = sorted(filtered, key=lambda e: e.start, reverse=True)
        result = text
        for entity in sorted_entities:
            token = self._get_or_create_token(entity.value, entity.entity_type)
            result = result[: entity.start] + token + result[entity.end :]

        return result

    def pseudonymize_value(self, value: str, entity_type: str) -> str:
        """Pseudonymize a single known-PII value."""
        return self._get_or_create_token(value, entity_type)

    def pseudonymize_schema(
        self,
        data: Any,
        fields_to_pseudonymize: dict[str, str] | None = None,
    ) -> Any:
        """
        Recursively pseudonymize a dict/list.

        *fields_to_pseudonymize*: {field_name: entity_type}
        If None, scans every string value with the detector.
        """
        if isinstance(data, dict):
            return {
                key: self._pseudo_dict_value(key, value, fields_to_pseudonymize)
                for key, value in data.items()
            }
        elif isinstance(data, list):
            return [self.pseudonymize_schema(item, fields_to_pseudonymize) for item in data]
        return data

    def get_mapping(self) -> dict[str, str]:
        """Return a copy of the current value→token mapping (for audit log)."""
        return dict(self._map)

    def reverse_lookup(self, token: str) -> str | None:
        """Given a token, return the original value (for authorised re-identification)."""
        for value, t in self._map.items():
            if t == token:
                return value
        return None

    def export_state(self) -> dict:
        """Serialise session state for persistence across requests."""
        return {
            "map": dict(self._map),
            "counters": dict(self._counters),
        }

    # ── Internal ──────────────────────────────────────────────────────────────
    def _get_or_create_token(self, value: str, entity_type: str) -> str:
        if value in self._map:
            return self._map[value]
        prefix = _PREFIX_MAP.get(entity_type, _DEFAULT_PREFIX)
        self._counters[prefix] += 1
        token = f"{prefix}_{self._counters[prefix]:02d}"
        self._map[value] = token
        return token

    def _pseudo_dict_value(self, key: str, value: Any, fields: dict | None) -> Any:
        if isinstance(value, str):
            if fields is not None and key in fields:
                return self._get_or_create_token(value, fields[key])
            elif fields is None:
                # Scan and pseudonymize all detected PII
                entities = detect(value)
                return self.pseudonymize_text(value, entities)
            return value
        elif isinstance(value, (dict, list)):
            return self.pseudonymize_schema(value, fields)
        return value

    def _restore(self, state: dict) -> None:
        self._map = dict(state.get("map", {}))
        self._counters = defaultdict(int, state.get("counters", {}))
