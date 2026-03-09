from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import List
import spacy


_NLP = spacy.load("en_core_web_sm")

@dataclass
class DetectedEntity:
    entity_type: str        # EMAIL | IP_ADDRESS | PHONE | PERSON | ORG | ...
    value: str              # raw matched text
    start: int              # char offset (start)
    end: int                # char offset (end, exclusive)
    confidence: float = 1.0 # 1.0 for regex; model probability for spaCy

    def to_dict(self) -> dict:
        return {
            "entity_type": self.entity_type,
            "value": self.value,
            "start": self.start,
            "end": self.end,
            "confidence": round(self.confidence, 3),
        }


_REGEX_PATTERNS: list[tuple[str, re.Pattern]] = [
    (
        "EMAIL",
        re.compile(
            r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
            re.IGNORECASE,
        ),
    ),
    (
        "IP_ADDRESS",
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        ),
    ),
    (
        "PHONE",
        re.compile(
            r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b"
        ),
    ),
    (
        "CREDIT_CARD",
        re.compile(
            r"\b(?:4[0-9]{12}(?:[0-9]{3})?|"          # Visa
            r"5[1-5][0-9]{14}|"                        # MC
            r"3[47][0-9]{13}|"                         # Amex
            r"6(?:011|5[0-9]{2})[0-9]{12})\b"          # Discover
        ),
    ),
    (
        "SSN",
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    ),
    (
        "URL",
        re.compile(
            r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?:/[^\s]*)?"
        ),
    ),
    (
        "USERNAME",
        re.compile(r"(?<!\w)@[A-Za-z0-9_]{3,30}\b"),
    ),
    (
        "CUSTOMER_ID",
        re.compile(r"\bCUST-\d{3,10}\b", re.IGNORECASE),
    ),
]

# spaCy label → our entity type mapping
_SPACY_LABEL_MAP = {
    "PERSON": "PERSON",
    "ORG":    "ORGANIZATION",
    "GPE":    "LOCATION",
    "LOC":    "LOCATION",
}

# Common English words that spaCy frequently misclassifies as PERSON
_SPACY_PERSON_BLOCKLIST = {
    "email", "phone", "call", "send", "check", "login", "user",
    "admin", "server", "alert", "error", "request", "response",
    "access", "data", "report", "log", "note", "status", "message",
    "contact", "notify", "info", "details", "subject", "body",
}

# Minimum spaCy confidence to accept a NER result (avoids weak guesses)
_SPACY_MIN_CONFIDENCE = 0.60


def detect(text: str) -> List[DetectedEntity]:
    entities: List[DetectedEntity] = []

    # 1. Regex pass — skip any match that overlaps an already-accepted entity
    for entity_type, pattern in _REGEX_PATTERNS:
        for match in pattern.finditer(text):
            if _overlaps_any(match.start(), match.end(), entities):
                continue
            entities.append(
                DetectedEntity(
                    entity_type=entity_type,
                    value=match.group(),
                    start=match.start(),
                    end=match.end(),
                    confidence=1.0,
                )
            )

    doc = _NLP(text)
    for ent in doc.ents:
        mapped = _SPACY_LABEL_MAP.get(ent.label_)
        if mapped is None:
            continue

        # Skip low-confidence predictions
        confidence = float(ent._.score) if ent.has_extension("score") else 0.85
        if confidence < _SPACY_MIN_CONFIDENCE:
            continue

        # Skip common words misclassified as PERSON
        if mapped == "PERSON" and ent.text.lower() in _SPACY_PERSON_BLOCKLIST:
            continue

        # Skip single-word PERSON tags that are ALL-CAPS (likely acronyms)
        if mapped == "PERSON" and ent.text.isupper() and len(ent.text) <= 5:
            continue

        # Skip if already covered by a regex match
        if _overlaps_any(ent.start_char, ent.end_char, entities):
            continue

        entities.append(
            DetectedEntity(
                entity_type=mapped,
                value=ent.text,
                start=ent.start_char,
                end=ent.end_char,
                confidence=round(confidence, 3),
            )
        )

    # Sort by position
    entities.sort(key=lambda e: e.start)
    return entities


def detect_types(text: str) -> List[str]:
    return list({e.entity_type for e in detect(text)})

def _overlaps_any(start: int, end: int, existing: List[DetectedEntity]) -> bool:
    for e in existing:
        if start < e.end and end > e.start:
            return True
    return False
