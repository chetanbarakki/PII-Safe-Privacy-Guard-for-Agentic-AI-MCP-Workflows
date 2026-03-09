"""
api/pipeline.py
---------------
The central pipeline that connects all components.

Given raw text + operation type, it:
  1. Detects all PII entities
  2. Evaluates policy for each entity type
  3. Applies the appropriate sanitization action
  4. Computes a risk score
  5. Returns a structured SanitizationResult

This is the single function both the FastAPI server and the MCP server call.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any
from detector.entity_detector import detect, DetectedEntity
from detector.schema_detector import detect_in_schema
from policy.engine import PolicyEngine, PolicyDecision
from sanitizer.redactor import redact_text, REDACT_PLACEHOLDER
from sanitizer.pseudonymizer import PseudonymSession
from sanitizer.risk_scorer import score_entities, risk_label


# Singleton policy engine (rules loaded once at import time)
_ENGINE = PolicyEngine()


@dataclass
class EntityAction:
    entity_type: str
    action: str        # allow | pseudonymize | redact | block
    reason: str
    count: int = 0     # how many instances of this type were found


@dataclass
class SanitizationResult:
    original_text: str
    sanitized_text: str
    operation: str
    entities_found: list[EntityAction]
    risk_score: float
    risk_label: str
    was_blocked: bool = False
    block_reason: str = ""
    pseudonym_mapping: dict = field(default_factory=dict)  # only for authorised callers
    audit_log: list[dict] = field(default_factory=list)

    def to_dict(self, include_mapping: bool = False) -> dict:
        return {
            "sanitized": self.sanitized_text,
            "operation": self.operation,
            "was_blocked": self.was_blocked,
            "block_reason": self.block_reason,
            "risk_score": self.risk_score,
            "risk_label": self.risk_label,
            "entities_found": [
                {
                    "entity_type": e.entity_type,
                    "action": e.action,
                    "reason": e.reason,
                    "count": e.count,
                }
                for e in self.entities_found
            ],
            **({"pseudonym_mapping": self.pseudonym_mapping} if include_mapping else {}),
            "audit_log": self.audit_log,
        }


def run_pipeline(
    text: str,
    operation: str,
    session: PseudonymSession | None = None,
    reload_rules: bool = False,
) -> SanitizationResult:
    """
    Full sanitization pipeline for free text.

    Args:
        text:         Raw input text that may contain PII.
        operation:    One of: analysis, export, storage, logging.
        session:      Existing PseudonymSession for cross-request consistency.
                      If None, a new session is created (single-request scope).
        reload_rules: If True, reload policy rules from disk before evaluation.

    Returns:
        SanitizationResult with sanitized text and full audit information.
    """
    if reload_rules:
        _ENGINE.reload()

    if session is None:
        session = PseudonymSession()

    # ── 1. Detect all entities ───────────────────────────────────────────────
    entities: list[DetectedEntity] = detect(text)

    if not entities:
        score, _ = score_entities([])
        return SanitizationResult(
            original_text=text,
            sanitized_text=text,
            operation=operation,
            entities_found=[],
            risk_score=0.0,
            risk_label="NONE",
            audit_log=[{"step": "detection", "result": "no PII found"}],
        )

    # ── 2. Evaluate policy for each unique entity type ───────────────────────
    unique_types = list({e.entity_type for e in entities})
    decisions: dict[str, PolicyDecision] = _ENGINE.evaluate_all(operation, unique_types)

    # ── 3. Check for block decisions first ───────────────────────────────────
    for entity_type, decision in decisions.items():
        if decision.action == "block":
            count = sum(1 for e in entities if e.entity_type == entity_type)
            return SanitizationResult(
                original_text=text,
                sanitized_text="[BLOCKED]",
                operation=operation,
                entities_found=[
                    EntityAction(
                        entity_type=entity_type,
                        action="block",
                        reason=decision.reason,
                        count=count,
                    )
                ],
                risk_score=1.0,
                risk_label="CRITICAL",
                was_blocked=True,
                block_reason=decision.reason,
                audit_log=[
                    {
                        "step": "policy",
                        "entity_type": entity_type,
                        "action": "block",
                        "reason": decision.reason,
                    }
                ],
            )

    # ── 4. Apply sanitization per entity ─────────────────────────────────────
    # Separate entities by action (process in reverse position order)
    redact_entities = [e for e in entities if decisions[e.entity_type].action == "redact"]
    pseudo_entities = [e for e in entities if decisions[e.entity_type].action == "pseudonymize"]
    # "allow" entities are left as-is

    # Apply pseudonymization first (also in reverse offset order internally)
    sanitized = text
    if pseudo_entities:
        pseudo_types = {e.entity_type for e in pseudo_entities}
        sanitized = session.pseudonymize_text(sanitized, entities, only_types=pseudo_types)

    # Re-detect positions after pseudonymization (offsets may have shifted)
    if redact_entities:
        # Re-run detection to get fresh offsets after pseudonymization
        fresh_entities = detect(sanitized)
        redact_types = {e.entity_type for e in redact_entities}
        fresh_redact = [e for e in fresh_entities if e.entity_type in redact_types]
        sanitized = redact_text(sanitized, fresh_redact)

    # ── 5. Build entity action summary ───────────────────────────────────────
    entity_actions: list[EntityAction] = []
    for et in unique_types:
        count = sum(1 for e in entities if e.entity_type == et)
        decision = decisions[et]
        entity_actions.append(
            EntityAction(
                entity_type=et,
                action=decision.action,
                reason=decision.reason,
                count=count,
            )
        )

    # ── 6. Risk score ─────────────────────────────────────────────────────────
    score, _ = score_entities(unique_types)
    label = risk_label(score)

    # ── 7. Audit log ─────────────────────────────────────────────────────────
    audit = [
        {
            "step": "detection",
            "entities_found": [e.entity_type for e in entities],
        },
        {
            "step": "policy_evaluation",
            "operation": operation,
            "decisions": {et: d.action for et, d in decisions.items()},
        },
        {
            "step": "sanitization",
            "redacted_types": [e.entity_type for e in redact_entities],
            "pseudonymized_types": [e.entity_type for e in pseudo_entities],
        },
    ]

    return SanitizationResult(
        original_text=text,
        sanitized_text=sanitized,
        operation=operation,
        entities_found=entity_actions,
        risk_score=score,
        risk_label=label,
        pseudonym_mapping=session.get_mapping(),
        audit_log=audit,
    )


def run_pipeline_on_schema(
    data: Any,
    operation: str,
    session: PseudonymSession | None = None,
) -> dict:
    """
    Run the pipeline on a JSON/dict structure.
    Returns sanitized dict + metadata.
    """
    if session is None:

        session = PseudonymSession()

    schema_entities = detect_in_schema(data)
    if not schema_entities:
        return {"sanitized": data, "entities_found": [], "risk_score": 0.0}

    unique_types = list({e.entity_type for e in schema_entities})
    decisions = _ENGINE.evaluate_all(operation, unique_types)

    field_actions: dict[str, tuple[str, str]] = {}
    for entity in schema_entities:
        decision = decisions.get(entity.entity_type)
        if decision:
            field_actions[entity.json_path] = (decision.action, entity.entity_type)

    sanitized = _sanitize_schema_with_session(
        data=data,
        path="",
        field_actions=field_actions,
        session=session,
    )

    score, _ = score_entities(unique_types)
    return {
        "sanitized": sanitized,
        "entities_found": [
            {"field": e.json_path, "entity_type": e.entity_type, "action": decisions[e.entity_type].action}
            for e in schema_entities
        ],
        "risk_score": round(score, 3),
        "risk_label": risk_label(score),
    }


def _sanitize_schema_with_session(
    data: Any,
    path: str,
    field_actions: dict[str, tuple[str, str]],
    session: PseudonymSession,
) -> Any:
    if isinstance(data, dict):
        sanitized_dict: dict[str, Any] = {}
        for key, value in data.items():
            current_path = f"{path}.{key}" if path else key
            sanitized_dict[key] = _sanitize_schema_with_session(
                data=value,
                path=current_path,
                field_actions=field_actions,
                session=session,
            )
        return sanitized_dict

    if isinstance(data, list):
        return [
            _sanitize_schema_with_session(
                data=item,
                path=f"{path}[{idx}]",
                field_actions=field_actions,
                session=session,
            )
            for idx, item in enumerate(data)
        ]

    if isinstance(data, str):
        action_meta = field_actions.get(path)
        if not action_meta:
            return data

        action, entity_type = action_meta
        if action == "redact":
            return REDACT_PLACEHOLDER
        if action == "pseudonymize":
            entities = detect(data)
            if entities:
                return session.pseudonymize_text(data, entities, only_types={entity_type})
            return session.pseudonymize_value(data, entity_type)
        if action == "block":
            return "[BLOCKED]"
        return data

    return data
