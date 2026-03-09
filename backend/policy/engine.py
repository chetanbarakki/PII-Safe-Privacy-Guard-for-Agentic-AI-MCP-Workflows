from __future__ import annotations
import os
from dataclasses import dataclass
from typing import List
import yaml


RULES_FILE = os.path.join(os.path.dirname(__file__), "rules.yaml")

VALID_ACTIONS = {"allow", "pseudonymize", "redact", "block"}


@dataclass
class PolicyDecision:
    action: str         # allow | pseudonymize | redact | block
    reason: str         # human-readable explanation
    matched_rule: dict  # the raw rule that matched (for debugging)

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "reason": self.reason,
        }

class PolicyEngine:
    def __init__(self, rules_path: str = RULES_FILE):
        print(f"Loading policy rules from {rules_path}...")
        self._rules: List[dict] = self._load(rules_path)

    def evaluate(self, operation: str, entity_type: str) -> PolicyDecision:
        operation = operation.lower().strip()
        entity_type = entity_type.upper().strip()

        for rule in self._rules:
            rule_op = str(rule.get("operation", "*")).strip()
            rule_et = str(rule.get("entity_type", "*")).strip().upper()
            op_match = rule_op == "*" or rule_op.lower() == operation
            et_match = rule_et == "*" or rule_et == entity_type
            print(f"Evaluating rule: op_match={op_match}, et_match={et_match}, rule_op={rule_op}, rule_et={rule_et}")
            if op_match and et_match:
                action = rule.get("action", "redact")
                if action not in VALID_ACTIONS:
                    action = "redact"
                return PolicyDecision(
                    action=action,
                    reason=rule.get("reason", "Policy rule matched."),
                    matched_rule=rule,
                )

        # No rule matched → safe default
        return PolicyDecision(
            action="redact",
            reason="No matching rule found; defaulting to redact.",
            matched_rule={},
        )

    def evaluate_all(self, operation: DetectedEntity, entity_types: List[str]) -> dict[str, PolicyDecision]:
        """Evaluate a list of entity types at once. Returns {entity_type: decision}."""
        return {et: self.evaluate(operation, et) for et in entity_types}

    def reload(self, rules_path: str = RULES_FILE) -> None:
        """Reload rules from disk (useful for hot-reload in development)."""
        self._rules = self._load(rules_path)

    # ── Internal ──────────────────────────────────────────────────────────────
    @staticmethod
    def _load(path: str) -> List[dict]:
        with open(path, "r") as f:
            data = yaml.safe_load(f)
        rules = data.get("rules", [])
        if not isinstance(rules, list):
            raise ValueError(f"rules.yaml must contain a top-level 'rules' list.")
        return rules
