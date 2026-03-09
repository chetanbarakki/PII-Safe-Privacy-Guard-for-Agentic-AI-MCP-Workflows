from __future__ import annotations

from typing import Any


def summarize_logs(
    sanitized_text: str,
    operation: str,
    risk_label: str,
    entities_found: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Generate deterministic local incident-style summary from sanitized text."""
    entities_found = entities_found or []
    entity_types = sorted(
        {str(e.get("entity_type", "")).upper() for e in entities_found if e.get("entity_type")}
    )

    tokens = [w for w in sanitized_text.replace("\n", " ").split(" ") if w]
    event_hint = "authentication activity" if "login" in sanitized_text.lower() else "application event sequence"
    summary = (
        f"Sanitized logs indicate {event_hint} under operation '{operation}'. "
        f"Risk is {risk_label}. Detected entity types: {', '.join(entity_types) if entity_types else 'none'}."
    )

    findings = [
        f"Processed approximately {len(tokens)} tokens of sanitized log text.",
        "No raw PII is present in this summary path.",
    ]
    actions = [
        "Correlate repeated pseudonymized identities and source markers across log lines.",
        "Escalate to incident workflow if repeated failures or abnormal access patterns continue.",
        "Retain sanitized logs and restrict raw-log access to authorized investigators.",
    ]

    return {
        "summary": summary,
        "likely_incident_type": (
            "Suspicious Access Pattern" if "failed" in sanitized_text.lower() else "Operational Event"
        ),
        "priority": risk_label,
        "key_findings": findings,
        "recommended_actions": actions,
        "source": "local",
    }
