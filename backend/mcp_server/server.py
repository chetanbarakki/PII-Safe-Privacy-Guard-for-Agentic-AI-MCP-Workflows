from __future__ import annotations
import argparse
import json
import uuid
from typing import Any
from fastmcp import FastMCP
from api.analysis import summarize_logs
from api.pipeline import run_pipeline, run_pipeline_on_schema
from policy.engine import PolicyEngine
from sanitizer.pseudonymizer import PseudonymSession
from sanitizer.risk_scorer import risk_label, score_text

_sessions: dict[str, PseudonymSession] = {}
_policy_engine = PolicyEngine()


def _get_session(session_id: str | None) -> PseudonymSession | None:
    if not session_id:
        return None
    return _sessions.get(session_id)


def _persist_session(session_id: str | None, session: PseudonymSession | None) -> None:
    if session_id and session is not None:
        _sessions[session_id] = session


mcp = FastMCP(
    name="pii-safe",
    instructions=(
        "Sanitize text and JSON payloads before sending them to LLMs. "
        "Use sanitize_text or sanitize_json before model calls when data may include PII."
    ),
)


@mcp.tool(name="sanitize_text")
def sanitize_text(
    text: str,
    operation: str = "analysis",
    session_id: str | None = None,
) -> dict[str, Any]:
    """Detect and sanitize PII in free text."""
    session = _get_session(session_id)
    result = run_pipeline(text=text, operation=operation, session=session)
    _persist_session(session_id, session)
    return result.to_dict()


@mcp.tool(name="sanitize_json")
def sanitize_json(
    data: dict[str, Any],
    operation: str = "analysis",
    session_id: str | None = None,
) -> dict[str, Any]:
    """Detect and sanitize PII in a JSON object."""
    session = _get_session(session_id)
    result = run_pipeline_on_schema(data=data, operation=operation, session=session)
    _persist_session(session_id, session)
    return result


@mcp.tool(name="create_session")
def create_session(label: str = "") -> dict[str, str]:
    """Create a pseudonym session for consistent replacements across calls."""
    session_id = str(uuid.uuid4())
    _sessions[session_id] = PseudonymSession()
    return {"session_id": session_id, "label": label}


@mcp.tool(name="get_session_mapping")
def get_session_mapping(session_id: str) -> dict[str, Any]:
    """Return pseudonym mapping for a session."""
    session = _sessions.get(session_id)
    if not session:
        return {"error": f"Session '{session_id}' not found."}
    return {"session_id": session_id, "mapping": session.get_mapping()}


@mcp.tool(name="evaluate_policy")
def evaluate_policy(operation: str, entity_type: str) -> dict[str, str]:
    """Return policy decision for an entity type in a given operation context."""
    decision = _policy_engine.evaluate(operation, entity_type)
    return decision.to_dict()


@mcp.tool(name="score_risk")
def score_risk(text: str) -> dict[str, Any]:
    """Compute privacy risk score without sanitizing the text."""
    score, entity_types = score_text(text)
    return {
        "risk_score": score,
        "risk_label": risk_label(score),
        "entity_types_found": entity_types,
    }


@mcp.tool(name="analyze_sanitized_text")
def analyze_sanitized_text(
    sanitized_text: str,
    operation: str = "analysis",
    risk_label_value: str = "NONE",
    entities_found: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Generate AI-assisted incident summary for sanitized logs."""
    return summarize_logs(
        sanitized_text=sanitized_text,
        operation=operation,
        risk_label=risk_label_value,
        entities_found=entities_found,
    )


def handle_tool_call(name: str, arguments: dict[str, Any]) -> str:
    """Compatibility helper for direct function dispatch in tests/scripts."""
    handlers = {
        "sanitize_text": sanitize_text,
        "sanitize_json": sanitize_json,
        "create_session": create_session,
        "get_session_mapping": get_session_mapping,
        "evaluate_policy": evaluate_policy,
        "score_risk": score_risk,
        "analyze_sanitized_text": analyze_sanitized_text,
    }
    handler = handlers.get(name)
    if handler is None:
        return json.dumps({"error": f"Unknown tool: {name}"})
    return json.dumps(handler(**arguments))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the PII-Safe FastMCP server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "http", "sse", "streamable-http"],
        default="stdio",
        help="MCP transport to run",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Host for HTTP transports")
    parser.add_argument("--port", type=int, default=8005, help="Port for HTTP transports")
    parser.add_argument("--path", default="/mcp", help="Path for HTTP transports")
    return parser.parse_args()


def run_mcp_server() -> None:
    args = parse_args()
    if args.transport == "stdio":
        mcp.run(transport="stdio")
        return

    mcp.run(
        transport=args.transport,
        host=args.host,
        port=args.port,
        path=args.path,
    )


if __name__ == "__main__":
    run_mcp_server()
