"""
api/main.py
-----------
FastAPI application exposing PII-Safe as a REST API.

Endpoints:
  POST /sanitize          – sanitize free text
  POST /sanitize/schema   – sanitize a JSON object
  POST /session/create    – create a named persistent session
  GET  /session/{id}      – retrieve session mapping
  DELETE /session/{id}    – delete session
  GET  /health            – health check
  GET  /policy/rules      – list loaded policy rules

Run with:
  uvicorn api.main:app --reload --port 8000
"""

from __future__ import annotations
import uuid
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from api.pipeline import run_pipeline, run_pipeline_on_schema
from mcp_server.server import analyze_sanitized_text
from sanitizer.pseudonymizer import PseudonymSession
from policy.engine import PolicyEngine


# ── App setup ─────────────────────────────────────────────────────────────────
app = FastAPI(
    title="PII-Safe API",
    description="Privacy middleware that detects, redacts, and pseudonymizes PII before it reaches an LLM.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory session store (use Redis in production)
_sessions: dict[str, PseudonymSession] = {}

_policy_engine = PolicyEngine()


# ── Request / Response models ─────────────────────────────────────────────────
class SanitizeRequest(BaseModel):
    text: str = Field(..., description="Raw text that may contain PII")
    operation: str = Field(
        "analysis",
        description="Operation context: analysis | export | storage | logging",
    )
    session_id: Optional[str] = Field(
        None,
        description="Reuse an existing pseudonym session for cross-request consistency",
    )
    include_mapping: bool = Field(
        False,
        description="Include the pseudonym↔original mapping in the response (authorised use only)",
    )


class SanitizeSchemaRequest(BaseModel):
    data: Any = Field(..., description="JSON object to sanitize")
    operation: str = Field("analysis")
    session_id: Optional[str] = None


class SessionCreateRequest(BaseModel):
    label: Optional[str] = Field(None, description="Optional human label for this session")


class AnalyzeSanitizedRequest(BaseModel):
    sanitized_text: str = Field(..., description="Already sanitized text")
    operation: str = Field("analysis")
    risk_label: str = Field("NONE")
    entities_found: list[dict[str, Any]] = Field(default_factory=list)


# ── Routes ────────────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok", "version": "0.1.0"}


@app.get("/policy/rules")
def list_rules():
    """Return the loaded policy rules (useful for debugging)."""
    import yaml, os
    rules_path = os.path.join(os.path.dirname(__file__), "..", "policy", "rules.yaml")
    with open(rules_path) as f:
        rules = yaml.safe_load(f)
    return rules


@app.post("/sanitize")
def sanitize_text(req: SanitizeRequest):
    """
    Sanitize free text.

    - Detects PII entities using regex + spaCy NER
    - Evaluates policy for the given operation
    - Applies redaction / pseudonymization / allow
    - Returns sanitized text + risk score + audit log
    """
    session = _get_or_none(req.session_id)

    result = run_pipeline(
        text=req.text,
        operation=req.operation,
        session=session,
    )

    # Persist session if session_id provided
    if req.session_id and session is not None:
        _sessions[req.session_id] = session

    return result.to_dict(include_mapping=req.include_mapping)


@app.post("/sanitize/schema")
def sanitize_schema(req: SanitizeSchemaRequest):
    """
    Sanitize a JSON/dict object field by field.
    """
    session = _get_or_none(req.session_id)
    result = run_pipeline_on_schema(req.data, req.operation, session)

    if req.session_id and session is not None:
        _sessions[req.session_id] = session

    return result


@app.post("/session/create")
def create_session(req: SessionCreateRequest):
    """Create a new pseudonym session and return its ID."""
    session_id = str(uuid.uuid4())
    _sessions[session_id] = PseudonymSession()
    return {"session_id": session_id, "label": req.label}


@app.get("/session/{session_id}")
def get_session(session_id: str, include_mapping: bool = Query(False)):
    """Retrieve session metadata and optionally the pseudonym mapping."""
    session = _sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    response = {"session_id": session_id, "token_count": len(session.get_mapping())}
    if include_mapping:
        response["mapping"] = session.get_mapping()
    return response


@app.delete("/session/{session_id}")
def delete_session(session_id: str):
    """Delete a session and its mapping."""
    if session_id not in _sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    del _sessions[session_id]
    return {"deleted": session_id}


@app.post("/policy/evaluate")
def evaluate_policy(operation: str, entity_type: str):
    """Test what action the policy engine returns for a given (operation, entity_type) pair."""
    decision = _policy_engine.evaluate(operation, entity_type)
    return decision.to_dict()


@app.post("/analyze/sanitized")
def analyze_sanitized(req: AnalyzeSanitizedRequest):
    """Generate AI summary of sanitized logs."""
    return analyze_sanitized_text(
        sanitized_text=req.sanitized_text,
        operation=req.operation,
        risk_label_value=req.risk_label,
        entities_found=req.entities_found,
    )


# ── Helpers ───────────────────────────────────────────────────────────────────
def _get_or_none(session_id: str | None) -> PseudonymSession | None:
    if session_id is None:
        return None
    return _sessions.get(session_id)
