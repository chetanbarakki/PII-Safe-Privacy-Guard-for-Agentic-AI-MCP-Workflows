"""
examples/demo.py
-----------------
Demonstrates the full PII-Safe pipeline with realistic examples.

Run with:
    python examples/demo.py
"""

import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from api.pipeline import run_pipeline, run_pipeline_on_schema
from sanitizer.pseudonymizer import PseudonymSession
from sanitizer.risk_scorer import score_text, risk_label

SEP = "─" * 60


def section(title: str):
    print(f"\n{SEP}")
    print(f"  {title}")
    print(SEP)


# ── Demo 1: Free text sanitization ────────────────────────────────────────────
section("DEMO 1: Free Text – Analysis Operation")

log_line = (
    "2024-03-01 14:22 | FAILED LOGIN | user: john.smith@acmecorp.com "
    "| ip: 192.168.1.105 | customer: CUST-7823 | phone: +1-555-867-5309"
)

print(f"\nINPUT:\n  {log_line}")

result = run_pipeline(log_line, "analysis")

print(f"\nSANITIZED:\n  {result.sanitized_text}")
print(f"\nRISK SCORE: {result.risk_score}  ({result.risk_label})")
print("\nENTITY ACTIONS:")
for e in result.entities_found:
    print(f"  {e.entity_type:<16} → {e.action:<14} ({e.count} instance(s))")


# ── Demo 2: Same incident – session ensures consistency ───────────────────────
section("DEMO 2: Multi-Log Session Consistency")

session = PseudonymSession()
logs = [
    "john.smith@acmecorp.com failed login from 192.168.1.105",
    "john.smith@acmecorp.com failed login from 192.168.1.105 again",
    "Account CUST-7823 (john.smith@acmecorp.com) now locked",
]

print()
for i, log in enumerate(logs, 1):
    r = run_pipeline(log, "analysis", session)
    print(f"  Log {i}: {r.sanitized_text}")

print(f"\n  Pseudonym mapping (for re-identification by authorised staff):")
for original, token in session.get_mapping().items():
    print(f"    {token:<14} → {original}")


# ── Demo 3: Export operation – strict redaction ───────────────────────────────
section("DEMO 3: Export Operation – Strict Redaction")

text = "Export record: alice@partner.com | 10.20.30.40 | CUST-1001"
print(f"\nINPUT:     {text}")
result_export = run_pipeline(text, "export")
print(f"SANITIZED: {result_export.sanitized_text}")


# ── Demo 4: Block on SSN ──────────────────────────────────────────────────────
section("DEMO 4: SSN Triggers Full Block")

ssn_text = "Customer SSN on file: 123-45-6789. Please verify."
print(f"\nINPUT:   {ssn_text}")
result_block = run_pipeline(ssn_text, "analysis")
print(f"OUTPUT:  {result_block.sanitized_text}")
print(f"BLOCKED: {result_block.was_blocked}")
print(f"REASON:  {result_block.block_reason}")


# ── Demo 5: JSON schema sanitization ─────────────────────────────────────────
section("DEMO 5: JSON Schema Sanitization")

with open(os.path.join(os.path.dirname(__file__), "sample_security_log.json")) as f:
    incident = json.load(f)

print("\nOriginal first event:")
print(json.dumps(incident["events"][0], indent=2))

schema_result = run_pipeline_on_schema(incident, "analysis")

print("\nSanitized first event:")
print(json.dumps(schema_result["sanitized"]["events"][0], indent=2))

print(f"\nRisk score: {schema_result['risk_score']} ({schema_result['risk_label']})")


# ── Demo 6: Risk scoring without sanitization ─────────────────────────────────
section("DEMO 6: Risk Scoring Only")

samples = [
    "Server restarted at 02:00",
    "User alice@company.com logged in",
    "Card 4111111111111111 charged $50",
    "SSN 987-65-4321 verified",
]

print()
for s in samples:
    score, types = score_text(s)
    label = risk_label(score)
    print(f"  [{label:<8}] ({score:.2f})  {s[:50]}")


# ── Demo 7: MCP tool handler ──────────────────────────────────────────────────
section("DEMO 7: MCP Tool Call (no SDK needed)")

from mcp_server.server import handle_tool_call

mcp_result = json.loads(handle_tool_call("sanitize_text", {
    "text": "Debug: user dev@company.com hit 429 from 172.16.0.5",
    "operation": "logging",
}))

print(f"\nMCP Input:     Debug: user dev@company.com hit 429 from 172.16.0.5")
print(f"MCP Sanitized: {mcp_result['sanitized']}")
print(f"Risk:          {mcp_result['risk_score']} ({mcp_result['risk_label']})")

print(f"\n{SEP}")
print("  All demos complete.")
print(SEP)
