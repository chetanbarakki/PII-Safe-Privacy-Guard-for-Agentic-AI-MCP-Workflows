"""
tests/test_pipeline.py
-----------------------
Full test suite covering all components.

Run with:
    pytest tests/ -v
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

# ─────────────────────────────────────────────────────────────────────────────
# 1. Entity Detector Tests
# ─────────────────────────────────────────────────────────────────────────────
from detector.entity_detector import detect, detect_types


class TestEntityDetector:

    def test_detects_email(self):
        entities = detect("Contact me at john.doe@example.com for more info.")
        types_found = {e.entity_type for e in entities}
        assert "EMAIL" in types_found

    def test_detects_ip_address(self):
        entities = detect("Request came from 192.168.1.105")
        types_found = {e.entity_type for e in entities}
        assert "IP_ADDRESS" in types_found

    def test_detects_phone(self):
        entities = detect("Call me at 555-867-5309")
        types_found = {e.entity_type for e in entities}
        assert "PHONE" in types_found

    def test_detects_ssn(self):
        entities = detect("SSN: 123-45-6789")
        types_found = {e.entity_type for e in entities}
        assert "SSN" in types_found

    def test_detects_credit_card(self):
        entities = detect("Card number 4111111111111111")
        types_found = {e.entity_type for e in entities}
        assert "CREDIT_CARD" in types_found

    def test_detects_customer_id(self):
        entities = detect("Customer CUST-7823 reported the issue")
        types_found = {e.entity_type for e in entities}
        assert "CUSTOMER_ID" in types_found

    def test_detects_url(self):
        entities = detect("Visit https://malicious-site.com/payload")
        types_found = {e.entity_type for e in entities}
        assert "URL" in types_found

    def test_multiple_entities_in_one_text(self):
        text = "User john@test.com from 10.0.0.1 called 555-1234"
        found_types = detect_types(text)
        assert "EMAIL" in found_types
        assert "IP_ADDRESS" in found_types
        assert "PHONE" in found_types

    def test_no_false_positive_on_clean_text(self):
        entities = detect("The weather today is sunny and warm.")
        pii_types = {"EMAIL", "IP_ADDRESS", "PHONE", "SSN", "CREDIT_CARD"}
        found_types = {e.entity_type for e in entities}
        assert len(found_types & pii_types) == 0

    def test_entity_offsets_are_correct(self):
        text = "Email: test@example.com end"
        entities = detect(text)
        email_entity = next(e for e in entities if e.entity_type == "EMAIL")
        assert text[email_entity.start:email_entity.end] == "test@example.com"


# ─────────────────────────────────────────────────────────────────────────────
# 2. Schema Detector Tests
# ─────────────────────────────────────────────────────────────────────────────
from detector.schema_detector import detect_in_schema


class TestSchemaDetector:

    def test_detects_email_field(self):
        data = {"user_email": "alice@company.com", "message": "hello"}
        results = detect_in_schema(data)
        found = {r.entity_type for r in results}
        assert "EMAIL" in found

    def test_detects_ip_field(self):
        data = {"source_ip": "10.20.30.40", "action": "login"}
        results = detect_in_schema(data)
        found = {r.entity_type for r in results}
        assert "IP_ADDRESS" in found

    def test_nested_dict(self):
        data = {"user": {"contact": {"email": "bob@test.com"}}}
        results = detect_in_schema(data)
        paths = [r.json_path for r in results]
        assert any("email" in p for p in paths)

    def test_list_of_records(self):
        data = [
            {"email": "a@b.com"},
            {"email": "c@d.com"},
        ]
        results = detect_in_schema(data)
        assert len(results) == 2

    def test_clean_schema_no_results(self):
        data = {"action": "login", "status": "success", "count": 3}
        results = detect_in_schema(data)
        assert len(results) == 0

    def test_user_agent_is_not_flagged_as_username(self):
        data = {"user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"}
        results = detect_in_schema(data)
        assert results == []


# ─────────────────────────────────────────────────────────────────────────────
# 3. Policy Engine Tests
# ─────────────────────────────────────────────────────────────────────────────
from policy.engine import PolicyEngine


class TestPolicyEngine:

    def setup_method(self):
        self.engine = PolicyEngine()

    def test_email_analysis_is_pseudonymize(self):
        decision = self.engine.evaluate("analysis", "EMAIL")
        assert decision.action == "pseudonymize"

    def test_email_export_is_redact(self):
        decision = self.engine.evaluate("export", "EMAIL")
        assert decision.action == "redact"

    def test_ssn_is_always_block(self):
        for op in ["analysis", "export", "storage", "logging"]:
            decision = self.engine.evaluate(op, "SSN")
            assert decision.action == "block", f"SSN should be blocked for operation '{op}'"

    def test_credit_card_is_always_block(self):
        for op in ["analysis", "export", "storage", "logging"]:
            decision = self.engine.evaluate(op, "CREDIT_CARD")
            assert decision.action == "block"

    def test_org_analysis_is_allow(self):
        decision = self.engine.evaluate("analysis", "ORGANIZATION")
        assert decision.action == "allow"

    def test_unknown_entity_gets_redact_fallback(self):
        decision = self.engine.evaluate("analysis", "UNKNOWN_ENTITY_XYZ")
        assert decision.action == "redact"

    def test_decision_has_reason(self):
        decision = self.engine.evaluate("analysis", "EMAIL")
        assert len(decision.reason) > 0

    def test_evaluate_all(self):
        decisions = self.engine.evaluate_all("analysis", ["EMAIL", "IP_ADDRESS", "PERSON"])
        assert set(decisions.keys()) == {"EMAIL", "IP_ADDRESS", "PERSON"}
        assert all(d.action in {"allow", "redact", "pseudonymize", "block"} for d in decisions.values())


# ─────────────────────────────────────────────────────────────────────────────
# 4. Redactor Tests
# ─────────────────────────────────────────────────────────────────────────────
from sanitizer.redactor import redact_text, redact_value, REDACT_PLACEHOLDER


class TestRedactor:

    def test_redacts_email(self):
        result = redact_text("Send results to alice@company.com please")
        assert "alice@company.com" not in result
        assert REDACT_PLACEHOLDER in result

    def test_redacts_multiple_entities(self):
        result = redact_text("Email: bob@test.com IP: 1.2.3.4")
        assert "bob@test.com" not in result
        assert "1.2.3.4" not in result

    def test_clean_text_unchanged(self):
        text = "No personal data here at all."
        result = redact_text(text)
        assert result == text

    def test_redact_value(self):
        assert redact_value("anything") == REDACT_PLACEHOLDER


# ─────────────────────────────────────────────────────────────────────────────
# 5. Pseudonymizer Tests (the most important ones)
# ─────────────────────────────────────────────────────────────────────────────
from sanitizer.pseudonymizer import PseudonymSession


class TestPseudonymizer:

    def test_same_email_gets_same_token(self):
        session = PseudonymSession()
        t1 = session.pseudonymize_value("john@example.com", "EMAIL")
        t2 = session.pseudonymize_value("john@example.com", "EMAIL")
        assert t1 == t2, "Same value must always map to the same token"

    def test_different_emails_get_different_tokens(self):
        session = PseudonymSession()
        t1 = session.pseudonymize_value("alice@x.com", "EMAIL")
        t2 = session.pseudonymize_value("bob@x.com", "EMAIL")
        assert t1 != t2

    def test_token_format_email(self):
        session = PseudonymSession()
        token = session.pseudonymize_value("x@y.com", "EMAIL")
        assert token.startswith("USER_")

    def test_token_format_ip(self):
        session = PseudonymSession()
        token = session.pseudonymize_value("192.168.1.1", "IP_ADDRESS")
        assert token.startswith("IP_")

    def test_token_format_person(self):
        session = PseudonymSession()
        token = session.pseudonymize_value("John Smith", "PERSON")
        assert token.startswith("PERSON_")

    def test_pseudonymize_text_replaces_pii(self):
        session = PseudonymSession()
        result = session.pseudonymize_text("Login by john@test.com failed")
        assert "john@test.com" not in result
        assert "USER_" in result

    def test_consistency_across_multiple_texts(self):
        session = PseudonymSession()
        r1 = session.pseudonymize_text("First: john@x.com logged in")
        r2 = session.pseudonymize_text("Second: john@x.com logged out")
        # Extract the token used in each
        token_in_r1 = [w for w in r1.split() if w.startswith("USER_")][0]
        token_in_r2 = [w for w in r2.split() if w.startswith("USER_")][0]
        assert token_in_r1 == token_in_r2, "Same email must produce same token across calls"

    def test_reverse_lookup(self):
        session = PseudonymSession()
        token = session.pseudonymize_value("secret@company.com", "EMAIL")
        original = session.reverse_lookup(token)
        assert original == "secret@company.com"

    def test_session_export_and_restore(self):
        session1 = PseudonymSession()
        session1.pseudonymize_value("a@b.com", "EMAIL")
        state = session1.export_state()

        session2 = PseudonymSession(existing_mapping=state)
        token = session2.pseudonymize_value("a@b.com", "EMAIL")
        assert token == session1.get_mapping()["a@b.com"]


# ─────────────────────────────────────────────────────────────────────────────
# 6. Risk Scorer Tests
# ─────────────────────────────────────────────────────────────────────────────
from sanitizer.risk_scorer import score_text, score_entities, risk_label


class TestRiskScorer:

    def test_clean_text_scores_zero(self):
        score, types = score_text("The meeting is at 3pm tomorrow.")
        assert score == 0.0

    def test_ssn_scores_critical(self):
        score, _ = score_entities(["SSN"])
        assert score == 1.0

    def test_risk_label_critical(self):
        assert risk_label(1.0) == "CRITICAL"
        assert risk_label(0.8) == "CRITICAL"

    def test_risk_label_high(self):
        assert risk_label(0.6) == "HIGH"

    def test_risk_label_medium(self):
        assert risk_label(0.3) == "MEDIUM"

    def test_risk_label_low(self):
        assert risk_label(0.1) == "LOW"

    def test_risk_label_none(self):
        assert risk_label(0.0) == "NONE"

    def test_multiple_entities_accumulate(self):
        score1, _ = score_entities(["EMAIL"])
        score2, _ = score_entities(["EMAIL", "PHONE"])
        assert score2 > score1

    def test_score_capped_at_one(self):
        score, _ = score_entities(["SSN", "CREDIT_CARD", "EMAIL", "PHONE", "PERSON"])
        assert score <= 1.0


# ─────────────────────────────────────────────────────────────────────────────
# 7. Full Pipeline Integration Tests
# ─────────────────────────────────────────────────────────────────────────────
from api.pipeline import run_pipeline, run_pipeline_on_schema
from sanitizer.pseudonymizer import PseudonymSession


class TestPipelineIntegration:

    def test_analysis_pipeline_pseudonymizes_email(self):
        result = run_pipeline("Login failed for alice@corp.com", "analysis")
        assert "alice@corp.com" not in result.sanitized_text
        assert "USER_" in result.sanitized_text

    def test_export_pipeline_fully_redacts(self):
        result = run_pipeline("Export data for bob@corp.com", "export")
        assert "bob@corp.com" not in result.sanitized_text
        assert "[REDACTED]" in result.sanitized_text

    def test_ssn_blocks_entire_request(self):
        result = run_pipeline("SSN is 123-45-6789", "analysis")
        assert result.was_blocked is True
        assert result.sanitized_text == "[BLOCKED]"
        assert result.risk_score == 1.0

    def test_clean_text_passes_through(self):
        text = "Server restarted successfully at 14:32."
        result = run_pipeline(text, "analysis")
        assert result.sanitized_text == text
        assert result.risk_score == 0.0

    def test_session_preserves_mapping_across_calls(self):
        session = PseudonymSession()
        r1 = run_pipeline("User: john@test.com logged in", "analysis", session)
        r2 = run_pipeline("User: john@test.com failed auth", "analysis", session)
        # Token for john@test.com should be the same in both
        token = list(session.get_mapping().values())[0]
        assert token in r1.sanitized_text
        assert token in r2.sanitized_text

    def test_result_has_all_required_fields(self):
        result = run_pipeline("Test: x@y.com", "analysis")
        d = result.to_dict()
        for key in ["sanitized", "operation", "was_blocked", "risk_score", "risk_label", "entities_found", "audit_log"]:
            assert key in d, f"Missing field: {key}"

    def test_schema_pipeline_sanitizes_json(self):
        data = {"user_email": "carol@company.com", "action": "delete"}
        result = run_pipeline_on_schema(data, "export")
        assert result["sanitized"]["user_email"] == "[REDACTED]"
        assert result["sanitized"]["action"] == "delete"  # non-PII untouched

    def test_schema_pipeline_reuses_same_session_mapping_for_nested_email(self):
        session = PseudonymSession()
        data = {
            "user_email": "john@company.com",
            "details": "Failed login attempt for john@company.com",
        }
        result = run_pipeline_on_schema(data, "analysis", session)
        assert result["sanitized"]["user_email"] == "USER_01"
        assert "USER_01" in result["sanitized"]["details"]
        assert "USER_02" not in result["sanitized"]["details"]

    def test_multiple_entity_types_handled(self):
        text = "Call john@x.com at 555-1234 from 10.0.0.1"
        result = run_pipeline(text, "analysis")
        found_types = {e.entity_type for e in result.entities_found}
        assert "EMAIL" in found_types
        assert "PHONE" in found_types or "IP_ADDRESS" in found_types


# ─────────────────────────────────────────────────────────────────────────────
# 8. MCP Tool Handler Tests (no MCP SDK required)
# ─────────────────────────────────────────────────────────────────────────────
import json as json_lib
from mcp_server.server import handle_tool_call


class TestMCPToolHandler:

    def test_sanitize_text_tool(self):
        result = json_lib.loads(handle_tool_call("sanitize_text", {
            "text": "Email me at dev@example.com",
            "operation": "analysis",
        }))
        assert "sanitized" in result
        assert "dev@example.com" not in result["sanitized"]

    def test_score_risk_tool(self):
        result = json_lib.loads(handle_tool_call("score_risk", {
            "text": "SSN: 123-45-6789",
        }))
        assert result["risk_score"] == 1.0
        assert result["risk_label"] == "CRITICAL"

    def test_evaluate_policy_tool(self):
        result = json_lib.loads(handle_tool_call("evaluate_policy", {
            "operation": "export",
            "entity_type": "EMAIL",
        }))
        assert result["action"] == "redact"

    def test_create_and_use_session(self):
        create_result = json_lib.loads(handle_tool_call("create_session", {"label": "test"}))
        session_id = create_result["session_id"]
        assert len(session_id) > 0

        # Use session across two calls
        r1 = json_lib.loads(handle_tool_call("sanitize_text", {
            "text": "user@test.com",
            "operation": "analysis",
            "session_id": session_id,
        }))
        r2 = json_lib.loads(handle_tool_call("sanitize_text", {
            "text": "user@test.com again",
            "operation": "analysis",
            "session_id": session_id,
        }))
        # Same email should produce the same token in both
        token_r1 = r1["sanitized"].strip()
        assert token_r1 in r2["sanitized"]

    def test_unknown_tool_returns_error(self):
        result = json_lib.loads(handle_tool_call("nonexistent_tool", {}))
        assert "error" in result
