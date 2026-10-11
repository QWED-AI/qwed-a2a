"""
Tests for A2A Pydantic schema validation.
"""

import pytest
from pydantic import ValidationError

from qwed_a2a.protocol.schema import (
    AgentMessage,
    InterceptorConfig,
    PayloadType,
    VerdictStatus,
    VerificationVerdict,
)


class TestAgentMessage:
    """AgentMessage schema validation tests."""

    def test_valid_message(self):
        """A well-formed message should pass validation."""
        msg = AgentMessage(
            sender_agent_id="agent-A",
            receiver_agent_id="agent-B",
            payload_type=PayloadType.GENERAL,
            payload={"data": "test"},
        )
        assert msg.sender_agent_id == "agent-A"
        assert msg.payload_type == PayloadType.GENERAL

    def test_empty_sender_rejected(self):
        """Empty sender ID should be rejected."""
        with pytest.raises(ValidationError):
            AgentMessage(
                sender_agent_id="",
                receiver_agent_id="agent-B",
                payload={"data": "test"},
            )

    def test_control_chars_rejected(self):
        """Agent IDs with control characters should be rejected."""
        with pytest.raises(ValidationError):
            AgentMessage(
                sender_agent_id="agent\x00evil",
                receiver_agent_id="agent-B",
                payload={"data": "test"},
            )

    def test_whitespace_trimmed(self):
        """Leading/trailing whitespace should be stripped from agent IDs."""
        msg = AgentMessage(
            sender_agent_id="  agent-A  ",
            receiver_agent_id="  agent-B  ",
            payload={"data": "test"},
        )
        assert msg.sender_agent_id == "agent-A"
        assert msg.receiver_agent_id == "agent-B"

    def test_default_payload_type(self):
        """Default payload type should be GENERAL."""
        msg = AgentMessage(
            sender_agent_id="agent-A",
            receiver_agent_id="agent-B",
            payload={"data": "test"},
        )
        assert msg.payload_type == PayloadType.GENERAL

    def test_missing_payload_rejected(self):
        """Missing payload field should be rejected."""
        with pytest.raises(ValidationError):
            AgentMessage(
                sender_agent_id="agent-A",
                receiver_agent_id="agent-B",
            )


class TestVerificationVerdict:
    """VerificationVerdict schema tests."""

    def test_valid_verdict(self):
        """A well-formed verdict should pass validation."""
        v = VerificationVerdict(
            status=VerdictStatus.FORWARDED,
            audit_trace_id="a2a_test123",
        )
        assert v.status == VerdictStatus.FORWARDED
        assert v.reason is None

    def test_blocked_verdict_can_have_reason(self):
        """A blocked verdict can include a reason."""
        v = VerificationVerdict(
            status=VerdictStatus.BLOCKED,
            audit_trace_id="a2a_blocked456",
            reason="Math hallucination detected",
        )
        assert v.status == VerdictStatus.BLOCKED
        assert "hallucination" in v.reason

    def test_blocked_verdict_without_reason_allowed(self):
        """A blocked verdict without reason is allowed (reason is optional)."""
        v = VerificationVerdict(
            status=VerdictStatus.BLOCKED,
            audit_trace_id="a2a_noreason789",
        )
        assert v.status == VerdictStatus.BLOCKED
        assert v.reason is None

    def test_serialization_roundtrip(self):
        """Verdict should serialize and deserialize correctly."""
        v = VerificationVerdict(
            status=VerdictStatus.FORWARDED,
            audit_trace_id="a2a_serial789",
            engine_used="finance_guard",
        )
        data = v.model_dump(mode="json")
        assert data["status"] == "forwarded"
        assert data["audit_trace_id"] == "a2a_serial789"


class TestInterceptorConfig:
    """InterceptorConfig validation tests."""

    def test_default_config(self):
        """Default config should have all verifications enabled."""
        config = InterceptorConfig()
        assert config.enable_financial_verification is True
        assert config.enable_logic_verification is True
        assert config.enable_code_verification is True
        assert config.block_on_error is True

    def test_block_on_error_false_is_deprecated(self):
        """block_on_error=False is accepted for compatibility but warns (#38)."""
        with pytest.warns(DeprecationWarning, match="deprecated and ignored"):
            InterceptorConfig(block_on_error=False)

    def test_block_on_error_warning_points_at_caller(self):
        """The warning is attributed to the caller, not pydantic internals, so
        default filters and IDEs report it at the offending line."""
        import warnings

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            InterceptorConfig(block_on_error=False)
            InterceptorConfig.model_validate({"block_on_error": False})

        assert len(caught) == 2
        for w in caught:
            assert w.filename == __file__

    def test_block_on_error_false_is_logged(self, caplog):
        """Deprecation is also logged — DeprecationWarning is hidden by default
        outside __main__, and a former fail-open deployment must notice."""
        import logging

        with caplog.at_level(logging.WARNING, logger="qwed_a2a"):
            with pytest.warns(DeprecationWarning):
                InterceptorConfig(block_on_error=False)
        assert "block_on_error is deprecated and ignored" in caplog.text

    def test_block_on_error_true_is_silent(self, caplog):
        """The default value neither warns nor logs."""
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("error")
            InterceptorConfig(block_on_error=True)
        assert "block_on_error" not in caplog.text

    def test_payload_size_bounds(self):
        """Payload size must be within bounds."""
        with pytest.raises(ValidationError):
            InterceptorConfig(max_payload_size_bytes=512)  # Below minimum 1024

    def test_custom_config(self):
        """Custom config should override defaults."""
        config = InterceptorConfig(
            enable_financial_verification=False,
            trusted_agents=["agent-vip"],
        )
        assert config.enable_financial_verification is False
        assert "agent-vip" in config.trusted_agents
