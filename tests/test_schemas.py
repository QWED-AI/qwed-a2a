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

    def test_blocked_verdict_with_reason(self):
        """A blocked verdict should include a reason."""
        v = VerificationVerdict(
            status=VerdictStatus.BLOCKED,
            audit_trace_id="a2a_blocked456",
            reason="Math hallucination detected",
        )
        assert v.status == VerdictStatus.BLOCKED
        assert "hallucination" in v.reason

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
