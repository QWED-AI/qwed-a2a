"""
Tests for issue #6 regression:
GENERAL and DATA_QUERY passthrough must return UNVERIFIABLE, not FORWARDED.
No JWT attestation must be issued for UNVERIFIABLE verdicts.
"""

import pytest

from qwed_a2a.interceptor import A2AVerificationInterceptor
from qwed_a2a.protocol.schema import AgentMessage, PayloadType, VerdictStatus
from qwed_a2a.security.trust_boundary import TrustBoundary


@pytest.fixture
def open_interceptor():
    """Interceptor with default_allow=True — trust boundary open for these tests."""
    return A2AVerificationInterceptor(trust_boundary=TrustBoundary(default_allow=True))


@pytest.fixture
def general_message():
    return AgentMessage(
        sender_agent_id="agent-a",
        receiver_agent_id="agent-b",
        payload_type=PayloadType.GENERAL,
        payload={"content": "hello world"},
    )


@pytest.fixture
def data_query_message():
    return AgentMessage(
        sender_agent_id="query-agent",
        receiver_agent_id="data-agent",
        payload_type=PayloadType.DATA_QUERY,
        payload={"query": "SELECT * FROM users"},
    )


class TestUnverifiablePassthrough:
    """
    Regression suite for A2A-002.

    GENERAL and DATA_QUERY have no verification engine — they must
    return UNVERIFIABLE, not FORWARDED. No JWT may be issued for
    content that was never actually checked.
    """

    @pytest.mark.asyncio
    async def test_general_returns_unverifiable_not_forwarded(
        self, open_interceptor, general_message
    ):
        """GENERAL payload must produce UNVERIFIABLE verdict, not FORWARDED."""
        verdict = await open_interceptor.intercept(
            general_message, trace_id="t_general_unverifiable"
        )
        assert verdict.status == VerdictStatus.UNVERIFIABLE, (
            f"Expected UNVERIFIABLE, got {verdict.status}. "
            "GENERAL payloads must not be falsely endorsed as verified."
        )

    @pytest.mark.asyncio
    async def test_data_query_returns_unverifiable_not_forwarded(
        self, open_interceptor, data_query_message
    ):
        """DATA_QUERY payload must produce UNVERIFIABLE verdict, not FORWARDED."""
        verdict = await open_interceptor.intercept(
            data_query_message, trace_id="t_data_query_unverifiable"
        )
        assert verdict.status == VerdictStatus.UNVERIFIABLE, (
            f"Expected UNVERIFIABLE, got {verdict.status}. "
            "DATA_QUERY payloads must not be falsely endorsed as verified."
        )

    @pytest.mark.asyncio
    async def test_general_has_no_attestation_jwt(
        self, open_interceptor, general_message
    ):
        """GENERAL passthrough must NOT carry a signed JWT attestation."""
        verdict = await open_interceptor.intercept(
            general_message, trace_id="t_general_no_jwt"
        )
        assert verdict.attestation_jwt is None, (
            "attestation_jwt must be None for UNVERIFIABLE verdicts. "
            "Issuing a JWT for unverified content is a false cryptographic claim."
        )

    @pytest.mark.asyncio
    async def test_data_query_has_no_attestation_jwt(
        self, open_interceptor, data_query_message
    ):
        """DATA_QUERY passthrough must NOT carry a signed JWT attestation."""
        verdict = await open_interceptor.intercept(
            data_query_message, trace_id="t_data_query_no_jwt"
        )
        assert (
            verdict.attestation_jwt is None
        ), "attestation_jwt must be None for UNVERIFIABLE verdicts."

    @pytest.mark.asyncio
    async def test_general_engine_is_passthrough(
        self, open_interceptor, general_message
    ):
        """Engine used must be 'passthrough' — not a real verification engine."""
        verdict = await open_interceptor.intercept(
            general_message, trace_id="t_general_engine"
        )
        assert verdict.engine_used == "passthrough"

    @pytest.mark.asyncio
    async def test_unverifiable_reason_is_present(
        self, open_interceptor, general_message
    ):
        """UNVERIFIABLE verdict must carry a reason explaining why."""
        verdict = await open_interceptor.intercept(
            general_message, trace_id="t_general_reason"
        )
        assert verdict.reason is not None
        assert len(verdict.reason) > 0

    @pytest.mark.asyncio
    async def test_verified_payload_still_gets_jwt(self, open_interceptor):
        """
        Sanity check: verified payloads (FINANCIAL etc.) still get JWT attestation.
        This ensures UNVERIFIABLE fix didn't break the normal signing path.
        """
        from decimal import Decimal

        financial_msg = AgentMessage(
            sender_agent_id="procurement-agent",
            receiver_agent_id="treasury-agent",
            payload_type=PayloadType.FINANCIAL_TRANSACTION,
            payload={
                "data": {
                    "claimed_total": Decimal("100.00"),
                    "line_items": [
                        {
                            "description": "Widget",
                            "amount": Decimal("100.00"),
                            "quantity": 1,
                        }
                    ],
                }
            },
        )
        verdict = await open_interceptor.intercept(
            financial_msg, trace_id="t_financial_jwt_sanity"
        )
        assert verdict.status == VerdictStatus.FORWARDED
        assert (
            verdict.attestation_jwt is not None
        ), "Verified FINANCIAL payloads must still receive JWT attestation."
