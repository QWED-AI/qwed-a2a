"""
Tests for the core A2A Verification Interceptor.
"""

from decimal import Decimal

import pytest

from qwed_a2a.interceptor import A2AVerificationInterceptor
from qwed_a2a.protocol.schema import InterceptorConfig, VerdictStatus


@pytest.mark.asyncio
class TestInterceptorFinancial:
    """Financial transaction verification tests."""

    async def test_valid_financial_forwarded(self, interceptor, valid_financial_message):
        """Correct financial totals should be forwarded."""
        verdict = await interceptor.intercept(valid_financial_message)
        assert verdict.status == VerdictStatus.FORWARDED
        assert verdict.engine_used == "finance_guard"
        assert verdict.attestation_jwt is not None

    async def test_hallucinated_financial_blocked(self, interceptor, hallucinated_financial_message):
        """Incorrect financial totals should be blocked."""
        verdict = await interceptor.intercept(hallucinated_financial_message)
        assert verdict.status == VerdictStatus.BLOCKED
        assert "hallucination" in verdict.reason.lower()
        assert verdict.engine_used == "finance_guard"
        assert verdict.details is not None
        assert Decimal(str(verdict.details["computed_total"])) == Decimal("150.00")
        assert Decimal(str(verdict.details["claimed_total"])) == Decimal("999.99")


@pytest.mark.asyncio
class TestInterceptorCode:
    """Code execution verification tests."""

    async def test_dangerous_code_blocked(self, interceptor, dangerous_code_message):
        """Code with dangerous patterns should be blocked."""
        verdict = await interceptor.intercept(dangerous_code_message)
        assert verdict.status == VerdictStatus.BLOCKED
        assert "os.system" in verdict.reason
        assert verdict.engine_used == "code_guard"

    async def test_safe_code_forwarded(self, interceptor, safe_code_message):
        """Safe code should be forwarded."""
        verdict = await interceptor.intercept(safe_code_message)
        assert verdict.status == VerdictStatus.FORWARDED
        assert verdict.engine_used == "code_guard"


@pytest.mark.asyncio
class TestInterceptorLogic:
    """Logic assertion verification tests."""

    async def test_contradiction_blocked(self, interceptor, contradictory_logic_message):
        """Contradictory assertions should be blocked."""
        verdict = await interceptor.intercept(contradictory_logic_message)
        assert verdict.status == VerdictStatus.BLOCKED
        assert "contradiction" in verdict.reason.lower()
        assert verdict.engine_used == "logic_guard"


@pytest.mark.asyncio
class TestInterceptorGeneral:
    """General message handling tests."""

    async def test_general_passthrough(self, interceptor, general_message):
        """General messages should pass through without verification."""
        verdict = await interceptor.intercept(general_message)
        assert verdict.status == VerdictStatus.FORWARDED
        assert verdict.engine_used == "passthrough"

    async def test_attestation_always_present(self, interceptor, general_message):
        """Every verdict must have an attestation JWT."""
        verdict = await interceptor.intercept(general_message)
        assert verdict.attestation_jwt is not None
        assert len(verdict.attestation_jwt) > 0

    async def test_audit_trace_unique(self, interceptor, general_message):
        """Each intercept must produce a unique trace ID."""
        v1 = await interceptor.intercept(general_message)
        v2 = await interceptor.intercept(general_message)
        assert v1.audit_trace_id != v2.audit_trace_id


@pytest.mark.asyncio
class TestTrustBoundaryIntegration:
    """Tests for trust boundary enforcement within the interceptor."""

    async def test_blocked_sender_rejected(self, interceptor, general_message):
        """Messages from blocked agents should be rejected."""
        interceptor.trust.block_agent(general_message.sender_agent_id)
        verdict = await interceptor.intercept(general_message)
        assert verdict.status == VerdictStatus.BLOCKED
        assert "trust boundary" in verdict.reason.lower()

    async def test_trusted_agent_bypass(self, crypto_service, trust_boundary, general_message):
        """Trusted agents should bypass verification."""
        config = InterceptorConfig(
            trusted_agents=[general_message.sender_agent_id]
        )
        interceptor = A2AVerificationInterceptor(
            config=config,
            crypto_service=crypto_service,
            trust_boundary=trust_boundary,
        )
        verdict = await interceptor.intercept(general_message)
        assert verdict.status == VerdictStatus.FORWARDED
        assert verdict.engine_used == "bypass"
