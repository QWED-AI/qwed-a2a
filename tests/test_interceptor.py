"""
Tests for the core A2A Verification Interceptor.
"""

from decimal import Decimal

import pytest

from qwed_a2a.interceptor import A2AVerificationInterceptor
from qwed_a2a.protocol.schema import (
    AgentMessage,
    InterceptorConfig,
    PayloadType,
    VerdictStatus,
)


@pytest.mark.asyncio
class TestInterceptorFinancial:
    """Financial transaction verification tests."""

    async def test_valid_financial_forwarded(
        self, interceptor, valid_financial_message
    ):
        """Correct financial totals should be forwarded."""
        verdict = await interceptor.intercept(
            valid_financial_message, trace_id="t_fin_valid"
        )
        assert verdict.status == VerdictStatus.FORWARDED
        assert verdict.engine_used == "finance_guard"
        assert verdict.attestation_jwt is not None
        assert verdict.audit_trace_id == "t_fin_valid"

    async def test_hallucinated_financial_blocked(
        self, interceptor, hallucinated_financial_message
    ):
        """Incorrect financial totals should be blocked."""
        verdict = await interceptor.intercept(
            hallucinated_financial_message, trace_id="t_fin_bad"
        )
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
        verdict = await interceptor.intercept(
            dangerous_code_message, trace_id="t_code_bad"
        )
        assert verdict.status == VerdictStatus.BLOCKED
        assert "system" in verdict.reason
        assert verdict.engine_used == "code_guard"

    async def test_safe_code_forwarded(self, interceptor, safe_code_message):
        """Safe code should be forwarded."""
        verdict = await interceptor.intercept(safe_code_message, trace_id="t_code_safe")
        assert verdict.status == VerdictStatus.HEURISTIC_PASS
        assert verdict.engine_used == "code_guard"


@pytest.mark.asyncio
class TestInterceptorLogic:
    """Logic assertion verification tests."""

    async def test_contradiction_blocked(
        self, interceptor, contradictory_logic_message
    ):
        """Contradictory assertions should be blocked."""
        verdict = await interceptor.intercept(
            contradictory_logic_message, trace_id="t_logic"
        )
        assert verdict.status == VerdictStatus.BLOCKED
        assert "contradiction" in verdict.reason.lower()
        assert verdict.engine_used == "logic_guard"


@pytest.mark.asyncio
class TestInterceptorGeneral:
    """General message handling tests."""

    async def test_missing_crypto_dependencies_fail_startup(self, monkeypatch):
        """Missing crypto dependencies should fail closed during startup."""
        monkeypatch.setattr("qwed_a2a.interceptor.HAS_CRYPTO", False)

        with pytest.raises(RuntimeError, match="requires 'cryptography' and 'PyJWT'"):
            A2AVerificationInterceptor()

    async def test_attestation_signing_failure_is_not_returned_as_normal_verdict(
        self, trust_boundary
    ):
        """Signing failures on verified payloads must raise — no unsigned verdict emitted."""
        from decimal import Decimal

        financial_message = AgentMessage(
            sender_agent_id="agent-a",
            receiver_agent_id="agent-b",
            payload_type=PayloadType.FINANCIAL_TRANSACTION,
            payload={
                "data": {
                    "claimed_total": Decimal("50.00"),
                    "line_items": [
                        {
                            "description": "Item",
                            "amount": Decimal("50.00"),
                            "quantity": 1,
                        }
                    ],
                }
            },
        )

        class FailingCryptoService:
            def sign_verdict(self, **_kwargs):
                raise RuntimeError("signer unavailable")

        interceptor = A2AVerificationInterceptor(
            crypto_service=FailingCryptoService(),
            trust_boundary=trust_boundary,
        )

        with pytest.raises(RuntimeError, match="Failed to sign attestation"):
            await interceptor.intercept(financial_message, trace_id="t_fin_sign_fail")

    async def test_empty_attestation_is_not_returned_as_normal_verdict(
        self, trust_boundary
    ):
        """Empty token from signer on verified payloads must fail closed."""
        from decimal import Decimal

        financial_message = AgentMessage(
            sender_agent_id="agent-a",
            receiver_agent_id="agent-b",
            payload_type=PayloadType.FINANCIAL_TRANSACTION,
            payload={
                "data": {
                    "claimed_total": Decimal("50.00"),
                    "line_items": [
                        {
                            "description": "Item",
                            "amount": Decimal("50.00"),
                            "quantity": 1,
                        }
                    ],
                }
            },
        )

        class EmptyTokenCryptoService:
            def sign_verdict(self, **_kwargs):
                return None

        interceptor = A2AVerificationInterceptor(
            crypto_service=EmptyTokenCryptoService(),
            trust_boundary=trust_boundary,
        )

        with pytest.raises(RuntimeError, match="sign_verdict returned an empty token"):
            await interceptor.intercept(financial_message, trace_id="t_fin_empty_token")

    async def test_general_passthrough(self, interceptor, general_message):
        """General messages route to passthrough and return UNVERIFIABLE — not FORWARDED."""
        verdict = await interceptor.intercept(general_message, trace_id="t_gen_pass")
        assert verdict.status == VerdictStatus.UNVERIFIABLE
        assert verdict.engine_used == "passthrough"

    async def test_unverifiable_verdict_has_no_attestation_jwt(
        self, interceptor, general_message
    ):
        """UNVERIFIABLE verdicts must not carry a JWT — issuing one would be a false claim."""
        verdict = await interceptor.intercept(general_message, trace_id="t_gen_attest")
        assert verdict.status == VerdictStatus.UNVERIFIABLE
        assert verdict.attestation_jwt is None

    async def test_deterministic_trace_id(self, interceptor, general_message):
        """Trace IDs are caller-driven and deterministic."""
        v1 = await interceptor.intercept(general_message, trace_id="deterministic_001")
        v2 = await interceptor.intercept(general_message, trace_id="deterministic_002")
        assert v1.audit_trace_id == "deterministic_001"
        assert v2.audit_trace_id == "deterministic_002"


@pytest.mark.asyncio
class TestTrustBoundaryIntegration:
    """Tests for trust boundary enforcement within the interceptor."""

    async def test_blocked_sender_rejected(self, interceptor, general_message):
        """Messages from blocked agents should be rejected."""
        interceptor.trust.block_agent(general_message.sender_agent_id)
        verdict = await interceptor.intercept(general_message, trace_id="t_trust_block")
        assert verdict.status == VerdictStatus.BLOCKED
        assert "trust boundary" in verdict.reason.lower()

    async def test_trusted_agent_general_returns_unverifiable(
        self, crypto_service, trust_boundary, general_message
    ):
        """Trusted agents sending GENERAL payloads still get UNVERIFIABLE — no engine exists."""
        config = InterceptorConfig(trusted_agents=[general_message.sender_agent_id])
        interceptor = A2AVerificationInterceptor(
            config=config,
            crypto_service=crypto_service,
            trust_boundary=trust_boundary,
        )
        verdict = await interceptor.intercept(
            general_message, trace_id="t_trust_no_bypass"
        )
        assert verdict.status == VerdictStatus.UNVERIFIABLE
        assert verdict.engine_used == "passthrough"

    async def test_trusted_agent_financial_fraud_is_blocked(
        self, crypto_service, trust_boundary, hallucinated_financial_message
    ):
        """Trusted agents are still verified and blocked on financial hallucinations."""
        config = InterceptorConfig(
            trusted_agents=[hallucinated_financial_message.sender_agent_id]
        )
        interceptor = A2AVerificationInterceptor(
            config=config,
            crypto_service=crypto_service,
            trust_boundary=trust_boundary,
        )

        verdict = await interceptor.intercept(
            hallucinated_financial_message, trace_id="t_trust_fin_fraud"
        )

        assert verdict.status == VerdictStatus.BLOCKED
        assert verdict.engine_used == "finance_guard"
        assert verdict.reason is not None
        assert "hallucination" in verdict.reason.lower()
