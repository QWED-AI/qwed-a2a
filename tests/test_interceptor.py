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

    async def test_valid_financial_verified(
        self, interceptor, valid_financial_message
    ):
        """Correct financial totals are VERIFIED."""
        verdict = await interceptor.intercept(
            valid_financial_message, trace_id="t_fin_valid"
        )
        assert verdict.status == VerdictStatus.VERIFIED
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

    async def test_empty_financial_returns_unverifiable(
        self, interceptor, empty_financial_message
    ):
        """Empty financial payload must return UNVERIFIABLE, not VERIFIED."""
        verdict = await interceptor.intercept(
            empty_financial_message, trace_id="t_fin_empty"
        )
        assert verdict.status == VerdictStatus.UNVERIFIABLE
        assert verdict.engine_used == "finance_guard"
        assert verdict.attestation_jwt is None
        assert verdict.reason is not None
        assert "claimed_total" in verdict.reason

    async def test_missing_claimed_total_returns_unverifiable(
        self, interceptor, financial_missing_claimed_total_message
    ):
        """Missing claimed_total with line_items present returns UNVERIFIABLE."""
        verdict = await interceptor.intercept(
            financial_missing_claimed_total_message, trace_id="t_fin_missing_ct"
        )
        assert verdict.status == VerdictStatus.UNVERIFIABLE
        assert verdict.engine_used == "finance_guard"
        assert verdict.attestation_jwt is None
        assert verdict.reason is not None
        assert "claimed_total" in verdict.reason

    async def test_empty_line_items_returns_unverifiable(
        self, interceptor, financial_empty_line_items_message
    ):
        """Empty line_items with claimed_total present returns UNVERIFIABLE."""
        verdict = await interceptor.intercept(
            financial_empty_line_items_message, trace_id="t_fin_empty_li"
        )
        assert verdict.status == VerdictStatus.UNVERIFIABLE
        assert verdict.engine_used == "finance_guard"
        assert verdict.attestation_jwt is None
        assert verdict.reason is not None
        assert "line_items" in verdict.reason

    async def test_malformed_data_returns_unverifiable(
        self, interceptor, financial_malformed_data_message
    ):
        """data=None returns UNVERIFIABLE, not a generic engine error."""
        verdict = await interceptor.intercept(
            financial_malformed_data_message, trace_id="t_fin_mal_data"
        )
        assert verdict.status == VerdictStatus.UNVERIFIABLE
        assert verdict.engine_used == "finance_guard"
        assert verdict.attestation_jwt is None
        assert verdict.reason is not None
        assert "data" in verdict.reason

    async def test_malformed_line_items_returns_unverifiable(
        self, interceptor, financial_malformed_line_items_message
    ):
        """Non-list line_items returns UNVERIFIABLE, not a generic error."""
        verdict = await interceptor.intercept(
            financial_malformed_line_items_message, trace_id="t_fin_mal_li"
        )
        assert verdict.status == VerdictStatus.UNVERIFIABLE
        assert verdict.engine_used == "finance_guard"
        assert verdict.attestation_jwt is None
        assert verdict.reason is not None
        assert "line_items" in verdict.reason

    async def test_non_dict_line_item_returns_unverifiable(
        self, interceptor, financial_non_dict_line_item_message
    ):
        """Non-mapping line item entry returns UNVERIFIABLE."""
        verdict = await interceptor.intercept(
            financial_non_dict_line_item_message, trace_id="t_fin_non_dict_item"
        )
        assert verdict.status == VerdictStatus.UNVERIFIABLE
        assert verdict.engine_used == "finance_guard"
        assert verdict.attestation_jwt is None
        assert verdict.reason is not None
        assert "line item" in verdict.reason

    async def test_missing_amount_line_item_returns_unverifiable(
        self, interceptor, financial_missing_amount_line_item_message
    ):
        """Line item without amount key returns UNVERIFIABLE, not VERIFIED."""
        verdict = await interceptor.intercept(
            financial_missing_amount_line_item_message, trace_id="t_fin_missing_amt"
        )
        assert verdict.status == VerdictStatus.UNVERIFIABLE
        assert verdict.engine_used == "finance_guard"
        assert verdict.attestation_jwt is None
        assert verdict.reason is not None
        assert "amount" in verdict.reason

    async def test_null_amount_line_item_returns_unverifiable(
        self, interceptor, financial_null_amount_line_item_message
    ):
        """Line item with null amount returns UNVERIFIABLE, not crashing."""
        verdict = await interceptor.intercept(
            financial_null_amount_line_item_message, trace_id="t_fin_null_amt"
        )
        assert verdict.status == VerdictStatus.UNVERIFIABLE
        assert verdict.engine_used == "finance_guard"
        assert verdict.attestation_jwt is None
        assert verdict.reason is not None
        assert "amount" in verdict.reason

    async def test_null_quantity_line_item_returns_unverifiable(
        self, interceptor, financial_null_quantity_line_item_message
    ):
        """Line item with null quantity returns UNVERIFIABLE, not crashing."""
        verdict = await interceptor.intercept(
            financial_null_quantity_line_item_message, trace_id="t_fin_null_qty"
        )
        assert verdict.status == VerdictStatus.UNVERIFIABLE
        assert verdict.engine_used == "finance_guard"
        assert verdict.attestation_jwt is None
        assert verdict.reason is not None
        assert "quantity" in verdict.reason

    async def test_non_numeric_claimed_total_returns_unverifiable(
        self, interceptor, financial_non_numeric_claimed_total_message
    ):
        """Non-numeric claimed_total returns UNVERIFIABLE, not crashing."""
        verdict = await interceptor.intercept(
            financial_non_numeric_claimed_total_message, trace_id="t_fin_bad_ct"
        )
        assert verdict.status == VerdictStatus.UNVERIFIABLE
        assert verdict.engine_used == "finance_guard"
        assert verdict.attestation_jwt is None
        assert verdict.reason is not None
        assert "claimed_total" in verdict.reason

    async def test_non_numeric_amount_returns_unverifiable(
        self, interceptor, financial_non_numeric_amount_message
    ):
        """Non-numeric line item amount returns UNVERIFIABLE, not crashing."""
        verdict = await interceptor.intercept(
            financial_non_numeric_amount_message, trace_id="t_fin_bad_amt"
        )
        assert verdict.status == VerdictStatus.UNVERIFIABLE
        assert verdict.engine_used == "finance_guard"
        assert verdict.attestation_jwt is None
        assert verdict.reason is not None
        assert "amount" in verdict.reason


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

    async def test_safe_code_heuristic_pass(self, interceptor, safe_code_message):
        """Safe code should return HEURISTIC_PASS — heuristic scan, not deterministic proof."""
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

    async def test_empty_logic_returns_unverifiable(
        self, interceptor, empty_logic_message
    ):
        """Empty logic assertions must return UNVERIFIABLE, not VERIFIED."""
        verdict = await interceptor.intercept(
            empty_logic_message, trace_id="t_logic_empty"
        )
        assert verdict.status == VerdictStatus.UNVERIFIABLE
        assert verdict.engine_used == "logic_guard"
        assert verdict.attestation_jwt is None
        assert verdict.reason is not None
        assert "assertions" in verdict.reason

    async def test_malformed_assertions_returns_unverifiable(
        self, interceptor, logic_malformed_assertions_message
    ):
        """Non-list assertions returns UNVERIFIABLE, not a generic error."""
        verdict = await interceptor.intercept(
            logic_malformed_assertions_message, trace_id="t_logic_mal"
        )
        assert verdict.status == VerdictStatus.UNVERIFIABLE
        assert verdict.engine_used == "logic_guard"
        assert verdict.attestation_jwt is None
        assert verdict.reason is not None
        assert "assertions" in verdict.reason

    async def test_non_dict_assertion_returns_unverifiable(
        self, interceptor, logic_non_dict_assertion_message
    ):
        """Non-mapping assertion entry returns UNVERIFIABLE."""
        verdict = await interceptor.intercept(
            logic_non_dict_assertion_message, trace_id="t_logic_non_dict"
        )
        assert verdict.status == VerdictStatus.UNVERIFIABLE
        assert verdict.engine_used == "logic_guard"
        assert verdict.attestation_jwt is None
        assert verdict.reason is not None
        assert "assertion" in verdict.reason

    async def test_missing_claim_assertion_returns_unverifiable(
        self, interceptor, logic_missing_claim_assertion_message
    ):
        """Assertion without claim key returns UNVERIFIABLE, not VERIFIED."""
        verdict = await interceptor.intercept(
            logic_missing_claim_assertion_message, trace_id="t_logic_missing_claim"
        )
        assert verdict.status == VerdictStatus.UNVERIFIABLE
        assert verdict.engine_used == "logic_guard"
        assert verdict.attestation_jwt is None
        assert verdict.reason is not None
        assert "claim" in verdict.reason


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
        """General messages route to passthrough and return UNVERIFIABLE — not VERIFIED."""
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


def _crash_financial_engine(monkeypatch, interceptor) -> None:
    """Make the finance engine raise, independent of the Decimal context."""
    from decimal import InvalidOperation

    def boom(_payload):
        raise InvalidOperation("injected engine failure")

    monkeypatch.setattr(interceptor, "_verify_financial", boom)


@pytest.mark.asyncio
class TestEngineErrorVerdict:
    """#38 / #15: engine exceptions always fail closed with a first-class ERROR."""

    async def test_engine_crash_returns_error_not_blocked(
        self, interceptor, valid_financial_message, monkeypatch
    ):
        """An engine crash yields ERROR — distinct from a content BLOCKED."""
        _crash_financial_engine(monkeypatch, interceptor)
        verdict = await interceptor.intercept(
            valid_financial_message, trace_id="t_err_crash"
        )
        assert verdict.status == VerdictStatus.ERROR
        assert verdict.engine_used == "error_handler"

    async def test_real_quantize_overflow_returns_error(self, interceptor):
        """Regression: the reported 1E+30 trigger crashes the real engine under
        the default 28-digit context and must fail closed as ERROR."""
        import decimal

        message = AgentMessage(
            sender_agent_id="agent-a",
            receiver_agent_id="agent-b",
            payload_type=PayloadType.FINANCIAL_TRANSACTION,
            payload={"data": {"claimed_total": 1, "line_items": [{"amount": "1E+30"}]}},
        )
        with decimal.localcontext() as ctx:
            ctx.prec = 28
            verdict = await interceptor.intercept(message, trace_id="t_err_1e30")
        assert verdict.status == VerdictStatus.ERROR
        assert verdict.engine_used == "error_handler"
        assert "InvalidOperation" in verdict.reason

    async def test_error_attestation_declares_error_verdict(
        self, interceptor, crypto_service, valid_financial_message, monkeypatch
    ):
        """The signed claim says "error" — never "verified" — and still verifies."""
        from qwed_a2a.security.crypto import AttestationContext

        _crash_financial_engine(monkeypatch, interceptor)
        message = valid_financial_message
        verdict = await interceptor.intercept(message, trace_id="t_err_jwt")
        assert verdict.attestation_jwt is not None

        ok, claims, err = crypto_service.verify_attestation(
            verdict.attestation_jwt,
            AttestationContext(
                sender_agent_id=message.sender_agent_id,
                receiver_agent_id=message.receiver_agent_id,
                payload=message.payload,
            ),
        )
        assert ok is True, err
        assert claims["qwed_a2a"]["verdict"] == "error"
        assert claims["qwed_a2a"]["engine"] == "error_handler"

    async def test_block_on_error_false_no_longer_fails_open(
        self, crypto_service, trust_boundary, valid_financial_message, monkeypatch
    ):
        """The former shadow-mode flag is ignored: a crash is never VERIFIED."""
        with pytest.warns(DeprecationWarning, match="block_on_error"):
            config = InterceptorConfig(block_on_error=False)
        interceptor = A2AVerificationInterceptor(
            config=config,
            crypto_service=crypto_service,
            trust_boundary=trust_boundary,
        )
        _crash_financial_engine(monkeypatch, interceptor)
        verdict = await interceptor.intercept(
            valid_financial_message, trace_id="t_err_flag_off"
        )
        assert verdict.status == VerdictStatus.ERROR

    async def test_error_reason_and_log_carry_type_only(
        self, interceptor, valid_financial_message, monkeypatch, caplog
    ):
        """Exception messages may echo payload data — only the type is surfaced."""
        import logging

        def boom(_message):
            raise ValueError("secret-payload-fragment")

        monkeypatch.setattr(interceptor, "_route_to_engine", boom)
        with caplog.at_level(logging.ERROR, logger="qwed_a2a"):
            verdict = await interceptor.intercept(
                valid_financial_message, trace_id="t_err_leak"
            )

        assert verdict.status == VerdictStatus.ERROR
        assert verdict.reason == "Verification engine raised ValueError - fail closed"
        assert "secret-payload-fragment" not in caplog.text
        assert "ValueError" in caplog.text

    async def test_error_counted_in_total_errors(
        self, interceptor, valid_financial_message, monkeypatch
    ):
        """total_errors is reachable; crashes no longer inflate forwards/blocks."""
        from qwed_a2a.utils.telemetry import get_metrics

        _crash_financial_engine(monkeypatch, interceptor)
        await interceptor.intercept(valid_financial_message, trace_id="t_err_metrics")
        metrics = get_metrics()
        assert metrics.total_errors == 1
        assert metrics.total_verified == 0
        assert metrics.total_blocked == 0
        assert metrics.by_engine.get("error_handler") == 1
