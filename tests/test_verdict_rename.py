"""
FORWARDED -> VERIFIED rename (#13).

VERIFIED (wire value "verified") is the only admissible verdict and is
emitted only by the deterministic finance engine. The logic engine's
no-contradiction result is a HEURISTIC_PASS. ``FORWARDED`` and the legacy
wire value "forwarded" stay accepted as deprecated aliases so 0.3.x
tokens and consumers keep working through the transition.
"""

import jwt as pyjwt
import pytest

from qwed_a2a.protocol.schema import (
    AgentMessage,
    PayloadType,
    VerdictStatus,
    VerificationVerdict,
)
from qwed_a2a.security.crypto import A2ACryptoService, AttestationContext
from qwed_a2a.utils.telemetry import get_metrics


class TestEnum:
    def test_verified_wire_value(self):
        assert VerdictStatus.VERIFIED.value == "verified"

    def test_forwarded_is_alias_not_a_member(self):
        assert VerdictStatus.FORWARDED is VerdictStatus.VERIFIED
        assert "forwarded" not in {s.value for s in VerdictStatus}
        assert len(list(VerdictStatus)) == 5

    def test_legacy_wire_value_parses_to_verified(self):
        assert VerdictStatus("forwarded") is VerdictStatus.VERIFIED

    @pytest.mark.parametrize("value", ["Forwarded", "FORWARDED", "forwarded "])
    def test_legacy_match_is_exact(self, value):
        with pytest.raises(ValueError):
            VerdictStatus(value)

    def test_old_http_verdict_parses(self):
        """Consumers re-parsing a 0.3.x /a2a/intercept response."""
        v = VerificationVerdict.model_validate(
            {"status": "forwarded", "audit_trace_id": "t"}
        )
        assert v.status is VerdictStatus.VERIFIED
        assert v.admissible is True
        assert v.model_dump(mode="json")["status"] == "verified"


class TestAttestationTransition:
    def _context(self):
        return AttestationContext("agent-a", "agent-b", {"data": "x"})

    def _sign(self, svc, trace_id, verdict):
        return svc.sign_verdict(
            trace_id=trace_id,
            verdict_status=verdict,
            engine="finance_guard",
            sender_id="agent-a",
            receiver_id="agent-b",
            payload_hash=A2ACryptoService.payload_hash({"data": "x"}),
        )

    def test_new_tokens_carry_verified(self, crypto_service):
        token = self._sign(crypto_service, "t_ren_new", VerdictStatus.VERIFIED)
        ok, claims, err = crypto_service.verify_attestation(token, self._context())
        assert ok is True, err
        assert claims["qwed_a2a"]["verdict"] == "verified"

    def test_signing_legacy_value_normalizes(self, crypto_service):
        """sign_verdict("forwarded") never emits the legacy value."""
        token = self._sign(crypto_service, "t_ren_norm", "forwarded")
        raw = pyjwt.decode(token, options={"verify_signature": False})
        assert raw["qwed_a2a"]["verdict"] == "verified"

    def test_legacy_token_still_verifies_and_admits(self, crypto_service):
        """A token minted by a 0.3.x replica (verdict="forwarded") still
        verifies during a rolling deploy, and is admissible."""
        token = self._sign(crypto_service, "t_ren_legacy", "verified")
        raw = pyjwt.decode(token, options={"verify_signature": False})
        raw["qwed_a2a"]["verdict"] = "forwarded"
        raw["jti"] = "t_ren_legacy_resigned"
        legacy = pyjwt.encode(
            raw,
            crypto_service._ensure_key_pair().private_key_pem,
            algorithm=A2ACryptoService.ALGORITHM,
        )
        ok, claims, err = crypto_service.verify_attestation(legacy, self._context())
        assert ok is True, err
        assert A2ACryptoService.is_admissible(claims) is True


def _message(payload_type, payload):
    return AgentMessage(
        sender_agent_id="agent-a",
        receiver_agent_id="agent-b",
        payload_type=payload_type,
        payload=payload,
    )


@pytest.mark.asyncio
class TestEngineVerdicts:
    async def test_finance_pass_is_verified(self, interceptor, valid_financial_message):
        v = await interceptor.intercept(valid_financial_message, trace_id="t_ren_fin")
        assert v.status is VerdictStatus.VERIFIED
        assert v.admissible is True

    async def test_logic_pass_is_heuristic(self, interceptor, crypto_service):
        """No detected contradiction is not proof of consistency."""
        msg = _message(
            PayloadType.LOGIC_ASSERTION,
            {"assertions": [{"claim": "paid"}, {"claim": "unpaid", "negated": True}]},
        )
        v = await interceptor.intercept(msg, trace_id="t_ren_logic")
        assert v.status is VerdictStatus.HEURISTIC_PASS
        assert v.engine_used == "logic_guard"
        assert v.admissible is False
        assert "heuristic" in v.reason.lower()

        ok, claims, err = crypto_service.verify_attestation(
            v.attestation_jwt, AttestationContext("agent-a", "agent-b", msg.payload)
        )
        assert ok is True, err
        assert claims["qwed_a2a"]["verdict"] == "heuristic_pass"
        assert A2ACryptoService.is_admissible(claims) is False

    async def test_logic_contradiction_still_blocked(self, interceptor):
        msg = _message(
            PayloadType.LOGIC_ASSERTION,
            {"assertions": [{"claim": "paid"}, {"claim": "PAID", "negated": True}]},
        )
        v = await interceptor.intercept(msg, trace_id="t_ren_logic_block")
        assert v.status is VerdictStatus.BLOCKED


@pytest.mark.asyncio
class TestMetrics:
    async def test_verified_counted_with_legacy_alias(
        self, interceptor, valid_financial_message
    ):
        await interceptor.intercept(valid_financial_message, trace_id="t_ren_metrics")
        metrics = get_metrics()
        assert metrics.total_verified == 1
        assert metrics.total_forwarded == 1  # deprecated alias
        data = metrics.to_dict()
        assert data["total_verified"] == data["total_forwarded"] == 1
