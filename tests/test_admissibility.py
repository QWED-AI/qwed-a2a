"""
Admissibility contract (#13).

Only VERIFIED is admissible. HEURISTIC_PASS, UNVERIFIABLE, BLOCKED and
ERROR all deny — so the lazy ``status != "blocked"`` consumer check is
never the right gate. The contract is exposed three ways that must agree:
``VerdictStatus.admissible``, ``VerificationVerdict.admissible`` (also in
the serialised HTTP verdict) and ``A2ACryptoService.is_admissible(claims)``
for attestation consumers.
"""

from decimal import InvalidOperation

import pytest

from qwed_a2a import ADMISSIBLE_VERDICTS
from qwed_a2a.protocol.schema import VerdictStatus, VerificationVerdict
from qwed_a2a.security.crypto import A2ACryptoService, AttestationContext


class TestVerdictStatusAdmissible:
    def test_only_verified_is_admissible(self):
        assert ADMISSIBLE_VERDICTS == frozenset({VerdictStatus.VERIFIED})

    @pytest.mark.parametrize("status", list(VerdictStatus))
    def test_property_matches_contract(self, status):
        assert status.admissible is (status is VerdictStatus.VERIFIED)


class TestVerificationVerdictAdmissible:
    @pytest.mark.parametrize("status", list(VerdictStatus))
    def test_derived_from_status_and_serialised(self, status):
        verdict = VerificationVerdict(status=status, audit_trace_id="t")
        assert verdict.admissible is status.admissible
        assert verdict.model_dump(mode="json")["admissible"] is status.admissible

    def test_input_cannot_override(self):
        """A forged admissible=True on a blocked verdict is ignored."""
        verdict = VerificationVerdict.model_validate(
            {"status": "blocked", "audit_trace_id": "t", "admissible": True}
        )
        assert verdict.admissible is False


@pytest.mark.asyncio
class TestInterceptorAdmissible:
    """End to end: every interceptor outcome carries the right flag."""

    async def test_verified_financial_admissible(
        self, interceptor, valid_financial_message
    ):
        v = await interceptor.intercept(valid_financial_message, trace_id="t_adm_fin")
        assert v.status == VerdictStatus.VERIFIED
        assert v.admissible is True

    async def test_blocked_not_admissible(
        self, interceptor, hallucinated_financial_message
    ):
        v = await interceptor.intercept(
            hallucinated_financial_message, trace_id="t_adm_block"
        )
        assert v.status == VerdictStatus.BLOCKED
        assert v.admissible is False

    async def test_heuristic_pass_not_admissible(self, interceptor, safe_code_message):
        v = await interceptor.intercept(safe_code_message, trace_id="t_adm_heur")
        assert v.status == VerdictStatus.HEURISTIC_PASS
        assert v.admissible is False

    async def test_unverifiable_not_admissible(self, interceptor, general_message):
        v = await interceptor.intercept(general_message, trace_id="t_adm_unv")
        assert v.status == VerdictStatus.UNVERIFIABLE
        assert v.admissible is False

    async def test_error_not_admissible(
        self, interceptor, valid_financial_message, monkeypatch
    ):
        def boom(_payload):
            raise InvalidOperation("injected")

        monkeypatch.setattr(interceptor, "_verify_financial", boom)
        v = await interceptor.intercept(valid_financial_message, trace_id="t_adm_err")
        assert v.status == VerdictStatus.ERROR
        assert v.admissible is False


class TestAttestationIsAdmissible:
    @staticmethod
    def _claims(verdict):
        return {"qwed_a2a": {"verdict": verdict}}

    def test_verified_claims_admissible(self):
        assert A2ACryptoService.is_admissible(self._claims("verified")) is True

    def test_legacy_forwarded_claims_admissible(self):
        """0.3.x issuers emitted "forwarded" for the same outcome (#13)."""
        assert A2ACryptoService.is_admissible(self._claims("forwarded")) is True

    @pytest.mark.parametrize(
        "verdict", ["blocked", "heuristic_pass", "unverifiable", "error"]
    )
    def test_other_verdicts_deny(self, verdict):
        assert A2ACryptoService.is_admissible(self._claims(verdict)) is False

    @pytest.mark.parametrize(
        "claims",
        [
            None,
            {},
            "verified",
            {"qwed_a2a": None},
            {"qwed_a2a": "verified"},
            {"qwed_a2a": {}},
            {"qwed_a2a": {"verdict": None}},
            {"qwed_a2a": {"verdict": ["verified"]}},
            {"qwed_a2a": {"verdict": "FORWARDED"}},
            {"qwed_a2a": {"verdict": "VERIFIED"}},
            {"qwed_a2a": {"verdict": "Forwarded"}},
        ],
    )
    def test_malformed_claims_fail_closed(self, claims):
        assert A2ACryptoService.is_admissible(claims) is False

    @pytest.mark.parametrize(
        ("verdict", "expected"), [("verified", True), ("blocked", False)]
    )
    def test_round_trip_through_verify(self, crypto_service, verdict, expected):
        """A genuine blocked attestation verifies, yet is not admissible."""
        payload = {"data": "x"}
        token = crypto_service.sign_verdict(
            trace_id=f"t_adm_rt_{verdict}",
            verdict_status=verdict,
            engine="finance_guard",
            sender_id="agent-a",
            receiver_id="agent-b",
            payload_hash=A2ACryptoService.payload_hash(payload),
        )
        ok, claims, err = crypto_service.verify_attestation(
            token, AttestationContext("agent-a", "agent-b", payload)
        )
        assert ok is True, err
        assert A2ACryptoService.is_admissible(claims) is expected
