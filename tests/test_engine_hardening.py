"""
Engine hardening (#86).

Logic: case, whitespace, compatibility-form and invisible-character
variants of a claim must not evade contradiction detection, and
``negated`` must be a real boolean.

Finance: negative amounts, quantities and totals have no sign convention
in this payload, so they are UNVERIFIABLE (fail closed), never FORWARDED.
"""

import pytest

from qwed_a2a.protocol.schema import AgentMessage, PayloadType, VerdictStatus


def _logic(assertions) -> AgentMessage:
    return AgentMessage(
        sender_agent_id="agent-a",
        receiver_agent_id="agent-b",
        payload_type=PayloadType.LOGIC_ASSERTION,
        payload={"assertions": assertions},
    )


def _finance(claimed_total, line_items) -> AgentMessage:
    return AgentMessage(
        sender_agent_id="agent-a",
        receiver_agent_id="agent-b",
        payload_type=PayloadType.FINANCIAL_TRANSACTION,
        payload={"data": {"claimed_total": claimed_total, "line_items": line_items}},
    )


@pytest.mark.asyncio
class TestLogicNormalization:
    @pytest.mark.parametrize(
        ("positive", "negative"),
        [
            ("UserIsAdmin", "userisadmin"),  # case
            ("payment sent", "payment  sent"),  # double space
            ("payment sent", "payment\tsent"),  # tab
            ("payment sent", " payment sent \n"),  # padding
            ("Straße", "STRASSE"),  # casefold, not just lower()
            ("payment sent", "ｐａｙｍｅｎｔ ｓｅｎｔ"),  # full-width (NFKC)
            ("payment sent", "pay\u200bment sent"),  # zero-width space
            ("payment sent", "\ufeffpayment sent"),  # BOM
        ],
    )
    async def test_variant_contradiction_blocked(self, interceptor, positive, negative):
        """The audit's executed bypasses (and siblings) are now caught."""
        verdict = await interceptor.intercept(
            _logic(
                [
                    {"claim": positive, "negated": False},
                    {"claim": negative, "negated": True},
                ]
            ),
            trace_id="t_logic_variant",
        )
        assert verdict.status == VerdictStatus.BLOCKED
        assert verdict.engine_used == "logic_guard"
        assert "contradiction" in verdict.reason.lower()

    async def test_audit_reproducer_blocked(self, interceptor):
        """Exact payload from #86: previously forwarded with a signed JWT."""
        verdict = await interceptor.intercept(
            _logic(
                [
                    {"claim": "UserIsAdmin", "negated": False},
                    {"claim": "userisadmin", "negated": True},
                    {"claim": "payment sent", "negated": False},
                    {"claim": "payment  sent", "negated": True},
                ]
            ),
            trace_id="t_logic_86",
        )
        assert verdict.status == VerdictStatus.BLOCKED
        assert verdict.details["contradictions"] == ["payment sent", "userisadmin"]

    async def test_distinct_claims_still_forwarded(self, interceptor):
        """Normalization must not merge genuinely different claims."""
        verdict = await interceptor.intercept(
            _logic(
                [
                    {"claim": "payment sent", "negated": False},
                    {"claim": "payment received", "negated": True},
                ]
            ),
            trace_id="t_logic_distinct",
        )
        assert verdict.status == VerdictStatus.FORWARDED

    @pytest.mark.parametrize("claim", ["\u200b", " \u200b\ufeff ", "\t\n"])
    async def test_claim_empty_after_normalization_unverifiable(
        self, interceptor, claim
    ):
        """A claim made only of invisible characters has no content to check."""
        verdict = await interceptor.intercept(
            _logic([{"claim": claim, "negated": False}]),
            trace_id="t_logic_empty_norm",
        )
        assert verdict.status == VerdictStatus.UNVERIFIABLE
        assert verdict.attestation_jwt is None

    @pytest.mark.parametrize("negated", ["false", "true", 0, 1, None, [], {}])
    async def test_non_bool_negated_unverifiable(self, interceptor, negated):
        """ "false" is truthy — a non-bool polarity is malformed, not guessed."""
        verdict = await interceptor.intercept(
            _logic([{"claim": "x", "negated": negated}]),
            trace_id="t_logic_negated_type",
        )
        assert verdict.status == VerdictStatus.UNVERIFIABLE
        assert "negated must be a boolean" in verdict.reason

    async def test_omitted_negated_defaults_to_positive(self, interceptor):
        verdict = await interceptor.intercept(
            _logic([{"claim": "x"}, {"claim": "X", "negated": True}]),
            trace_id="t_logic_default_neg",
        )
        assert verdict.status == VerdictStatus.BLOCKED


@pytest.mark.asyncio
class TestFinanceSignDomain:
    async def test_audit_reproducer_unverifiable(self, interceptor):
        """Exact all-negative transaction from #86: previously forwarded."""
        verdict = await interceptor.intercept(
            _finance(
                "-150.00",
                [
                    {"amount": "-50.00", "quantity": 2},
                    {"amount": "-25.00", "quantity": 2},
                ],
            ),
            trace_id="t_fin_86",
        )
        assert verdict.status == VerdictStatus.UNVERIFIABLE
        assert verdict.engine_used == "finance_guard"
        assert verdict.attestation_jwt is None
        assert verdict.admissible is False

    async def test_negative_claimed_total_unverifiable(self, interceptor):
        verdict = await interceptor.intercept(
            _finance("-10.00", [{"amount": "10.00"}]), trace_id="t_fin_neg_total"
        )
        assert verdict.status == VerdictStatus.UNVERIFIABLE
        assert "claimed_total must not be negative" in verdict.reason

    @pytest.mark.parametrize(
        "item",
        [
            {"amount": "-10.00"},
            {"amount": "10.00", "quantity": -1},
            {"amount": "-10.00", "quantity": -1},  # product would be positive
        ],
    )
    async def test_negative_line_item_unverifiable(self, interceptor, item):
        verdict = await interceptor.intercept(
            _finance("10.00", [{"amount": "20.00"}, item]),
            trace_id="t_fin_neg_item",
        )
        assert verdict.status == VerdictStatus.UNVERIFIABLE
        assert "must not be negative" in verdict.reason

    async def test_negative_zero_is_zero(self, interceptor):
        """-0 is not negative: a zero-value line still verifies."""
        verdict = await interceptor.intercept(
            _finance("10.00", [{"amount": "10.00"}, {"amount": "-0"}]),
            trace_id="t_fin_neg_zero",
        )
        assert verdict.status == VerdictStatus.FORWARDED

    async def test_non_negative_still_forwarded(self, interceptor):
        verdict = await interceptor.intercept(
            _finance("25.00", [{"amount": "10.00", "quantity": 2}, {"amount": "5.00"}]),
            trace_id="t_fin_ok",
        )
        assert verdict.status == VerdictStatus.FORWARDED
