"""
CodSpeed performance benchmarks for qwed-a2a.

These benchmarks cover the hot paths that every intercepted agent message
flows through:

- Schema validation (Pydantic AgentMessage construction)
- The verification engines (financial, logic, code)
- Trust boundary evaluation and rate limiting
- JWT attestation signing and verification (ECDSA P-256)
- The full end-to-end intercept pipeline

Each benchmark builds its inputs outside the measured callable so that only
the operation of interest is timed.
"""

import asyncio
from decimal import Decimal

import pytest

from qwed_a2a.interceptor import A2AVerificationInterceptor
from qwed_a2a.protocol.schema import (
    AgentMessage,
    InterceptorConfig,
    PayloadType,
)
from qwed_a2a.security.crypto import A2ACryptoService, AttestationContext
from qwed_a2a.security.trust_boundary import TrustBoundary

# --------------------------------------------------------------------------- #
# Helpers / shared inputs
# --------------------------------------------------------------------------- #


def _financial_payload(num_line_items: int) -> dict:
    line_items = [
        {"description": f"Item {i}", "amount": Decimal("50.00"), "quantity": 2}
        for i in range(num_line_items)
    ]
    total = Decimal("100.00") * num_line_items
    return {"data": {"claimed_total": total, "line_items": line_items}}


def _financial_message(num_line_items: int) -> AgentMessage:
    return AgentMessage(
        sender_agent_id="procurement-agent-001",
        receiver_agent_id="treasury-agent-002",
        payload_type=PayloadType.FINANCIAL_TRANSACTION,
        payload=_financial_payload(num_line_items),
    )


def _logic_message(num_assertions: int) -> AgentMessage:
    assertions = [
        {"claim": f"fact_{i}", "negated": i % 2 == 0} for i in range(num_assertions)
    ]
    return AgentMessage(
        sender_agent_id="reasoning-agent-006",
        receiver_agent_id="planner-agent-007",
        payload_type=PayloadType.LOGIC_ASSERTION,
        payload={"assertions": assertions},
    )


SAFE_CODE = """
def compute(values):
    total = 0
    for v in values:
        total += v * 2
    return sorted([total, len(values), max(values)])


result = compute([1, 2, 3, 4, 5])
"""

DANGEROUS_CODE = "import os; os.system('rm -rf /')"


def _code_message(code: str) -> AgentMessage:
    return AgentMessage(
        sender_agent_id="code-agent-004",
        receiver_agent_id="executor-agent-005",
        payload_type=PayloadType.CODE_EXECUTION,
        payload={"code": code},
    )


def _build_interceptor() -> A2AVerificationInterceptor:
    return A2AVerificationInterceptor(
        config=InterceptorConfig(block_on_error=True),
        crypto_service=A2ACryptoService(issuer_id="did:qwed:a2a:bench"),
        trust_boundary=TrustBoundary(
            max_requests_per_minute=1_000_000, default_allow=True
        ),
    )


# --------------------------------------------------------------------------- #
# Schema validation
# --------------------------------------------------------------------------- #


def test_schema_validation_financial(benchmark):
    payload = _financial_payload(10)

    @benchmark
    def _():
        AgentMessage(
            sender_agent_id="procurement-agent-001",
            receiver_agent_id="treasury-agent-002",
            payload_type=PayloadType.FINANCIAL_TRANSACTION,
            payload=payload,
        )


# --------------------------------------------------------------------------- #
# Verification engines
# --------------------------------------------------------------------------- #


def test_verify_financial_small(benchmark):
    interceptor = _build_interceptor()
    payload = _financial_payload(5)
    benchmark(interceptor._verify_financial, payload)


def test_verify_financial_large(benchmark):
    interceptor = _build_interceptor()
    payload = _financial_payload(200)
    benchmark(interceptor._verify_financial, payload)


def test_verify_logic(benchmark):
    interceptor = _build_interceptor()
    payload = _logic_message(100).payload
    benchmark(interceptor._verify_logic, payload)


def test_verify_code_safe(benchmark):
    interceptor = _build_interceptor()
    payload = {"code": SAFE_CODE}
    benchmark(interceptor._verify_code, payload)


def test_verify_code_dangerous(benchmark):
    interceptor = _build_interceptor()
    payload = {"code": DANGEROUS_CODE}
    benchmark(interceptor._verify_code, payload)


# --------------------------------------------------------------------------- #
# Trust boundary
# --------------------------------------------------------------------------- #


def test_trust_boundary_evaluate(benchmark):
    trust = TrustBoundary(max_requests_per_minute=1_000_000, default_allow=True)
    benchmark(
        trust.evaluate,
        "sender-agent-001",
        "receiver-agent-002",
        payload_type="financial_transaction",
    )


# --------------------------------------------------------------------------- #
# Cryptographic attestation
# --------------------------------------------------------------------------- #


def test_sign_verdict(benchmark):
    crypto = A2ACryptoService(issuer_id="did:qwed:a2a:bench")
    payload = _financial_payload(5)
    payload_hash = crypto.payload_hash(payload)
    counter = {"n": 0}

    def _sign():
        counter["n"] += 1
        return crypto.sign_verdict(
            trace_id=f"trace-{counter['n']}",
            verdict_status="forwarded",
            engine="finance_guard",
            sender_id="procurement-agent-001",
            receiver_id="treasury-agent-002",
            payload_hash=payload_hash,
        )

    benchmark(_sign)


def test_verify_attestation(benchmark):
    crypto = A2ACryptoService(issuer_id="did:qwed:a2a:bench")
    payload = _financial_payload(5)
    payload_hash = crypto.payload_hash(payload)
    token = crypto.sign_verdict(
        trace_id="trace-verify",
        verdict_status="forwarded",
        engine="finance_guard",
        sender_id="procurement-agent-001",
        receiver_id="treasury-agent-002",
        payload_hash=payload_hash,
    )
    context = AttestationContext(
        sender_agent_id="procurement-agent-001",
        receiver_agent_id="treasury-agent-002",
        payload=payload,
    )

    def _verify():
        # jti replay protection is stateful: clear the registry each iteration
        # so we always exercise the full (successful) verification path rather
        # than short-circuiting on a replay detection after the first call.
        crypto._jti_registry._seen.clear()
        return crypto.verify_attestation(token, context)

    benchmark(_verify)


def test_payload_hash(benchmark):
    payload = _financial_payload(50)
    benchmark(A2ACryptoService.payload_hash, payload)


# --------------------------------------------------------------------------- #
# End-to-end intercept pipeline
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "message_factory,trace_prefix",
    [
        (lambda: _financial_message(10), "fin"),
        (lambda: _logic_message(20), "logic"),
        (lambda: _code_message(SAFE_CODE), "code"),
    ],
    ids=["financial", "logic", "code"],
)
def test_intercept_end_to_end(benchmark, message_factory, trace_prefix):
    interceptor = _build_interceptor()
    message = message_factory()
    counter = {"n": 0}

    def _run():
        counter["n"] += 1
        return asyncio.run(
            interceptor.intercept(message, trace_id=f"{trace_prefix}-{counter['n']}")
        )

    benchmark(_run)
