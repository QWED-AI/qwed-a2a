"""
Shared test fixtures for qwed-a2a test suite.
"""

import pytest

from qwed_a2a.interceptor import A2AVerificationInterceptor
from qwed_a2a.protocol.schema import AgentMessage, InterceptorConfig, PayloadType
from qwed_a2a.security.crypto import A2ACryptoService
from qwed_a2a.security.trust_boundary import TrustBoundary
from qwed_a2a.utils.telemetry import reset_metrics


@pytest.fixture(autouse=True)
def _reset_telemetry():
    """Reset metrics before each test."""
    reset_metrics()
    yield


@pytest.fixture
def crypto_service():
    """Fresh crypto service for each test."""
    return A2ACryptoService(issuer_id="did:qwed:a2a:test")


@pytest.fixture
def trust_boundary():
    """Fresh trust boundary for each test."""
    return TrustBoundary(max_requests_per_minute=100)


@pytest.fixture
def interceptor(crypto_service, trust_boundary):
    """Fully configured interceptor for testing."""
    config = InterceptorConfig(block_on_error=True)
    return A2AVerificationInterceptor(
        config=config,
        crypto_service=crypto_service,
        trust_boundary=trust_boundary,
    )


@pytest.fixture
def valid_financial_message():
    """A valid financial transaction message with correct totals."""
    return AgentMessage(
        sender_agent_id="procurement-agent-001",
        receiver_agent_id="treasury-agent-002",
        payload_type=PayloadType.FINANCIAL_TRANSACTION,
        payload={
            "data": {
                "claimed_total": 150.00,
                "line_items": [
                    {"description": "Widget A", "amount": 50.00, "quantity": 2},
                    {"description": "Widget B", "amount": 25.00, "quantity": 2},
                ],
            }
        },
    )


@pytest.fixture
def hallucinated_financial_message():
    """A financial message with an incorrect claimed total."""
    return AgentMessage(
        sender_agent_id="sales-agent-003",
        receiver_agent_id="treasury-agent-002",
        payload_type=PayloadType.FINANCIAL_TRANSACTION,
        payload={
            "data": {
                "claimed_total": 999.99,
                "line_items": [
                    {"description": "Product X", "amount": 100.00, "quantity": 1},
                    {"description": "Product Y", "amount": 50.00, "quantity": 1},
                ],
            }
        },
    )


@pytest.fixture
def dangerous_code_message():
    """A code execution message containing dangerous patterns."""
    return AgentMessage(
        sender_agent_id="code-agent-004",
        receiver_agent_id="executor-agent-005",
        payload_type=PayloadType.CODE_EXECUTION,
        payload={"code": "import os; os.system('rm -rf /')"},
    )


@pytest.fixture
def safe_code_message():
    """A safe code execution message."""
    return AgentMessage(
        sender_agent_id="code-agent-004",
        receiver_agent_id="executor-agent-005",
        payload_type=PayloadType.CODE_EXECUTION,
        payload={"code": "result = sum([1, 2, 3, 4, 5])"},
    )


@pytest.fixture
def contradictory_logic_message():
    """A logic assertion message with contradictions."""
    return AgentMessage(
        sender_agent_id="reasoning-agent-006",
        receiver_agent_id="planner-agent-007",
        payload_type=PayloadType.LOGIC_ASSERTION,
        payload={
            "assertions": [
                {"claim": "sky_is_blue", "negated": False},
                {"claim": "sky_is_blue", "negated": True},
            ]
        },
    )


@pytest.fixture
def general_message():
    """A general message that passes through without verification."""
    return AgentMessage(
        sender_agent_id="agent-alpha",
        receiver_agent_id="agent-beta",
        payload_type=PayloadType.GENERAL,
        payload={"greeting": "Hello, how are you?"},
    )
