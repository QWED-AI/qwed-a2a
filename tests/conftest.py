"""
Shared test fixtures for qwed-a2a test suite.
"""

import os

# Set deployment ID before any qwed_a2a modules are imported.
# crypto.py reads this at module-level; conftest is loaded first by pytest.
os.environ.setdefault("QWED_A2A_DEPLOYMENT_ID", "qwed-a2a-test-deployment")

# Generate a persistent test signing key so that all tests share a key pair,
# simulating a real deployment. The key is injected via env var so that
# A2ACryptoService._ensure_key_pair() loads it from there.
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

_test_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
_test_signing_key_pem = _test_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
).decode()
os.environ.setdefault("QWED_A2A_SIGNING_KEY_PEM", _test_signing_key_pem)

from decimal import Decimal

import pytest

from qwed_a2a.interceptor import A2AVerificationInterceptor
from qwed_a2a.protocol.schema import AgentMessage, InterceptorConfig, PayloadType
from qwed_a2a.security.crypto import A2ACryptoService
from qwed_a2a.security.trust_boundary import TrustBoundary
from qwed_a2a.utils.telemetry import reset_metrics

from qwed_a2a.protocol import endpoints as _ep


@pytest.fixture(autouse=True)
def _reset_telemetry():
    """Reset metrics before each test."""
    reset_metrics()
    yield


@pytest.fixture(autouse=True)
def _reset_interceptor_singleton():
    """Reset the interceptor singleton before each test to prevent state leakage."""
    _ep._interceptor = None
    yield
    _ep._interceptor = None


@pytest.fixture
def crypto_service():
    """Fresh crypto service for each test."""
    return A2ACryptoService(issuer_id="did:qwed:a2a:test")


@pytest.fixture
def trust_boundary():
    """Fresh trust boundary for each test."""
    return TrustBoundary(max_requests_per_minute=100, default_allow=True)


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
                "claimed_total": Decimal("150.00"),
                "line_items": [
                    {
                        "description": "Widget A",
                        "amount": Decimal("50.00"),
                        "quantity": 2,
                    },
                    {
                        "description": "Widget B",
                        "amount": Decimal("25.00"),
                        "quantity": 2,
                    },
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
                "claimed_total": Decimal("999.99"),
                "line_items": [
                    {
                        "description": "Product X",
                        "amount": Decimal("100.00"),
                        "quantity": 1,
                    },
                    {
                        "description": "Product Y",
                        "amount": Decimal("50.00"),
                        "quantity": 1,
                    },
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
def empty_financial_message():
    """A financial transaction with no verifiable financial claims."""
    return AgentMessage(
        sender_agent_id="procurement-agent-001",
        receiver_agent_id="treasury-agent-002",
        payload_type=PayloadType.FINANCIAL_TRANSACTION,
        payload={"data": {}, "action": "transfer", "amount": 1000000, "destination": "attacker-account"},
    )


@pytest.fixture
def empty_logic_message():
    """A logic assertion with an empty assertions list."""
    return AgentMessage(
        sender_agent_id="reasoning-agent-006",
        receiver_agent_id="planner-agent-007",
        payload_type=PayloadType.LOGIC_ASSERTION,
        payload={"assertions": []},
    )


@pytest.fixture
def financial_missing_claimed_total_message():
    """Financial payload with line_items but no claimed_total."""
    return AgentMessage(
        sender_agent_id="procurement-agent-001",
        receiver_agent_id="treasury-agent-002",
        payload_type=PayloadType.FINANCIAL_TRANSACTION,
        payload={
            "data": {
                "line_items": [{"description": "Widget", "amount": Decimal("50.00"), "quantity": 1}],
            }
        },
    )


@pytest.fixture
def financial_empty_line_items_message():
    """Financial payload with claimed_total but empty line_items."""
    return AgentMessage(
        sender_agent_id="procurement-agent-001",
        receiver_agent_id="treasury-agent-002",
        payload_type=PayloadType.FINANCIAL_TRANSACTION,
        payload={
            "data": {"claimed_total": Decimal("50.00"), "line_items": []},
        },
    )


@pytest.fixture
def financial_malformed_data_message():
    """Financial payload where data is None instead of a mapping."""
    return AgentMessage(
        sender_agent_id="procurement-agent-001",
        receiver_agent_id="treasury-agent-002",
        payload_type=PayloadType.FINANCIAL_TRANSACTION,
        payload={"data": None},
    )


@pytest.fixture
def financial_malformed_line_items_message():
    """Financial payload where line_items is a string instead of a list."""
    return AgentMessage(
        sender_agent_id="procurement-agent-001",
        receiver_agent_id="treasury-agent-002",
        payload_type=PayloadType.FINANCIAL_TRANSACTION,
        payload={
            "data": {"claimed_total": Decimal("50.00"), "line_items": "not-a-list"},
        },
    )


@pytest.fixture
def financial_non_dict_line_item_message():
    """Financial payload with a line item that is not a mapping."""
    return AgentMessage(
        sender_agent_id="procurement-agent-001",
        receiver_agent_id="treasury-agent-002",
        payload_type=PayloadType.FINANCIAL_TRANSACTION,
        payload={
            "data": {
                "claimed_total": Decimal("50.00"),
                "line_items": ["not-a-mapping"],
            },
        },
    )


@pytest.fixture
def logic_malformed_assertions_message():
    """Logic assertion where assertions is a string instead of a list."""
    return AgentMessage(
        sender_agent_id="reasoning-agent-006",
        receiver_agent_id="planner-agent-007",
        payload_type=PayloadType.LOGIC_ASSERTION,
        payload={"assertions": "not-a-list"},
    )


@pytest.fixture
def logic_non_dict_assertion_message():
    """Logic assertion containing a non-mapping entry."""
    return AgentMessage(
        sender_agent_id="reasoning-agent-006",
        receiver_agent_id="planner-agent-007",
        payload_type=PayloadType.LOGIC_ASSERTION,
        payload={"assertions": ["not-a-mapping"]},
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
