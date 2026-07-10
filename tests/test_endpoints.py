"""
Tests for QWED A2A protocol endpoints — FastAPI gateway layer.
Covers: get_interceptor(), configure_interceptor(), _load_trusted_agents(),
        /a2a/intercept, /a2a/health, /a2a/metrics routes.
"""

from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from qwed_a2a.protocol import endpoints as ep
from qwed_a2a.protocol.endpoints import (
    _load_trusted_agents,
    configure_interceptor,
    get_interceptor,
    router,
    wellknown_router,
)
from qwed_a2a.protocol.schema import InterceptorConfig


# ─── fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def reset_interceptor_singleton():
    ep._interceptor = None
    yield
    ep._interceptor = None


@pytest.fixture
def app():
    application = FastAPI()
    application.include_router(router)
    return application


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.fixture
def general_payload():
    return {
        "sender_agent_id": "agent-alpha",
        "receiver_agent_id": "agent-beta",
        "payload_type": "general",
        "payload": {"msg": "hello"},
    }


@pytest.fixture
def financial_payload():
    return {
        "sender_agent_id": "procurement-agent",
        "receiver_agent_id": "treasury-agent",
        "payload_type": "financial_transaction",
        "payload": {
            "data": {
                "claimed_total": "100.00",
                "line_items": [
                    {"description": "Widget", "amount": "100.00", "quantity": 1}
                ],
            }
        },
    }


# ─── _load_trusted_agents ──────────────────────────────────────────────────────


class TestLoadTrustedAgents:
    def test_loads_agents_from_env(self, monkeypatch):
        monkeypatch.setenv("QWED_A2A_TRUSTED_AGENTS", "agent-a,agent-b")
        interceptor = MagicMock()
        _load_trusted_agents(interceptor)
        assert interceptor.trust.trust_agent.call_count == 2
        calls = [c.args[0] for c in interceptor.trust.trust_agent.call_args_list]
        assert "agent-a" in calls
        assert "agent-b" in calls

    def test_ignores_empty_entries(self, monkeypatch):
        monkeypatch.setenv("QWED_A2A_TRUSTED_AGENTS", "agent-a,,  ,agent-b")
        interceptor = MagicMock()
        _load_trusted_agents(interceptor)
        assert interceptor.trust.trust_agent.call_count == 2

    def test_no_env_var_no_agents_registered(self, monkeypatch):
        monkeypatch.delenv("QWED_A2A_TRUSTED_AGENTS", raising=False)
        interceptor = MagicMock()
        _load_trusted_agents(interceptor)
        interceptor.trust.trust_agent.assert_not_called()

    def test_whitespace_stripped_from_agent_ids(self, monkeypatch):
        monkeypatch.setenv("QWED_A2A_TRUSTED_AGENTS", "  agent-x  ,  agent-y  ")
        interceptor = MagicMock()
        _load_trusted_agents(interceptor)
        calls = [c.args[0] for c in interceptor.trust.trust_agent.call_args_list]
        assert "agent-x" in calls
        assert "agent-y" in calls


# ─── singleton ────────────────────────────────────────────────────────────────


class TestInterceptorSingleton:
    def test_get_interceptor_returns_instance(self, monkeypatch):
        monkeypatch.delenv("QWED_A2A_TRUSTED_AGENTS", raising=False)
        assert get_interceptor() is not None

    def test_get_interceptor_is_singleton(self, monkeypatch):
        monkeypatch.delenv("QWED_A2A_TRUSTED_AGENTS", raising=False)
        assert get_interceptor() is get_interceptor()

    def test_configure_interceptor_replaces_singleton(self, monkeypatch):
        monkeypatch.delenv("QWED_A2A_TRUSTED_AGENTS", raising=False)
        original = get_interceptor()
        configure_interceptor(InterceptorConfig())
        assert get_interceptor() is not original


# ─── /a2a/health ──────────────────────────────────────────────────────────────


class TestHealthEndpoint:
    def test_returns_200(self, client):
        assert client.get("/a2a/health").status_code == 200

    def test_returns_correct_fields(self, client):
        data = client.get("/a2a/health").json()
        assert data["status"] == "healthy"
        assert data["service"] == "qwed-a2a"
        assert "version" in data


# ─── /a2a/metrics ─────────────────────────────────────────────────────────────


class TestMetricsEndpoint:
    def test_returns_200(self, client, monkeypatch):
        monkeypatch.delenv("QWED_A2A_TRUSTED_AGENTS", raising=False)
        assert client.get("/a2a/metrics").status_code == 200

    def test_returns_dict(self, client, monkeypatch):
        monkeypatch.delenv("QWED_A2A_TRUSTED_AGENTS", raising=False)
        assert isinstance(client.get("/a2a/metrics").json(), dict)


# ─── /a2a/intercept ───────────────────────────────────────────────────────────


class TestInterceptEndpoint:
    def test_general_message_returns_200(self, client, general_payload, monkeypatch):
        monkeypatch.delenv("QWED_A2A_TRUSTED_AGENTS", raising=False)
        assert client.post("/a2a/intercept", json=general_payload).status_code == 200

    def test_returns_verdict_fields(self, client, general_payload, monkeypatch):
        monkeypatch.delenv("QWED_A2A_TRUSTED_AGENTS", raising=False)
        data = client.post("/a2a/intercept", json=general_payload).json()
        assert "status" in data
        assert "audit_trace_id" in data

    def test_valid_financial_forwarded(self, client, financial_payload, monkeypatch):
        # Both agents must be trusted so the zero-trust boundary allows the request
        monkeypatch.setenv(
            "QWED_A2A_TRUSTED_AGENTS", "procurement-agent,treasury-agent"
        )
        resp = client.post("/a2a/intercept", json=financial_payload)
        assert resp.status_code == 200
        assert resp.json()["status"] == "forwarded"

    def test_malformed_body_returns_422(self, client, monkeypatch):
        monkeypatch.delenv("QWED_A2A_TRUSTED_AGENTS", raising=False)
        assert client.post("/a2a/intercept", json={"bad": "data"}).status_code == 422

    def test_runtime_error_returns_503(self, client, general_payload, monkeypatch):
        monkeypatch.delenv("QWED_A2A_TRUSTED_AGENTS", raising=False)

        async def _raise(*a, **kw):
            raise RuntimeError("crypto unavailable")

        with patch.object(ep.A2AVerificationInterceptor, "intercept", new=_raise):
            assert (
                client.post("/a2a/intercept", json=general_payload).status_code == 503
            )

    def test_unexpected_error_returns_500(self, client, general_payload, monkeypatch):
        monkeypatch.delenv("QWED_A2A_TRUSTED_AGENTS", raising=False)

        async def _raise(*a, **kw):
            raise ValueError("unexpected boom")

        with patch.object(ep.A2AVerificationInterceptor, "intercept", new=_raise):
            assert (
                client.post("/a2a/intercept", json=general_payload).status_code == 500
            )


# ─── /.well-known/jwks.json ────────────────────────────────────────────────────


class TestJWKSEndpoint:
    def test_returns_200(self, monkeypatch):
        monkeypatch.delenv("QWED_A2A_TRUSTED_AGENTS", raising=False)
        application = FastAPI()
        application.include_router(wellknown_router)
        client = TestClient(application)
        assert client.get("/.well-known/jwks.json").status_code == 200

    def test_returns_valid_jwk_set(self, monkeypatch):
        monkeypatch.delenv("QWED_A2A_TRUSTED_AGENTS", raising=False)
        application = FastAPI()
        application.include_router(wellknown_router)
        client = TestClient(application)
        data = client.get("/.well-known/jwks.json").json()
        assert "keys" in data
        assert len(data["keys"]) == 1
        key = data["keys"][0]
        assert key["kty"] == "EC"
        assert key["crv"] == "P-256"
        assert "x" in key
        assert "y" in key
        assert "kid" in key
        assert key["use"] == "sig"
