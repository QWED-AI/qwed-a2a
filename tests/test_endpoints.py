"""
Tests for QWED A2A protocol endpoints — FastAPI gateway layer.
Covers: get_interceptor(), configure_interceptor(), _load_trusted_agents(),
        /a2a/intercept, /a2a/health, /a2a/metrics routes.
"""

from unittest.mock import MagicMock, patch

import json

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
from qwed_a2a.security.trust_boundary import TrustBoundary

# ─── fixtures ──────────────────────────────────────────────────────────────────


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
        interceptor.trust = TrustBoundary(default_allow=False)
        _load_trusted_agents(interceptor)
        assert interceptor.trust.is_trusted("agent-a")
        assert interceptor.trust.is_trusted("agent-b")

    def test_ignores_empty_entries(self, monkeypatch):
        monkeypatch.setenv("QWED_A2A_TRUSTED_AGENTS", "agent-a,,  ,agent-b")
        interceptor = MagicMock()
        interceptor.trust = TrustBoundary(default_allow=False)
        _load_trusted_agents(interceptor)
        assert interceptor.trust.is_trusted("agent-a")
        assert interceptor.trust.is_trusted("agent-b")

    def test_no_env_var_no_agents_registered(self, monkeypatch):
        monkeypatch.delenv("QWED_A2A_TRUSTED_AGENTS", raising=False)
        interceptor = MagicMock()
        interceptor.trust = TrustBoundary(default_allow=False)
        _load_trusted_agents(interceptor)
        assert not interceptor.trust.is_trusted("any-agent")

    def test_whitespace_stripped_from_agent_ids(self, monkeypatch):
        monkeypatch.setenv("QWED_A2A_TRUSTED_AGENTS", "  agent-x  ,  agent-y  ")
        interceptor = MagicMock()
        interceptor.trust = TrustBoundary(default_allow=False)
        _load_trusted_agents(interceptor)
        assert interceptor.trust.is_trusted("agent-x")
        assert interceptor.trust.is_trusted("agent-y")


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
    # #83: every /a2a/intercept call authenticates now — tests below run
    # with keys configured unless the test is about auth itself.
    @staticmethod
    def _auth_env(monkeypatch, mapping=None):
        monkeypatch.setenv(
            "QWED_A2A_API_KEYS",
            json.dumps(
                mapping
                or {
                    "key-alpha": "agent-alpha",
                    "key-procurement": "procurement-agent",
                }
            ),
        )

    @staticmethod
    def _auth_headers(key="key-alpha"):
        return {"x-api-key": key}

    def test_general_message_returns_200(self, client, general_payload, monkeypatch):
        monkeypatch.delenv("QWED_A2A_TRUSTED_AGENTS", raising=False)
        self._auth_env(monkeypatch)
        assert (
            client.post(
                "/a2a/intercept", json=general_payload, headers=self._auth_headers()
            ).status_code
            == 200
        )

    def test_returns_verdict_fields(self, client, general_payload, monkeypatch):
        monkeypatch.delenv("QWED_A2A_TRUSTED_AGENTS", raising=False)
        self._auth_env(monkeypatch)
        data = client.post(
            "/a2a/intercept", json=general_payload, headers=self._auth_headers()
        ).json()
        assert "status" in data
        assert "audit_trace_id" in data

    def test_valid_financial_forwarded(self, client, financial_payload, monkeypatch):
        # Both agents must be trusted so the zero-trust boundary allows the request
        monkeypatch.setenv(
            "QWED_A2A_TRUSTED_AGENTS", "procurement-agent,treasury-agent"
        )
        self._auth_env(monkeypatch)
        resp = client.post(
            "/a2a/intercept",
            json=financial_payload,
            headers=self._auth_headers("key-procurement"),
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "forwarded"

    def test_malformed_body_returns_422(self, client, monkeypatch):
        monkeypatch.delenv("QWED_A2A_TRUSTED_AGENTS", raising=False)
        self._auth_env(monkeypatch)
        assert (
            client.post(
                "/a2a/intercept",
                json={"bad": "data"},
                headers=self._auth_headers(),
            ).status_code
            == 422
        )

    def test_runtime_error_returns_503(self, client, general_payload, monkeypatch):
        monkeypatch.delenv("QWED_A2A_TRUSTED_AGENTS", raising=False)
        self._auth_env(monkeypatch)

        async def _raise(*a, **kw):
            raise RuntimeError("crypto unavailable")

        with patch.object(ep.A2AVerificationInterceptor, "intercept", new=_raise):
            assert (
                client.post(
                    "/a2a/intercept",
                    json=general_payload,
                    headers=self._auth_headers(),
                ).status_code
                == 503
            )

    def test_unexpected_error_returns_500(self, client, general_payload, monkeypatch):
        monkeypatch.delenv("QWED_A2A_TRUSTED_AGENTS", raising=False)
        self._auth_env(monkeypatch)

        async def _raise(*a, **kw):
            raise ValueError("unexpected boom")

        with patch.object(ep.A2AVerificationInterceptor, "intercept", new=_raise):
            assert (
                client.post(
                    "/a2a/intercept",
                    json=general_payload,
                    headers=self._auth_headers(),
                ).status_code
                == 500
            )


# ─── /a2a/intercept authentication (#83) ─────────────────────────────────


class TestInterceptAuth:
    """Transport authentication: the API-key identity overrides the body."""

    def _keys(self, monkeypatch, mapping):
        monkeypatch.setenv("QWED_A2A_API_KEYS", json.dumps(mapping))

    def test_missing_key_denied(self, client, general_payload, monkeypatch):
        self._keys(monkeypatch, {"key-alpha": "agent-alpha"})
        resp = client.post("/a2a/intercept", json=general_payload)
        assert resp.status_code == 401

    def test_unknown_key_denied(self, client, general_payload, monkeypatch):
        self._keys(monkeypatch, {"key-alpha": "agent-alpha"})
        resp = client.post(
            "/a2a/intercept", json=general_payload, headers={"x-api-key": "nope"}
        )
        assert resp.status_code == 401

    def test_unconfigured_keys_deny_all(self, client, general_payload, monkeypatch):
        monkeypatch.delenv("QWED_A2A_API_KEYS", raising=False)
        monkeypatch.setenv(
            "QWED_A2A_TRUSTED_AGENTS", "agent-alpha,agent-beta"
        )
        resp = client.post(
            "/a2a/intercept", json=general_payload, headers={"x-api-key": "whatever"}
        )
        assert resp.status_code == 401

    def test_malformed_keys_deny_all(self, client, general_payload, monkeypatch):
        monkeypatch.setenv("QWED_A2A_API_KEYS", "{not-json")
        resp = client.post(
            "/a2a/intercept", json=general_payload, headers={"x-api-key": "whatever"}
        )
        assert resp.status_code == 401

    def test_spoofed_sender_overridden_by_key_identity(
        self, client, financial_payload, monkeypatch
    ):
        """#83 repro: key for procurement-agent, body claims treasury-agent.

        The request is processed — and attested — AS procurement-agent.
        """
        import jwt as pyjwt

        monkeypatch.setenv(
            "QWED_A2A_TRUSTED_AGENTS", "procurement-agent,treasury-agent"
        )
        self._keys(monkeypatch, {"key-procurement": "procurement-agent"})
        spoofed = dict(financial_payload)
        spoofed["sender_agent_id"] = "treasury-agent"
        resp = client.post(
            "/a2a/intercept",
            json=spoofed,
            headers={"x-api-key": "key-procurement"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "forwarded"
        claims = pyjwt.decode(
            body["attestation_jwt"], options={"verify_signature": False}
        )
        assert claims["qwed_a2a"]["sender"] == "procurement-agent"

    def test_key_rotation_without_restart(
        self, client, general_payload, monkeypatch
    ):
        """Keys load per request: rotating env changes who can call."""
        monkeypatch.delenv("QWED_A2A_TRUSTED_AGENTS", raising=False)
        self._keys(monkeypatch, {"key-alpha": "agent-alpha"})
        ok = client.post(
            "/a2a/intercept",
            json=general_payload,
            headers={"x-api-key": "key-alpha"},
        )
        assert ok.status_code == 200
        self._keys(monkeypatch, {"key-alpha-rotated": "agent-alpha"})
        assert (
            client.post(
                "/a2a/intercept",
                json=general_payload,
                headers={"x-api-key": "key-alpha"},
            ).status_code
            == 401
        )
        assert (
            client.post(
                "/a2a/intercept",
                json=general_payload,
                headers={"x-api-key": "key-alpha-rotated"},
            ).status_code
            == 200
        )

    def test_signature_field_ignored(self, client, general_payload, monkeypatch):
        """#19: the dead signature field is not part of the contract —
        extra fields never affect parsing or identity."""
        self._keys(monkeypatch, {"key-alpha": "agent-alpha"})
        payload = dict(general_payload)
        payload["signature"] = "dead-on-arrival"
        resp = client.post(
            "/a2a/intercept", json=payload, headers={"x-api-key": "key-alpha"}
        )
        assert resp.status_code == 200

    def test_padded_agent_id_normalized(
        self, client, financial_payload, monkeypatch
    ):
        """Configured IDs canonicalize: padded mapping authenticates as
        the trimmed agent everywhere (trust, JWT, telemetry)."""
        import jwt as pyjwt

        monkeypatch.setenv(
            "QWED_A2A_TRUSTED_AGENTS", "procurement-agent,treasury-agent"
        )
        self._keys(monkeypatch, {"key-padded": "  procurement-agent  "})
        resp = client.post(
            "/a2a/intercept",
            json=financial_payload,
            headers={"x-api-key": "key-padded"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "forwarded"
        claims = pyjwt.decode(
            resp.json()["attestation_jwt"], options={"verify_signature": False}
        )
        assert claims["qwed_a2a"]["sender"] == "procurement-agent"

    def test_control_char_agent_id_rejected(
        self, client, general_payload, monkeypatch
    ):
        """Agent IDs violating the AgentMessage contract never enter the
        map — their keys fail closed as unknown."""
        self._keys(monkeypatch, {"key-evil": "bad\x00agent"})
        resp = client.post(
            "/a2a/intercept",
            json=general_payload,
            headers={"x-api-key": "key-evil"},
        )
        assert resp.status_code == 401

    def test_overlong_agent_id_rejected(
        self, client, general_payload, monkeypatch
    ):
        self._keys(monkeypatch, {"key-long": "a" * 257})
        resp = client.post(
            "/a2a/intercept",
            json=general_payload,
            headers={"x-api-key": "key-long"},
        )
        assert resp.status_code == 401

    def test_oversized_key_config_rejected(self):
        """Absurdly large key maps fail closed instead of reaching the parser.

        (70KB cannot travel via real env vars on all platforms, so the
        sanitizer is exercised directly — the endpoint path is covered by
        test_malformed_keys_deny_all.)
        """
        with pytest.raises(ValueError):
            ep._sanitize_keys_json("{" + "x" * 70000)
        with pytest.raises(ValueError):
            ep._sanitize_keys_json("[1, 2]")
        assert ep._sanitize_keys_json('{"k": "v"}') == '{"k": "v"}'

    def test_surrogate_key_denied_not_500(
        self, client, general_payload, monkeypatch
    ):
        """A misconfigured key that cannot UTF-8-encode fails closed with
        401 — never a 500 (Sentry: surrogate escape in key JSON)."""
        monkeypatch.setenv("QWED_A2A_API_KEYS", '{"k\\udc00": "agent-alpha"}')
        resp = client.post(
            "/a2a/intercept",
            json=general_payload,
            headers={"x-api-key": "k"},
        )
        assert resp.status_code == 401

    def test_first_misconfig_warns_on_fresh_boot(self, monkeypatch, caplog):
        """A fresh host (monotonic clock below the interval) still logs
        the first misconfiguration instead of denying silently."""
        import logging
        import time as time_mod

        monkeypatch.setattr(time_mod, "monotonic", lambda: 5.0)
        monkeypatch.setattr(ep, "_API_KEYS_LAST_WARN", None)
        monkeypatch.delenv("QWED_A2A_API_KEYS", raising=False)
        with caplog.at_level(logging.WARNING):
            ep._load_api_keys()
        assert any("denies all" in r.getMessage() for r in caplog.records)

    def test_misconfig_warning_rate_limited(self, client, monkeypatch, caplog):
        """Alternating broken configs warn at most once per minute."""
        import logging
        import time as time_mod

        now = [1000.0]
        monkeypatch.setattr(time_mod, "monotonic", lambda: now[0])
        monkeypatch.setattr(ep, "_API_KEYS_LAST_WARN", None)
        with caplog.at_level(logging.WARNING):
            monkeypatch.delenv("QWED_A2A_API_KEYS", raising=False)
            ep._load_api_keys()
            monkeypatch.setenv("QWED_A2A_API_KEYS", "{broken")
            ep._load_api_keys()
            denied = [
                r
                for r in caplog.records
                if "denies all" in r.getMessage()
            ]
            assert len(denied) == 1
            now[0] += 61.0
            ep._load_api_keys()
            denied = [
                r
                for r in caplog.records
                if "denies all" in r.getMessage()
            ]
            assert len(denied) == 2


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
        assert key["alg"] == "ES256"
