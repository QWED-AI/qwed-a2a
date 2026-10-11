"""
Payload size enforcement (#33).

- HTTP: the router's route class rejects oversized request bodies with 413
  before they are buffered or parsed — Content-Length fast path and a
  streaming cap for chunked bodies. The handler never runs.
- Library: ``intercept()`` blocks payloads over ``max_payload_size_bytes``
  before trust evaluation or any engine runs.
- Code guard: code over 256 KiB is blocked before ``ast.parse``.
"""

import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from qwed_a2a import interceptor as interceptor_module
from qwed_a2a.interceptor import A2AVerificationInterceptor
from qwed_a2a.protocol import endpoints as ep
from qwed_a2a.protocol.schema import (
    AgentMessage,
    InterceptorConfig,
    PayloadType,
    VerdictStatus,
)
from qwed_a2a.security.crypto import AttestationContext
from qwed_a2a.utils.telemetry import get_metrics

LIMIT = 2048


def _message(payload, payload_type=PayloadType.GENERAL) -> AgentMessage:
    return AgentMessage(
        sender_agent_id="agent-a",
        receiver_agent_id="agent-b",
        payload_type=payload_type,
        payload=payload,
    )


@pytest.fixture
def small_interceptor(crypto_service, trust_boundary):
    return A2AVerificationInterceptor(
        config=InterceptorConfig(max_payload_size_bytes=LIMIT),
        crypto_service=crypto_service,
        trust_boundary=trust_boundary,
    )


@pytest.mark.asyncio
class TestInterceptSizeLimit:
    async def test_oversized_payload_blocked(self, small_interceptor, crypto_service):
        msg = _message({"blob": "A" * (LIMIT + 1)})
        v = await small_interceptor.intercept(msg, trace_id="t_size_over")

        assert v.status == VerdictStatus.BLOCKED
        assert v.engine_used == "size_limit"
        assert f"max_payload_size_bytes={LIMIT}" in v.reason
        assert v.admissible is False

        ok, claims, err = crypto_service.verify_attestation(
            v.attestation_jwt, AttestationContext("agent-a", "agent-b", msg.payload)
        )
        assert ok is True, err
        assert claims["qwed_a2a"]["verdict"] == "blocked"
        assert claims["qwed_a2a"]["engine"] == "size_limit"

    async def test_within_limit_proceeds(self, small_interceptor):
        v = await small_interceptor.intercept(
            _message({"blob": "A" * 100}), trace_id="t_size_ok"
        )
        assert v.engine_used == "passthrough"
        assert v.status == VerdictStatus.UNVERIFIABLE

    async def test_exact_limit_proceeds(self, small_interceptor):
        """The limit is inclusive: a payload of exactly LIMIT bytes passes."""
        overhead = len(json.dumps({"blob": ""}, separators=(",", ":")))
        payload = {"blob": "A" * (LIMIT - overhead)}
        assert A2AVerificationInterceptor._payload_size(payload) == LIMIT
        v = await small_interceptor.intercept(_message(payload), trace_id="t_size_eq")
        assert v.engine_used == "passthrough"

    async def test_no_engine_or_trust_work_when_oversized(
        self, small_interceptor, monkeypatch
    ):
        """Size is checked first: neither the trust boundary nor an engine runs."""

        def boom(*_a, **_k):
            raise AssertionError("must not run for an oversized payload")

        monkeypatch.setattr(small_interceptor, "_route_to_engine", boom)
        monkeypatch.setattr(small_interceptor.trust, "evaluate", boom)
        v = await small_interceptor.intercept(
            _message({"blob": "A" * (LIMIT * 2)}), trace_id="t_size_first"
        )
        assert v.engine_used == "size_limit"

    async def test_size_is_utf8_bytes_not_escaped_json(self, small_interceptor):
        """Non-ASCII counts as UTF-8 bytes (2 for e-acute), not as 6-byte
        JSON escapes, so the limit tracks what a client actually sends."""
        payload = {"blob": chr(0xE9) * 900}  # 1800 UTF-8 bytes; ~5400 escaped
        assert A2AVerificationInterceptor._payload_size(payload) < LIMIT
        v = await small_interceptor.intercept(_message(payload), trace_id="t_size_u8")
        assert v.engine_used == "passthrough"

    async def test_lone_surrogate_does_not_crash(self, small_interceptor):
        v = await small_interceptor.intercept(
            _message({"blob": chr(0xD800)}), trace_id="t_size_surrogate"
        )
        assert v.engine_used == "passthrough"

    async def test_counted_as_blocked(self, small_interceptor):
        await small_interceptor.intercept(
            _message({"blob": "A" * (LIMIT + 1)}), trace_id="t_size_metrics"
        )
        metrics = get_metrics()
        assert metrics.total_blocked == 1
        assert metrics.by_engine.get("size_limit") == 1


@pytest.mark.asyncio
class TestCodeSubCap:
    CAP = A2AVerificationInterceptor._MAX_CODE_BYTES

    async def test_cap_is_256_kib(self):
        assert self.CAP == 256 * 1024

    async def test_oversized_code_blocked_before_parse(self, interceptor, monkeypatch):
        """Code within max_payload_size_bytes but over the sub-cap is blocked
        without ever reaching ast.parse."""

        def no_parse(*_a, **_k):
            raise AssertionError("ast.parse must not run on oversized code")

        monkeypatch.setattr(interceptor_module.ast, "parse", no_parse)
        code = "x = 1\n" * (self.CAP // 6 + 1)
        v = await interceptor.intercept(
            _message({"code": code}, PayloadType.CODE_EXECUTION),
            trace_id="t_code_cap",
        )
        assert v.status == VerdictStatus.BLOCKED
        assert v.engine_used == "code_guard"
        assert "analysis limit" in v.reason

    async def test_code_at_cap_is_analysed(self, interceptor):
        code = "#" * (self.CAP - 1) + "\n"
        v = await interceptor.intercept(
            _message({"code": code}, PayloadType.CODE_EXECUTION),
            trace_id="t_code_at_cap",
        )
        assert v.status == VerdictStatus.HEURISTIC_PASS


class TestHttpBodyLimit:
    @pytest.fixture
    def client(self, monkeypatch):
        monkeypatch.setenv("QWED_A2A_API_KEYS", json.dumps({"key-a": "agent-a"}))
        monkeypatch.delenv("QWED_A2A_TRUSTED_AGENTS", raising=False)
        ep.configure_interceptor(InterceptorConfig(max_payload_size_bytes=LIMIT))
        app = FastAPI()
        app.include_router(ep.router)
        return TestClient(app)

    @pytest.fixture
    def intercept_calls(self, monkeypatch):
        calls = []
        interceptor = ep.get_interceptor()
        original = interceptor.intercept

        async def spy(message, trace_id):
            calls.append(trace_id)
            return await original(message, trace_id=trace_id)

        monkeypatch.setattr(interceptor, "intercept", spy)
        return calls

    @staticmethod
    def _body(blob_len):
        return {
            "sender_agent_id": "agent-a",
            "receiver_agent_id": "agent-b",
            "payload_type": "general",
            "payload": {"blob": "A" * blob_len},
        }

    def _limit(self):
        return LIMIT + ep.ENVELOPE_ALLOWANCE_BYTES

    def test_declared_oversized_body_413(self, client, intercept_calls):
        resp = client.post(
            "/a2a/intercept",
            json=self._body(self._limit() + 1),
            headers={"x-api-key": "key-a"},
        )
        assert resp.status_code == 413
        assert intercept_calls == []

    def test_chunked_oversized_body_413(self, client, intercept_calls):
        """No Content-Length: the streamed body is capped as it arrives."""
        chunk = b"A" * 8192

        def body():
            yield b'{"sender_agent_id":"agent-a","receiver_agent_id":"agent-b",'
            yield b'"payload_type":"general","payload":{"blob":"'
            for _ in range(self._limit() // len(chunk) + 2):
                yield chunk
            yield b'"}}'

        resp = client.post(
            "/a2a/intercept",
            content=body(),
            headers={"x-api-key": "key-a", "content-type": "application/json"},
        )
        assert resp.status_code == 413
        assert intercept_calls == []

    def test_unauthenticated_oversized_body_413_before_auth(
        self, client, intercept_calls
    ):
        """Size is rejected before auth or parsing — cheapest check first."""
        resp = client.post("/a2a/intercept", json=self._body(self._limit() + 1))
        assert resp.status_code == 413

    def test_invalid_content_length_400(self, client, intercept_calls):
        resp = client.post(
            "/a2a/intercept",
            content=b"{}",
            headers={
                "x-api-key": "key-a",
                "content-type": "application/json",
                "content-length": "abc",
            },
        )
        assert resp.status_code == 400
        assert intercept_calls == []

    def test_body_within_allowance_reaches_interceptor(self, client, intercept_calls):
        """A body over max_payload_size_bytes but within the envelope
        allowance is parsed; intercept() then applies the payload limit."""
        resp = client.post(
            "/a2a/intercept",
            json=self._body(LIMIT + 1),
            headers={"x-api-key": "key-a"},
        )
        assert resp.status_code == 200
        assert len(intercept_calls) == 1
        assert resp.json()["engine_used"] == "size_limit"

    def test_small_body_ok(self, client, intercept_calls):
        resp = client.post(
            "/a2a/intercept", json=self._body(10), headers={"x-api-key": "key-a"}
        )
        assert resp.status_code == 200
        assert len(intercept_calls) == 1

    def test_get_routes_unaffected(self, client):
        assert client.get("/a2a/health").status_code == 200

    def test_openapi_keeps_request_model(self, client):
        schema = client.app.openapi()
        assert "requestBody" in schema["paths"]["/a2a/intercept"]["post"]
