"""
Tests for A2A cryptographic signing and verification.

Covers:
- JWT round-trip (sign → verify via separate verifier instance)
- Tamper detection
- Cross-instance isolation
- Hash determinism
- Replay prevention (issue #8)
- JtiRegistry unit tests
- Context binding (deployment_id, session_id)
- Validity window reduction (300s default)

NOTE on test design:
In production, sign_verdict() is called by the ISSUER service and
verify_attestation() is called by a DOWNSTREAM CONSUMER — always on
different service instances with independent jti registries.
Tests mirror this by using a dedicated `verifier` fixture that shares
the issuer's key pair but has a fresh, independent registry.
"""

import time
import threading

import pytest

from qwed_a2a.security.crypto import A2ACryptoService, JtiRegistry


# ─── helpers ──────────────────────────────────────────────────────────────────


def _generate_test_pem() -> str:
    """Generate a fresh ECDSA P-256 PEM key for testing."""
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization

    pk = ec.generate_private_key(ec.SECP256R1(), default_backend())
    return pk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


# ─── fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def crypto_service():
    """Fresh issuer crypto service per test (loads key from env var)."""
    return A2ACryptoService(issuer_id="did:qwed:a2a:test")


@pytest.fixture
def verifier(crypto_service):
    """
    Separate verifier instance that shares the issuer's key pair but
    has an independent jti registry — mirrors the real-world topology
    where sign and verify happen on different services.
    """
    v = A2ACryptoService(
        issuer_id=crypto_service.issuer_id,
        validity_seconds=crypto_service.validity_seconds,
    )
    # Share the issuer key pair so cross-service verification works
    crypto_service._ensure_key_pair()
    v._key_pair = crypto_service._key_pair
    return v


# ─── helpers ──────────────────────────────────────────────────────────────────


def _sign(service: A2ACryptoService, trace_id: str = "t001", **kwargs) -> str:
    defaults = dict(
        verdict_status="forwarded",
        engine="finance_guard",
        sender_id="agent-A",
        receiver_id="agent-B",
        payload_hash="sha256:abc123",
    )
    defaults.update(kwargs)
    return service.sign_verdict(trace_id=trace_id, **defaults)


# ─── JtiRegistry unit tests ───────────────────────────────────────────────────


class TestJtiRegistry:
    """Unit tests for the replay-prevention registry (independent of JWT)."""

    def test_new_jti_accepted(self):
        registry = JtiRegistry(ttl_seconds=300)
        assert registry.check_and_register("jti-001") is True

    def test_duplicate_jti_rejected(self):
        registry = JtiRegistry(ttl_seconds=300)
        registry.check_and_register("jti-dup")
        assert registry.check_and_register("jti-dup") is False

    def test_different_jtis_both_accepted(self):
        registry = JtiRegistry(ttl_seconds=300)
        assert registry.check_and_register("jti-a") is True
        assert registry.check_and_register("jti-b") is True

    def test_expired_entry_evicted_and_reaccepted(self):
        """After TTL expires the jti slot is released — same jti can be seen again."""
        registry = JtiRegistry(ttl_seconds=1)
        now = time.time()
        registry.check_and_register("jti-expire", now=now)
        assert registry.check_and_register("jti-expire", now=now + 2) is True

    def test_unexpired_entry_still_rejected(self):
        registry = JtiRegistry(ttl_seconds=300)
        now = time.time()
        registry.check_and_register("jti-fresh", now=now)
        assert registry.check_and_register("jti-fresh", now=now + 1) is False

    def test_registry_len(self):
        registry = JtiRegistry(ttl_seconds=300)
        assert len(registry) == 0
        registry.check_and_register("a")
        registry.check_and_register("b")
        assert len(registry) == 2

    def test_eviction_does_not_grow_unbounded(self):
        """Expired entries are evicted — len stays bounded."""
        registry = JtiRegistry(ttl_seconds=1)
        now = time.time()
        for i in range(100):
            registry.check_and_register(f"jti-{i}", now=now)
        assert len(registry) == 100
        # Advance clock past TTL — next registration evicts all old entries
        registry.check_and_register("jti-new", now=now + 2)
        assert len(registry) == 1

    def test_thread_safety(self):
        """Concurrent registrations must not cause races or double-accepts.

        threading.Barrier ensures all 20 threads are blocked at the gate
        before any one of them calls check_and_register — this maximises
        contention and exercises the lock under genuine concurrency.
        """
        registry = JtiRegistry(ttl_seconds=300)
        results = []
        lock = threading.Lock()
        barrier = threading.Barrier(20, timeout=5)

        def register():
            barrier.wait()  # hold until all threads are ready, or timeout
            result = registry.check_and_register("shared-jti")
            with lock:
                results.append(result)

        threads = [threading.Thread(target=register) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)
            assert not t.is_alive(), "Thread did not complete within timeout"

        assert results.count(True) == 1
        assert results.count(False) == 19


# ─── JWT round-trip ───────────────────────────────────────────────────────────


class TestJWTRoundTrip:
    """JWT creation and verification round-trip tests."""

    def test_sign_and_verify(self, crypto_service, verifier):
        """A signed verdict should verify successfully on a separate verifier."""
        token = _sign(crypto_service, trace_id="test_trace_001")

        is_valid, claims, error = verifier.verify_attestation(token)
        assert is_valid is True, f"Unexpected failure: {error}"
        assert error is None
        assert claims["jti"] == "test_trace_001"
        assert claims["qwed_a2a"]["verdict"] == "forwarded"
        assert claims["qwed_a2a"]["engine"] == "finance_guard"

    def test_different_traces_produce_different_tokens(self, crypto_service):
        """Two different verdicts should produce distinct JWTs."""
        token_a = _sign(crypto_service, trace_id="trace_a", verdict_status="forwarded")
        token_b = _sign(crypto_service, trace_id="trace_b", verdict_status="blocked")
        assert token_a != token_b

    def test_claims_contain_deployment_id(self, crypto_service, verifier):
        """Every JWT must carry a deployment_id for context binding."""
        token = _sign(crypto_service, trace_id="t_deploy")
        is_valid, claims, _ = verifier.verify_attestation(token)
        assert is_valid is True
        assert "deployment_id" in claims["qwed_a2a"]
        assert claims["qwed_a2a"]["deployment_id"] is not None

    def test_session_id_propagated_into_claims(self, crypto_service, verifier):
        """Caller-supplied session_id must appear in JWT claims."""
        token = crypto_service.sign_verdict(
            trace_id="t_session",
            verdict_status="forwarded",
            engine="passthrough",
            sender_id="a",
            receiver_id="b",
            payload_hash="sha256:x",
            session_id="sess-abc-123",
        )
        is_valid, claims, _ = verifier.verify_attestation(token)
        assert is_valid is True
        assert claims["qwed_a2a"]["session_id"] == "sess-abc-123"

    def test_default_validity_is_300_seconds(self):
        """Default JWT validity must be ≤ 5 minutes."""
        service = A2ACryptoService()
        assert service.validity_seconds == 300

    def test_exp_claim_is_within_validity_window(self, crypto_service):
        """exp must be set to approximately now + validity_seconds."""
        import jwt as pyjwt

        before = int(time.time())
        token = _sign(crypto_service, trace_id="t_exp_check")
        after = int(time.time())

        raw = pyjwt.decode(token, options={"verify_signature": False})
        assert (
            before + crypto_service.validity_seconds
            <= raw["exp"]
            <= after + crypto_service.validity_seconds + 1
        )


# ─── Tamper detection ─────────────────────────────────────────────────────────


class TestTamperDetection:
    """Tests for tampered payload detection."""

    def test_tampered_token_rejected(self, crypto_service, verifier):
        """A manually modified JWT should fail verification."""
        token = _sign(crypto_service, trace_id="tamper_test")

        parts = token.split(".")
        sig = list(parts[2])
        sig[0] = "X" if sig[0] != "X" else "Y"
        parts[2] = "".join(sig)
        tampered = ".".join(parts)

        is_valid, claims, error = verifier.verify_attestation(tampered)
        assert is_valid is False
        assert claims is None
        assert error is not None


# ─── Cross-instance isolation ─────────────────────────────────────────────────


class TestCrossServiceVerification:
    """Tests for cross-instance verification behavior."""

    def test_different_instance_cannot_verify(self):
        """A token signed by one service should not verify with a different key pair."""
        key_a = _generate_test_pem()
        key_b = _generate_test_pem()

        service_a = A2ACryptoService(
            issuer_id="did:qwed:a2a:node-A", pem_key=key_a
        )
        service_b = A2ACryptoService(
            issuer_id="did:qwed:a2a:node-B", pem_key=key_b
        )

        token = _sign(service_a, trace_id="cross_test")

        is_valid, _, error = service_b.verify_attestation(token)
        assert is_valid is False


# ─── Hash determinism ─────────────────────────────────────────────────────────


class TestHashContent:
    """Tests for deterministic content hashing."""

    def test_same_input_same_hash(self):
        h1 = A2ACryptoService.hash_content("hello world")
        h2 = A2ACryptoService.hash_content("hello world")
        assert h1 == h2
        assert h1.startswith("sha256:")

    def test_different_input_different_hash(self):
        h1 = A2ACryptoService.hash_content("hello")
        h2 = A2ACryptoService.hash_content("world")
        assert h1 != h2


# ─── Replay prevention (issue #8) ────────────────────────────────────────────


class TestReplayPrevention:
    """
    Regression suite for A2A-004 — JWT replay vulnerability.

    Topology: issuer (crypto_service) signs → consumer (verifier) verifies.
    Each has an independent jti registry. Replay is detected when the SAME
    consumer sees the same jti twice — exactly the real-world attack vector.
    """

    def test_same_token_rejected_on_second_presentation(self, crypto_service, verifier):
        """Presenting the same JWT twice to the same verifier must fail second time."""
        token = _sign(crypto_service, trace_id="t_replay_001")

        is_valid_1, _, error_1 = verifier.verify_attestation(token)
        assert is_valid_1 is True, f"First verification failed: {error_1}"

        is_valid_2, claims_2, error_2 = verifier.verify_attestation(token)
        assert is_valid_2 is False
        assert claims_2 is None
        assert "Replay" in error_2

    def test_replay_error_message_is_descriptive(self, crypto_service, verifier):
        """Error message must clearly identify the rejection reason."""
        token = _sign(crypto_service, trace_id="t_replay_msg")
        verifier.verify_attestation(token)  # consume
        _, _, error = verifier.verify_attestation(token)
        assert error == "Replay detected: jti already seen"

    def test_different_jtis_both_verify_once(self, crypto_service, verifier):
        """Two tokens with distinct jti values must each verify once."""
        token_a = _sign(crypto_service, trace_id="t_replay_a")
        token_b = _sign(crypto_service, trace_id="t_replay_b")

        valid_a, _, _ = verifier.verify_attestation(token_a)
        valid_b, _, _ = verifier.verify_attestation(token_b)
        assert valid_a is True
        assert valid_b is True

    def test_jti_registered_on_sign_at_issuer(self, crypto_service):
        """Issuer registers jti at signing time — not only at verify time."""
        _sign(crypto_service, trace_id="t_sign_reg")
        assert len(crypto_service._jti_registry) == 1

    def test_issuer_rejects_replay_of_own_token(self, crypto_service):
        """Issuer also rejects a token it already signed if asked to re-verify it."""
        token = _sign(crypto_service, trace_id="t_self_replay")
        # Issuer has already registered this jti at sign time
        is_valid, _, error = crypto_service.verify_attestation(token)
        assert is_valid is False
        assert "Replay" in error

    def test_expiry_error_takes_precedence_over_replay_error(self):
        """Expiry check runs BEFORE replay check — confirms correct ordering."""
        import jwt as pyjwt

        service = A2ACryptoService(validity_seconds=300)
        token = _sign(service, trace_id="t_order_check")

        # Decode without verification, move exp to the past, re-sign
        key_pair = service._ensure_key_pair()
        raw = pyjwt.decode(token, options={"verify_signature": False})
        raw["exp"] = raw["iat"] - 10  # expired before it was even issued

        expired_token = pyjwt.encode(
            raw,
            key_pair.private_key_pem,
            algorithm=A2ACryptoService.ALGORITHM,
        )

        # Verifier with the same key pair but independent registry.
        # Pre-register the jti so that a replay-first implementation
        # would incorrectly return a replay error instead of expiry.
        verifier = A2ACryptoService(
            issuer_id=service.issuer_id,
            validity_seconds=service.validity_seconds,
        )
        verifier._key_pair = key_pair
        # Seed the jti — if verify_attestation checked replay before expiry
        # it would return "Replay detected" here instead of "expired".
        verifier._jti_registry.check_and_register(raw["jti"])

        is_valid, _, error = verifier.verify_attestation(expired_token)
        assert is_valid is False
        assert error is not None
        # Must be expiry error — proves expiry check runs before replay check.
        assert (
            "expired" in error.lower()
        ), f"Expected expiry error (proving ordering), got: {error!r}"

    def test_tampered_token_does_not_pollute_verifier_registry(
        self, crypto_service, verifier
    ):
        """Tampered (invalid signature) token must not register its jti in verifier."""
        token = _sign(crypto_service, trace_id="t_tamper_reg")

        parts = token.split(".")
        sig = list(parts[2])
        sig[0] = "X" if sig[0] != "X" else "Y"
        parts[2] = "".join(sig)
        tampered = ".".join(parts)

        size_before = len(verifier._jti_registry)
        verifier.verify_attestation(tampered)
        assert len(verifier._jti_registry) == size_before


# ─── Deployment context validation (Codex P1) ─────────────────────────────────────────


class TestDeploymentContextValidation:
    """
    verify_attestation() must enforce deployment_id to close the cross-deployment
    replay vector in shared-key environments.

    Architecture note: _DEPLOYMENT_ID is a module-level constant — stable for
    the lifetime of the Python process. All A2ACryptoService instances in the
    same process share one deployment_id, so legitimate same-deployment
    verification always succeeds. Different deployments (different processes)
    produce different deployment_ids.
    """

    def test_valid_token_passes_deployment_check(self, crypto_service, verifier):
        """Tokens issued in the same deployment must pass deployment_id check."""
        token = _sign(crypto_service, trace_id="t_deploy_ok")
        is_valid, claims, error = verifier.verify_attestation(token)
        assert is_valid is True, f"Unexpected failure: {error}"

    def test_cross_deployment_token_rejected(self):
        """
        A token whose deployment_id does not match the verifier's deployment_id
        must be rejected — even if the cryptographic signature is valid.

        We simulate a different deployment by patching _DEPLOYMENT_ID in the
        crypto module so that the issuer embeds a foreign deployment_id.
        """
        from unittest.mock import patch
        import qwed_a2a.security.crypto as crypto_module

        issuer = A2ACryptoService(issuer_id="did:qwed:a2a:test")

        # Patch the module-level _DEPLOYMENT_ID seen by sign_verdict()
        # so the token is stamped with a deployment that does not match
        # the current runtime.
        with patch.object(crypto_module, "_DEPLOYMENT_ID", "foreign-deployment-xyz"):
            token = _sign(issuer, trace_id="t_cross_deploy")

        # Now verify with a service that sees the REAL _DEPLOYMENT_ID
        issuer._ensure_key_pair()
        verifier = A2ACryptoService(
            issuer_id=issuer.issuer_id,
            validity_seconds=issuer.validity_seconds,
        )
        verifier._key_pair = issuer._key_pair

        is_valid, claims, error = verifier.verify_attestation(token)
        assert is_valid is False
        assert claims is None
        assert "Deployment context mismatch" in error

    def test_missing_deployment_id_rejected(self, crypto_service):
        """
        A token with no deployment_id in qwed_a2a claims must be rejected.
        This guards against older tokens (pre-fix) being replayed post-upgrade.
        """
        import jwt as pyjwt

        # Sign a normal token then strip deployment_id from raw payload
        token = _sign(crypto_service, trace_id="t_no_deploy")
        key_pair = crypto_service._ensure_key_pair()

        raw = pyjwt.decode(token, options={"verify_signature": False})
        # Remove deployment_id from qwed_a2a claims block
        raw["qwed_a2a"].pop("deployment_id", None)

        # Re-sign with same key so signature is valid
        patched_token = pyjwt.encode(
            raw,
            key_pair.private_key_pem,
            algorithm=A2ACryptoService.ALGORITHM,
        )

        verifier = A2ACryptoService(
            issuer_id=crypto_service.issuer_id,
            validity_seconds=crypto_service.validity_seconds,
        )
        verifier._key_pair = key_pair

        is_valid, _, error = verifier.verify_attestation(patched_token)
        # Missing deployment_id fails Pydantic validation before
        # the explicit deployment context check runs.
        assert is_valid is False
        assert error in (
            "Invalid qwed_a2a claims structure",
            "Deployment context mismatch: token not issued by this deployment",
        )

    def test_deployment_id_check_runs_before_jti_check(self):
        """
        Deployment context validation runs before jti replay check.
        A cross-deployment token must not register its jti in the verifier's
        registry — otherwise an attacker could pre-burn legitimate jti values.
        """
        from unittest.mock import patch
        import qwed_a2a.security.crypto as crypto_module

        issuer = A2ACryptoService(issuer_id="did:qwed:a2a:test")

        with patch.object(crypto_module, "_DEPLOYMENT_ID", "foreign-deployment-abc"):
            token = _sign(issuer, trace_id="t_order_deploy")

        issuer._ensure_key_pair()
        verifier = A2ACryptoService(
            issuer_id=issuer.issuer_id,
            validity_seconds=issuer.validity_seconds,
        )
        verifier._key_pair = issuer._key_pair

        size_before = len(verifier._jti_registry)
        verifier.verify_attestation(token)
        # Registry must not have grown — cross-deployment token was rejected
        # before the jti check ran
        assert len(verifier._jti_registry) == size_before


class TestClaimsValidation:
    """
    Tests for Pydantic structural validation of JWT claims.

    verify_attestation() validates qwed_a2a as a typed model before
    accessing deployment_id — preventing AttributeError on malformed tokens.
    """

    def test_malformed_qwed_a2a_claim_rejected(self, crypto_service):
        """A token with qwed_a2a set to a non-mapping must be cleanly rejected."""
        import jwt as pyjwt

        token = _sign(crypto_service, trace_id="t_malform")
        key_pair = crypto_service._ensure_key_pair()

        raw = pyjwt.decode(token, options={"verify_signature": False})
        raw["qwed_a2a"] = "this-should-be-a-dict-not-a-string"

        bad_token = pyjwt.encode(
            raw,
            key_pair.private_key_pem,
            algorithm=A2ACryptoService.ALGORITHM,
        )

        verifier = A2ACryptoService(
            issuer_id=crypto_service.issuer_id,
            validity_seconds=crypto_service.validity_seconds,
        )
        verifier._key_pair = key_pair

        is_valid, claims, error = verifier.verify_attestation(bad_token)
        assert is_valid is False
        assert claims is None
        assert "Invalid qwed_a2a claims" in error

    def test_missing_qwed_a2a_claim_rejected(self, crypto_service):
        """A token with qwed_a2a entirely absent must be rejected."""
        import jwt as pyjwt

        token = _sign(crypto_service, trace_id="t_no_qwed_a2a")
        key_pair = crypto_service._ensure_key_pair()

        raw = pyjwt.decode(token, options={"verify_signature": False})
        raw.pop("qwed_a2a", None)

        bad_token = pyjwt.encode(
            raw,
            key_pair.private_key_pem,
            algorithm=A2ACryptoService.ALGORITHM,
        )

        verifier = A2ACryptoService(
            issuer_id=crypto_service.issuer_id,
            validity_seconds=crypto_service.validity_seconds,
        )
        verifier._key_pair = key_pair

        is_valid, claims, error = verifier.verify_attestation(bad_token)
        assert is_valid is False
        assert claims is None
        assert "Invalid qwed_a2a claims" in error


# ─── Audit continuity — persistent signing key ─────────────────────────────────


class TestPersistentSigningKey:
    """Tests for issue #11: process-local ephemeral keys."""

    def test_missing_pem_raises_on_key_access(self):
        """Service must fail closed if QWED_A2A_SIGNING_KEY_PEM is not set."""
        import os

        original = os.environ.pop("QWED_A2A_SIGNING_KEY_PEM", None)
        try:
            service = A2ACryptoService(issuer_id="did:qwed:a2a:test")
            with pytest.raises(RuntimeError, match="QWED_A2A_SIGNING_KEY_PEM"):
                service._ensure_key_pair()
        finally:
            if original is not None:
                os.environ["QWED_A2A_SIGNING_KEY_PEM"] = original

    def test_signing_key_loaded_from_injected_pem(self):
        """A PEM passed to the constructor must be used instead of the env var."""
        key_a = _generate_test_pem()
        service = A2ACryptoService(issuer_id="did:qwed:a2a:test", pem_key=key_a)
        service._ensure_key_pair()
        assert service._key_pair is not None

    def test_same_pem_produces_same_key_id(self):
        """Loading the same PEM twice must produce the same key_id."""
        pem = _generate_test_pem()

        s1 = A2ACryptoService(issuer_id="did:qwed:a2a:test", pem_key=pem)
        s1._ensure_key_pair()
        kid1 = s1._key_pair.key_id

        s2 = A2ACryptoService(issuer_id="did:qwed:a2a:test", pem_key=pem)
        s2._ensure_key_pair()
        kid2 = s2._key_pair.key_id

        assert kid1 == kid2

    def test_key_id_is_fingerprint_based(self):
        """key_id must include a fingerprint, not be 'signing-key-v1'."""
        pem = _generate_test_pem()
        service = A2ACryptoService(issuer_id="did:qwed:a2a:test", pem_key=pem)
        service._ensure_key_pair()
        kid = service._key_pair.key_id
        assert "#key-" in kid, f"Expected fingerprint-based key_id, got: {kid}"
        assert "signing-key-v1" not in kid

    def test_audit_continuity_after_restart(self):
        """
        A JWT signed before restart must be verifiable after restart
        when the same PEM key is loaded again — audit continuity.
        """
        pem = _generate_test_pem()

        s1 = A2ACryptoService(issuer_id="did:qwed:a2a:test", pem_key=pem)
        token = _sign(s1, trace_id="t_audit_cont")

        s2 = A2ACryptoService(issuer_id="did:qwed:a2a:test", pem_key=pem)

        is_valid, claims, error = s2.verify_attestation(token)
        assert is_valid is True, (
            f"JWT signed before restart is not verifiable after restart: {error}"
        )
        assert claims["jti"] == "t_audit_cont"

    def test_two_instances_with_same_pem_produce_mutually_verifiable_jwts(self):
        """
        Two service instances with the same PEM must be able to verify
        each other's JWTs — enables horizontal scaling.
        """
        pem = _generate_test_pem()

        s1 = A2ACryptoService(issuer_id="did:qwed:a2a:test", pem_key=pem)
        s2 = A2ACryptoService(issuer_id="did:qwed:a2a:test", pem_key=pem)

        token = _sign(s1, trace_id="t_mutual")

        is_valid, claims, error = s2.verify_attestation(token)
        assert is_valid is True, f"Cross-instance verification failed: {error}"

    def test_get_public_key_jwk_returns_valid_jwk(self):
        """get_public_key_jwk() must return a dict with required JWK fields."""
        pem = _generate_test_pem()
        service = A2ACryptoService(issuer_id="did:qwed:a2a:test", pem_key=pem)
        jwk = service.get_public_key_jwk()

        assert jwk["kty"] == "EC"
        assert jwk["crv"] == "P-256"
        assert "x" in jwk
        assert "y" in jwk
        assert "kid" in jwk
        assert jwk["use"] == "sig"
        assert jwk["alg"] == "ES256"

    @pytest.mark.asyncio
    async def test_interceptor_intercept_without_pem_fails_closed(self, monkeypatch):
        """Interceptor must fail closed if no key is available on first sign."""
        from decimal import Decimal
        from qwed_a2a.interceptor import A2AVerificationInterceptor
        from qwed_a2a.protocol.schema import AgentMessage, PayloadType
        from qwed_a2a.security.trust_boundary import TrustBoundary

        monkeypatch.delenv("QWED_A2A_SIGNING_KEY_PEM", raising=False)
        interceptor = A2AVerificationInterceptor(
            trust_boundary=TrustBoundary(default_allow=True)
        )
        msg = AgentMessage(
            sender_agent_id="a",
            receiver_agent_id="b",
            payload_type=PayloadType.FINANCIAL_TRANSACTION,
            payload={
                "data": {
                    "claimed_total": Decimal("10.00"),
                    "line_items": [
                        {"description": "Item", "amount": Decimal("10.00"), "quantity": 1}
                    ],
                }
            },
        )
        with pytest.raises(RuntimeError, match="sign attestation"):
            await interceptor.intercept(msg, trace_id="t_no_pem")
