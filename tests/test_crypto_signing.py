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

import json
import time
import threading

import pytest

from qwed_a2a.security.crypto import A2ACryptoService, JtiRegistry, AttestationContext

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


_TEST_PAYLOAD: dict[str, object] = {"data": "test"}
_TEST_PAYLOAD_HASH: str = A2ACryptoService.hash_content(
    json.dumps(_TEST_PAYLOAD, sort_keys=True, default=str)
)


def _sign(service: A2ACryptoService, trace_id: str = "t001", **kwargs) -> str:
    defaults = dict(
        verdict_status="forwarded",
        engine="finance_guard",
        sender_id="agent-A",
        receiver_id="agent-B",
        payload_hash=_TEST_PAYLOAD_HASH,
    )
    defaults.update(kwargs)
    return service.sign_verdict(trace_id=trace_id, **defaults)


def _default_context(**overrides) -> AttestationContext:
    ctx = AttestationContext(
        sender_agent_id="agent-A",
        receiver_agent_id="agent-B",
        payload=_TEST_PAYLOAD,
    )
    for k, v in overrides.items():
        setattr(ctx, k, v)
    return ctx


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

    def test_release_withdraws_reservation(self):
        """Released jtis can be registered again; missing keys are a no-op."""
        registry = JtiRegistry(ttl_seconds=300)
        registry.check_and_register("jti-rel")
        registry.release("jti-rel")
        assert registry.check_and_register("jti-rel") is True
        registry.release("never-seen")  # must not raise
        assert len(registry) == 1

    def test_eviction_reaches_behind_long_lived_head(self):
        """Per-token lifetimes break insertion==expiry order; eviction
        must not stop at a live head and leak expired entries behind it."""
        registry = JtiRegistry(ttl_seconds=100)
        now = time.time()
        registry.check_and_register("long", now=now, valid_until=now + 3600)
        registry.check_and_register("short", now=now)  # expires at now+100
        # Past the short slot's expiry but before the long one's: short
        # is evicted and re-accepted while long still denies replay.
        assert registry.check_and_register("short", now=now + 200) is True
        assert registry.check_and_register("long", now=now + 200) is False

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

        is_valid, claims, error = verifier.verify_attestation(token, _default_context())
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
        is_valid, claims, _ = verifier.verify_attestation(token, _default_context())
        assert is_valid is True
        assert "deployment_id" in claims["qwed_a2a"]
        assert claims["qwed_a2a"]["deployment_id"] is not None

    def test_session_id_propagated_into_claims(self, crypto_service, verifier):
        """Caller-supplied session_id must appear in JWT claims."""
        token = _sign(crypto_service, trace_id="t_session", session_id="sess-abc-123")
        is_valid, claims, _ = verifier.verify_attestation(
            token, _default_context(session_id="sess-abc-123")
        )
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

        is_valid, claims, error = verifier.verify_attestation(
            tampered, _default_context()
        )
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

        service_a = A2ACryptoService(issuer_id="did:qwed:a2a:node-A", pem_key=key_a)
        service_b = A2ACryptoService(issuer_id="did:qwed:a2a:node-B", pem_key=key_b)

        token = _sign(service_a, trace_id="cross_test")

        is_valid, _, error = service_b.verify_attestation(token, _default_context())
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

        is_valid_1, _, error_1 = verifier.verify_attestation(token, _default_context())
        assert is_valid_1 is True, f"First verification failed: {error_1}"

        is_valid_2, claims_2, error_2 = verifier.verify_attestation(
            token, _default_context()
        )
        assert is_valid_2 is False
        assert claims_2 is None
        assert "Replay" in error_2

    def test_replay_error_message_is_descriptive(self, crypto_service, verifier):
        """Error message must clearly identify the rejection reason."""
        token = _sign(crypto_service, trace_id="t_replay_msg")
        verifier.verify_attestation(token, _default_context())  # consume
        _, _, error = verifier.verify_attestation(token, _default_context())
        assert error == "Replay detected: jti already seen"

    def test_different_jtis_both_verify_once(self, crypto_service, verifier):
        """Two tokens with distinct jti values must each verify once."""
        token_a = _sign(crypto_service, trace_id="t_replay_a")
        token_b = _sign(crypto_service, trace_id="t_replay_b")

        valid_a, _, _ = verifier.verify_attestation(token_a, _default_context())
        valid_b, _, _ = verifier.verify_attestation(token_b, _default_context())
        assert valid_a is True
        assert valid_b is True

    def test_sign_consumes_no_replay_slot_at_issuer(self, crypto_service):
        """#85: signing records issuance only — never a consumption slot."""
        _sign(crypto_service, trace_id="t_sign_reg")
        assert len(crypto_service._jti_registry) == 0

    def test_issuer_verifies_own_token_once_then_replay(self, crypto_service):
        """#85: the issuer CAN verify its own attestation (once)."""
        token = _sign(crypto_service, trace_id="t_self_verify")
        is_valid, _, error = crypto_service.verify_attestation(
            token, _default_context()
        )
        assert is_valid is True, f"Self-verification failed: {error}"
        is_valid_2, _, error_2 = crypto_service.verify_attestation(
            token, _default_context()
        )
        assert is_valid_2 is False
        assert "Replay" in error_2

    def test_duplicate_trace_id_refused_at_issuance(self, crypto_service):
        """#85: a reused trace_id raises instead of minting a twin-jti JWT."""
        import pytest

        _sign(crypto_service, trace_id="t_dup_trace")
        with pytest.raises(ValueError, match="duplicate trace_id"):
            _sign(
                crypto_service,
                trace_id="t_dup_trace",
                verdict_status="blocked",
            )
        # The refused second signing consumed no replay slot either.
        assert len(crypto_service._jti_registry) == 0

    def test_sign_key_failure_does_not_burn_trace(self, monkeypatch):
        """Failed signing reserves nothing — fixing the key unblocks retry."""
        import pytest

        monkeypatch.delenv("QWED_A2A_SIGNING_KEY_PEM", raising=False)
        svc = A2ACryptoService(issuer_id="did:qwed:a2a:retry")
        with pytest.raises(RuntimeError, match="QWED_A2A_SIGNING_KEY_PEM"):
            _sign(svc, trace_id="t_retry_trace")
        # Nothing reserved: same trace works once the key is configured.
        svc._pem_key = _generate_test_pem()
        token = _sign(svc, trace_id="t_retry_trace")
        ok, _, err = svc.verify_attestation(token, _default_context())
        assert ok, err

    def test_short_ttl_injected_registry_rejected(self):
        """Registries expiring entries while tokens live are refused fast."""
        import pytest

        from qwed_a2a.security.crypto import JtiRegistry

        pem = _generate_test_pem()
        registry = JtiRegistry(ttl_seconds=1)
        with pytest.raises(ValueError, match="ttl_seconds"):
            A2ACryptoService(
                issuer_id="did:qwed:a2a:short",
                validity_seconds=300,
                pem_key=pem,
                jti_registry=registry,
            )

    def test_registry_without_ttl_rejected(self):
        """A registry that does not report retention is unverifiable:
        refused rather than trusted to retain live entries."""
        import pytest

        class _NoTtlRegistry:
            def check_and_register(self, jti, now=None, *, valid_until=None):
                return True

            def __len__(self):
                return 0

        with pytest.raises(ValueError, match="ttl_seconds"):
            A2ACryptoService(
                issuer_id="did:qwed:a2a:nottl",
                pem_key=_generate_test_pem(),
                jti_registry=_NoTtlRegistry(),
            )

    def test_retention_follows_token_expiry(self):
        """A token valid longer than the TTL keeps its slot past the TTL."""
        import time

        from qwed_a2a.security.crypto import JtiRegistry

        registry = JtiRegistry(ttl_seconds=10)
        now = time.time()
        assert registry.check_and_register("t-long", now=now, valid_until=now + 3600)
        # Past the 10s TTL the slot is still held (token lives 1h).
        assert registry.check_and_register("t-long", now=now + 20) is False
        # Past the token's own expiry the slot is released.
        assert registry.check_and_register("t-long", now=now + 3700) is True

    def test_consumption_slot_outlives_short_ttl(self):
        """End to end: the stored slot expiry matches the token's exp."""
        import time

        import jwt as pyjwt
        import qwed_a2a.security.crypto as crypto_mod
        from qwed_a2a.security.crypto import JtiRegistry

        pem_a = _generate_test_pem()
        issuer = A2ACryptoService(issuer_id="did:qwed:a2a:alpha", pem_key=pem_a)
        shared = JtiRegistry(ttl_seconds=300)
        verifier = A2ACryptoService(
            issuer_id="did:qwed:a2a:alpha",
            pem_key=pem_a,
            jti_registry=shared,
        )
        verifier._key_pair = issuer._ensure_key_pair()

        now = int(time.time())
        body = {
            "iss": issuer.issuer_id,
            "sub": A2ACryptoService.payload_hash({"data": "long"}),
            "iat": now,
            "exp": now + 3600,
            "jti": "t-slot-long",
            "qwed_a2a": {
                "version": "1.0",
                "verdict": "forwarded",
                "engine": "e",
                "sender": "a1",
                "receiver": "b1",
                "deployment_id": crypto_mod._DEPLOYMENT_ID,
                "session_id": None,
            },
        }
        token = pyjwt.encode(
            body,
            issuer._key_pair.private_key_pem,
            algorithm="ES256",
            headers={"kid": issuer.get_public_key_jwk()["kid"]},
        )
        ctx = AttestationContext(
            sender_agent_id="a1", receiver_agent_id="b1", payload={"data": "long"}
        )
        ok, _, err = verifier.verify_attestation(token, ctx)
        assert ok, err
        # Slot retained to token expiry, not registry TTL.
        assert shared._seen["t-slot-long"] == now + 3600

    def test_malformed_exp_reads_invalid_not_crash(self):
        """exp=None (valid signature) denies as invalid, never raises."""
        import jwt as pyjwt
        import qwed_a2a.security.crypto as crypto_mod

        pem_a = _generate_test_pem()
        issuer = A2ACryptoService(issuer_id="did:qwed:a2a:alpha", pem_key=pem_a)
        peer = A2ACryptoService(
            issuer_id="did:qwed:a2a:peer-beta", pem_key=_generate_test_pem()
        )
        body = {
            "iss": issuer.issuer_id,
            "sub": A2ACryptoService.payload_hash({"data": "badexp"}),
            "iat": 1700000000,
            "exp": None,
            "jti": "t-badexp",
            "qwed_a2a": {
                "version": "1.0",
                "verdict": "forwarded",
                "engine": "e",
                "sender": "a1",
                "receiver": "b1",
                "deployment_id": crypto_mod._DEPLOYMENT_ID,
                "session_id": None,
            },
        }
        token = pyjwt.encode(
            body,
            issuer._ensure_key_pair().private_key_pem,
            algorithm="ES256",
            headers={"kid": issuer.get_public_key_jwk()["kid"]},
        )
        ctx = AttestationContext(
            sender_agent_id="a1", receiver_agent_id="b1", payload={"data": "badexp"}
        )
        entry = {
            issuer.issuer_id: {
                "deployment_id": crypto_mod._DEPLOYMENT_ID,
                "jwks": {"keys": [issuer.get_public_key_jwk()]},
            }
        }
        ok, _, _ = peer.verify_attestation(token, ctx, trusted_issuers=entry)
        assert not ok

    def test_string_exp_coerced_and_retained(self):
        """exp='4102444800' verifies (PyJWT integer-coercible) with the
        coerced int driving retention — never a comparison crash."""
        import jwt as pyjwt
        import qwed_a2a.security.crypto as crypto_mod
        from qwed_a2a.security.crypto import JtiRegistry

        pem_a = _generate_test_pem()
        issuer = A2ACryptoService(issuer_id="did:qwed:a2a:alpha", pem_key=pem_a)
        shared = JtiRegistry(ttl_seconds=300)
        verifier = A2ACryptoService(
            issuer_id="did:qwed:a2a:alpha",
            pem_key=pem_a,
            jti_registry=shared,
        )
        verifier._key_pair = issuer._ensure_key_pair()

        body = {
            "iss": issuer.issuer_id,
            "sub": A2ACryptoService.payload_hash({"data": "strexp"}),
            "iat": 1700000000,
            "exp": "4102444800",
            "jti": "t-strexp",
            "qwed_a2a": {
                "version": "1.0",
                "verdict": "forwarded",
                "engine": "e",
                "sender": "a1",
                "receiver": "b1",
                "deployment_id": crypto_mod._DEPLOYMENT_ID,
                "session_id": None,
            },
        }
        token = pyjwt.encode(
            body,
            issuer._key_pair.private_key_pem,
            algorithm="ES256",
            headers={"kid": issuer.get_public_key_jwk()["kid"]},
        )
        ctx = AttestationContext(
            sender_agent_id="a1", receiver_agent_id="b1", payload={"data": "strexp"}
        )
        ok, _, err = verifier.verify_attestation(token, ctx)
        assert ok, err
        assert shared._seen["t-strexp"] == 4102444800

    def test_shared_registry_blocks_cross_worker_replay(self):
        """#85: an injected shared consumption registry closes the
        cross-worker replay window — what one worker consumed, another
        rejects."""
        from qwed_a2a.security.crypto import JtiRegistry

        pem_a = _generate_test_pem()
        issuer = A2ACryptoService(issuer_id="did:qwed:a2a:alpha", pem_key=pem_a)
        shared = JtiRegistry(ttl_seconds=300)
        worker_1 = A2ACryptoService(
            issuer_id="did:qwed:a2a:alpha",
            pem_key=pem_a,
            jti_registry=shared,
        )
        worker_1._key_pair = issuer._ensure_key_pair()
        worker_2 = A2ACryptoService(
            issuer_id="did:qwed:a2a:alpha",
            pem_key=pem_a,
            jti_registry=shared,
        )
        worker_2._key_pair = issuer._key_pair

        token = _sign(issuer, trace_id="t_shared_replay")
        ok_1, _, err_1 = worker_1.verify_attestation(token, _default_context())
        assert ok_1 is True, f"First consumption failed: {err_1}"
        ok_2, _, err_2 = worker_2.verify_attestation(token, _default_context())
        assert ok_2 is False
        assert "Replay" in err_2

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

        is_valid, _, error = verifier.verify_attestation(
            expired_token, _default_context()
        )
        assert is_valid is False
        assert error is not None
        # Must be expiry error — proves expiry check runs before replay check.
        assert "expired" in error.lower(), (
            f"Expected expiry error (proving ordering), got: {error!r}"
        )

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
        verifier.verify_attestation(tampered, _default_context())
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
        is_valid, claims, error = verifier.verify_attestation(token, _default_context())
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

        is_valid, claims, error = verifier.verify_attestation(token, _default_context())
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

        is_valid, _, error = verifier.verify_attestation(
            patched_token, _default_context()
        )
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
        verifier.verify_attestation(token, _default_context())
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

        is_valid, claims, error = verifier.verify_attestation(
            bad_token, _default_context()
        )
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

        is_valid, claims, error = verifier.verify_attestation(
            bad_token, _default_context()
        )
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

        is_valid, claims, error = s2.verify_attestation(token, _default_context())
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

        is_valid, claims, error = s2.verify_attestation(token, _default_context())
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
                        {
                            "description": "Item",
                            "amount": Decimal("10.00"),
                            "quantity": 1,
                        }
                    ],
                }
            },
        )
        with pytest.raises(RuntimeError, match="sign attestation"):
            await interceptor.intercept(msg, trace_id="t_no_pem")

    def test_rsa_key_rejected(self):
        """An RSA key must be rejected with a clear error about wrong key type."""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization as ser

        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = rsa_key.private_bytes(
            encoding=ser.Encoding.PEM,
            format=ser.PrivateFormat.PKCS8,
            encryption_algorithm=ser.NoEncryption(),
        ).decode()
        service = A2ACryptoService(issuer_id="did:qwed:a2a:test", pem_key=pem)
        with pytest.raises(RuntimeError, match="must be an EC P-256"):
            service._ensure_key_pair()

    def test_wrong_ec_curve_rejected(self):
        """A P-384 key must be rejected with a clear error about wrong curve."""
        from cryptography.hazmat.primitives.asymmetric import ec as ec_curves
        from cryptography.hazmat.primitives import serialization as ser

        p384_key = ec_curves.generate_private_key(ec_curves.SECP384R1())
        pem = p384_key.private_bytes(
            encoding=ser.Encoding.PEM,
            format=ser.PrivateFormat.PKCS8,
            encryption_algorithm=ser.NoEncryption(),
        ).decode()
        service = A2ACryptoService(issuer_id="did:qwed:a2a:test", pem_key=pem)
        with pytest.raises(RuntimeError, match="must use curve SECP256R1"):
            service._ensure_key_pair()

    def test_bad_pem_raises_clear_error(self):
        """Truncated or garbage PEM must be wrapped into RuntimeError."""
        service = A2ACryptoService(
            issuer_id="did:qwed:a2a:test",
            pem_key="-----BEGIN GARBAGE-----\nnot-a-real-key\n-----END GARBAGE-----",
        )
        with pytest.raises(RuntimeError, match="must be an unencrypted"):
            service._ensure_key_pair()

    def test_jwks_endpoint_returns_503_when_no_pem(self, monkeypatch):
        """/.well-known/jwks.json must return 503 if no signing key configured."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from qwed_a2a.protocol.endpoints import wellknown_router

        monkeypatch.delenv("QWED_A2A_SIGNING_KEY_PEM", raising=False)
        app = FastAPI()
        app.include_router(wellknown_router)
        client = TestClient(app)
        resp = client.get("/.well-known/jwks.json")
        assert resp.status_code == 503
        assert "unavailable" in resp.json()["detail"]

    def test_ensure_key_pair_fails_without_crypto_lib(self, monkeypatch):
        """_ensure_key_pair must raise RuntimeError if cryptography is unavailable."""
        import qwed_a2a.security.crypto as crypto_mod

        monkeypatch.setattr(crypto_mod, "HAS_CRYPTO", False)
        service = A2ACryptoService(
            issuer_id="did:qwed:a2a:test",
            pem_key=_generate_test_pem(),
        )
        with pytest.raises(RuntimeError, match="cryptography and PyJWT"):
            service._ensure_key_pair()


class TestPeerIssuerVerification:
    """#84: cross-agent verification via a trusted-issuer key set.

    Two services with DISTINCT keys and issuer IDs: without a trusted
    entry the peer token fails closed; with the peer's real JWKS entry
    it verifies. No shared private key anywhere.
    """

    @pytest.fixture
    def service_a(self):
        return A2ACryptoService(
            issuer_id="did:qwed:a2a:alpha", pem_key=_generate_test_pem()
        )

    @pytest.fixture
    def service_b(self):
        return A2ACryptoService(
            issuer_id="did:qwed:a2a:peer-beta", pem_key=_generate_test_pem()
        )

    def _signed(self, svc, payload, trace_id, sender="a1", receiver="b1"):
        from qwed_a2a.security.crypto import AttestationContext  # noqa: F401

        token = svc.sign_verdict(
            trace_id=trace_id,
            verdict_status="forwarded",
            engine="e",
            sender_id=sender,
            receiver_id=receiver,
            payload_hash=A2ACryptoService.payload_hash(payload),
        )
        ctx = AttestationContext(
            sender_agent_id=sender, receiver_agent_id=receiver, payload=payload
        )
        return token, ctx

    def _entry(self, svc, deployment):
        return {
            svc.issuer_id: {
                "deployment_id": deployment,
                "jwks": {"keys": [svc.get_public_key_jwk()]},
            }
        }

    def test_cross_key_verifies_with_trusted_entry(self, service_a, service_b):
        """The #84 repro inverted: distinct keys verify via registered JWKS."""
        import qwed_a2a.security.crypto as crypto_mod

        token, ctx = self._signed(service_a, {"data": "x"}, "t-peer-ok")
        entry = self._entry(service_a, crypto_mod._DEPLOYMENT_ID)
        ok, _, err = service_b.verify_attestation(token, ctx, trusted_issuers=entry)
        assert ok, err

    def test_unknown_issuer_denied(self, service_a, service_b):
        token, ctx = self._signed(service_a, {"data": "x"}, "t-unknown")
        ok, _, err = service_b.verify_attestation(token, ctx)
        assert not ok
        assert "no trusted key verified" in (err or "")

    def test_wrong_kid_denied(self, service_a, service_b):
        """Right key, wrong label: kid mismatch fails closed.

        Registers service_a's REAL key under a rotated label so the
        signature verifies and the token reaches the kid-binding check
        (registering an unrelated key would fail earlier at the
        signature, never exercising this branch).
        """
        import qwed_a2a.security.crypto as crypto_mod

        token, ctx = self._signed(service_a, {"data": "x"}, "t-badkid")
        # Real key of service_a, but registered under a different kid label.
        relabelled = service_a.get_public_key_jwk()
        relabelled["kid"] = relabelled["kid"] + "-rotated"
        entry = {
            service_a.issuer_id: {
                "deployment_id": crypto_mod._DEPLOYMENT_ID,
                "jwks": {"keys": [relabelled]},
            }
        }
        ok, _, err = service_b.verify_attestation(token, ctx, trusted_issuers=entry)
        assert not ok
        assert "Key id mismatch" in (err or "")

    def test_deployment_mismatch_denied(self, service_a, service_b):
        """Peer tokens bind to the REGISTERED deployment, not ours."""
        import qwed_a2a.security.crypto as crypto_mod

        token, ctx = self._signed(service_a, {"data": "x"}, "t-baddep")
        entry = self._entry(service_a, crypto_mod._DEPLOYMENT_ID + "-other")
        ok, _, err = service_b.verify_attestation(token, ctx, trusted_issuers=entry)
        assert not ok
        assert "Deployment context mismatch" in (err or "")

    def _kidless_token(self, pem, issuer_id, deployment_id, payload, jti):
        """Hand-mint a token with NO kid header (sign_verdict always sets one)."""
        import time

        import jwt as pyjwt

        now = int(time.time())
        body = {
            "iss": issuer_id,
            "sub": A2ACryptoService.payload_hash(payload),
            "iat": now,
            "exp": now + 300,
            "jti": jti,
            "qwed_a2a": {
                "version": "1.0",
                "verdict": "forwarded",
                "engine": "e",
                "sender": "a1",
                "receiver": "b1",
                "deployment_id": deployment_id,
                "session_id": None,
            },
        }
        return pyjwt.encode(body, pem, algorithm="ES256")

    def test_no_kid_single_key_ok(self, service_b):
        """A kid-less token verifies against a single-key entry."""
        import qwed_a2a.security.crypto as crypto_mod
        from qwed_a2a.security.crypto import AttestationContext

        pem_a = _generate_test_pem()
        service_a = A2ACryptoService(issuer_id="did:qwed:a2a:alpha", pem_key=pem_a)
        payload = {"data": "nokid"}
        token = self._kidless_token(
            pem_a, service_a.issuer_id, crypto_mod._DEPLOYMENT_ID, payload, "t-nokid"
        )
        ctx = AttestationContext(
            sender_agent_id="a1", receiver_agent_id="b1", payload=payload
        )
        entry = self._entry(service_a, crypto_mod._DEPLOYMENT_ID)
        ok, _, err = service_b.verify_attestation(token, ctx, trusted_issuers=entry)
        assert ok, err

    def test_no_kid_multi_key_verifies(self, service_b):
        """A kid-less token verifies under whichever key signs it (#84 fix).

        The pre-#84 strict routing denied kid-less tokens against
        multi-key entries as "ambiguous". Try-each-key makes that
        moot: the signature itself selects the key, order-independently
        (RFC 7515: kid is only a hint; with no kid there is nothing to
        confuse). The token here is signed by the SECOND key so the
        test also proves the first non-matching key is skipped, not
        treated as authoritative.
        """
        import qwed_a2a.security.crypto as crypto_mod
        from qwed_a2a.security.crypto import AttestationContext

        other = A2ACryptoService(
            issuer_id="did:qwed:a2a:other", pem_key=_generate_test_pem()
        )
        pem_a = _generate_test_pem()
        service_a = A2ACryptoService(issuer_id="did:qwed:a2a:alpha", pem_key=pem_a)
        payload = {"data": "unambiguous-by-signature"}
        token = self._kidless_token(
            pem_a,
            service_a.issuer_id,
            crypto_mod._DEPLOYMENT_ID,
            payload,
            "t-sig-picks",
        )
        ctx = AttestationContext(
            sender_agent_id="a1", receiver_agent_id="b1", payload=payload
        )
        entry = {
            service_a.issuer_id: {
                "deployment_id": crypto_mod._DEPLOYMENT_ID,
                "jwks": {
                    "keys": [
                        other.get_public_key_jwk(),
                        service_a.get_public_key_jwk(),
                    ]
                },
            }
        }
        ok, _, err = service_b.verify_attestation(token, ctx, trusted_issuers=entry)
        assert ok, err

    def test_duplicate_kids_verify_order_independent(self, service_b):
        """Same kid label on two keys: verification cannot depend on order.

        A misconfigured entry may label two keys identically. Trying each
        key means the token verifies regardless of which same-labeled key
        is listed first — and the verified iss still binds to the entry
        owner either way.
        """
        import qwed_a2a.security.crypto as crypto_mod

        pem_a = _generate_test_pem()
        service_a = A2ACryptoService(issuer_id="did:qwed:a2a:alpha", pem_key=pem_a)
        other = A2ACryptoService(
            issuer_id="did:qwed:a2a:other", pem_key=_generate_test_pem()
        )
        payload = {"data": "dupe-kid"}
        token, ctx = self._signed(service_a, payload, "t-dupe-kid")
        # NOTE: _signed uses sender/receiver a1/b1 already matching ctx.
        jwk_a = service_a.get_public_key_jwk()
        jwk_other = other.get_public_key_jwk()
        jwk_other["kid"] = jwk_a["kid"]  # duplicate label, different key
        for keys in ([jwk_a, jwk_other], [jwk_other, jwk_a]):
            entry = {
                service_a.issuer_id: {
                    "deployment_id": crypto_mod._DEPLOYMENT_ID,
                    "jwks": {"keys": keys},
                }
            }
            fresh_b = A2ACryptoService(
                issuer_id="did:qwed:a2a:peer-beta", pem_key=_generate_test_pem()
            )
            ok, _, err = fresh_b.verify_attestation(token, ctx, trusted_issuers=entry)
            assert ok, err

    def test_same_key_relabelled_verifies_regardless_of_order(self, service_b):
        """Same key under two kid labels: JWKS order must not decide.

        Rotation re-registers one key under a new kid. The token verifies
        under the first-listed copy but mismatches its label; verification
        must continue to the matching copy instead of denying outright.
        """
        import qwed_a2a.security.crypto as crypto_mod

        pem_a = _generate_test_pem()
        service_a = A2ACryptoService(issuer_id="did:qwed:a2a:alpha", pem_key=pem_a)
        token, ctx = self._signed(service_a, {"data": "relabel"}, "t-relabel")
        jwk_real = service_a.get_public_key_jwk()
        jwk_rotated = service_a.get_public_key_jwk()
        jwk_rotated["kid"] = jwk_real["kid"] + "-rotated"
        for keys in ([jwk_rotated, jwk_real], [jwk_real, jwk_rotated]):
            entry = {
                service_a.issuer_id: {
                    "deployment_id": crypto_mod._DEPLOYMENT_ID,
                    "jwks": {"keys": keys},
                }
            }
            fresh_b = A2ACryptoService(
                issuer_id="did:qwed:a2a:peer-beta", pem_key=_generate_test_pem()
            )
            ok, _, err = fresh_b.verify_attestation(token, ctx, trusted_issuers=entry)
            assert ok, err

    def test_shared_key_across_issuers_denied(self, service_a, service_b):
        """One private key registered as two issuers cannot impersonate.

        The peer entry reusing the local key is skipped (warned); a token
        hand-minted with the shared key but claiming the peer issuer then
        fails closed instead of verifying as the peer deployment.
        """
        import time

        import jwt as pyjwt

        peer_issuer = "did:qwed:a2a:peer-evil"
        payload = {"data": "impersonate"}
        payload_hash = A2ACryptoService.payload_hash(payload)
        now = int(time.time())
        pem_a = service_a._ensure_key_pair().private_key_pem
        body = {
            "iss": peer_issuer,
            "sub": payload_hash,
            "iat": now,
            "exp": now + 300,
            "jti": "t-shared-key-evil",
            "qwed_a2a": {
                "version": "1.0",
                "verdict": "forwarded",
                "engine": "e",
                "sender": "a1",
                "receiver": "b1",
                "deployment_id": "peer-deploy-evil",
                "session_id": None,
            },
        }
        token = pyjwt.encode(
            body,
            pem_a,
            algorithm="ES256",
            headers={"kid": service_a.get_public_key_jwk()["kid"]},
        )
        ctx = AttestationContext(
            sender_agent_id="a1", receiver_agent_id="b1", payload=payload
        )
        entry = {
            peer_issuer: {
                "deployment_id": "peer-deploy-evil",
                "jwks": {"keys": [service_a.get_public_key_jwk()]},
            }
        }
        # Verified BY service_a itself: its own key and the peer entry share
        # one private key, so the peer candidate is skipped as a duplicate
        # and the peer-claiming token fails closed.
        ok, _, err = service_a.verify_attestation(token, ctx, trusted_issuers=entry)
        assert not ok

    def test_env_fallback_loads_issuers(self, service_a, service_b, monkeypatch):
        """QWED_A2A_TRUSTED_ISSUERS works without an explicit argument."""
        import qwed_a2a.security.crypto as crypto_mod

        token, ctx = self._signed(service_a, {"data": "env"}, "t-env")
        entry = self._entry(service_a, crypto_mod._DEPLOYMENT_ID)
        monkeypatch.setenv("QWED_A2A_TRUSTED_ISSUERS", json.dumps(entry))
        ok, _, err = service_b.verify_attestation(token, ctx)
        assert ok, err

    def test_malformed_env_stays_local_only(self, service_a, service_b, monkeypatch):
        token, ctx = self._signed(service_a, {"data": "envbad"}, "t-envbad")
        monkeypatch.setenv("QWED_A2A_TRUSTED_ISSUERS", "{broken")
        ok, _, err = service_b.verify_attestation(token, ctx)
        assert not ok
        assert "no trusted key verified" in (err or "")

    def test_oversized_env_stays_local_only(self, service_a, service_b, monkeypatch):
        """A >64KB env config fails closed before parsing (DoS guard).

        NOTE: Windows caps real env vars at 32767 chars, so the oversize
        boundary is exercised directly against the sanitizer; the env
        path is covered by test_malformed_env_stays_local_only.
        """
        import pytest

        from qwed_a2a.security.crypto import _sanitize_issuer_config_json

        with pytest.raises(ValueError, match="size limit"):
            _sanitize_issuer_config_json('{"pad": "' + "x" * 70000 + '"}')
        with pytest.raises(ValueError, match="control characters"):
            _sanitize_issuer_config_json('{"a": "b\x01c"}')
        with pytest.raises(ValueError, match="must be a JSON object"):
            _sanitize_issuer_config_json("[1, 2, 3]")
        with pytest.raises(TypeError, match="must be text"):
            _sanitize_issuer_config_json(None)
        assert _sanitize_issuer_config_json('{"a": 1}') == '{"a": 1}'

    def test_verifier_without_local_key_verifies_peer(self, service_a, monkeypatch):
        """Verifier-only nodes (no signing key) verify peer tokens.

        Previously ``verify_attestation`` raised via ``_ensure_key_pair``
        for self-issued routing before peer keys were even considered;
        try-each-key simply skips the unconfigured local key.
        """
        import qwed_a2a.security.crypto as crypto_mod

        monkeypatch.delenv("QWED_A2A_SIGNING_KEY_PEM", raising=False)
        bare = A2ACryptoService(issuer_id="did:qwed:a2a:bare")
        token, ctx = self._signed(service_a, {"data": "bare"}, "t-bare")
        entry = self._entry(service_a, crypto_mod._DEPLOYMENT_ID)
        ok, _, err = bare.verify_attestation(token, ctx, trusted_issuers=entry)
        assert ok, err

    def test_verifier_without_any_key_reports_unavailable(self, monkeypatch):
        """No local key and no trusted issuers: explicit unavailable error."""
        from qwed_a2a.security.crypto import AttestationContext

        monkeypatch.delenv("QWED_A2A_SIGNING_KEY_PEM", raising=False)
        bare = A2ACryptoService(issuer_id="did:qwed:a2a:bare")
        ctx = AttestationContext(
            sender_agent_id="a1", receiver_agent_id="b1", payload={"data": "x"}
        )
        ok, _, err = bare.verify_attestation("junk.token.here", ctx)
        assert not ok
        assert "No verification keys available" in (err or "")

    def test_expired_reported_despite_unverifiable_first_candidate(
        self, service_a, service_b
    ):
        """An expired token reports expiry even when tried after a miss.

        The first candidate (unrelated key) fails the signature; the true
        issuer's key then verifies the signature but finds expiry. The
        caller must see "expired", not a misleading signature error.
        """
        import time

        import jwt as pyjwt
        import qwed_a2a.security.crypto as crypto_mod

        other = A2ACryptoService(
            issuer_id="did:qwed:a2a:other", pem_key=_generate_test_pem()
        )
        pem_a = service_a._ensure_key_pair().private_key_pem
        now = int(time.time())
        body = {
            "iss": service_a.issuer_id,
            "sub": A2ACryptoService.payload_hash({"data": "old"}),
            "iat": now - 600,
            "exp": now - 300,
            "jti": "t-expired-order",
            "qwed_a2a": {
                "version": "1.0",
                "verdict": "forwarded",
                "engine": "e",
                "sender": "a1",
                "receiver": "b1",
                "deployment_id": crypto_mod._DEPLOYMENT_ID,
                "session_id": None,
            },
        }
        token = pyjwt.encode(
            body,
            pem_a,
            algorithm="ES256",
            headers={"kid": service_a.get_public_key_jwk()["kid"]},
        )
        ctx = AttestationContext(
            sender_agent_id="a1", receiver_agent_id="b1", payload={"data": "old"}
        )
        entry = {
            other.issuer_id: {
                "deployment_id": crypto_mod._DEPLOYMENT_ID,
                "jwks": {"keys": [other.get_public_key_jwk()]},
            },
            service_a.issuer_id: {
                "deployment_id": crypto_mod._DEPLOYMENT_ID,
                "jwks": {"keys": [service_a.get_public_key_jwk()]},
            },
        }
        ok, _, err = service_b.verify_attestation(token, ctx, trusted_issuers=entry)
        assert not ok
        assert "expired" in (err or "").lower()

    def test_cross_issuer_jti_does_not_shadow(self, service_a, service_b):
        """Same jti from two issuers: both verify (namespaced registry).

        Trace IDs are not globally unique across issuers; without
        issuer-namespacing the second issuer's token would be rejected
        as a "replay" of the first.
        """
        import qwed_a2a.security.crypto as crypto_mod
        from qwed_a2a.security.crypto import AttestationContext

        other = A2ACryptoService(
            issuer_id="did:qwed:a2a:other", pem_key=_generate_test_pem()
        )
        payload = {"data": "shared-trace"}
        ctx = AttestationContext(
            sender_agent_id="a1", receiver_agent_id="b1", payload=payload
        )
        entry = {
            service_a.issuer_id: {
                "deployment_id": crypto_mod._DEPLOYMENT_ID,
                "jwks": {"keys": [service_a.get_public_key_jwk()]},
            },
            other.issuer_id: {
                "deployment_id": crypto_mod._DEPLOYMENT_ID,
                "jwks": {"keys": [other.get_public_key_jwk()]},
            },
        }
        token_a, _ = self._signed(service_a, payload, "t-shared")
        # Hand-mint other's token with the SAME jti but other's key/iss.
        payload_hash = A2ACryptoService.payload_hash(payload)
        import time

        import jwt as pyjwt

        now = int(time.time())
        other_pem = other._ensure_key_pair().private_key_pem
        body = {
            "iss": other.issuer_id,
            "sub": payload_hash,
            "iat": now,
            "exp": now + 300,
            "jti": "t-shared",
            "qwed_a2a": {
                "version": "1.0",
                "verdict": "forwarded",
                "engine": "e",
                "sender": "a1",
                "receiver": "b1",
                "deployment_id": crypto_mod._DEPLOYMENT_ID,
                "session_id": None,
            },
        }
        token_other = pyjwt.encode(
            body,
            other_pem,
            algorithm="ES256",
            headers={"kid": other.get_public_key_jwk()["kid"]},
        )
        ok_a, _, err_a = service_b.verify_attestation(
            token_a, ctx, trusted_issuers=entry
        )
        assert ok_a, err_a
        ok_o, _, err_o = service_b.verify_attestation(
            token_other, ctx, trusted_issuers=entry
        )
        assert ok_o, err_o

    def test_non_string_envelope_claims_denied(self, service_a, service_b):
        """Non-string iss/sub/jti fail the strict envelope (RFC 7519).

        Previously an int jti could stringify into a registry key and
        verify; now the envelope gate denies before any trust decision.
        """
        import time

        import jwt as pyjwt
        import qwed_a2a.security.crypto as crypto_mod

        def _mint(payload, trace):
            now = int(time.time())
            body = {
                "iss": service_a.issuer_id,
                "sub": A2ACryptoService.payload_hash({"data": "typed"}),
                "iat": now,
                "exp": now + 300,
                "jti": trace,
                "qwed_a2a": {
                    "version": "1.0",
                    "verdict": "forwarded",
                    "engine": "e",
                    "sender": "a1",
                    "receiver": "b1",
                    "deployment_id": crypto_mod._DEPLOYMENT_ID,
                    "session_id": None,
                },
            }
            body.update(payload)
            return pyjwt.encode(
                body,
                service_a._ensure_key_pair().private_key_pem,
                algorithm="ES256",
                headers={"kid": service_a.get_public_key_jwk()["kid"]},
            )

        ctx = AttestationContext(
            sender_agent_id="a1", receiver_agent_id="b1", payload={"data": "typed"}
        )
        entry = {
            service_a.issuer_id: {
                "deployment_id": crypto_mod._DEPLOYMENT_ID,
                "jwks": {"keys": [service_a.get_public_key_jwk()]},
            }
        }
        for bad in ({"jti": 12345}, {"sub": None}):
            token = _mint(bad, f"t-nonstr-{len(str(bad))}")
            ok, _, _ = service_b.verify_attestation(token, ctx, trusted_issuers=entry)
            assert not ok

        # A list iss cannot even be minted via PyJWT (encode-side guard),
        # but hand-crafted tokens reach the decode path — the envelope
        # must reject it there.
        import pytest
        from pydantic import ValidationError
        from qwed_a2a.security.crypto import _AttestationEnvelope

        with pytest.raises(ValidationError):
            _AttestationEnvelope.model_validate(
                {"iss": ["did:qwed:a2a:alpha"], "sub": "x", "jti": "t-x"}
            )

    def test_reject_garbage_jwks(self, service_a, service_b):
        """RSA JWKs, missing coordinates, and junk never become keys."""
        import qwed_a2a.security.crypto as crypto_mod

        token, ctx = self._signed(service_a, {"data": "junk"}, "t-junk")
        entry = {
            service_a.issuer_id: {
                "deployment_id": crypto_mod._DEPLOYMENT_ID,
                "jwks": {
                    "keys": [
                        {"kty": "RSA", "n": "abc", "e": "AQAB"},
                        {"kty": "EC", "crv": "P-256"},
                        "not-a-jwk",
                        {"kty": "EC", "crv": "P-256", "x": "!!!", "y": "!!!"},
                    ]
                },
            }
        }
        ok, _, _ = service_b.verify_attestation(token, ctx, trusted_issuers=entry)
        assert not ok


class TestStrictBase64Decode:
    """Differential tests for the hand-rolled JWK coordinate decoder.

    The stdlib decoder silently discards non-alphabet characters, so
    crypto.py ships a strict manual decoder. These tests pin it to the
    stdlib on valid inputs and pin rejection on junk.
    """

    def test_matches_stdlib_on_random_vectors(self):
        import base64
        import random

        from qwed_a2a.security.crypto import _b64_decode_strict

        rnd = random.Random(42)
        for length in (1, 2, 3, 31, 32, 33, 64, 100):
            raw = bytes(rnd.randrange(256) for _ in range(length))
            std = base64.b64encode(raw).decode()
            assert _b64_decode_strict(std) == raw

    def test_rejects_non_alphabet_and_bad_padding(self):
        import pytest

        from qwed_a2a.security.crypto import _b64_decode_strict

        for bad in ("!!!", "AB*C", "AB C", "A", "ABCDE", "AB=C"):
            with pytest.raises(ValueError):
                _b64_decode_strict(bad)

    def test_jwk_coordinates_survive_strict_decode(self):
        """A real exported JWK still converts (decoder accepts P-256 coords)."""
        from qwed_a2a.security.crypto import _jwk_to_public_pem

        svc = A2ACryptoService(
            issuer_id="did:qwed:a2a:alpha", pem_key=_generate_test_pem()
        )
        assert _jwk_to_public_pem(svc.get_public_key_jwk()) is not None
