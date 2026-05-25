"""
Tests for A2A cryptographic signing and verification.
"""

from qwed_a2a.security.crypto import A2ACryptoService


class TestJWTRoundTrip:
    """JWT creation and verification round-trip tests."""

    def test_sign_and_verify(self, crypto_service):
        """A signed verdict should verify successfully."""
        token = crypto_service.sign_verdict(
            trace_id="test_trace_001",
            verdict_status="forwarded",
            engine="finance_guard",
            sender_id="agent-A",
            receiver_id="agent-B",
            payload_hash="sha256:abc123",
        )

        is_valid, claims, error = crypto_service.verify_attestation(token)
        assert is_valid is True
        assert error is None
        assert claims["jti"] == "test_trace_001"
        assert claims["qwed_a2a"]["verdict"] == "forwarded"
        assert claims["qwed_a2a"]["engine"] == "finance_guard"

    def test_different_traces_produce_different_tokens(self, crypto_service):
        """Two different verdicts should produce distinct JWTs."""
        token_a = crypto_service.sign_verdict(
            trace_id="trace_a",
            verdict_status="forwarded",
            engine="passthrough",
            sender_id="x",
            receiver_id="y",
            payload_hash="sha256:aaa",
        )
        token_b = crypto_service.sign_verdict(
            trace_id="trace_b",
            verdict_status="blocked",
            engine="code_guard",
            sender_id="x",
            receiver_id="y",
            payload_hash="sha256:bbb",
        )
        assert token_a != token_b


class TestTamperDetection:
    """Tests for tampered payload detection."""

    def test_tampered_token_rejected(self, crypto_service):
        """A manually modified JWT should fail verification."""
        token = crypto_service.sign_verdict(
            trace_id="tamper_test",
            verdict_status="forwarded",
            engine="passthrough",
            sender_id="a",
            receiver_id="b",
            payload_hash="sha256:original",
        )

        # Tamper with the token by flipping a character in the signature
        parts = token.split(".")
        sig = list(parts[2])
        sig[0] = "X" if sig[0] != "X" else "Y"
        parts[2] = "".join(sig)
        tampered = ".".join(parts)

        is_valid, claims, error = crypto_service.verify_attestation(tampered)
        assert is_valid is False
        assert claims is None
        assert error is not None


class TestCrossServiceVerification:
    """Tests for cross-instance verification behavior."""

    def test_different_instance_cannot_verify(self):
        """A token signed by one service should not verify with another instance's keys."""
        service_a = A2ACryptoService(issuer_id="did:qwed:a2a:node-A")
        service_b = A2ACryptoService(issuer_id="did:qwed:a2a:node-B")

        token = service_a.sign_verdict(
            trace_id="cross_test",
            verdict_status="forwarded",
            engine="passthrough",
            sender_id="x",
            receiver_id="y",
            payload_hash="sha256:cross",
        )

        is_valid, _, error = service_b.verify_attestation(token)
        assert is_valid is False


class TestHashContent:
    """Tests for deterministic content hashing."""

    def test_same_input_same_hash(self):
        """Identical input should produce identical hashes."""
        h1 = A2ACryptoService.hash_content("hello world")
        h2 = A2ACryptoService.hash_content("hello world")
        assert h1 == h2
        assert h1.startswith("sha256:")

    def test_different_input_different_hash(self):
        """Different input should produce different hashes."""
        h1 = A2ACryptoService.hash_content("hello")
        h2 = A2ACryptoService.hash_content("world")
        assert h1 != h2
