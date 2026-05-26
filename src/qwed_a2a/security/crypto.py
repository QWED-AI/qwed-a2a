"""
QWED A2A Cryptographic Services.

Provides ECDSA P-256 JWT attestation signing and verification with:
- Short-lived tokens (5-minute validity — one A2A hop lifetime)
- Thread-safe jti replay prevention registry
- Session and deployment context binding
"""

import hashlib
import os
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

try:
    import jwt
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


@dataclass
class KeyPair:
    """ECDSA P-256 key pair for A2A attestation signing."""

    issuer_id: str
    key_id: str
    _private_key: object = None
    _public_key: object = None

    def __post_init__(self):
        if not HAS_CRYPTO:
            raise RuntimeError(
                "cryptography and PyJWT packages required. "
                "Install with: pip install cryptography PyJWT"
            )
        self._private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self._public_key = self._private_key.public_key()

    @property
    def private_key_pem(self) -> bytes:
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @property
    def public_key_pem(self) -> bytes:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )


class JtiRegistry:
    """
    Thread-safe, TTL-based jti (JWT ID) replay-prevention registry.

    RFC 7519 §4.1.7 requires implementations to reject tokens whose jti
    has already been seen. This registry tracks issued jti values and
    evicts entries after their TTL to bound memory growth.

    The TTL mirrors the JWT validity window — a jti only needs to be
    remembered for as long as the token it belongs to could still be valid.
    """

    def __init__(self, ttl_seconds: int = 300) -> None:
        # OrderedDict preserves insertion order — oldest entry is first,
        # which makes O(1) eviction possible without a heap.
        self._seen: OrderedDict[str, float] = OrderedDict()
        self._ttl = ttl_seconds
        self._lock = threading.Lock()

    def check_and_register(self, jti: str, now: Optional[float] = None) -> bool:
        """
        Return True and register jti if it has never been seen.
        Return False (without registering) if jti is already in the registry.

        Args:
            jti: The JWT ID to check.
            now: Current epoch time (injectable for testing). Defaults to time.time().
        """
        if now is None:
            now = time.time()

        with self._lock:
            self._evict(now)
            if jti in self._seen:
                return False
            self._seen[jti] = now
            return True

    def _evict(self, now: float) -> None:
        """Remove entries older than TTL. Runs in O(k) where k = expired entries."""
        while self._seen:
            oldest_jti, timestamp = next(iter(self._seen.items()))
            if now - timestamp > self._ttl:
                self._seen.popitem(last=False)
            else:
                break

    def __len__(self) -> int:
        """Return the number of currently registered jti values."""
        with self._lock:
            return len(self._seen)


# Module-level deployment ID — shared across all processes in the same
# logical deployment. Set QWED_A2A_DEPLOYMENT_ID in the environment so
# that the signing service and the verifying service see the same value.
#
# Without the env var, each process gets a random ID — suitable for
# single-process testing but unusable for cross-process verification.
# In production this MUST be set explicitly.
_DEPLOYMENT_ID: str = os.environ.get(
    "QWED_A2A_DEPLOYMENT_ID",
    f"qwed-a2a-{os.urandom(8).hex()}",  # random fallback — not pid-tied
)


class A2ACryptoService:
    """
    Handles cryptographic signing and verification for A2A payloads.

    - Signs verification verdicts with short-lived ES256 JWT attestations.
    - Verifies incoming agent message signatures.
    - Manages ECDSA P-256 key pairs.
    - Enforces jti replay prevention via JtiRegistry.
    """

    ALGORITHM = "ES256"
    TOKEN_TYPE = "qwed-a2a-attestation+jwt"

    def __init__(
        self,
        issuer_id: str = "did:qwed:a2a:local",
        validity_seconds: int = 300,
    ):
        self.issuer_id = issuer_id
        self.validity_seconds = validity_seconds
        self._key_pair: Optional[KeyPair] = None
        # Each service instance owns its replay registry.
        # TTL is aligned with the validity window so entries are never
        # held longer than the tokens they protect against.
        self._jti_registry = JtiRegistry(ttl_seconds=validity_seconds)

    def _ensure_key_pair(self) -> KeyPair:
        if self._key_pair is None:
            key_id = f"{self.issuer_id}#signing-key-v1"
            self._key_pair = KeyPair(issuer_id=self.issuer_id, key_id=key_id)
        return self._key_pair

    @staticmethod
    def hash_content(content: str) -> str:
        """Create a deterministic SHA-256 hash of content."""
        return f"sha256:{hashlib.sha256(content.encode('utf-8')).hexdigest()}"

    def sign_verdict(
        self,
        trace_id: str,
        verdict_status: str,
        engine: str,
        sender_id: str,
        receiver_id: str,
        payload_hash: str,
        session_id: Optional[str] = None,
    ) -> str:
        """
        Create a signed JWT attestation for a verification verdict.

        The issued token is:
        - Valid for validity_seconds (default 300s / 5 minutes)
        - Bound to the current deployment instance via deployment_id
        - Bound to the caller-supplied session_id when provided
        - Registered in the jti replay registry immediately upon signing

        Args:
            trace_id:       Unique trace ID (becomes jti).
            verdict_status: Verdict outcome string (forwarded/blocked/unverifiable).
            engine:         Verification engine name.
            sender_id:      Sending agent identifier.
            receiver_id:    Receiving agent identifier.
            payload_hash:   SHA-256 hash of the verified payload.
            session_id:     Optional caller-supplied session identifier.

        Returns:
            Signed JWT token string.
        """
        key_pair = self._ensure_key_pair()
        now = int(time.time())

        payload = {
            "iss": self.issuer_id,
            "sub": payload_hash,
            "iat": now,
            "exp": now + self.validity_seconds,
            "jti": trace_id,
            "qwed_a2a": {
                "version": "1.0",
                "verdict": verdict_status,
                "engine": engine,
                "sender": sender_id,
                "receiver": receiver_id,
                "deployment_id": _DEPLOYMENT_ID,
                "session_id": session_id,
            },
        }

        header = {
            "alg": self.ALGORITHM,
            "typ": self.TOKEN_TYPE,
            "kid": key_pair.key_id,
        }

        token = jwt.encode(
            payload,
            key_pair.private_key_pem,
            algorithm=self.ALGORITHM,
            headers=header,
        )

        # Register jti immediately after signing so the issuing service
        # itself rejects replay of tokens it has issued.
        self._jti_registry.check_and_register(trace_id)

        return token

    def verify_attestation(
        self, token: str
    ) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """
        Verify a JWT attestation token.

        Verification steps (all must pass):
        1. Cryptographic signature check (ES256 / ECDSA P-256)
        2. Expiry check (exp claim)
        3. Required claims check (iss, sub, iat, exp, jti)
        4. Deployment context check — deployment_id in claims must match
           this service's deployment_id (prevents cross-deployment replay
           in shared-key environments)
        5. jti replay check — rejects previously seen jti values

        Returns:
            Tuple of (is_valid, decoded_claims, error_message).
        """
        key_pair = self._ensure_key_pair()

        try:
            claims = jwt.decode(
                token,
                key_pair.public_key_pem,
                algorithms=[self.ALGORITHM],
                options={"require": ["iss", "sub", "iat", "exp", "jti"]},
            )
        except jwt.ExpiredSignatureError:
            return False, None, "Attestation has expired"
        except jwt.InvalidTokenError as exc:
            return False, None, f"Invalid token: {exc}"

        # Step 4: deployment context check — runs after signature validation
        # so we only inspect claims from cryptographically sound tokens.
        # This blocks cross-deployment replay in environments where signing
        # keys are shared across multiple QWED-A2A deployments.
        qwed_claims = claims.get("qwed_a2a", {})
        token_deployment_id = qwed_claims.get("deployment_id")
        if token_deployment_id != _DEPLOYMENT_ID:
            return (
                False,
                None,
                "Deployment context mismatch: token not issued by this deployment",
            )

        # Step 5: replay check — must happen AFTER all other validation
        # so we don't pollute the registry with otherwise-invalid tokens.
        jti = claims.get("jti")
        if not jti:
            return False, None, "Missing jti claim"

        if not self._jti_registry.check_and_register(jti):
            return False, None, "Replay detected: jti already seen"

        return True, claims, None
