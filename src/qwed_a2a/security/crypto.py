"""
QWED A2A Cryptographic Services.

Provides ECDSA P-256 JWT attestation signing and verification with:
- Short-lived tokens (5-minute validity — one A2A hop lifetime)
- Thread-safe jti replay prevention registry
- Session and deployment context binding
"""

import base64
import hashlib
import os
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from pydantic import BaseModel, ValidationError

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
    """ECDSA P-256 key pair for A2A attestation signing.

    Keys are injected at construction — never generated internally.
    Use A2ACryptoService which loads the key from QWED_A2A_SIGNING_KEY_PEM.
    """

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
        if self._private_key is None or self._public_key is None:
            raise RuntimeError(
                "KeyPair requires both _private_key and _public_key. "
                "Use A2ACryptoService which loads keys from QWED_A2A_SIGNING_KEY_PEM."
            )

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
# logical deployment. QWED_A2A_DEPLOYMENT_ID MUST be set in the environment;
# a random fallback would silently make cross-process verification always
# fail (a different process would get a different ID), violating fail-closed.
_DEPLOYMENT_ID: Optional[str] = os.environ.get("QWED_A2A_DEPLOYMENT_ID")
if not _DEPLOYMENT_ID:
    raise RuntimeError(
        "QWED_A2A_DEPLOYMENT_ID environment variable is not set. "
        "All services in the same logical deployment must share a stable ID "
        "so that attestation tokens can be verified across processes. "
        "Set QWED_A2A_DEPLOYMENT_ID before importing qwed_a2a."
    )


class _QwedA2AClaims(BaseModel):
    """Typed model for the qwed_a2a nested claim block in attestation JWTs."""

    version: str
    verdict: str
    engine: str
    sender: str
    receiver: str
    deployment_id: str
    session_id: Optional[str] = None


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
        pem_key: Optional[str] = None,
    ):
        self.issuer_id = issuer_id
        self.validity_seconds = validity_seconds
        self._pem_key = pem_key
        self._key_pair: Optional[KeyPair] = None
        # Each service instance owns its replay registry.
        # TTL is aligned with the validity window so entries are never
        # held longer than the tokens they protect against.
        self._jti_registry = JtiRegistry(ttl_seconds=validity_seconds)

    def _ensure_key_pair(self) -> KeyPair:
        if self._key_pair is not None:
            return self._key_pair

        pem = self._pem_key or os.environ.get("QWED_A2A_SIGNING_KEY_PEM")
        if not pem:
            raise RuntimeError(
                "QWED_A2A_SIGNING_KEY_PEM environment variable is not set. "
                "QWED-A2A requires a persistent signing key for audit continuity. "
                "Generate with: openssl ecparam -name prime256v1 -genkey -noout | "
                "openssl pkcs8 -topk8 -nocrypt"
            )

        private_key = serialization.load_pem_private_key(pem.encode(), password=None)
        public_key = private_key.public_key()
        fingerprint = self._compute_fingerprint(public_key)
        key_id = f"{self.issuer_id}#key-{fingerprint[:16]}"

        self._key_pair = KeyPair(
            issuer_id=self.issuer_id,
            key_id=key_id,
            _private_key=private_key,
            _public_key=public_key,
        )
        return self._key_pair

    @staticmethod
    def _compute_fingerprint(public_key) -> str:
        """Compute a deterministic SHA-256 fingerprint for a public key."""
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(public_bytes).hexdigest()

    def get_public_key_jwk(self) -> dict:
        """Return the current public key in JWK format for external consumers."""
        key_pair = self._ensure_key_pair()
        public_key = key_pair._public_key
        numbers = public_key.public_numbers()
        x = numbers.x.to_bytes(32, byteorder="big")
        y = numbers.y.to_bytes(32, byteorder="big")

        return {
            "kty": "EC",
            "crv": "P-256",
            "x": base64.urlsafe_b64encode(x).rstrip(b"=").decode(),
            "y": base64.urlsafe_b64encode(y).rstrip(b"=").decode(),
            "kid": key_pair.key_id,
            "use": "sig",
        }

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
            raw_claims = jwt.decode(
                token,
                key_pair.public_key_pem,
                algorithms=[self.ALGORITHM],
                options={"require": ["iss", "sub", "iat", "exp", "jti"]},
            )
        except jwt.ExpiredSignatureError:
            return False, None, "Attestation has expired"
        except jwt.InvalidTokenError as exc:
            return False, None, f"Invalid token: {exc}"

        # Step 4: structural validation of the qwed_a2a nested claim block.
        # jwt.decode() only validates standard claims and the signature; it
        # does not enforce that qwed_a2a is a mapping with required fields.
        # A signed token with qwed_a2a set to a non-mapping would raise an
        # AttributeError rather than returning a clean rejection tuple.
        try:
            qwed_claims = _QwedA2AClaims.model_validate(raw_claims.get("qwed_a2a", {}))
        except ValidationError:
            return False, None, "Invalid qwed_a2a claims structure"

        # Step 5: deployment context check — runs after structural validation
        # so we only act on well-formed tokens from cryptographically sound JWTs.
        if qwed_claims.deployment_id != _DEPLOYMENT_ID:
            return (
                False,
                None,
                "Deployment context mismatch: token not issued by this deployment",
            )

        # Step 6: replay check — must happen AFTER all other validation
        # so we don't pollute the registry with otherwise-invalid tokens.
        jti = raw_claims.get("jti")
        if not jti:
            return False, None, "Missing jti claim"

        if not self._jti_registry.check_and_register(jti):
            return False, None, "Replay detected: jti already seen"

        return True, raw_claims, None
