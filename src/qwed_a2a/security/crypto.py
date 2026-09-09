"""
QWED A2A Cryptographic Services.

Provides ECDSA P-256 JWT attestation signing and verification with:
- Short-lived tokens (5-minute default validity)
- Thread-safe jti replay prevention registry
- Session and deployment context binding
"""

import base64
import hashlib
import json
import logging
import os
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ValidationError

logger = logging.getLogger("qwed_a2a")

try:
    import jwt
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

    def check_and_register(self, jti: str, now: float | None = None) -> bool:
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
            _, timestamp = next(iter(self._seen.items()))
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
_DEPLOYMENT_ID: str | None = os.environ.get("QWED_A2A_DEPLOYMENT_ID")
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
    session_id: str | None = None


@dataclass
class AttestationContext:
    """
    Expected context for attestation verification.

    All fields compared against JWT claims — mismatch = rejection.
    The payload is hashed internally using the same deterministic
    method as sign_verdict() so callers never handle raw hashes.
    """

    sender_agent_id: str
    receiver_agent_id: str
    payload: Any
    session_id: str | None = None


# Monotonic timestamp of the last trusted-issuer misconfiguration
# warning. Same rationale as the API-key equivalent: loud once per
# minute, never a log-spam vector.
_TRUSTED_ISSUERS_LAST_WARN: float | None = None
_TRUSTED_ISSUERS_WARN_INTERVAL = 60.0


def _warn_issuers_misconfigured(message: str) -> None:
    """Log a trusted-issuer config problem, rate-limited to one per minute."""
    global _TRUSTED_ISSUERS_LAST_WARN
    now = time.monotonic()
    if (
        _TRUSTED_ISSUERS_LAST_WARN is None
        or now - _TRUSTED_ISSUERS_LAST_WARN >= _TRUSTED_ISSUERS_WARN_INTERVAL
    ):
        _TRUSTED_ISSUERS_LAST_WARN = now
        logger.warning(message)


def _jwk_to_public_pem(jwk: Any) -> str | None:
    """Convert an EC P-256 JWK to a PEM public key for verification.

    Accepts exactly the shape ``get_public_key_jwk()`` emits so operators
    can copy a peer's ``/.well-known/jwks.json`` entry verbatim. Returns
    None for anything else — callers fail closed.
    """
    try:
        if not HAS_CRYPTO or not isinstance(jwk, dict):
            return None
        if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
            return None
        x_b64 = jwk.get("x")
        y_b64 = jwk.get("y")
        if not isinstance(x_b64, str) or not isinstance(y_b64, str):
            return None

        def _b64url_uint(s: str) -> int:
            padded = s + "=" * (-len(s) % 4)
            return int.from_bytes(base64.urlsafe_b64decode(padded), "big")

        numbers = ec.EllipticCurvePublicNumbers(
            _b64url_uint(x_b64), _b64url_uint(y_b64), ec.SECP256R1()
        )
        public_key = numbers.public_key()
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
    except Exception:
        return None


def _load_trusted_issuers(explicit: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    """Resolve the trusted-issuer set for peer attestation verification.

    Explicit ``trusted_issuers`` wins; when None, ``QWED_A2A_TRUSTED_ISSUERS``
    is read fresh (rotation without restart). Shape per issuer::

        {"deployment_id": "<peer deployment>", "jwks": {"keys": [{...JWK...}]}}

    Entries missing a usable deployment ID or usable keys are dropped —
    their issuer then fails closed as unknown. Malformed config warns
    and yields an empty set (local-only verification, unchanged default).
    """
    raw: Any = explicit
    if raw is None:
        env_raw = os.environ.get("QWED_A2A_TRUSTED_ISSUERS", "")
        if not env_raw.strip():
            return {}
        try:
            raw = json.loads(env_raw)
        except (ValueError, RecursionError):
            _warn_issuers_misconfigured(
                "QWED_A2A_TRUSTED_ISSUERS is not valid JSON; peer "
                "attestation verification stays local-only until fixed."
            )
            return {}
    if not isinstance(raw, dict):
        _warn_issuers_misconfigured(
            "QWED_A2A_TRUSTED_ISSUERS must be a JSON object mapping issuer "
            "IDs to {deployment_id, jwks}; peer verification stays "
            "local-only until fixed."
        )
        return {}
    issuers: dict[str, dict[str, Any]] = {}
    for issuer_id, entry in raw.items():
        if not isinstance(issuer_id, str) or not issuer_id:
            continue
        if not isinstance(entry, dict):
            continue
        deployment_id = entry.get("deployment_id")
        jwks = entry.get("jwks")
        if not isinstance(deployment_id, str) or not deployment_id:
            continue
        keys = jwks.get("keys") if isinstance(jwks, dict) else None
        if not isinstance(keys, list) or not keys:
            continue
        usable = [k for k in keys if _jwk_to_public_pem(k) is not None]
        if not usable:
            continue
        issuers[issuer_id] = {"deployment_id": deployment_id, "keys": usable}
    if not issuers and raw:
        _warn_issuers_misconfigured(
            "QWED_A2A_TRUSTED_ISSUERS contains no usable issuer entries; "
            "peer attestation verification stays local-only until fixed."
        )
    return issuers


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
        pem_key: str | None = None,
    ):
        self.issuer_id = issuer_id
        self.validity_seconds = validity_seconds
        self._pem_key = pem_key
        self._key_pair: KeyPair | None = None
        self._key_lock = threading.Lock()
        # Each service instance owns its replay registry.
        # TTL is aligned with the validity window so entries are never
        # held longer than the tokens they protect against.
        self._jti_registry = JtiRegistry(ttl_seconds=validity_seconds)

    def _ensure_key_pair(self) -> KeyPair:
        if not HAS_CRYPTO:
            raise RuntimeError(
                "cryptography and PyJWT packages required. "
                "Install with: pip install cryptography PyJWT"
            )
        if self._key_pair is not None:
            return self._key_pair

        with self._key_lock:
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

            try:
                private_key = serialization.load_pem_private_key(
                    pem.encode(), password=None
                )
            except Exception as exc:
                raise RuntimeError(
                    "QWED_A2A_SIGNING_KEY_PEM must be an unencrypted EC P-256 "
                    "private key in PEM format."
                ) from exc

            if not isinstance(private_key, ec.EllipticCurvePrivateKey):
                raise RuntimeError(  # noqa: TRY004  # deployment config error, not user-data type error
                    "QWED_A2A_SIGNING_KEY_PEM must be an EC P-256 (prime256v1) private key. "
                    f"Got {type(private_key).__name__}."
                )
            if not isinstance(private_key.curve, ec.SECP256R1):
                raise RuntimeError(  # noqa: TRY004  # deployment config error, not user-data type error
                    "QWED_A2A_SIGNING_KEY_PEM must use curve SECP256R1 (prime256v1, P-256). "
                    f"Got curve {private_key.curve.name}."
                )

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
            "alg": "ES256",
        }

    @staticmethod
    def hash_content(content: str) -> str:
        """Create a deterministic SHA-256 hash of content."""
        return f"sha256:{hashlib.sha256(content.encode('utf-8')).hexdigest()}"

    @staticmethod
    def payload_hash(payload: Any) -> str:
        """Canonical JSON serialization + SHA-256 hash of a payload dict.

        Uses the same ``json.dumps(..., sort_keys=True, default=str)``
        expression everywhere so signing and verification always agree.
        """
        return A2ACryptoService.hash_content(
            json.dumps(payload, sort_keys=True, default=str)
        )

    def sign_verdict(
        self,
        trace_id: str,
        verdict_status: str,
        engine: str,
        sender_id: str,
        receiver_id: str,
        payload_hash: str,
        session_id: str | None = None,
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

    @staticmethod
    def _select_peer_key(keys: list[dict[str, Any]], token_kid: Any) -> str | None:
        """Select a peer verification key by kid (None when unusable).

        A token ``kid`` must match a registered key exactly; a token
        without ``kid`` verifies only against a single-key entry (never
        an ambiguous pick among several).
        """
        if token_kid is not None:
            for candidate in keys:
                if isinstance(candidate, dict) and candidate.get("kid") == token_kid:
                    return _jwk_to_public_pem(candidate)
            return None
        if len(keys) == 1:
            return _jwk_to_public_pem(keys[0])
        return None

    def verify_attestation(
        self,
        token: str,
        context: AttestationContext,
        trusted_issuers: dict[str, Any] | None = None,
    ) -> tuple[bool, dict[str, Any] | None, str | None]:
        """
        Verify a JWT attestation token against the current request context.

        Verification steps (all must pass):
        0. Issuer-key resolution (#84) — the token's ``iss`` selects the
           verification key: this service's own key for self-issued
           tokens, a registered peer key for trusted issuers, rejection
           for unknown issuers. Header/payload are decoded unverified
           ONLY for this routing; nothing is trusted until the signature
           check against the resolved key succeeds.
        1. Cryptographic signature check (ES256 / ECDSA P-256)
        2. Expiry check (exp claim)
        3. Required claims check (iss, sub, iat, exp, jti)
        4. Structural validation of the qwed_a2a nested claim block
        5. Deployment context check — deployment_id must match this
           instance for self-issued tokens, or the registered deployment
           ID of the trusted peer issuer
        6. Context binding — sender, receiver, payload hash, and session
           (if provided) all matched against the AttestationContext
        7. jti replay check — rejects previously seen jti values

        ``trusted_issuers`` maps issuer IDs to
        ``{"deployment_id": ..., "jwks": {"keys": [...]}}`` (the JWKS shape
        ``get_public_key_jwk()`` emits — copy a peer's
        ``/.well-known/jwks.json`` entry verbatim). When None,
        ``QWED_A2A_TRUSTED_ISSUERS`` is read instead; when both are absent
        only self-issued tokens verify (unchanged default).

        Returns:
            Tuple of (is_valid, decoded_claims, error_message).
            ``True`` means the token is cryptographically valid AND bound to
            the provided context — not just that the signature is valid.
        """
        if not HAS_CRYPTO:
            return False, None, "Cryptography backend unavailable"
        try:
            header = jwt.get_unverified_header(token)
            token_kid = header.get("kid") if isinstance(header, dict) else None
        except jwt.InvalidTokenError as exc:
            return False, None, f"Invalid token: {exc}"
        try:
            unverified = jwt.decode(token, options={"verify_signature": False})
        except jwt.InvalidTokenError as exc:
            return False, None, f"Invalid token: {exc}"
        token_iss = unverified.get("iss") if isinstance(unverified, dict) else None

        expected_deployment_id = _DEPLOYMENT_ID
        if token_iss == self.issuer_id:
            verification_key = self._ensure_key_pair().public_key_pem
        else:
            issuers = _load_trusted_issuers(trusted_issuers)
            entry = issuers.get(token_iss) if isinstance(token_iss, str) else None
            if entry is None:
                return (
                    False,
                    None,
                    "Unknown issuer: token is not from this deployment "
                    "or a trusted peer",
                )
            verification_key = self._select_peer_key(entry["keys"], token_kid)
            if verification_key is None:
                return False, None, "No usable key for trusted issuer"
            expected_deployment_id = entry["deployment_id"]

        try:
            raw_claims = jwt.decode(
                token,
                verification_key,
                algorithms=[self.ALGORITHM],
                options={"require": ["iss", "sub", "iat", "exp", "jti"]},
            )
        except jwt.ExpiredSignatureError:
            return False, None, "Attestation has expired"
        except jwt.InvalidTokenError as exc:
            return False, None, f"Invalid token: {exc}"

        # Step 4: structural validation of the qwed_a2a nested claim block.
        try:
            qwed_claims = _QwedA2AClaims.model_validate(raw_claims.get("qwed_a2a", {}))
        except ValidationError:
            return False, None, "Invalid qwed_a2a claims structure"

        # Step 5: deployment context check — the deployment bound at
        # issuance must match this instance (self-issued) or the
        # registered deployment of the trusted peer issuer.
        if qwed_claims.deployment_id != expected_deployment_id:
            return (
                False,
                None,
                "Deployment context mismatch: token not issued by this deployment",
            )

        # Step 6: context binding — sender, receiver, payload hash, session
        if qwed_claims.sender != context.sender_agent_id:
            return (
                False,
                None,
                (
                    f"Attestation sender mismatch: "
                    f"expected={context.sender_agent_id}, got={qwed_claims.sender}"
                ),
            )

        if qwed_claims.receiver != context.receiver_agent_id:
            return (
                False,
                None,
                (
                    f"Attestation receiver mismatch: "
                    f"expected={context.receiver_agent_id}, got={qwed_claims.receiver}"
                ),
            )

        expected_hash = self.payload_hash(context.payload)
        if raw_claims.get("sub") != expected_hash:
            return (
                False,
                None,
                "Attestation payload hash mismatch — detached attestation rejected",
            )

        if (
            context.session_id is not None
            and qwed_claims.session_id != context.session_id
        ):
            return (
                False,
                None,
                (
                    f"Attestation session mismatch: "
                    f"expected={context.session_id}, got={qwed_claims.session_id}"
                ),
            )

        # Step 7: replay check — runs after context binding so we don't
        # pollute the registry with out-of-context tokens.
        jti = raw_claims.get("jti")
        if not jti:
            return False, None, "Missing jti claim"

        if not self._jti_registry.check_and_register(jti):
            return False, None, "Replay detected: jti already seen"

        return True, raw_claims, None
