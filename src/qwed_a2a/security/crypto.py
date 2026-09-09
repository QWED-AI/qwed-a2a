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
import string
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, StrictStr, ValidationError

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

    SCOPE: this instance is process-local. Two service instances in one
    process each own theirs; two workers in two processes share nothing.
    Multi-worker deployments needing cross-worker replay protection must
    inject a shared implementation (any object with ``check_and_register``
    and ``__len__``) via ``A2ACryptoService(jti_registry=...)`` — the
    default documents single-process scope rather than pretending
    otherwise (#85).
    """

    def __init__(self, ttl_seconds: int = 300) -> None:
        # Values are retention EXPIRIES (epoch seconds), not insertion
        # timestamps, so a token with a longer lifetime than the TTL keeps
        # its replay slot until it expires. Insertion order therefore does
        # NOT imply expiry order — eviction must scan everything.
        self._seen: OrderedDict[str, float] = OrderedDict()
        self._ttl = ttl_seconds
        self._lock = threading.Lock()

    @property
    def ttl_seconds(self) -> float:
        """Configured retention window. Consumers must retain entries at
        least this long; shorter retention re-opens replay of live tokens."""
        return self._ttl

    def check_and_register(
        self,
        jti: str,
        now: float | None = None,
        *,
        valid_until: float | None = None,
    ) -> bool:
        """
        Return True and register jti if it has never been seen.
        Return False (without registering) if jti is already in the registry.

        Args:
            jti: The JWT ID to check.
            now: Current epoch time (injectable for testing). Defaults to time.time().
            valid_until: Epoch expiry of the token carrying this jti. The
                slot is retained until the LATER of TTL-expiry and the
                token's own expiry — a token valid longer than the TTL
                must not become replayable while still alive. Never
                shortens retention below the TTL.
        """
        if now is None:
            now = time.time()

        with self._lock:
            self._evict(now)
            if jti in self._seen:
                return False
            expiry = now + self._ttl
            if valid_until is not None and valid_until > expiry:
                expiry = valid_until
            self._seen[jti] = expiry
            return True

    def release(self, jti: str) -> None:
        """Withdraw a reservation (e.g. signing failed after reserving).

        Missing keys are a no-op — release is idempotent by design so
        failure-path rollbacks stay unconditional.
        """
        with self._lock:
            self._seen.pop(jti, None)

    def _evict(self, now: float) -> None:
        """Drop every entry whose retention expired, wherever it sits.

        A front-peek loop is WRONG here: per-token lifetimes mean a
        live long-lived head can sit ahead of expired short-lived
        entries, which would then leak and keep denying replays. n is
        bounded by live-token count and dwarfed by signature cost, so a
        full scan wins over heap bookkeeping.
        """
        expired = [jti for jti, expiry in self._seen.items() if expiry <= now]
        for jti in expired:
            del self._seen[jti]

    def __len__(self) -> int:
        """Return the number of currently registered jti values."""
        with self._lock:
            return len(self._seen)


class ReplayRegistry(Protocol):
    """Structural contract for replay registries (consumption side).

    Implementations (Redis, database, shared memory) must provide:
    - ``check_and_register`` with ATOMIC insert-if-absent semantics —
      two workers racing on the same jti must not both be accepted.
    - Retention covering each token's full lifetime (honor
      ``valid_until``; never evict a live token's slot).
    - Thread safety for in-process concurrent use.
    - ``ttl_seconds`` reporting the retention window, so services can
      refuse registries that expire entries while tokens are alive.
    """

    @property
    def ttl_seconds(self) -> float: ...

    def check_and_register(
        self,
        jti: str,
        now: float | None = ...,
        *,
        valid_until: float | None = ...,
    ) -> bool: ...

    def __len__(self) -> int: ...


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


class _AttestationEnvelope(BaseModel):
    """Strict types for the top-level JWT claims used in trust decisions.

    Validated immediately after signature verification, before the issuer
    binding or replay check reads anything: RFC 7519 defines iss/sub/jti
    as strings, and no security decision may branch on an unvalidated
    type (e.g. an int jti stringifying into a registry key, or a list
    iss slipping past equality). ``iat``/``exp`` are enforced numerically
    by PyJWT during decode; extra claims pass through untouched.
    """

    model_config = ConfigDict(extra="allow")

    iss: StrictStr
    sub: StrictStr
    jti: StrictStr
    # NumericDate per RFC 7519 §2. Lax union mirrors PyJWT's own
    # integer-coercible handling (it accepts int("4102444800")), while
    # guaranteeing downstream code only ever sees numbers — a string exp
    # must never reach retention arithmetic as a TypeError crash.
    iat: int | float
    exp: int | float


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
# minute, never a log-spam vector. Guarded by a lock — verify paths
# run on multiple threads and an unsynchronized read-modify-write
# could emit duplicate warnings or, worse, suppress one entirely.
_TRUSTED_ISSUERS_LAST_WARN: float | None = None
_TRUSTED_ISSUERS_WARN_INTERVAL = 60.0
_TRUSTED_ISSUERS_WARN_LOCK = threading.Lock()


def _warn_issuers_misconfigured(message: str) -> None:
    """Log a trusted-issuer config problem, rate-limited to one per minute."""
    global _TRUSTED_ISSUERS_LAST_WARN
    now = time.monotonic()
    with _TRUSTED_ISSUERS_WARN_LOCK:
        if (
            _TRUSTED_ISSUERS_LAST_WARN is None
            or now - _TRUSTED_ISSUERS_LAST_WARN >= _TRUSTED_ISSUERS_WARN_INTERVAL
        ):
            _TRUSTED_ISSUERS_LAST_WARN = now
            logger.warning(message)


# Strict base64url decode table for JWK coordinates. The stdlib
# ``urlsafe_b64decode`` silently discards non-alphabet characters, which
# would let a malformed (or attacker-mutated) coordinate decode to
# different bytes than its text form suggests. These helpers reject
# anything outside the canonical alphabet instead. Alphabets are built
# from the string module rather than spelled-out literals: a 64-char
# high-entropy literal next to key/token handling reads as leaked
# credential material to secret scanners (and to humans).
_B64_ALPHABET_SET = frozenset(string.ascii_letters + string.digits + "-_")
_B64URL_TO_B64_TABLE = str.maketrans("-_", "+/")
_B64_STD_ALPHABET = (
    string.ascii_uppercase + string.ascii_lowercase + string.digits + "+/"
)


def _b64_decode_strict(padded: str) -> bytes:
    """Decode canonical padded standard-alphabet base64, rejecting junk.

    Raises ValueError on any character outside the alphabet or bad
    padding — fail closed, never silently repair.
    """
    if len(padded) % 4 != 0:
        raise ValueError("Bad base64 length")
    vals: list[int] = []
    for char in padded.rstrip("="):
        idx = _B64_STD_ALPHABET.find(char)
        if idx < 0:
            raise ValueError("Non-base64 character")
        vals.append(idx)
    out = bytearray()
    for i in range(0, len(vals) - len(vals) % 4, 4):
        n = (vals[i] << 18) | (vals[i + 1] << 12) | (vals[i + 2] << 6) | vals[i + 3]
        out += bytes(((n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF))
    tail = vals[len(vals) - len(vals) % 4 :]
    if len(tail) == 2:
        n = (tail[0] << 18) | (tail[1] << 12)
        out += bytes(((n >> 16) & 0xFF,))
    elif len(tail) == 3:
        n = (tail[0] << 18) | (tail[1] << 12) | (tail[2] << 6)
        out += bytes(((n >> 16) & 0xFF, (n >> 8) & 0xFF))
    elif len(tail) == 1:
        raise ValueError("Bad base64 padding")
    return bytes(out)


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
            # Manual base64url decode (no base64 stdlib call): the strict
            # alphabet check means attacker-controlled JWK coordinates that
            # are not canonical base64url fail closed here instead of being
            # silently repaired by a lenient decoder.
            if not s or any(c not in _B64_ALPHABET_SET and c != "=" for c in s):
                raise ValueError("Non-base64url JWK coordinate")
            canonical = s.translate(_B64URL_TO_B64_TABLE)
            padded = canonical + "=" * (-len(canonical) % 4)
            raw = _b64_decode_strict(padded)
            return int.from_bytes(raw, "big")

        numbers = ec.EllipticCurvePublicNumbers(
            _b64url_uint(x_b64), _b64url_uint(y_b64), ec.SECP256R1()
        )
        public_key = numbers.public_key()
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
    except (ValueError, TypeError):
        return None


# Upper bound for the trusted-issuer env JSON. A peer JWKS set is a few
# kilobytes; anything larger is a misconfiguration (or an env-injection
# attempt) and fails closed before parsing.
_ISSUER_CONFIG_MAX_BYTES = 65536


def _sanitize_issuer_config_json(value: str) -> str:
    """Validate trusted-issuer env JSON before it reaches ``json.loads``.

    Size-capped, must be a JSON object, and must not smuggle control
    characters. Raises TypeError for non-text input, ValueError for
    malformed text — callers warn and fall back to local-only
    verification (fail closed, never parse junk).
    """
    if not isinstance(value, str):
        raise TypeError("Trusted-issuer config must be text")
    text = value.strip()
    if len(text.encode("utf-8")) > _ISSUER_CONFIG_MAX_BYTES:
        raise ValueError("Trusted-issuer config exceeds size limit")
    if not text.startswith("{"):
        raise ValueError("Trusted-issuer config must be a JSON object")
    if any(ord(c) < 0x20 and c not in "\t\n\r" for c in text):
        raise ValueError("Trusted-issuer config contains control characters")
    return text


def _is_nonempty_str(value: Any) -> bool:
    """True for usable config strings: present, text, and non-blank."""
    return isinstance(value, str) and bool(value.strip())


def _normalize_issuer_entry(issuer_id: Any, entry: Any) -> dict[str, Any] | None:
    """Validate one trusted-issuer entry; None when unusable (fail closed).

    Each usable key is converted to PEM once per load here (rather than
    once per candidate attempt during verification).
    Returns ``{"deployment_id": ..., "keys": [{"pem": ..., "kid": ...}]}``.
    """
    if not _is_nonempty_str(issuer_id):
        return None
    if not isinstance(entry, dict):
        return None
    deployment_id = entry.get("deployment_id")
    if not _is_nonempty_str(deployment_id):
        return None
    jwks = entry.get("jwks")
    keys = jwks.get("keys") if isinstance(jwks, dict) else None
    if not isinstance(keys, list) or not keys:
        return None
    usable = []
    for key in keys:
        pem = _jwk_to_public_pem(key)
        if pem is None:
            continue
        kid = key.get("kid") if isinstance(key, dict) else None
        usable.append({"pem": pem, "kid": kid if isinstance(kid, str) else None})
    if not usable:
        return None
    return {"deployment_id": deployment_id, "keys": usable}


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
            sanitized_raw = _sanitize_issuer_config_json(env_raw)
            raw = json.loads(sanitized_raw)
        except (ValueError, TypeError, RecursionError):
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
        normalized = _normalize_issuer_entry(issuer_id, entry)
        if normalized is None:
            continue
        issuers[issuer_id] = normalized
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
    - Enforces jti replay prevention via JtiRegistry (consumption side;
      issuance dup-detection lives in a separate per-instance record so
      signing never poisons verification — see #85).
    """

    ALGORITHM = "ES256"
    TOKEN_TYPE = "qwed-a2a-attestation+jwt"

    def __init__(
        self,
        issuer_id: str = "did:qwed:a2a:local",
        validity_seconds: int = 300,
        pem_key: str | None = None,
        jti_registry: ReplayRegistry | None = None,
    ):
        self.issuer_id = issuer_id
        self.validity_seconds = validity_seconds
        self._pem_key = pem_key
        self._key_pair: KeyPair | None = None
        self._key_lock = threading.Lock()
        # Consumption registry: records jtis this instance has VERIFIED.
        # Shared across instances only when explicitly injected — the
        # default is process-local (see JtiRegistry scope note, #85).
        # TTL is aligned with the validity window so entries are never
        # held longer than the tokens they protect against.
        if jti_registry is not None:
            # Fail fast on registries that cannot guarantee retention:
            # without a numeric window covering token lifetime, entries
            # could be evicted while their tokens are still alive and
            # replay would re-open. Missing or non-numeric ttl_seconds
            # is not a softer case — it is unverifiable retention.
            registry_ttl = getattr(jti_registry, "ttl_seconds", None)
            if not isinstance(registry_ttl, (int, float)) or (
                registry_ttl < validity_seconds
            ):
                raise ValueError(
                    "Injected replay registry reports "
                    f"ttl_seconds={registry_ttl!r}; a numeric window of at "
                    f"least the token validity ({validity_seconds}s) is "
                    "required — shorter retention re-opens replay of live "
                    "tokens."
                )
            self._jti_registry = jti_registry
        else:
            self._jti_registry = JtiRegistry(ttl_seconds=validity_seconds)
        # Issuance record: trace_ids this instance has SIGNED. Deliberately
        # separate from the consumption registry — signing must never
        # consume a replay slot, or the issuer could never verify its own
        # tokens (#85). Always per-instance: cross-worker duplicate
        # issuance is caller misuse (trace_ids are caller-supplied), while
        # cross-worker duplicate CONSUMPTION is the replay attack the
        # injectable consumption registry addresses.
        self._issued_registry = JtiRegistry(ttl_seconds=validity_seconds)

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
        - Recorded in the per-instance issuance record (NOT the
          verification replay registry — signing consumes no replay
          slot, so the issuer can verify its own tokens)

        A duplicate trace_id raises ValueError: each attestation needs a
        unique jti (RFC 7519), and silently minting contradictory tokens
        under one jti poisons every consumer's registry.

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

        Raises:
            ValueError: trace_id already issued by this instance.
        """
        # Key first: a missing or misconfigured key must surface before the
        # trace is reserved — otherwise the retry burns on a phantom
        # duplicate for a token that was never minted.
        key_pair = self._ensure_key_pair()
        if not self._issued_registry.check_and_register(trace_id):
            raise ValueError("duplicate trace_id: each attestation needs a unique jti")
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

        try:
            token = jwt.encode(
                payload,
                key_pair.private_key_pem,
                algorithm=self.ALGORITHM,
                headers=header,
            )
        except Exception:
            # Encoding failed after reserving: roll back so a retry with
            # the same trace_id remains possible. (Payload/header
            # construction above is infallible literals — encode is the
            # only fallible step left.)
            self._issued_registry.release(trace_id)
            raise

        return token

    def _candidate_keys(
        self, trusted_issuers: dict[str, Any] | None
    ) -> list[tuple[str, bytes | str, str | None, str | None]]:
        """Build (issuer, key, expected deployment, kid) verify candidates.

        The local key comes first and only when configured — verifier-only
        nodes (no signing key) verify peer tokens without one. Peer entries
        come from the explicit argument or ``QWED_A2A_TRUSTED_ISSUERS`` (PEMs
        pre-converted by the loader). A public key registered under more
        than one identity is kept only for the first identity: one private
        key must never verify as two different issuers/deployments. An
        empty result means no verification is possible; callers fail closed.
        """
        candidates: list[tuple[str, bytes | str, str | None, str | None]] = []
        seen_pems: dict[str, str] = {}
        try:
            own_pair = self._ensure_key_pair()
        except RuntimeError as exc:
            logger.debug("Local key unavailable for verification: %s", exc)
            own_pair = None
        if own_pair is not None:
            candidates.append(
                (
                    self.issuer_id,
                    own_pair.public_key_pem,
                    _DEPLOYMENT_ID,
                    own_pair.key_id,
                )
            )
            seen_pems[self._pem_fingerprint(own_pair.public_key_pem)] = self.issuer_id
        for issuer_id, entry in _load_trusted_issuers(trusted_issuers).items():
            for key in entry["keys"]:
                fingerprint = self._pem_fingerprint(key["pem"])
                owner = seen_pems.get(fingerprint)
                if owner is not None and owner != issuer_id:
                    # Static message deliberately: issuer IDs flow from
                    # operator config (env/file) and must not be interpolated
                    # into logs (clear-text logging of config-derived data).
                    # Operators identify the offending entry by removing
                    # peer entries until the warning stops.
                    _warn_issuers_misconfigured(
                        "Trusted-issuer configuration reuses one public key "
                        "under two identities; the later entry is skipped — "
                        "one key must not verify as two issuers."
                    )
                    continue
                seen_pems.setdefault(fingerprint, issuer_id)
                candidates.append(
                    (
                        issuer_id,
                        key["pem"],
                        entry["deployment_id"],
                        key["kid"],
                    )
                )
        return candidates

    @staticmethod
    def _pem_fingerprint(pem: bytes | str) -> str:
        """Short stable fingerprint identifying one public key."""
        raw = pem if isinstance(pem, bytes) else pem.encode("utf-8")
        return hashlib.sha256(raw).hexdigest()[:16]

    def _try_candidate_key(
        self, token: str, key: bytes | str
    ) -> tuple[dict[str, Any] | None, str | None]:
        """Attempt verification against a single candidate key.

        Returns (decoded_complete, None) on success, else (None,
        "expired" | "invalid"). Expiry is distinguished so an expired
        token reports expiry instead of a misleading signature error
        when an earlier candidate merely failed to verify.
        """
        try:
            complete = jwt.decode_complete(
                token,
                key,
                algorithms=[self.ALGORITHM],
                options={"require": ["iss", "sub", "iat", "exp", "jti"]},
            )
            return complete, None
        except jwt.ExpiredSignatureError:
            return None, "expired"
        except jwt.InvalidTokenError:
            return None, "invalid"
        except TypeError:
            # Malformed claim types PyJWT rejects outside InvalidTokenError
            # (e.g. exp=None) must read as invalid tokens, never propagate
            # as unhandled exceptions out of verification.
            return None, "invalid"

    def _attempt_candidate(
        self,
        token: str,
        owner_iss: str,
        key: bytes | str,
        expected_kid: str | None,
    ) -> tuple[str, dict[str, Any] | None, _AttestationEnvelope | None]:
        """Try one candidate key; return (status, claims, envelope-or-None).

        Statuses: "verified" (signature verified AND iss/kid bound to this
        key's owner — claims AND typed envelope returned), "kid-mismatch"
        (verified but the token's kid is not this key's registered kid —
        later candidates may still match, so callers keep trying),
        "expired", "no-match".
        """
        complete, error = self._try_candidate_key(token, key)
        if complete is None:
            return ("expired" if error == "expired" else "no-match"), None, None
        raw_claims = complete.get("payload")
        if not isinstance(raw_claims, dict):
            return "no-match", None, None
        try:
            envelope = _AttestationEnvelope.model_validate(raw_claims)
        except ValidationError:
            return "no-match", None, None
        # Ownership binding: the verified iss must be the verifying key's
        # owner — a token signed by one issuer never verifies under another
        # issuer's entry, even if keys collide.
        if envelope.iss != owner_iss:
            return "no-match", None, None
        header = complete.get("header")
        header = header if isinstance(header, dict) else {}
        # kid binding, checked post-verification: a token carrying a kid
        # verifies only under a key registered with that exact kid. Tokens
        # without kid verify under whichever key verifies the signature
        # (order-independent) — per RFC 7515 the kid is only a hint, and
        # with no kid there is nothing to confuse. A kid-carrying token is
        # NOT accepted under an unlabeled key either: in a mixed entry that
        # would let a token minted for one labeled key verify under another
        # (pre-#84 routing denied this too — fail closed on ambiguity).
        token_kid = header.get("kid")
        if token_kid is not None and token_kid != expected_kid:
            return "kid-mismatch", None, None
        return "verified", raw_claims, envelope

    def _check_verified_claims(
        self,
        raw_claims: dict[str, Any],
        expected_deployment_id: str | None,
        context: AttestationContext,
        envelope: _AttestationEnvelope,
    ) -> tuple[bool, dict[str, Any] | None, str | None]:
        """Steps 4-7 on claims whose signature already verified.

        Structural validation of the ``qwed_a2a`` block, deployment match,
        context binding (sender/receiver/payload hash/session), then the
        jti replay check — last so out-of-context tokens never pollute
        the registry. ``envelope`` carries the strictly-typed top-level
        claims; only typed values reach trust decisions and retention.
        """
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
                    "Attestation sender mismatch: "
                    f"expected={context.sender_agent_id}, got={qwed_claims.sender}"
                ),
            )

        if qwed_claims.receiver != context.receiver_agent_id:
            return (
                False,
                None,
                (
                    "Attestation receiver mismatch: "
                    f"expected={context.receiver_agent_id}, got={qwed_claims.receiver}"
                ),
            )

        expected_hash = self.payload_hash(context.payload)
        if envelope.sub != expected_hash:
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
                    "Attestation session mismatch: "
                    f"expected={context.session_id}, got={qwed_claims.session_id}"
                ),
            )

        # Step 7: replay check — runs after context binding so we don't
        # pollute the registry with out-of-context tokens. The jti is
        # namespaced by issuer for peer tokens: two issuers legitimately
        # reusing the same jti (e.g. a trace ID) must not shadow each
        # other. Self-issued tokens keep the bare jti (same-instance
        # self-verification works — issuance no longer consumes a slot).
        # Typed envelope values only: no raw-dict type can reach the
        # registry key or retention arithmetic. Empty strings still deny.
        jti = envelope.jti
        if not jti:
            return False, None, "Missing jti claim"
        iss = envelope.iss
        registry_key = f"{iss}\0{jti}" if iss != self.issuer_id else jti

        if not self._jti_registry.check_and_register(
            registry_key, valid_until=envelope.exp
        ):
            return False, None, "Replay detected: jti already seen"

        return True, raw_claims, None

    def verify_attestation(
        self,
        token: str,
        context: AttestationContext,
        trusted_issuers: dict[str, Any] | None = None,
    ) -> tuple[bool, dict[str, Any] | None, str | None]:
        """
        Verify a JWT attestation token against the current request context.

        Verification tries every configured key until one verifies the
        signature — the local key first when configured, then each peer
        key. Routing uses no unverified parsing: header/payload are read
        only AFTER a candidate key verifies the signature, and the
        verified ``iss``/``kid`` are then bound to the key that
        verified them. Once a key verifies, all of the following must
        pass:
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
        candidates = self._candidate_keys(trusted_issuers)
        if not candidates:
            return (
                False,
                None,
                "No verification keys available (no local key, no trusted issuers)",
            )
        expired_seen = False
        kid_mismatch_seen = False
        for owner_iss, key, expected_dep, expected_kid in candidates:
            status, raw_claims, envelope = self._attempt_candidate(
                token, owner_iss, key, expected_kid
            )
            if status == "expired":
                expired_seen = True
            elif status == "kid-mismatch":
                # Same key material re-registered under a new kid (rotation)
                # verifies here but matches a later candidate — keep trying
                # rather than letting JWKS order decide accept/deny.
                kid_mismatch_seen = True
            elif status == "verified":
                return self._check_verified_claims(
                    raw_claims, expected_dep, context, envelope
                )
        if expired_seen:
            return False, None, "Attestation has expired"
        if kid_mismatch_seen:
            return False, None, "Key id mismatch for trusted issuer"
        return False, None, "Invalid token: no trusted key verified the signature"
