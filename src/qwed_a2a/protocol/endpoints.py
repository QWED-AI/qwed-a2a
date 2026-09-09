"""
QWED A2A Protocol Endpoints.

FastAPI router exposing the A2A verification gateway via HTTP.
"""

import hmac
import json
import os
import threading
import time
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request

from qwed_a2a import __version__
from qwed_a2a.interceptor import A2AVerificationInterceptor
from qwed_a2a.protocol.schema import AgentMessage, InterceptorConfig
from qwed_a2a.utils.telemetry import get_metrics, logger

router = APIRouter(prefix="/a2a", tags=["A2A Interceptor"])

# Thread-safe interceptor singleton
_interceptor_lock = threading.Lock()
_interceptor: A2AVerificationInterceptor | None = None


def _load_trusted_agents(interceptor: A2AVerificationInterceptor) -> None:
    """Load trusted agents from QWED_A2A_TRUSTED_AGENTS environment variable.

    Supports comma-separated agent IDs (backward compatible) or a JSON array
    for scoped trust entries::

        # Simple format (unrestricted scope, no expiry)
        QWED_A2A_TRUSTED_AGENTS=agent-a,agent-b

        # JSON format (full scope control)
        QWED_A2A_TRUSTED_AGENTS='[{"agent_id":"agent-a","allowed_receivers":["receiver-x"]}]'
    """
    trusted_env = os.environ.get("QWED_A2A_TRUSTED_AGENTS", "")
    if trusted_env:
        interceptor.trust.load_from_env(trusted_env, granted_by="env")
        logger.info("Zero-trust boundary initialized from environment")
    else:
        logger.warning(
            "QWED_A2A_TRUSTED_AGENTS not set; zero-trust boundary will deny all requests"
        )


def get_interceptor() -> A2AVerificationInterceptor:
    """Get or create the interceptor singleton (thread-safe)."""
    global _interceptor
    with _interceptor_lock:
        if _interceptor is None:
            _interceptor = A2AVerificationInterceptor()
            _load_trusted_agents(_interceptor)

    return _interceptor


def configure_interceptor(config: InterceptorConfig) -> None:
    """Reconfigure the interceptor at runtime (atomic swap)."""
    global _interceptor
    new_interceptor = A2AVerificationInterceptor(config=config)

    # Reload trusted agents to maintain zero-trust allowlist
    _load_trusted_agents(new_interceptor)

    with _interceptor_lock:
        _interceptor = new_interceptor


# Monotonic timestamp of the last key-misconfiguration warning.
# Misconfiguration warnings must be loud (the endpoint denies everything
# until keys are configured) but must not become a log-spam vector under
# unauthenticated scanning — or flap forever when two broken configs
# alternate. At most one warning per minute, whatever the sequence.
_API_KEYS_LAST_WARN: float = 0.0
_API_KEYS_WARN_INTERVAL = 60.0


def _warn_api_keys_misconfigured(message: str) -> None:
    """Log a key-config problem, rate-limited to one per minute."""
    global _API_KEYS_LAST_WARN
    now = time.monotonic()
    if now - _API_KEYS_LAST_WARN >= _API_KEYS_WARN_INTERVAL:
        _API_KEYS_LAST_WARN = now
        logger.warning(message)


def _valid_agent_id(agent: object) -> str | None:
    """Normalize an env-configured agent ID to the AgentMessage contract.

    Strips surrounding whitespace and enforces the same rules as
    ``AgentMessage.validate_agent_id_format`` (non-empty, max 256 chars,
    no control characters). Returns the canonical ID, or None when the
    entry is unusable — its key then fails closed as unknown.
    """
    if not isinstance(agent, str):
        return None
    normalized = agent.strip()
    if not normalized or len(normalized) > 256:
        return None
    if any(ord(c) < 32 for c in normalized):
        return None
    return normalized


# Fail-closed bound on the operator key-map payload before parsing.
_MAX_KEYS_JSON_CHARS = 65536


def _sanitize_keys_json(raw: str) -> str:
    """Sanitize the operator key-map envelope before JSON parsing.

    Trust-boundary sanitizer (recognized by the QWED taint engine):
    only bounded, JSON-object-shaped text reaches ``json.loads``.
    Raises ValueError on anything else — callers fail closed.
    """
    text = raw.strip()
    if not text or len(text) > _MAX_KEYS_JSON_CHARS:
        raise ValueError("key map has invalid size")
    if not (text.startswith("{") and text.endswith("}")):
        raise ValueError("key map must be a JSON object")
    return text


def _load_api_keys() -> dict[str, str]:
    """Load the API-key -> agent-ID map from QWED_A2A_API_KEYS.

    Format is a JSON object mapping each key to its agent, e.g.
    ``{"key-abc123": "procurement-agent"}``. The map is read fresh on
    every call so key rotation takes effect without a restart. Returns
    an empty map when unconfigured or malformed (callers fail closed).
    """
    raw = os.environ.get("QWED_A2A_API_KEYS", "")
    if not raw.strip():
        _warn_api_keys_misconfigured(
            "QWED_A2A_API_KEYS is not set; /a2a/intercept denies all "
            "requests until per-agent API keys are configured."
        )
        return {}
    try:
        parsed = json.loads(_sanitize_keys_json(raw))
    except (ValueError, RecursionError):
        _warn_api_keys_misconfigured(
            "QWED_A2A_API_KEYS is not a JSON object; /a2a/intercept "
            "denies all requests until it is fixed."
        )
        return {}
    if not isinstance(parsed, dict):
        _warn_api_keys_misconfigured(
            "QWED_A2A_API_KEYS must be a JSON object mapping API keys "
            "to agent IDs; /a2a/intercept denies all requests until "
            "it is fixed."
        )
        return {}
    keys: dict[str, str] = {}
    for key, agent in parsed.items():
        if not (isinstance(key, str) and key):
            continue
        canonical = _valid_agent_id(agent)
        if canonical is None:
            continue
        keys[key] = canonical
    if not keys:
        _warn_api_keys_misconfigured(
            "QWED_A2A_API_KEYS contains no usable key->agent entries; "
            "/a2a/intercept denies all requests until it is fixed."
        )
    return keys


def require_agent_identity(request: Request) -> str:
    """Authenticate the caller and return its server-side agent ID (#83).

    The ``X-API-Key`` header selects the caller; the returned ID — never
    the body-declared ``sender_agent_id`` — is the identity the trust
    boundary and the attestation verdict bind to. Missing, unknown, or
    unconfigured keys fail closed with 401.
    """
    provided = request.headers.get("x-api-key", "")
    key_map = _load_api_keys()
    if not key_map:
        raise HTTPException(
            status_code=401,
            detail="API authentication is not configured for this service.",
        )
    try:
        provided_bytes = provided.encode("utf-8")
    except UnicodeEncodeError:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key.",
        ) from None
    for stored_key, agent_id in key_map.items():
        try:
            candidate = stored_key.encode("utf-8")
        except UnicodeEncodeError:
            # Misconfigured key that can never match — fail closed.
            continue
        if hmac.compare_digest(provided_bytes, candidate):
            return agent_id
    raise HTTPException(
        status_code=401,
        detail="Invalid or missing API key.",
    )


@router.post("/intercept", response_model=dict[str, Any])
async def intercept_message(
    message: AgentMessage,
    agent_id: Annotated[str, Depends(require_agent_identity)],
) -> dict[str, Any]:
    """
    Primary A2A verification gateway.

    Accepts an AgentMessage, runs it through the verification pipeline,
    and returns a VerificationVerdict.

    The authenticated API-key identity OVERRIDES the body-declared
    sender_agent_id (#83): trust evaluation, rate limiting, telemetry,
    and the attestation JWT all bind to the credential's agent, never
    to a self-declared string from the wire.
    """
    try:
        if message.sender_agent_id != agent_id:
            logger.warning(
                "sender_agent_id %r overridden by authenticated identity %r",
                message.sender_agent_id,
                agent_id,
            )
            message.sender_agent_id = agent_id
        interceptor = get_interceptor()
        trace_id = f"a2a_{uuid.uuid4().hex[:12]}"
        verdict = await interceptor.intercept(message, trace_id=trace_id)
        return verdict.model_dump(mode="json")
    except RuntimeError as exc:
        logger.error("Interceptor runtime error: %s", exc)
        raise HTTPException(status_code=503, detail="Signing key unavailable")
    except Exception as exc:  # noqa: BLE001  # generic 500 catch-all
        logger.error("Interceptor internal error: %s", exc)
        raise HTTPException(status_code=500, detail="Internal interceptor error")


@router.get("/health")
async def health_check() -> dict[str, str]:
    """Service health check."""
    return {
        "status": "healthy",
        "service": "qwed-a2a",
        "version": __version__,
    }


@router.get("/metrics")
async def metrics() -> dict[str, Any]:
    """Return aggregated intercept metrics."""
    return get_metrics().to_dict()


wellknown_router = APIRouter(tags=["JWKS"])


@wellknown_router.get(
    "/.well-known/jwks.json",
    responses={
        200: {
            "description": "JWKS key set",
            "content": {
                "application/json": {
                    "example": {
                        "keys": [
                            {
                                "kty": "EC",
                                "crv": "P-256",
                                "x": "...",
                                "y": "...",
                                "kid": "did:qwed:a2a:local#key-...",
                                "use": "sig",
                                "alg": "ES256",
                            }
                        ]
                    }
                }
            },
        },
        503: {
            "description": "Signing key unavailable — QWED_A2A_SIGNING_KEY_PEM not set or invalid"
        },
    },
)
async def jwks_endpoint() -> dict[str, Any]:
    """Public key set for JWT verification by external consumers."""
    try:
        interceptor = get_interceptor()
        jwk = interceptor.crypto.get_public_key_jwk()
        return {"keys": [jwk]}
    except RuntimeError as exc:
        logger.error("Failed to serve JWKS: %s", exc)
        raise HTTPException(status_code=503, detail="Signing key unavailable")
