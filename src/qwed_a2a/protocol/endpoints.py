"""
QWED A2A Protocol Endpoints.

FastAPI router exposing the A2A verification gateway via HTTP.
"""

import os
import threading
import uuid
from typing import Any, Dict

from fastapi import APIRouter, HTTPException

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


@router.post("/intercept", response_model=Dict[str, Any])
async def intercept_message(message: AgentMessage) -> Dict[str, Any]:
    """
    Primary A2A verification gateway.

    Accepts an AgentMessage, runs it through the verification pipeline,
    and returns a VerificationVerdict.
    """
    try:
        interceptor = get_interceptor()
        trace_id = f"a2a_{uuid.uuid4().hex[:12]}"
        verdict = await interceptor.intercept(message, trace_id=trace_id)
        return verdict.model_dump(mode="json")
    except RuntimeError as exc:
        logger.error("Interceptor runtime error: %s", exc)
        raise HTTPException(status_code=503, detail="Signing key unavailable")
    except Exception as exc:
        logger.error("Interceptor internal error: %s", exc)
        raise HTTPException(
            status_code=500, detail=f"Internal interceptor error: {exc}"
        )


@router.get("/health")
async def health_check() -> Dict[str, str]:
    """Service health check."""
    return {
        "status": "healthy",
        "service": "qwed-a2a",
        "version": __version__,
    }


@router.get("/metrics")
async def metrics() -> Dict[str, Any]:
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
async def jwks_endpoint() -> Dict[str, Any]:
    """Public key set for JWT verification by external consumers."""
    try:
        interceptor = get_interceptor()
        jwk = interceptor.crypto.get_public_key_jwk()
        return {"keys": [jwk]}
    except RuntimeError as exc:
        logger.error("Failed to serve JWKS: %s", exc)
        raise HTTPException(status_code=503, detail="Signing key unavailable")
