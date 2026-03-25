"""
QWED A2A Protocol Endpoints.

FastAPI router exposing the A2A verification gateway via HTTP.
"""

from typing import Any, Dict

from fastapi import APIRouter, HTTPException
from pydantic import ValidationError

from qwed_a2a.interceptor import A2AVerificationInterceptor
from qwed_a2a.protocol.schema import AgentMessage, InterceptorConfig
from qwed_a2a.utils.telemetry import get_metrics

router = APIRouter(prefix="/a2a", tags=["A2A Interceptor"])

# Module-level interceptor instance (configured at app startup)
_interceptor: A2AVerificationInterceptor | None = None


def get_interceptor() -> A2AVerificationInterceptor:
    """Get or create the interceptor singleton."""
    global _interceptor
    if _interceptor is None:
        _interceptor = A2AVerificationInterceptor()
    return _interceptor


def configure_interceptor(config: InterceptorConfig) -> None:
    """Reconfigure the interceptor at runtime."""
    global _interceptor
    _interceptor = A2AVerificationInterceptor(config=config)


@router.post("/intercept", response_model=Dict[str, Any])
async def intercept_message(message: AgentMessage) -> Dict[str, Any]:
    """
    Primary A2A verification gateway.

    Accepts an AgentMessage, runs it through the verification pipeline,
    and returns a VerificationVerdict.
    """
    interceptor = get_interceptor()
    verdict = await interceptor.intercept(message)
    return verdict.model_dump(mode="json")


@router.get("/health")
async def health_check() -> Dict[str, str]:
    """Service health check."""
    return {
        "status": "healthy",
        "service": "qwed-a2a",
        "version": "0.1.0",
    }


@router.get("/metrics")
async def metrics() -> Dict[str, Any]:
    """Return aggregated intercept metrics."""
    return get_metrics().to_dict()
