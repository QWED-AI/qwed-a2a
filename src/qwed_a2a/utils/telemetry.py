"""
QWED A2A Telemetry & Observability.

Provides Sentry integration, structured logging, and intercept metrics.
Mirrors the telemetry patterns from qwed-verification/core/telemetry.py.
"""

import functools
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable

# Imported here (not at top) to avoid circular imports —
# schema is a leaf module with no telemetry dependency.
from qwed_a2a.protocol.schema import VerdictStatus

# Conditional Sentry import
try:
    import sentry_sdk

    HAS_SENTRY = True
except ImportError:
    HAS_SENTRY = False


logger = logging.getLogger("qwed_a2a")


@dataclass
class InterceptMetrics:
    """Aggregated metrics for interceptor performance monitoring."""

    total_intercepts: int = 0
    total_forwarded: int = 0
    total_blocked: int = 0
    total_unverifiable: int = 0
    total_heuristic_pass: int = 0
    total_errors: int = 0
    total_latency_ms: float = 0.0
    by_engine: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    by_sender: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    @property
    def average_latency_ms(self) -> float:
        if self.total_intercepts == 0:
            return 0.0
        return self.total_latency_ms / self.total_intercepts

    @property
    def block_rate(self) -> float:
        if self.total_intercepts == 0:
            return 0.0
        return self.total_blocked / self.total_intercepts

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_intercepts": self.total_intercepts,
            "total_forwarded": self.total_forwarded,
            "total_blocked": self.total_blocked,
            "total_unverifiable": self.total_unverifiable,
            "total_heuristic_pass": self.total_heuristic_pass,
            "total_errors": self.total_errors,
            "average_latency_ms": round(self.average_latency_ms, 2),
            "block_rate": round(self.block_rate, 4),
            "by_engine": dict(self.by_engine),
            "by_sender": dict(self.by_sender),
        }


# Module-level singleton
_metrics = InterceptMetrics()


def get_metrics() -> InterceptMetrics:
    """Get the global metrics singleton."""
    return _metrics


def reset_metrics() -> None:
    """Reset all metrics (for testing)."""
    global _metrics
    _metrics = InterceptMetrics()


def init_telemetry(
    sentry_dsn: str | None = None,
    environment: str = "development",
    log_level: int = logging.INFO,
) -> None:
    """
    Initialize telemetry subsystem.

    Args:
        sentry_dsn: Sentry DSN for error tracking (optional).
        environment: Deployment environment name.
        log_level: Python logging level.
    """
    # Configure structured logging
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    # Initialize Sentry if DSN provided and SDK available
    if sentry_dsn and HAS_SENTRY:
        sentry_sdk.init(
            dsn=sentry_dsn,
            environment=environment,
            traces_sample_rate=0.1,
            send_default_pii=False,
        )
        logger.info("Sentry telemetry initialized for environment=%s", environment)
    elif sentry_dsn and not HAS_SENTRY:
        logger.warning("Sentry DSN provided but sentry-sdk not installed. Skipping.")

    logger.info(
        "QWED A2A telemetry initialized (level=%s)", logging.getLevelName(log_level)
    )


def record_intercept(
    status: VerdictStatus,
    engine: str | None,
    sender_id: str,
    latency_ms: float,
) -> None:
    """Record an intercept event in the metrics aggregator."""
    metrics = get_metrics()
    metrics.total_intercepts += 1
    metrics.total_latency_ms += latency_ms
    metrics.by_sender[sender_id] = metrics.by_sender.get(sender_id, 0) + 1

    if status == VerdictStatus.FORWARDED:
        metrics.total_forwarded += 1
    elif status == VerdictStatus.BLOCKED:
        metrics.total_blocked += 1
    elif status == VerdictStatus.UNVERIFIABLE:
        metrics.total_unverifiable += 1
    elif status == VerdictStatus.HEURISTIC_PASS:
        metrics.total_heuristic_pass += 1
    else:
        metrics.total_errors += 1

    if engine:
        metrics.by_engine[engine] = metrics.by_engine.get(engine, 0) + 1


def trace_intercept(func: Callable) -> Callable:
    """
    Decorator that automatically traces intercept function execution time.
    Logs entry, exit, and captures exceptions to Sentry.
    """

    @functools.wraps(func)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        start = time.perf_counter()
        logger.debug("Entering %s", func.__name__)

        try:
            result = await func(*args, **kwargs)
            elapsed_ms = (time.perf_counter() - start) * 1000
            logger.debug("Exiting %s (%.2fms)", func.__name__, elapsed_ms)
            return result

        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start) * 1000
            logger.error(
                "Exception in %s after %.2fms: %s",
                func.__name__,
                elapsed_ms,
                exc,
            )
            if HAS_SENTRY:
                sentry_sdk.capture_exception(exc)
            raise

    return wrapper
