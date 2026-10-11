"""
QWED A2A Protocol Schema Definitions.

Pydantic models enforcing typed contracts for Agent-to-Agent payloads.
All inter-agent messages MUST conform to these schemas before processing.
"""

import logging
import warnings
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, computed_field, field_validator

logger = logging.getLogger("qwed_a2a")


class PayloadType(str, Enum):
    """Supported agent payload categories for verification routing."""

    FINANCIAL_TRANSACTION = "financial_transaction"
    LOGIC_ASSERTION = "logic_assertion"
    CODE_EXECUTION = "code_execution"
    DATA_QUERY = "data_query"
    GENERAL = "general"


class VerdictStatus(str, Enum):
    """Possible outcomes of interceptor verification (#13).

    The states are NOT interchangeable, and only ``VERIFIED`` is admissible
    (see ``admissible`` / ``ADMISSIBLE_VERDICTS``):

    - VERIFIED: a deterministic engine (finance guard) recomputed the
      claims and they checked out. The only admissible outcome.
    - HEURISTIC_PASS: a heuristic check found no problem — code guard's
      AST/regex scan, or logic guard's normalized P/not-P string match.
      Not a proof, and not admissible.
    - UNVERIFIABLE: no engine could assess the payload (no engine for the
      type, or required fields missing). Unsigned; not admissible.
    - BLOCKED: verification failed or the trust boundary refused the
      message. Not admissible.
    - ERROR: the engine crashed before verification completed (possibly
      after partially processing the payload), so no outcome exists. Fail
      closed; not admissible.

    ``FORWARDED`` is a deprecated alias of ``VERIFIED`` (same member), and
    the legacy wire value ``"forwarded"`` still parses to ``VERIFIED`` so
    tokens minted by 0.3.x issuers keep verifying here. Both will be
    removed in a future minor release.
    """

    VERIFIED = "verified"
    BLOCKED = "blocked"
    UNVERIFIABLE = "unverifiable"
    HEURISTIC_PASS = "heuristic_pass"
    ERROR = "error"
    FORWARDED = "verified"  # noqa: PIE796 - deprecated alias (#13)

    @classmethod
    def _missing_(cls, value: object) -> "VerdictStatus | None":
        if value == LEGACY_FORWARDED_VALUE:
            return cls.VERIFIED
        return None

    @property
    def admissible(self) -> bool:
        """True only for outcomes a consumer may act on without its own checks."""
        return self in ADMISSIBLE_VERDICTS


# Pre-#13 wire value of VERIFIED, accepted on input only — never emitted.
LEGACY_FORWARDED_VALUE = "forwarded"

# The one place admissibility is defined. Consumers must gate on this (or
# ``VerdictStatus.admissible``), never on ``status != BLOCKED``: that lazy
# check admits HEURISTIC_PASS, UNVERIFIABLE and ERROR.
ADMISSIBLE_VERDICTS: frozenset[VerdictStatus] = frozenset({VerdictStatus.VERIFIED})


class AgentMessage(BaseModel):
    """
    Typed contract for an Agent-to-Agent message payload.

    Every message entering the interceptor MUST be validated against this schema.
    """

    sender_agent_id: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description=(
            "Unique identifier of the sending agent. Over HTTP, the "
            "authenticated API-key identity overrides this value — never "
            "trust it from the wire. Direct library callers own identity "
            "binding: do not pass untrusted IDs."
        ),
    )
    receiver_agent_id: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="Unique identifier of the receiving agent",
    )
    payload_type: PayloadType = Field(
        default=PayloadType.GENERAL, description="Classification of the payload content"
    )
    payload: dict[str, Any] = Field(
        ..., description="The actual data payload to be verified"
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="ISO 8601 timestamp of message creation",
    )
    metadata: dict[str, Any] | None = Field(
        default=None,
        description="Optional metadata (correlation IDs, trace context, etc.)",
    )

    @field_validator("sender_agent_id", "receiver_agent_id")
    @classmethod
    def validate_agent_id_format(cls, v: str) -> str:
        """Agent IDs must not contain control characters."""
        if any(ord(c) < 32 for c in v):
            raise ValueError("Agent ID must not contain control characters")
        return v.strip()


class VerificationVerdict(BaseModel):
    """
    Structured result returned by the interceptor after verification.
    """

    status: VerdictStatus = Field(
        ..., description="Verification outcome; see VerdictStatus for each state"
    )
    reason: str | None = Field(
        default=None, description="Human-readable explanation for blocking"
    )
    audit_trace_id: str = Field(
        ..., description="Unique trace ID for this verification event"
    )
    attestation_jwt: str | None = Field(
        default=None,
        description="Signed JWT attestation proving the verification took place",
    )
    engine_used: str | None = Field(
        default=None, description="Which verification engine handled the check"
    )
    verified_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp of the verification",
    )
    details: dict[str, Any] | None = Field(
        default=None, description="Raw verification engine output"
    )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def admissible(self) -> bool:
        """Whether the receiver may act on the message (#13).

        Derived from ``status`` alone, so it cannot disagree with it, and
        serialised with the verdict so HTTP consumers get it too.
        """
        return self.status.admissible


class InterceptorConfig(BaseModel):
    """
    Runtime configuration for the A2A interceptor.
    """

    enable_financial_verification: bool = Field(
        default=True, description="Route financial payloads to math verification"
    )
    enable_logic_verification: bool = Field(
        default=True, description="Route logic assertions to Z3-style checks"
    )
    enable_code_verification: bool = Field(
        default=True, description="Route code payloads to AST security scanning"
    )
    block_on_error: bool = Field(
        default=True,
        description=(
            "Deprecated, no effect: engine errors always fail closed with an "
            "ERROR verdict (#38). Kept for config compatibility; removal "
            "tracked in #15."
        ),
    )
    max_payload_size_bytes: int = Field(
        default=1_048_576,
        ge=1024,
        le=10_485_760,
        description="Maximum payload size (1MB default)",
    )
    trusted_agents: list[str] | None = Field(
        default=None,
        description=(
            "Agent IDs pre-added to the trust boundary allowlist. Trusted "
            "agents are still verified — trust never skips an engine (#5)."
        ),
    )

    @field_validator("block_on_error")
    @classmethod
    def warn_block_on_error_ignored(cls, v: bool) -> bool:
        """block_on_error=False used to fail open; say so loudly that it no longer does.

        Warned AND logged: DeprecationWarning is hidden by default outside
        __main__, but a deployment relying on the old fail-open must see
        it in its logs. stacklevel=3 skips this validator and pydantic's
        BaseModel.__init__/model_validate to land on the caller.
        """
        if v is False:
            message = (
                "InterceptorConfig.block_on_error is deprecated and ignored: "
                "engine errors always fail closed with an ERROR verdict."
            )
            warnings.warn(message, DeprecationWarning, stacklevel=3)
            logger.warning(message)
        return v
