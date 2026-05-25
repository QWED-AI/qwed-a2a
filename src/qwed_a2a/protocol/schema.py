"""
QWED A2A Protocol Schema Definitions.

Pydantic models enforcing typed contracts for Agent-to-Agent payloads.
All inter-agent messages MUST conform to these schemas before processing.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class PayloadType(str, Enum):
    """Supported agent payload categories for verification routing."""

    FINANCIAL_TRANSACTION = "financial_transaction"
    LOGIC_ASSERTION = "logic_assertion"
    CODE_EXECUTION = "code_execution"
    DATA_QUERY = "data_query"
    GENERAL = "general"


class VerdictStatus(str, Enum):
    """Possible outcomes of interceptor verification."""

    FORWARDED = "forwarded"
    BLOCKED = "blocked"
    UNVERIFIABLE = "unverifiable"
    ERROR = "error"


class AgentMessage(BaseModel):
    """
    Typed contract for an Agent-to-Agent message payload.

    Every message entering the interceptor MUST be validated against this schema.
    """

    sender_agent_id: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="Unique identifier of the sending agent",
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
    payload: Dict[str, Any] = Field(
        ..., description="The actual data payload to be verified"
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="ISO 8601 timestamp of message creation",
    )
    signature: Optional[str] = Field(
        default=None,
        description="Optional JWT signature from the sender for tamper detection",
    )
    metadata: Optional[Dict[str, Any]] = Field(
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
        ..., description="Whether the message was forwarded or blocked"
    )
    reason: Optional[str] = Field(
        default=None, description="Human-readable explanation for blocking"
    )
    audit_trace_id: str = Field(
        ..., description="Unique trace ID for this verification event"
    )
    attestation_jwt: Optional[str] = Field(
        default=None,
        description="Signed JWT attestation proving the verification took place",
    )
    engine_used: Optional[str] = Field(
        default=None, description="Which verification engine handled the check"
    )
    verified_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp of the verification",
    )
    details: Optional[Dict[str, Any]] = Field(
        default=None, description="Raw verification engine output"
    )


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
        description="Block forwarding if verification encounters an internal error",
    )
    max_payload_size_bytes: int = Field(
        default=1_048_576,
        ge=1024,
        le=10_485_760,
        description="Maximum payload size (1MB default)",
    )
    trusted_agents: Optional[List[str]] = Field(
        default=None, description="Allowlist of agent IDs that bypass verification"
    )
