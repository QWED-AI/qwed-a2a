"""
QWED A2A Trust Boundary Enforcement.

Implements zero-trust execution isolation for inter-agent communication.
Manages agent allowlists, blocklists, and token-bucket rate limiting
with automatic eviction of cold pairs.
"""

import json
import re
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Set, Tuple

from qwed_a2a.utils.telemetry import logger


# CodeQL wants sanitization before logging identifiers that come from env vars.
# Agent IDs in QWED are simple [a-zA-Z0-9_-] identifiers — strip anything else.
_SAFE_ID_PATTERN = re.compile(r"[^a-zA-Z0-9_-]")


def _safe(agent_id: str) -> str:
    """Strip unsafe characters from an agent identifier for safe audit logging."""
    return _SAFE_ID_PATTERN.sub("", agent_id)


@dataclass
class TokenBucket:
    """Token-bucket rate limiter for a single agent pair."""

    tokens: float
    capacity: float
    refill_rate: float  # tokens per second
    last_refill: float = 0.0

    def consume(self, now: float) -> bool:
        """
        Try to consume one token. Returns True if allowed, False if rate-limited.
        Automatically refills tokens based on elapsed time.
        """
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now

        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


@dataclass
class TrustEntry:
    """Scoped, expiring trust grant for a single agent."""

    agent_id: str
    allowed_receivers: Optional[Set[str]] = None
    allowed_payload_types: Optional[Set[str]] = None
    valid_until: Optional[float] = None
    granted_by: str = "config"
    granted_at: float = field(default_factory=time.time)

    def is_valid(self, now: float) -> bool:
        if self.valid_until is not None and now > self.valid_until:
            return False
        return True

    def allows(self, receiver: str, payload_type: str, now: float) -> bool:
        if not self.is_valid(now):
            return False
        if (
            self.allowed_receivers is not None
            and receiver not in self.allowed_receivers
        ):
            return False
        if (
            self.allowed_payload_types is not None
            and payload_type not in self.allowed_payload_types
        ):
            return False
        return True


class TrustBoundary:
    """
    Zero-trust boundary for Agent-to-Agent communication.

    Evaluates whether a given agent pair is allowed to communicate
    based on allowlists, blocklists, and token-bucket rate limits.

    Default policy is deny-all (default_allow=False) — agents must be
    explicitly trusted or allowlisted to communicate.
    """

    def __init__(
        self,
        max_requests_per_minute: int = 60,
        default_allow: bool = False,
    ):
        self.max_requests_per_minute = max_requests_per_minute
        self.default_allow = default_allow

        # Agent-level controls
        self._blocked_agents: Set[str] = set()
        self._trusted_agents: Dict[str, TrustEntry] = {}

        # Pair-level controls
        self._blocked_pairs: Set[Tuple[str, str]] = set()

        # Token-bucket rate limiting per agent pair
        self._rate_limits: Dict[Tuple[str, str], TokenBucket] = {}

        # Eviction threshold: remove idle buckets after this many seconds
        self._eviction_ttl: float = 300.0  # 5 minutes
        self._last_eviction: float = 0.0

    def block_agent(self, agent_id: str) -> None:
        """Add an agent to the global blocklist."""
        self._blocked_agents.add(agent_id)
        self._trusted_agents.pop(agent_id, None)
        logger.warning("Agent blocked: agent=%s", _safe(agent_id))

    def trust_agent(
        self,
        agent_id: str,
        allowed_receivers: Optional[Set[str]] = None,
        allowed_payload_types: Optional[Set[str]] = None,
        valid_until: Optional[float] = None,
        granted_by: str = "config",
    ) -> None:
        """Grant scoped, expiring trust to an agent."""
        entry = TrustEntry(
            agent_id=agent_id,
            allowed_receivers=allowed_receivers,
            allowed_payload_types=allowed_payload_types,
            valid_until=valid_until,
            granted_by=granted_by,
        )
        self._trusted_agents[agent_id] = entry
        self._blocked_agents.discard(agent_id)
        safe_id = _safe(agent_id)
        logger.info(
            "Trust granted: agent=%s receivers=%s types=%s until=%s by=%s",
            safe_id,
            "scoped" if allowed_receivers else "any",
            "scoped" if allowed_payload_types else "any",
            "expires" if valid_until else "process-lifetime",
            granted_by,
        )

    def revoke_agent(self, agent_id: str, revoked_by: str = "operator") -> bool:
        """Revoke trust for an agent at runtime. Returns True if agent was trusted."""
        if agent_id in self._trusted_agents:
            del self._trusted_agents[agent_id]
            logger.warning(
                "Trust revoked: agent=%s revoked_by=%s",
                _safe(agent_id),
                revoked_by,
            )
            return True
        return False

    def block_pair(self, sender_id: str, receiver_id: str) -> None:
        """Block a specific agent-to-agent communication pair."""
        self._blocked_pairs.add((sender_id, receiver_id))

    def unblock_pair(self, sender_id: str, receiver_id: str) -> None:
        """Unblock a specific agent pair."""
        self._blocked_pairs.discard((sender_id, receiver_id))

    def is_trusted(self, agent_id: str) -> bool:
        """Check if an agent has a valid (non-expired) trust entry."""
        entry = self._trusted_agents.get(agent_id)
        if entry is None:
            return False
        if not entry.is_valid(time.time()):
            return False
        return True

    def _evict_expired_trust(self, now: float) -> None:
        """Remove expired trust entries to prevent memory leaks."""
        expired = [
            aid
            for aid, entry in self._trusted_agents.items()
            if not entry.is_valid(now)
        ]
        for aid in expired:
            del self._trusted_agents[aid]
            logger.info("Trust expired: agent=%s", _safe(aid))

    def _evict_cold_buckets(self, now: float) -> None:
        """Remove token buckets for pairs idle beyond the TTL."""
        if now - self._last_eviction < 60.0:
            return
        self._last_eviction = now
        cold_pairs = [
            pair
            for pair, bucket in self._rate_limits.items()
            if now - bucket.last_refill > self._eviction_ttl
        ]
        for pair in cold_pairs:
            del self._rate_limits[pair]

    def evaluate(
        self, sender_id: str, receiver_id: str, payload_type: Optional[str] = None
    ) -> Tuple[bool, Optional[str]]:
        """Evaluate whether a sender->receiver communication is allowed.

        Args:
            sender_id: The agent sending the message.
            receiver_id: The agent receiving the message.
            payload_type: Optional payload type for scope checking.

        Returns:
            Tuple of (is_allowed, rejection_reason).
        """
        now = time.time()

        # Evict expired trust entries before evaluation
        self._evict_expired_trust(now)

        # Check global blocklist
        if sender_id in self._blocked_agents:
            return False, f"Sender '{sender_id}' is globally blocked"

        if receiver_id in self._blocked_agents:
            return False, f"Receiver '{receiver_id}' is globally blocked"

        # Check pair-level block
        pair = (sender_id, receiver_id)
        if pair in self._blocked_pairs:
            return False, f"Communication pair {sender_id}->{receiver_id} is blocked"

        # Default policy check BEFORE rate-limit allocation (prevents map spray)
        if not self.default_allow:
            sender_entry = self._trusted_agents.get(sender_id)
            receiver_entry = self._trusted_agents.get(receiver_id)

            sender_trusted = (
                sender_entry is not None
                and sender_entry.is_valid(now)
                and (
                    payload_type is None
                    or sender_entry.allows(receiver_id, payload_type, now)
                )
                and (
                    sender_entry.allowed_receivers is None
                    or receiver_id in sender_entry.allowed_receivers
                )
            )
            receiver_trusted = receiver_entry is not None and receiver_entry.is_valid(
                now
            )

            if not sender_trusted and not receiver_trusted:
                return (
                    False,
                    f"Neither sender '{sender_id}' nor receiver '{receiver_id}' is in the trust allowlist",
                )

        # Token-bucket rate limiting (only reached by allowed pairs)
        now_mono = time.monotonic()
        self._evict_cold_buckets(now_mono)

        if pair not in self._rate_limits:
            refill_rate = self.max_requests_per_minute / 60.0
            self._rate_limits[pair] = TokenBucket(
                tokens=float(self.max_requests_per_minute),
                capacity=float(self.max_requests_per_minute),
                refill_rate=refill_rate,
                last_refill=now_mono,
            )

        bucket = self._rate_limits[pair]
        if not bucket.consume(now_mono):
            return False, (
                f"Rate limit exceeded for {sender_id}->{receiver_id}: "
                f"{self.max_requests_per_minute}/minute"
            )

        return True, None

    def _load_json_entries(self, env_value: str, granted_by: str) -> None:
        """Parse and load trust entries from a JSON array string."""
        try:
            entries = json.loads(env_value)
        except json.JSONDecodeError:
            logger.error("Failed to parse QWED_A2A_TRUSTED_AGENTS as JSON")
            return

        for item in entries:
            agent_id = item.get("agent_id", "").strip()
            if not agent_id:
                continue
            receivers = (
                set(item["allowed_receivers"])
                if item.get("allowed_receivers")
                else None
            )
            types = (
                set(item["allowed_payload_types"])
                if item.get("allowed_payload_types")
                else None
            )
            valid_until = item.get("valid_until")
            self.trust_agent(
                agent_id=agent_id,
                allowed_receivers=receivers,
                allowed_payload_types=types,
                valid_until=valid_until,
                granted_by=granted_by,
            )

    def load_from_env(self, env_value: str, granted_by: str = "env") -> None:
        """Load scoped trust entries from a JSON or comma-separated env var.

        Supports both formats:
          - Simple:  "agent-a,agent-b" (backward compat, no scope)
          - JSON:    '[{"agent_id":"agent-a","allowed_receivers":["x"]}]'
        """
        if not env_value:
            return

        stripped = env_value.strip()

        if stripped.startswith("["):
            self._load_json_entries(stripped, granted_by)
            return

        for part in stripped.split(","):
            agent_id = part.strip()
            if agent_id:
                self.trust_agent(agent_id=agent_id, granted_by=granted_by)
