"""
QWED A2A Trust Boundary Enforcement.

Implements zero-trust execution isolation for inter-agent communication.
Manages agent allowlists, blocklists, and token-bucket rate limiting
with automatic eviction of cold pairs.
"""

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Optional, Set, Tuple


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
        # Refill tokens
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now

        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


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
        self._trusted_agents: Set[str] = set()

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
        self._trusted_agents.discard(agent_id)

    def trust_agent(self, agent_id: str) -> None:
        """Add an agent to the global allowlist (bypasses verification)."""
        self._trusted_agents.add(agent_id)
        self._blocked_agents.discard(agent_id)

    def block_pair(self, sender_id: str, receiver_id: str) -> None:
        """Block a specific agent-to-agent communication pair."""
        self._blocked_pairs.add((sender_id, receiver_id))

    def unblock_pair(self, sender_id: str, receiver_id: str) -> None:
        """Unblock a specific agent pair."""
        self._blocked_pairs.discard((sender_id, receiver_id))

    def is_trusted(self, agent_id: str) -> bool:
        """Check if an agent is on the global allowlist."""
        return agent_id in self._trusted_agents

    def _evict_cold_buckets(self, now: float) -> None:
        """Remove token buckets for pairs idle beyond the TTL."""
        if now - self._last_eviction < 60.0:
            return  # Only run eviction once per minute
        self._last_eviction = now
        cold_pairs = [
            pair for pair, bucket in self._rate_limits.items()
            if now - bucket.last_refill > self._eviction_ttl
        ]
        for pair in cold_pairs:
            del self._rate_limits[pair]

    def evaluate(
        self, sender_id: str, receiver_id: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Evaluate whether a sender->receiver communication is allowed.

        Returns:
            Tuple of (is_allowed, rejection_reason).
        """
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
            if sender_id not in self._trusted_agents:
                return False, f"Sender '{sender_id}' is not in the trust allowlist"
            if receiver_id not in self._trusted_agents:
                return False, f"Receiver '{receiver_id}' is not in the trust allowlist"

        # Token-bucket rate limiting (only reached by allowed pairs)
        now = time.monotonic()
        self._evict_cold_buckets(now)

        if pair not in self._rate_limits:
            refill_rate = self.max_requests_per_minute / 60.0
            self._rate_limits[pair] = TokenBucket(
                tokens=float(self.max_requests_per_minute),
                capacity=float(self.max_requests_per_minute),
                refill_rate=refill_rate,
                last_refill=now,
            )

        bucket = self._rate_limits[pair]
        if not bucket.consume(now):
            return False, (
                f"Rate limit exceeded for {sender_id}->{receiver_id}: "
                f"{self.max_requests_per_minute}/minute"
            )

        return True, None
