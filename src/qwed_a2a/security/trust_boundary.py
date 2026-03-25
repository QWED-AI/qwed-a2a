"""
QWED A2A Trust Boundary Enforcement.

Implements zero-trust execution isolation for inter-agent communication.
Manages agent allowlists, blocklists, and per-pair rate limiting.
"""

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Optional, Set, Tuple


@dataclass
class RateLimitEntry:
    """Tracks request counts for rate limiting."""

    count: int = 0
    window_start: float = 0.0


class TrustBoundary:
    """
    Zero-trust boundary for Agent-to-Agent communication.

    Evaluates whether a given agent pair is allowed to communicate
    based on allowlists, blocklists, and rate limits.
    """

    def __init__(
        self,
        max_requests_per_minute: int = 60,
        default_allow: bool = True,
    ):
        self.max_requests_per_minute = max_requests_per_minute
        self.default_allow = default_allow

        # Agent-level controls
        self._blocked_agents: Set[str] = set()
        self._trusted_agents: Set[str] = set()

        # Pair-level controls
        self._blocked_pairs: Set[Tuple[str, str]] = set()

        # Rate limiting per agent pair
        self._rate_limits: Dict[Tuple[str, str], RateLimitEntry] = defaultdict(
            RateLimitEntry
        )

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

        # Check rate limit
        now = time.monotonic()
        entry = self._rate_limits[pair]

        # Reset window if expired (60-second window)
        if now - entry.window_start > 60.0:
            entry.count = 0
            entry.window_start = now

        entry.count += 1

        if entry.count > self.max_requests_per_minute:
            return False, (
                f"Rate limit exceeded for {sender_id}->{receiver_id}: "
                f"{entry.count}/{self.max_requests_per_minute} per minute"
            )

        # Default policy
        if not self.default_allow:
            # In strict mode, both agents must be explicitly trusted
            if sender_id not in self._trusted_agents:
                return False, f"Sender '{sender_id}' is not in the trust allowlist"
            if receiver_id not in self._trusted_agents:
                return False, f"Receiver '{receiver_id}' is not in the trust allowlist"

        return True, None
