"""
Tests for scoped, expiring trust boundary (issue #12).

Covers: TrustEntry, trust_agent() with scope/TTL, revoke_agent(),
        expired entries, receiver/payload_type scoping, audit logging.
"""

import logging
import time

import pytest

from qwed_a2a.security.trust_boundary import TrustBoundary, TrustEntry


class TestTrustEntry:
    """Unit tests for the TrustEntry dataclass."""

    def test_unrestricted_entry_allows_anything(self):
        """An entry with no scope allows any receiver and payload type."""
        entry = TrustEntry(agent_id="agent-a")
        now = time.time()
        assert entry.allows("receiver-x", "financial_transaction", now)
        assert entry.allows("receiver-y", "code_execution", now)

    def test_expired_entry_rejects_all(self):
        """An expired entry must reject all receivers and payload types."""
        entry = TrustEntry(
            agent_id="agent-a",
            valid_until=time.time() - 1.0,
        )
        now = time.time()
        assert not entry.is_valid(now)
        assert not entry.allows("receiver-x", "general", now)

    def test_valid_entry_with_receiver_scope(self):
        """Entry with allowed_receivers must reject out-of-scope receivers."""
        entry = TrustEntry(
            agent_id="agent-a",
            allowed_receivers={"receiver-x", "receiver-y"},
        )
        now = time.time()
        assert entry.allows("receiver-x", "general", now)
        assert entry.allows("receiver-y", "general", now)
        assert not entry.allows("receiver-z", "general", now)

    def test_valid_entry_with_payload_type_scope(self):
        """Entry with allowed_payload_types must reject out-of-scope types."""
        entry = TrustEntry(
            agent_id="agent-a",
            allowed_payload_types={"financial_transaction"},
        )
        now = time.time()
        assert entry.allows("receiver-x", "financial_transaction", now)
        assert not entry.allows("receiver-x", "code_execution", now)

    def test_combined_scope(self):
        """Entry with both receiver and type scope must check both."""
        entry = TrustEntry(
            agent_id="agent-a",
            allowed_receivers={"ledger-agent"},
            allowed_payload_types={"financial_transaction"},
        )
        now = time.time()
        # Correct receiver + correct type = allowed
        assert entry.allows("ledger-agent", "financial_transaction", now)
        # Correct receiver + wrong type = rejected
        assert not entry.allows("ledger-agent", "code_execution", now)
        # Wrong receiver + correct type = rejected
        assert not entry.allows("payments-agent", "financial_transaction", now)


class TestTrustBoundaryScopedTrust:
    """Tests for the TrustBoundary scoped trust methods."""

    def test_trust_agent_no_scope(self):
        """trust_agent() with no scope params creates unrestricted entry."""
        tb = TrustBoundary(default_allow=False)
        tb.trust_agent("agent-a")
        assert tb.is_trusted("agent-a")

    def test_trust_agent_with_scope(self):
        """trust_agent() with allowed_receivers creates scoped entry."""
        tb = TrustBoundary(default_allow=False)
        tb.trust_agent(
            "agent-a",
            allowed_receivers={"ledger-agent"},
            allowed_payload_types={"financial_transaction"},
        )
        # Sender trusted + matching receiver scope = allowed
        allowed, reason = tb.evaluate(
            "agent-a", "ledger-agent", payload_type="financial_transaction"
        )
        assert allowed

        # Sender trusted + mismatched payload type = blocked (rejected by scope)
        allowed, reason = tb.evaluate(
            "agent-a", "ledger-agent", payload_type="code_execution"
        )
        assert not allowed

    def test_expired_trust_does_not_bypass(self):
        """Expired trust entry must not allow communication."""
        tb = TrustBoundary(default_allow=False)
        tb.trust_agent(
            "agent-a",
            valid_until=time.time() - 1.0,
        )
        allowed, reason = tb.evaluate("agent-a", "receiver-x")
        assert not allowed
        assert "trust allowlist" in reason.lower()

    def test_revoke_agent_removes_trust(self):
        """revoke_agent() must immediately remove the trust entry."""
        tb = TrustBoundary(default_allow=False)
        tb.trust_agent("agent-a")
        assert tb.is_trusted("agent-a")

        result = tb.revoke_agent("agent-a")
        assert result is True
        assert not tb.is_trusted("agent-a")

        allowed, reason = tb.evaluate("agent-a", "receiver-x")
        assert not allowed

    def test_revoke_nonexistent_agent_returns_false(self):
        """revoke_agent() on an untrusted agent must return False."""
        tb = TrustBoundary(default_allow=False)
        assert tb.revoke_agent("ghost-agent") is False

    def test_block_agent_removes_trust(self):
        """block_agent() must also remove any trust entry."""
        tb = TrustBoundary(default_allow=False)
        tb.trust_agent("agent-a")
        tb.block_agent("agent-a")
        assert not tb.is_trusted("agent-a")
        allowed, reason = tb.evaluate("agent-a", "receiver-x")
        assert not allowed
        assert "blocked" in reason.lower()

    def test_evict_expired_trust_cleans_up(self):
        """Expired trust entries must be automatically evicted on evaluate()."""
        tb = TrustBoundary(default_allow=False)
        tb.trust_agent(
            "agent-a",
            valid_until=time.time() - 1.0,
        )
        tb.trust_agent(
            "agent-b",
            valid_until=time.time() + 3600.0,
        )
        # Trigger eviction
        tb.evaluate("agent-b", "receiver-y")
        assert "agent-a" not in tb._trusted_agents
        assert "agent-b" in tb._trusted_agents

    def test_scoped_trust_with_unrestricted_receiver(self):
        """Entry with allowed_payload_types but no receiver scope works."""
        tb = TrustBoundary(default_allow=False)
        tb.trust_agent(
            "agent-a",
            allowed_payload_types={"financial_transaction"},
        )
        allowed, reason = tb.evaluate(
            "agent-a", "any-receiver", payload_type="financial_transaction"
        )
        assert allowed


class TestTrustBoundaryLoadFromEnv:
    """Tests for load_from_env()."""

    def test_simple_format_backward_compat(self):
        """Simple comma-separated format must create unrestricted entries."""
        tb = TrustBoundary(default_allow=False)
        tb.load_from_env("agent-a,agent-b")
        assert tb.is_trusted("agent-a")
        assert tb.is_trusted("agent-b")

    def test_json_format_scoped(self):
        """JSON format must create scoped trust entries."""
        tb = TrustBoundary(default_allow=False)
        tb.load_from_env(
            '[{"agent_id":"agent-a","allowed_receivers":["receiver-x"]}]'
        )
        allowed, reason = tb.evaluate("agent-a", "receiver-x")
        assert allowed
        allowed, reason = tb.evaluate("agent-a", "receiver-y")
        assert not allowed

    def test_json_format_with_payload_types(self):
        """JSON format with allowed_payload_types must scope by type."""
        tb = TrustBoundary(default_allow=False)
        tb.load_from_env(
            '[{"agent_id":"agent-a","allowed_payload_types":["financial_transaction"]}]'
        )
        allowed, reason = tb.evaluate(
            "agent-a", "receiver-x", payload_type="financial_transaction"
        )
        assert allowed
        allowed, reason = tb.evaluate(
            "agent-a", "receiver-x", payload_type="code_execution"
        )
        assert not allowed

    def test_json_format_with_expiry(self):
        """JSON format with valid_until must create expiring trust."""
        tb = TrustBoundary(default_allow=False)
        tb.load_from_env(
            '[{"agent_id":"agent-a","valid_until":1.0}]'
        )
        allowed, reason = tb.evaluate("agent-a", "receiver-x")
        assert not allowed

    def test_empty_env_does_nothing(self):
        """Empty string must not register any trust."""
        tb = TrustBoundary(default_allow=False)
        tb.load_from_env("")
        assert not tb.is_trusted("any-agent")

    def test_invalid_json_logs_error(self, caplog):
        """Invalid JSON must be logged as error, not crash."""
        tb = TrustBoundary(default_allow=False)
        with caplog.at_level(logging.ERROR):
            tb.load_from_env("[invalid")
            assert "Failed to parse" in caplog.text

    def test_non_object_json_entries_skipped(self, caplog):
        """Non-dict entries in JSON array must be skipped, not crash."""
        tb = TrustBoundary(default_allow=False)
        with caplog.at_level(logging.WARNING):
            tb.load_from_env('["agent-a", {"agent_id":"agent-b"}]')
        assert not tb.is_trusted("agent-a")
        assert tb.is_trusted("agent-b")

    def test_string_scope_skips_entry(self, caplog):
        """String value for allowed_receivers must skip the entry, not split."""
        tb = TrustBoundary(default_allow=False)
        with caplog.at_level(logging.ERROR):
            tb.load_from_env(
                '[{"agent_id":"agent-a","allowed_receivers":"receiver-x"}]'
            )
        assert not tb.is_trusted("agent-a")

    def test_string_valid_until_float_conversion(self):
        """String valid_until must be converted to float, not crash."""
        tb = TrustBoundary(default_allow=False)
        tb.load_from_env(
            '[{"agent_id":"agent-a","valid_until":"0.1"}]'
        )
        # Entry was created with valid_until=0.1
        assert tb.is_trusted("agent-a", now=0.0)
        # Entry is expired after 0.1
        allowed, reason = tb.evaluate("agent-a", "receiver-x")
        assert not allowed

    def test_non_numeric_valid_until_skips_entry(self, caplog):
        """Non-numeric string valid_until must skip entry entirely, not crash."""
        tb = TrustBoundary(default_allow=False)
        with caplog.at_level(logging.ERROR):
            tb.load_from_env(
                '[{"agent_id":"agent-a","valid_until":"not-a-number"}]'
            )
        assert not tb.is_trusted("agent-a")
        # Entry was skipped, agent is not trusted


class TestTrustBoundaryProperties:
    """Tests for public properties."""

    def test_trusted_agent_count(self):
        """trusted_agent_count must reflect number of trusted agents."""
        tb = TrustBoundary(default_allow=False)
        assert tb.trusted_agent_count == 0
        tb.trust_agent("agent-a")
        assert tb.trusted_agent_count == 1
        tb.trust_agent("agent-b")
        assert tb.trusted_agent_count == 2
        tb.revoke_agent("agent-a")
        assert tb.trusted_agent_count == 1

    def test_is_trusted_with_explicit_now(self):
        """is_trusted() must accept optional now parameter."""
        tb = TrustBoundary(default_allow=False)
        tb.trust_agent("agent-a", valid_until=100.0)
        assert tb.is_trusted("agent-a", now=50.0)
        assert not tb.is_trusted("agent-a", now=200.0)

    def test_is_trusted_without_now_defaults_to_wall_clock(self):
        """is_trusted() without now must use time.time()."""
        tb = TrustBoundary(default_allow=False)
        tb.trust_agent("agent-a")
        assert tb.is_trusted("agent-a")


class TestTrustBoundaryEvaluate:
    """Tests for the evaluate() method with scoped trust."""

    def test_untrusted_sender_blocked(self):
        """Sender not in any trust entry must be blocked."""
        tb = TrustBoundary(default_allow=False)
        allowed, reason = tb.evaluate("unknown-agent", "receiver-x")
        assert not allowed
        assert "trust allowlist" in reason.lower()

    def test_trusted_sender_allows_communication(self):
        """Trusted sender + any receiver = allowed (unrestricted by default)."""
        tb = TrustBoundary(default_allow=False)
        tb.trust_agent("agent-a")
        allowed, reason = tb.evaluate("agent-a", "any-receiver")
        assert allowed

    def test_trusted_receiver_allows_communication(self):
        """Trusted receiver also allows the communication."""
        tb = TrustBoundary(default_allow=False)
        tb.trust_agent("receiver-x")
        allowed, reason = tb.evaluate("unknown-sender", "receiver-x")
        assert allowed

    def test_payload_type_scope_on_evaluate(self):
        """Payload type scope must be enforced in evaluate()."""
        tb = TrustBoundary(default_allow=False)
        tb.trust_agent(
            "agent-a",
            allowed_payload_types={"financial_transaction"},
        )
        # Matching payload type → allowed
        allowed, reason = tb.evaluate(
            "agent-a", "receiver-x", payload_type="financial_transaction"
        )
        assert allowed
        # Wrong payload type → blocked
        allowed, reason = tb.evaluate(
            "agent-a", "receiver-x", payload_type="code_execution"
        )
        assert not allowed

    def test_evaluate_without_payload_type_defaults_to_unrestricted(self):
        """evaluate() without payload_type must not apply type scoping."""
        tb = TrustBoundary(default_allow=False)
        tb.trust_agent("agent-a", allowed_payload_types={"financial_transaction"})
        # When payload_type is None, type scope is bypassed → allowed
        allowed, reason = tb.evaluate("agent-a", "receiver-x")
        assert allowed

    def test_scoped_receiver_with_untrusted_sender(self):
        """Receiver scope must also be enforced when receiver_trusted."""
        tb = TrustBoundary(default_allow=False)
        tb.trust_agent("receiver-x", allowed_payload_types={"financial_transaction"})
        # Untrusted sender sending non-matching payload type to scoped receiver = blocked
        allowed, reason = tb.evaluate(
            "unknown-sender", "receiver-x", payload_type="code_execution"
        )
        assert not allowed
        # Untrusted sender sending matching payload type to scoped receiver = allowed
        allowed, reason = tb.evaluate(
            "unknown-sender", "receiver-x", payload_type="financial_transaction"
        )
        assert allowed