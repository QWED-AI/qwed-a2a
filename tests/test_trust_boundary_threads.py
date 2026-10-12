"""
TrustBoundary under concurrent threads (#133).

The boundary is shared by every request on an interceptor. Threaded callers
(sync frameworks running intercept per thread, admin threads calling
trust/revoke) used to interleave the token-bucket read-modify-write, so a
pair could be admitted past its rate limit. Every public method now runs
under the instance lock, and trust scopes are snapshotted at grant time.

Threads are daemons joined with a timeout, so a locking regression that
deadlocks fails the test instead of hanging the run.
"""

import sys
import threading
import time
from types import SimpleNamespace

import pytest

from qwed_a2a.security import trust_boundary as trust_module
from qwed_a2a.security.trust_boundary import TrustBoundary

JOIN_TIMEOUT = 10.0


@pytest.fixture
def tight_switching():
    """Force frequent thread switches so unsynchronized code interleaves."""
    previous = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    yield
    sys.setswitchinterval(previous)


@pytest.fixture
def frozen_clock(monkeypatch):
    """Stop the token buckets from refilling mid-test, so the admitted
    count measures concurrent consumption, not runner speed."""
    now, mono = time.time(), time.monotonic()
    monkeypatch.setattr(
        trust_module, "time", SimpleNamespace(time=lambda: now, monotonic=lambda: mono)
    )


def _run_concurrently(targets):
    start = threading.Event()

    def wrap(fn):
        def run():
            start.wait()
            fn()

        return run

    threads = [threading.Thread(target=wrap(fn), daemon=True) for fn in targets]
    for t in threads:
        t.start()
    start.set()
    for t in threads:
        t.join(JOIN_TIMEOUT)
    hung = [t for t in threads if t.is_alive()]
    assert not hung, f"{len(hung)} thread(s) still running: possible deadlock"


@pytest.mark.parametrize("trial", range(5))
def test_rate_limit_not_exceeded_under_concurrency(
    tight_switching, frozen_clock, trial
):
    """16 threads x 20 requests on one pair: exactly `capacity` admitted."""
    capacity = 50
    boundary = TrustBoundary(max_requests_per_minute=capacity, default_allow=True)
    admitted = []
    lock = threading.Lock()

    def hammer():
        for _ in range(20):
            ok, _ = boundary.evaluate("agent-a", "agent-b")
            if ok:
                with lock:
                    admitted.append(1)

    _run_concurrently([hammer] * 16)
    assert len(admitted) == capacity


def test_concurrent_mutation_and_evaluation(tight_switching):
    """Trust grants, expiry eviction, revocation and bucket allocation from
    several threads at once raise nothing and leave consistent state."""
    boundary = TrustBoundary(max_requests_per_minute=1000, default_allow=True)
    errors = []

    def guard(fn):
        def run():
            try:
                fn()
            except Exception as exc:  # noqa: BLE001 - surfaced via assertion
                errors.append(repr(exc))

        return run

    def churn_trust():
        for k in range(300):
            boundary.trust_agent(f"expired-{k}", valid_until=time.time() - 1)
            boundary.trust_agent(f"live-{k}")
            boundary.revoke_agent(f"live-{k}")

    def churn_pairs():
        for k in range(300):
            boundary.evaluate(f"s{k}", f"r{k}")
            boundary.block_pair(f"s{k}", f"r{k}")
            boundary.unblock_pair(f"s{k}", f"r{k}")

    def read_state():
        for _ in range(300):
            assert boundary.trusted_agent_count >= 0
            boundary.is_trusted("live-1")

    _run_concurrently([guard(churn_trust), guard(churn_pairs), guard(read_state)] * 2)
    assert errors == []
    assert boundary.trusted_agent_count == 0


def test_load_from_env_is_reentrant():
    """load_from_env holds the lock and calls trust_agent, which takes it
    again: the lock must be re-entrant (run in a joined thread so a
    deadlock fails instead of hanging)."""
    boundary = TrustBoundary()
    _run_concurrently([lambda: boundary.load_from_env("agent-x,agent-y")])
    assert boundary.is_trusted("agent-x")
    assert boundary.is_trusted("agent-y")


def test_scope_is_snapshotted_at_grant():
    """Mutating the caller's set after trust_agent does not change the grant
    (it would otherwise bypass the boundary's lock)."""
    boundary = TrustBoundary(default_allow=False)
    receivers = {"agent-b"}
    boundary.trust_agent("agent-a", allowed_receivers=receivers)

    receivers.add("agent-evil")
    receivers.discard("agent-b")

    assert boundary.evaluate("agent-a", "agent-b")[0] is True
    assert boundary.evaluate("agent-a", "agent-evil")[0] is False
