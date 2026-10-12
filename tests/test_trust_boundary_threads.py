"""
TrustBoundary under concurrent threads (#133).

The boundary is shared by every request on an interceptor. Threaded callers
(sync frameworks running intercept per thread, admin threads calling
trust/revoke) used to interleave the token-bucket read-modify-write, so a
pair could be admitted past its rate limit. Every public method now runs
under the instance lock.
"""

import sys
import threading
import time

import pytest

from qwed_a2a.security.trust_boundary import TrustBoundary


@pytest.fixture
def tight_switching():
    """Force frequent thread switches so unsynchronized code interleaves."""
    previous = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    yield
    sys.setswitchinterval(previous)


def _run_concurrently(targets):
    start = threading.Event()

    def wrap(fn):
        def run():
            start.wait()
            fn()

        return run

    threads = [threading.Thread(target=wrap(fn)) for fn in targets]
    for t in threads:
        t.start()
    start.set()
    for t in threads:
        t.join()


@pytest.mark.parametrize("trial", range(5))
def test_rate_limit_not_exceeded_under_concurrency(tight_switching, trial):
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
    again: the lock must be re-entrant."""
    boundary = TrustBoundary()
    boundary.load_from_env("agent-x,agent-y")
    assert boundary.is_trusted("agent-x")
    assert boundary.is_trusted("agent-y")
