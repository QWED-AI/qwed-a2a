"""
Engine execution budget (#122).

Engines run on a dedicated thread pool, off the event loop, under a
wall-clock budget (``engine_timeout_seconds``). A run that exceeds it fails
closed with ERROR; the loop — health, metrics, JWKS, other intercepts —
stays responsive while an engine is busy.
"""

import asyncio
import decimal
import json
import threading
import time

import httpx
import pytest
from pydantic import ValidationError

from qwed_a2a import interceptor as interceptor_module
from qwed_a2a.interceptor import A2AVerificationInterceptor
from qwed_a2a.protocol import endpoints as ep
from qwed_a2a.protocol.schema import InterceptorConfig, VerdictStatus
from qwed_a2a.security.crypto import AttestationContext
from qwed_a2a.utils.telemetry import get_metrics


class TestConfig:
    def test_default_is_five_seconds(self):
        assert InterceptorConfig().engine_timeout_seconds == 5.0

    @pytest.mark.parametrize("value", [0.1, 1, 60])
    def test_accepts_range(self, value):
        assert (
            InterceptorConfig(engine_timeout_seconds=value).engine_timeout_seconds
            == value
        )

    @pytest.mark.parametrize("value", [0, -1, 60.01, 3600])
    def test_rejects_out_of_range(self, value):
        with pytest.raises(ValidationError):
            InterceptorConfig(engine_timeout_seconds=value)


def _make(crypto_service, trust_boundary, timeout):
    return A2AVerificationInterceptor(
        config=InterceptorConfig(engine_timeout_seconds=timeout),
        crypto_service=crypto_service,
        trust_boundary=trust_boundary,
    )


def _slow_engine(seconds, seen=None):
    def engine(_message):
        if seen is not None:
            seen.append(threading.current_thread().name)
        time.sleep(seconds)
        return {"verified": True, "engine": "finance_guard"}

    return engine


@pytest.mark.asyncio
class TestTimeout:
    async def test_timeout_fails_closed_with_error(
        self, crypto_service, trust_boundary, valid_financial_message, monkeypatch
    ):
        icpt = _make(crypto_service, trust_boundary, timeout=0.2)
        monkeypatch.setattr(icpt, "_route_to_engine", _slow_engine(1.0))

        start = time.perf_counter()
        v = await icpt.intercept(valid_financial_message, trace_id="t_budget_to")
        elapsed = time.perf_counter() - start

        assert elapsed < 0.8, "the verdict must not wait for the engine to finish"
        assert v.status == VerdictStatus.ERROR
        assert v.engine_used == "engine_timeout"
        assert "timed out after 0.2s" in v.reason
        assert v.admissible is False

        ok, claims, err = crypto_service.verify_attestation(
            v.attestation_jwt,
            AttestationContext(
                valid_financial_message.sender_agent_id,
                valid_financial_message.receiver_agent_id,
                valid_financial_message.payload,
            ),
        )
        assert ok is True, err
        assert claims["qwed_a2a"]["verdict"] == "error"
        assert get_metrics().total_errors == 1

    async def test_engine_raised_timeout_error_is_an_engine_error(
        self, crypto_service, trust_boundary, valid_financial_message, monkeypatch
    ):
        """A TimeoutError raised by the engine itself is not the budget
        running out: it is reported as an engine error."""
        icpt = _make(crypto_service, trust_boundary, timeout=5.0)

        def engine(_message):
            raise TimeoutError("engine-internal")

        monkeypatch.setattr(icpt, "_route_to_engine", engine)
        v = await icpt.intercept(valid_financial_message, trace_id="t_own_to")
        assert v.status == VerdictStatus.ERROR
        assert v.engine_used == "error_handler"
        assert v.reason == "Verification engine raised TimeoutError - fail closed"

    async def test_within_budget_completes(
        self, crypto_service, trust_boundary, valid_financial_message
    ):
        icpt = _make(crypto_service, trust_boundary, timeout=5.0)
        v = await icpt.intercept(valid_financial_message, trace_id="t_budget_ok")
        assert v.status == VerdictStatus.VERIFIED

    async def test_saturated_pool_fails_closed_without_hanging(
        self, crypto_service, trust_boundary, valid_financial_message, monkeypatch
    ):
        """More slow runs than pool threads: queued runs also time out (fail
        closed) instead of hanging the caller."""
        icpt = _make(crypto_service, trust_boundary, timeout=0.2)
        monkeypatch.setattr(icpt, "_route_to_engine", _slow_engine(0.6))
        n = interceptor_module._ENGINE_WORKERS + 2

        start = time.perf_counter()
        verdicts = await asyncio.gather(
            *(
                icpt.intercept(valid_financial_message, trace_id=f"t_budget_sat_{i}")
                for i in range(n)
            )
        )
        assert time.perf_counter() - start < 1.0
        assert all(v.status == VerdictStatus.ERROR for v in verdicts)


@pytest.mark.asyncio
class TestOffLoop:
    async def test_engine_runs_on_dedicated_pool(
        self, crypto_service, trust_boundary, valid_financial_message, monkeypatch
    ):
        seen = []
        icpt = _make(crypto_service, trust_boundary, timeout=5.0)
        monkeypatch.setattr(icpt, "_route_to_engine", _slow_engine(0, seen))
        await icpt.intercept(valid_financial_message, trace_id="t_budget_thread")
        assert seen
        assert seen[0].startswith("qwed-a2a-engine")
        assert seen[0] != threading.main_thread().name

    async def test_loop_stays_responsive_during_engine_run(
        self, crypto_service, trust_boundary, valid_financial_message, monkeypatch
    ):
        icpt = _make(crypto_service, trust_boundary, timeout=5.0)
        monkeypatch.setattr(icpt, "_route_to_engine", _slow_engine(0.5))
        ticks = 0

        async def ticker():
            nonlocal ticks
            while True:
                await asyncio.sleep(0.01)
                ticks += 1

        task = asyncio.create_task(ticker())
        try:
            await icpt.intercept(valid_financial_message, trace_id="t_budget_tick")
        finally:
            task.cancel()
        # A blocking engine would allow ~0 ticks in that 0.5 s.
        assert ticks >= 20

    async def test_decimal_context_reaches_engine(
        self, crypto_service, trust_boundary, valid_financial_message, monkeypatch
    ):
        """The caller's context is copied into the engine thread, as
        asyncio.to_thread does."""
        seen = []

        def engine(_message):
            seen.append(decimal.getcontext().prec)
            return {"verified": True, "engine": "finance_guard"}

        icpt = _make(crypto_service, trust_boundary, timeout=5.0)
        monkeypatch.setattr(icpt, "_route_to_engine", engine)
        with decimal.localcontext() as ctx:
            ctx.prec = 41
            await icpt.intercept(valid_financial_message, trace_id="t_budget_ctx")
        assert seen == [41]

    async def test_loop_responsive_under_cpu_bound_engines(
        self, crypto_service, trust_boundary, valid_financial_message, monkeypatch
    ):
        """Pure-Python CPU work (holds the GIL between switch intervals) on
        every pool thread still leaves the loop ticking; a blocking engine
        would allow ~0 ticks."""

        def busy(_message):
            end = time.perf_counter() + 0.4
            while time.perf_counter() < end:
                sum(range(200))
            return {"verified": True, "engine": "finance_guard"}

        icpt = _make(crypto_service, trust_boundary, timeout=5.0)
        monkeypatch.setattr(icpt, "_route_to_engine", busy)
        ticks = 0

        async def ticker():
            nonlocal ticks
            while True:
                await asyncio.sleep(0.01)
                ticks += 1

        task = asyncio.create_task(ticker())
        try:
            verdicts = await asyncio.gather(
                *(
                    icpt.intercept(valid_financial_message, trace_id=f"t_cpu_{i}")
                    for i in range(interceptor_module._ENGINE_WORKERS)
                )
            )
        finally:
            task.cancel()
        assert all(v.status == VerdictStatus.VERIFIED for v in verdicts)
        assert ticks >= 5


@pytest.mark.asyncio
class TestBoundedQueue:
    async def test_over_capacity_refused_immediately(
        self, crypto_service, trust_boundary, valid_financial_message, monkeypatch
    ):
        """With every slot taken, a further run is refused at once (fail
        closed) instead of being queued without bound."""
        monkeypatch.setattr(interceptor_module, "_ENGINE_QUEUE", 0)
        icpt = _make(crypto_service, trust_boundary, timeout=5.0)
        monkeypatch.setattr(icpt, "_route_to_engine", _slow_engine(0.4))
        workers = interceptor_module._ENGINE_WORKERS

        busy = [
            asyncio.create_task(
                icpt.intercept(valid_financial_message, trace_id=f"t_busy_{i}")
            )
            for i in range(workers)
        ]
        await asyncio.sleep(0.05)  # let them take every slot
        start = time.perf_counter()
        refused = await icpt.intercept(valid_financial_message, trace_id="t_busy_x")
        assert time.perf_counter() - start < 0.2
        assert refused.status == VerdictStatus.ERROR
        assert refused.engine_used == "engine_busy"
        assert refused.admissible is False

        done = await asyncio.gather(*busy)
        assert all(v.status == VerdictStatus.VERIFIED for v in done)

    async def test_abandoned_queued_run_is_skipped_and_slot_freed(
        self, crypto_service, trust_boundary, valid_financial_message, monkeypatch
    ):
        """A queued run whose caller timed out never executes, and every slot
        returns once the pool drains (no leak)."""
        monkeypatch.setattr(interceptor_module, "_ENGINE_QUEUE", 1)
        icpt = _make(crypto_service, trust_boundary, timeout=0.1)
        calls = []

        def engine(_message):
            calls.append(1)
            time.sleep(0.4)
            return {"verified": True, "engine": "finance_guard"}

        monkeypatch.setattr(icpt, "_route_to_engine", engine)
        workers = interceptor_module._ENGINE_WORKERS
        verdicts = await asyncio.gather(
            *(
                icpt.intercept(valid_financial_message, trace_id=f"t_abandon_{i}")
                for i in range(workers + 1)
            )
        )
        assert all(v.engine_used == "engine_timeout" for v in verdicts)

        await asyncio.sleep(0.6)  # let the running engines finish
        assert len(calls) == workers  # the queued, abandoned run was skipped
        capacity = workers + 1
        for _ in range(capacity):
            assert icpt._engine_slots.acquire(blocking=False)
        assert not icpt._engine_slots.acquire(blocking=False)

    async def test_closed_interceptor_fails_closed(
        self, crypto_service, trust_boundary, valid_financial_message
    ):
        icpt = _make(crypto_service, trust_boundary, timeout=5.0)
        icpt.close()
        v = await icpt.intercept(valid_financial_message, trace_id="t_closed")
        assert v.status == VerdictStatus.ERROR
        assert v.admissible is False
        # The refused submit returned its slot.
        capacity = interceptor_module._ENGINE_WORKERS + interceptor_module._ENGINE_QUEUE
        for _ in range(capacity):
            assert icpt._engine_slots.acquire(blocking=False)

    async def test_late_engine_error_is_consumed_and_logged_by_type(
        self, crypto_service, trust_boundary, valid_financial_message, caplog
    ):
        """An engine that raises after its caller timed out must not surface
        as asyncio's "exception was never retrieved"; it is logged by type
        only (the message may echo payload data)."""
        import gc
        import logging

        reported = []
        loop = asyncio.get_running_loop()
        previous = loop.get_exception_handler()
        loop.set_exception_handler(lambda _l, ctx: reported.append(ctx["message"]))
        icpt = _make(crypto_service, trust_boundary, timeout=0.1)

        def late_failure(_message):
            time.sleep(0.3)
            raise ValueError("secret-payload-fragment")

        icpt._route_to_engine = late_failure
        try:
            with caplog.at_level(logging.WARNING, logger="qwed_a2a"):
                v = await icpt.intercept(valid_financial_message, trace_id="t_late")
                assert v.engine_used == "engine_timeout"
                await asyncio.sleep(0.5)
                gc.collect()
                await asyncio.sleep(0.05)
        finally:
            loop.set_exception_handler(previous)

        assert reported == []
        assert "Abandoned engine run raised ValueError" in caplog.text
        assert "secret-payload-fragment" not in caplog.text

    async def test_dropped_interceptor_threads_exit_without_close(
        self, crypto_service, trust_boundary, valid_financial_message
    ):
        """Replacing an interceptor (e.g. configure_interceptor) needs no
        close(): once unreferenced, its idle engine threads exit."""
        import gc

        def engine_threads():
            return [
                t for t in threading.enumerate() if t.name.startswith("qwed-a2a-engine")
            ]

        gc.collect()
        before = len(engine_threads())
        for i in range(3):
            icpt = _make(crypto_service, trust_boundary, timeout=5.0)
            await icpt.intercept(valid_financial_message, trace_id=f"t_drop_{i}")
            del icpt
        gc.collect()
        deadline = time.perf_counter() + 2.0
        while len(engine_threads()) > before and time.perf_counter() < deadline:
            await asyncio.sleep(0.05)
        assert len(engine_threads()) <= before


@pytest.mark.asyncio
async def test_health_answers_during_slow_intercept(monkeypatch):
    """HTTP leg: /a2a/health stays fast while an intercept's engine is busy."""
    from fastapi import FastAPI

    monkeypatch.setenv("QWED_A2A_API_KEYS", json.dumps({"key-a": "agent-a"}))
    monkeypatch.setenv("QWED_A2A_TRUSTED_AGENTS", "agent-a,agent-b")
    ep.configure_interceptor(InterceptorConfig(engine_timeout_seconds=5.0))
    monkeypatch.setattr(ep.get_interceptor(), "_route_to_engine", _slow_engine(1.0))

    app = FastAPI()
    app.include_router(ep.router)
    transport = httpx.ASGITransport(app=app)
    body = {
        "sender_agent_id": "agent-a",
        "receiver_agent_id": "agent-b",
        "payload_type": "financial_transaction",
        "payload": {
            "data": {"claimed_total": "1.00", "line_items": [{"amount": "1.00"}]}
        },
    }
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        start = time.perf_counter()
        slow = asyncio.create_task(
            client.post("/a2a/intercept", json=body, headers={"x-api-key": "key-a"})
        )
        await asyncio.sleep(0.1)  # let the intercept reach its engine
        health = await client.get("/a2a/health")
        health_done = time.perf_counter() - start
        # A blocking engine would delay even the sleep above until the
        # engine finished, so health could only answer after the intercept.
        intercept_still_running = not slow.done()
        resp = await slow

    assert health.status_code == 200
    assert intercept_still_running, "health answered only after the engine finished"
    assert health_done < 0.5, f"health answered {health_done:.2f}s after start"
    assert resp.status_code == 200
    assert resp.json()["status"] == "verified"
