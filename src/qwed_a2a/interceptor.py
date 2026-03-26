"""
QWED A2A Verification Interceptor.

The core pipeline that intercepts, verifies, and either forwards or blocks
payloads sent between autonomous agents using the A2A protocol.

This is the [QWED Core] module — all inter-agent messages flow through here.
"""

import json
import re
import time
from decimal import Decimal, ROUND_HALF_UP
from typing import Any, Dict, Optional

from qwed_a2a.protocol.schema import (
    AgentMessage,
    InterceptorConfig,
    PayloadType,
    VerdictStatus,
    VerificationVerdict,
)
from qwed_a2a.security.crypto import A2ACryptoService, HAS_CRYPTO
from qwed_a2a.security.trust_boundary import TrustBoundary
from qwed_a2a.utils.telemetry import logger, record_intercept, trace_intercept


class A2AVerificationInterceptor:
    """
    Intercepts and verifies payloads sent between autonomous agents
    using the A2A communication protocol.

    Architecture:
        1. Validate incoming message schema (Pydantic)
        2. Enforce trust boundary (allowlist/blocklist/rate limit)
        3. Route payload to appropriate verification engine
        4. Sign the verdict with JWT attestation (if crypto available)
        5. Return structured VerificationVerdict
    """

    def __init__(
        self,
        config: Optional[InterceptorConfig] = None,
        crypto_service: Optional[A2ACryptoService] = None,
        trust_boundary: Optional[TrustBoundary] = None,
    ):
        self.config = config or InterceptorConfig()
        self.trust = trust_boundary or TrustBoundary(default_allow=False)

        # Graceful crypto degradation — attestations disabled if deps missing
        if crypto_service is not None:
            self.crypto: Optional[A2ACryptoService] = crypto_service
        elif HAS_CRYPTO:
            self.crypto = A2ACryptoService()
        else:
            self.crypto = None
            logger.warning(
                "Crypto dependencies unavailable; attestation JWTs will be disabled"
            )

    @trace_intercept
    async def intercept(
        self,
        message: AgentMessage,
        trace_id: str,
    ) -> VerificationVerdict:
        """
        Primary entrypoint: intercept and verify an agent message.

        Args:
            message: Validated AgentMessage to process.
            trace_id: Caller-provided deterministic trace ID for this intercept.

        Returns:
            VerificationVerdict with status, attestation, and audit trace.
        """
        start_time = time.perf_counter()

        # --- Step 1: Enforce trust boundary ---
        allowed, rejection_reason = self.trust.evaluate(
            message.sender_agent_id, message.receiver_agent_id
        )
        if not allowed:
            verdict = self._build_verdict(
                trace_id=trace_id,
                status=VerdictStatus.BLOCKED,
                reason=f"Trust boundary violation: {rejection_reason}",
                engine="trust_boundary",
                message=message,
            )
            self._record(verdict, message.sender_agent_id, start_time)
            return verdict

        # --- Step 2: Check trusted agent bypass ---
        if self.config.trusted_agents and (
            message.sender_agent_id in self.config.trusted_agents
        ):
            verdict = self._build_verdict(
                trace_id=trace_id,
                status=VerdictStatus.FORWARDED,
                reason="Sender is on the trusted agents allowlist",
                engine="bypass",
                message=message,
            )
            self._record(verdict, message.sender_agent_id, start_time)
            return verdict

        # --- Step 3: Route to verification engine ---
        try:
            engine_result = self._route_to_engine(message)
        except Exception as exc:
            logger.error("Verification engine error: %s", exc)
            status = VerdictStatus.BLOCKED if self.config.block_on_error else VerdictStatus.FORWARDED
            verdict = self._build_verdict(
                trace_id=trace_id,
                status=status,
                reason=f"Verification engine error: {exc}",
                engine="error_handler",
                message=message,
            )
            self._record(verdict, message.sender_agent_id, start_time)
            return verdict

        # --- Step 4: Build verdict from engine result ---
        if engine_result["verified"]:
            verdict = self._build_verdict(
                trace_id=trace_id,
                status=VerdictStatus.FORWARDED,
                reason=None,
                engine=engine_result["engine"],
                message=message,
                details=engine_result,
            )
        else:
            verdict = self._build_verdict(
                trace_id=trace_id,
                status=VerdictStatus.BLOCKED,
                reason=(
                    f"QWED BLOCKED A2A TRANSFER: "
                    f"{engine_result.get('reason', 'Verification failed')} "
                    f"from {message.sender_agent_id}."
                ),
                engine=engine_result["engine"],
                message=message,
                details=engine_result,
            )

        self._record(verdict, message.sender_agent_id, start_time)
        return verdict

    def _route_to_engine(self, message: AgentMessage) -> Dict[str, Any]:
        """
        Route the message payload to the appropriate verification engine.

        Returns a dict with keys: verified (bool), engine (str), reason (str).
        """
        payload = message.payload
        payload_type = message.payload_type

        if (
            payload_type == PayloadType.FINANCIAL_TRANSACTION
            and self.config.enable_financial_verification
        ):
            return self._verify_financial(payload)

        if (
            payload_type == PayloadType.LOGIC_ASSERTION
            and self.config.enable_logic_verification
        ):
            return self._verify_logic(payload)

        if (
            payload_type == PayloadType.CODE_EXECUTION
            and self.config.enable_code_verification
        ):
            return self._verify_code(payload)

        # General or unrecognized types — pass through
        return {
            "verified": True,
            "engine": "passthrough",
            "reason": "No verification required for this payload type",
        }

    def _verify_financial(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Lightweight deterministic financial verification.

        Checks mathematical claims in the payload using Decimal arithmetic.
        All comparisons stay in Decimal to avoid floating-point precision loss.
        """
        data = payload.get("data", {})
        claimed_total = data.get("claimed_total")
        line_items = data.get("line_items", [])

        if claimed_total is None or not line_items:
            return {
                "verified": True,
                "engine": "finance_guard",
                "reason": "No verifiable financial claims in payload",
            }

        # Sum line items with Decimal precision
        computed_total = Decimal("0")
        for item in line_items:
            amount = item.get("amount", 0)
            quantity = item.get("quantity", 1)
            computed_total += Decimal(str(amount)) * Decimal(str(quantity))

        computed_total = computed_total.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        claimed_decimal = Decimal(str(claimed_total)).quantize(
            Decimal("0.01"), rounding=ROUND_HALF_UP
        )
        tolerance = Decimal("0.01")

        if abs(computed_total - claimed_decimal) > tolerance:
            return {
                "verified": False,
                "engine": "finance_guard",
                "reason": (
                    f"Mathematical hallucination detected: "
                    f"claimed_total={claimed_total}, computed_total={computed_total}"
                ),
                "computed_total": float(computed_total),
                "claimed_total": float(claimed_decimal),
            }

        return {
            "verified": True,
            "engine": "finance_guard",
            "reason": "Financial totals verified",
            "computed_total": float(computed_total),
        }

    def _verify_logic(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Lightweight logic assertion verification.

        Checks for obvious contradictions in boolean claims.
        """
        assertions = payload.get("assertions", [])

        if not assertions:
            return {
                "verified": True,
                "engine": "logic_guard",
                "reason": "No assertions to verify",
            }

        # Check for direct contradictions (P and NOT P)
        positive_claims = set()
        negative_claims = set()

        for assertion in assertions:
            claim = assertion.get("claim", "")
            negated = assertion.get("negated", False)

            if negated:
                negative_claims.add(claim)
            else:
                positive_claims.add(claim)

        contradictions = sorted(positive_claims & negative_claims)

        if contradictions:
            return {
                "verified": False,
                "engine": "logic_guard",
                "reason": (
                    f"Logical contradiction detected: "
                    f"claims both asserted and negated: {contradictions}"
                ),
                "contradictions": contradictions,
            }

        return {
            "verified": True,
            "engine": "logic_guard",
            "reason": "No contradictions found in assertions",
        }

    # Compiled regex patterns for case-insensitive, whitespace-tolerant detection
    _DANGEROUS_PATTERNS: Dict[str, re.Pattern] = {
        "eval": re.compile(r"\beval\s*\(", re.IGNORECASE),
        "exec": re.compile(r"\bexec\s*\(", re.IGNORECASE),
        "subprocess": re.compile(
            r"\b(?:subprocess\s*\.|import\s+subprocess\b|from\s+subprocess\s+import\b)",
            re.IGNORECASE,
        ),
        "os.system": re.compile(r"\bos\.system\s*\(", re.IGNORECASE),
        "os.popen": re.compile(r"\bos\.popen\s*\(", re.IGNORECASE),
        "__import__": re.compile(r"__import__\s*\(", re.IGNORECASE),
        "compile": re.compile(r"\bcompile\s*\(", re.IGNORECASE),
        "importlib": re.compile(r"\bimportlib\s*\.", re.IGNORECASE),
    }

    def _verify_code(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Lightweight code security verification.

        Scans for dangerous patterns using case-insensitive regex
        to prevent trivial bypass via casing or whitespace.
        """
        code = payload.get("code", "")

        if not code:
            return {
                "verified": True,
                "engine": "code_guard",
                "reason": "No code to verify",
            }

        found_threats = []
        for label, pattern in self._DANGEROUS_PATTERNS.items():
            if pattern.search(code):
                found_threats.append(label)

        if found_threats:
            return {
                "verified": False,
                "engine": "code_guard",
                "reason": (
                    f"Dangerous code patterns detected: {', '.join(found_threats)}"
                ),
                "threats": found_threats,
            }

        return {
            "verified": True,
            "engine": "code_guard",
            "reason": "No dangerous patterns found in code",
        }

    def _build_verdict(
        self,
        trace_id: str,
        status: VerdictStatus,
        reason: Optional[str],
        engine: str,
        message: AgentMessage,
        details: Optional[Dict[str, Any]] = None,
    ) -> VerificationVerdict:
        """Build a VerificationVerdict with optional JWT attestation."""
        attestation_jwt = None

        if self.crypto is not None:
            try:
                payload_hash = A2ACryptoService.hash_content(
                    json.dumps(message.payload, sort_keys=True, default=str)
                )
                attestation_jwt = self.crypto.sign_verdict(
                    trace_id=trace_id,
                    verdict_status=status.value,
                    engine=engine,
                    sender_id=message.sender_agent_id,
                    receiver_id=message.receiver_agent_id,
                    payload_hash=payload_hash,
                )
            except Exception as exc:
                logger.warning("Failed to sign attestation: %s", exc)

        return VerificationVerdict(
            status=status,
            reason=reason,
            audit_trace_id=trace_id,
            attestation_jwt=attestation_jwt,
            engine_used=engine,
            details=details,
        )

    def _record(
        self,
        verdict: VerificationVerdict,
        sender_id: str,
        start_time: float,
    ) -> None:
        """Record telemetry for this intercept."""
        latency_ms = (time.perf_counter() - start_time) * 1000
        record_intercept(
            status=verdict.status.value,
            engine=verdict.engine_used,
            sender_id=sender_id,
            latency_ms=latency_ms,
        )
        logger.info(
            "A2A Intercept [%s] %s -> engine=%s (%.1fms)",
            verdict.audit_trace_id,
            verdict.status.value.upper(),
            verdict.engine_used,
            latency_ms,
        )
