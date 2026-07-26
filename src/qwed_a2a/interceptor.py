"""
QWED A2A Verification Interceptor.

The core pipeline that intercepts, verifies, and either forwards or blocks
payloads sent between autonomous agents using the A2A protocol.

This is the [QWED Core] module — all inter-agent messages flow through here.
"""

import ast
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
        4. Sign the verdict with JWT attestation
        5. Return structured VerificationVerdict
    """

    def __init__(
        self,
        config: InterceptorConfig | None = None,
        crypto_service: A2ACryptoService | None = None,
        trust_boundary: TrustBoundary | None = None,
    ):
        self.config = config or InterceptorConfig()
        self.trust = trust_boundary or TrustBoundary(default_allow=False)

        # Sync trusted agents from configuration into the TrustBoundary allowlist
        if self.config.trusted_agents:
            for agent in self.config.trusted_agents:
                self.trust.trust_agent(agent)

        # Fail closed if the attestation stack is unavailable. Unsigned verdicts
        # would look operational while dropping QWED's core trust guarantee.
        if crypto_service is not None:
            self.crypto: A2ACryptoService = crypto_service
        elif HAS_CRYPTO:
            self.crypto = A2ACryptoService()
        else:
            raise RuntimeError(
                "QWED-A2A requires 'cryptography' and 'PyJWT' packages. "
                "Install with: pip install qwed-a2a. "
                "Operating without JWT attestations violates fail-closed policy."
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
            message.sender_agent_id,
            message.receiver_agent_id,
            payload_type=message.payload_type.value,
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

        # --- Step 2: Route to verification engine ---
        try:
            engine_result = self._route_to_engine(message)
        except Exception as exc:
            logger.error("Verification engine error: %s", exc)
            status = (
                VerdictStatus.BLOCKED
                if self.config.block_on_error
                else VerdictStatus.FORWARDED
            )
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
        if engine_result.get("status") == "unverifiable":
            verdict = self._build_verdict(
                trace_id=trace_id,
                status=VerdictStatus.UNVERIFIABLE,
                reason=engine_result.get("reason"),
                engine=engine_result["engine"],
                message=message,
                details=engine_result,
            )
        elif engine_result.get("status") == "heuristic_pass":
            verdict = self._build_verdict(
                trace_id=trace_id,
                status=VerdictStatus.HEURISTIC_PASS,
                reason=engine_result.get("reason"),
                engine=engine_result["engine"],
                message=message,
                details=engine_result,
            )
        elif engine_result["verified"]:
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

    def _route_to_engine(self, message: AgentMessage) -> dict[str, Any]:
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

        # GENERAL and DATA_QUERY have no verification engine.
        # Returning verified=False with status=unverifiable ensures no
        # JWT is issued claiming the content was checked.
        return {
            "verified": False,
            "engine": "passthrough",
            "status": "unverifiable",
            "reason": "No verification engine available for this payload type",
        }

    def _verify_financial(self, payload: dict[str, Any]) -> dict[str, Any]:
        """
        Lightweight deterministic financial verification.

        Checks mathematical claims in the payload using Decimal arithmetic.
        All comparisons stay in Decimal to avoid floating-point precision loss.
        """
        err = self._validate_financial_payload(payload)
        if err is not None:
            return err

        data = payload["data"]
        claimed_total = data["claimed_total"]
        line_items = data["line_items"]

        # Sum line items with Decimal precision
        computed_total = Decimal("0")
        for item in line_items:
            computed_total += Decimal(str(item["amount"])) * Decimal(
                str(item.get("quantity", 1))
            )

        computed_total = computed_total.quantize(
            Decimal("0.01"), rounding=ROUND_HALF_UP
        )
        try:
            claimed_decimal = Decimal(str(claimed_total)).quantize(
                Decimal("0.01"), rounding=ROUND_HALF_UP
            )
        except Exception:
            return {
                "verified": False,
                "status": "unverifiable",
                "engine": "finance_guard",
                "reason": (
                    "FINANCIAL_TRANSACTION payload contains malformed field: "
                    "data.claimed_total must be a numeric value."
                ),
            }
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

    def _validate_financial_payload(self, payload: dict[str, Any]) -> dict[str, Any] | None:
        """
        Validate structure and types of a FINANCIAL_TRANSACTION payload.

        Returns an UNVERIFIABLE result dict if invalid, or None if the payload
        passes all structural and type checks.
        """
        data = payload.get("data", {})
        if not isinstance(data, dict):
            return self._finance_unverifiable(
                "FINANCIAL_TRANSACTION payload missing required field: "
                "data must be a mapping for verification."
            )
        claimed_total = data.get("claimed_total")
        line_items = data.get("line_items", [])

        if not isinstance(line_items, list):
            return self._finance_unverifiable(
                "FINANCIAL_TRANSACTION payload missing required field: "
                "data.line_items must be a list for verification."
            )

        if claimed_total is None:
            return self._finance_unverifiable(
                "FINANCIAL_TRANSACTION payload missing required field: "
                "data.claimed_total must be present for verification."
            )

        if not line_items:
            return self._finance_unverifiable(
                "FINANCIAL_TRANSACTION payload missing required field: "
                "data.line_items must be present for verification."
            )

        for item in line_items:
            err = self._validate_line_item(item)
            if err is not None:
                return err
        return None

    def _validate_line_item(self, item: Any) -> dict[str, Any] | None:
        """
        Validate a single line item in a FINANCIAL_TRANSACTION payload.

        Returns an UNVERIFIABLE result dict if invalid, or None if the item
        passes all structural and type checks.
        """
        if not isinstance(item, dict):
            return self._finance_unverifiable(
                "FINANCIAL_TRANSACTION payload contains malformed "
                "line item: each line item must be a mapping."
            )
        if "amount" not in item or item["amount"] is None:
            return self._finance_unverifiable(
                "FINANCIAL_TRANSACTION payload contains incomplete "
                "line item: each line item must include a non-null amount."
            )
        if "quantity" in item and item["quantity"] is None:
            return self._finance_unverifiable(
                "FINANCIAL_TRANSACTION payload contains incomplete "
                "line item: quantity must not be null."
            )
        try:
            Decimal(str(item["amount"]))
            Decimal(str(item.get("quantity", 1)))
        except Exception:
            return self._finance_unverifiable(
                "FINANCIAL_TRANSACTION payload contains malformed "
                "line item: amount and quantity must be numeric values."
            )
        return None

    def _finance_unverifiable(self, reason: str) -> dict[str, Any]:
        """Build a finance_guard UNVERIFIABLE result dict."""
        return {
            "verified": False,
            "status": "unverifiable",
            "engine": "finance_guard",
            "reason": reason,
        }

    def _verify_logic(self, payload: dict[str, Any]) -> dict[str, Any]:
        """
        Lightweight logic assertion verification.

        Checks for obvious contradictions in boolean claims.
        """
        assertions = payload.get("assertions", [])

        if not isinstance(assertions, list):
            return {
                "verified": False,
                "status": "unverifiable",
                "engine": "logic_guard",
                "reason": (
                    "LOGIC_ASSERTION payload missing required field: "
                    "assertions must be a list for verification."
                ),
            }

        if not assertions:
            return {
                "verified": False,
                "status": "unverifiable",
                "engine": "logic_guard",
                "reason": (
                    "LOGIC_ASSERTION payload missing required field: "
                    "assertions list must be non-empty for verification."
                ),
            }

        # Check for direct contradictions (P and NOT P)
        positive_claims = set()
        negative_claims = set()

        for assertion in assertions:
            if not isinstance(assertion, dict):
                return {
                    "verified": False,
                    "status": "unverifiable",
                    "engine": "logic_guard",
                    "reason": (
                        "LOGIC_ASSERTION payload contains malformed "
                        "assertion entry: each assertion must be a mapping."
                    ),
                }
            if "claim" not in assertion:
                return {
                    "verified": False,
                    "status": "unverifiable",
                    "engine": "logic_guard",
                    "reason": (
                        "LOGIC_ASSERTION payload contains incomplete "
                        "assertion entry: each assertion must include a claim."
                    ),
                }
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

    # ── AST dangerous node types ─────────────────────────────────────────────
    # Used by _verify_code_ast() for structural (not textual) analysis.
    # These are deterministic: if the AST contains one of these constructs
    # the payload is blocked regardless of how obfuscated the source is.
    _DANGEROUS_CALL_NAMES: frozenset = frozenset(
        {
            "eval",
            "exec",
            "compile",
            "__import__",
        }
    )
    # Maps known dangerous module names to the specific method names that are
    # dangerous when called on that module. This is intentionally scoped to
    # (receiver, method) pairs to avoid false positives:
    #   thread.run()     — safe, receiver is not subprocess/os
    #   client.call()    — safe, receiver is not subprocess/os
    #   subprocess.run() — dangerous, receiver IS subprocess
    # Limitation: import aliasing (e.g., `import subprocess as sp; sp.run()`)
    # is not caught here — the regex heuristic layer provides partial coverage.
    _DANGEROUS_RECEIVER_METHODS: dict[str, frozenset] = {
        "subprocess": frozenset(
            {"run", "Popen", "call", "check_output", "check_call", "popen"}
        ),
        "os": frozenset({"system", "popen"}),
    }
    # Dangerous module import names (caught at ast.Import / ast.ImportFrom level)
    _DANGEROUS_IMPORTS: frozenset = frozenset(
        {
            "subprocess",
            "importlib",
            "ctypes",
            "pty",
        }
    )

    # ── Regex patterns as secondary heuristic layer ───────────────────────────
    # Catch obfuscation patterns that survive AST parsing: encoded strings,
    # getattr-based lookups, and dynamic attribute construction.
    _DANGEROUS_PATTERNS: dict[str, re.Pattern] = {
        "getattr_builtin": re.compile(
            r"""getattr\s*\(\s*(?:__builtins__|builtins)\s*""", re.IGNORECASE
        ),
        "builtins_dict_access": re.compile(
            r"""__builtins__\s*\.\s*__dict__\s*\[""", re.IGNORECASE
        ),
        "base64_exec": re.compile(
            r"""(?:base64\s*\.\s*b64decode|b64decode)\s*\(""", re.IGNORECASE
        ),
        "dynamic_import": re.compile(r"""__import__\s*\(""", re.IGNORECASE),
        "os_system": re.compile(r"""\bos\.system\s*\(""", re.IGNORECASE),
        "os_popen": re.compile(r"""\bos\.popen\s*\(""", re.IGNORECASE),
    }

    def _verify_code(self, payload: dict[str, Any]) -> dict[str, Any]:
        """
        Heuristic code security scan: AST structural analysis + regex patterns.

        Important: this is a heuristic scan, NOT deterministic verification.
        A HEURISTIC_PASS result means no known dangerous constructs were found —
        it does NOT mean the code is safe. Obfuscated or novel attack patterns
        may not be detected.

        Analysis layers (run in order):
          1. AST parse — catches direct dangerous calls and imports
             structurally, before any text-level obfuscation can hide them
          2. Regex scan — secondary heuristic for dynamic access patterns
             (getattr(__builtins__,...), base64-encoded payloads, etc.)

        Returns HEURISTIC_PASS when no threats found, BLOCKED when any found.
        """
        code = payload.get("code", "")

        if not code:
            return {
                "verified": False,
                "status": "heuristic_pass",
                "engine": "code_guard",
                "reason": "No code to analyze",
            }

        # ── Layer 1: AST structural analysis ──────────────────────────────────
        try:
            tree = ast.parse(code)
        except SyntaxError as exc:
            # Unparseable code could indicate obfuscation or raw bytecode;
            # fail closed — do not forward what we cannot analyse.
            return {
                "verified": False,
                "engine": "code_guard",
                "reason": f"Code failed AST parsing — cannot verify: {exc}",
            }

        ast_threats: list = []
        for node in ast.walk(tree):
            # Direct dangerous function calls: eval(...), exec(...), compile(...)
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name) and func.id in self._DANGEROUS_CALL_NAMES:
                    ast_threats.append(f"call:{func.id}()")
                # Receiver-scoped attribute calls: subprocess.run(...), os.system(...)
                # Only blocked when called on a known dangerous receiver — this avoids
                # false positives from legitimate .run()/.call() on other objects.
                elif isinstance(func, ast.Attribute):
                    if isinstance(func.value, ast.Name):
                        receiver = func.value.id
                        dangerous_methods = self._DANGEROUS_RECEIVER_METHODS.get(
                            receiver, frozenset()
                        )
                        if func.attr in dangerous_methods:
                            ast_threats.append(f"call:{receiver}.{func.attr}()")

            # Dangerous imports: import subprocess, from ctypes import ...
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    if root in self._DANGEROUS_IMPORTS:
                        ast_threats.append(f"import:{root}")
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    root = node.module.split(".")[0]
                    if root in self._DANGEROUS_IMPORTS:
                        ast_threats.append(f"import:{root}")

        if ast_threats:
            return {
                "verified": False,
                "engine": "code_guard",
                "reason": (
                    f"Dangerous constructs detected via AST analysis: "
                    f"{', '.join(ast_threats)}"
                ),
                "threats": ast_threats,
                "analysis": "ast",
            }

        # ── Layer 2: Regex heuristic scan ─────────────────────────────────────
        regex_threats: list = []
        for label, pattern in self._DANGEROUS_PATTERNS.items():
            if pattern.search(code):
                regex_threats.append(label)

        if regex_threats:
            return {
                "verified": False,
                "engine": "code_guard",
                "reason": (
                    f"Suspicious patterns detected via heuristic scan: "
                    f"{', '.join(regex_threats)}"
                ),
                "threats": regex_threats,
                "analysis": "regex",
            }

        # ── Both layers clean — heuristic pass, not verified ──────────────────
        return {
            "verified": False,
            "status": "heuristic_pass",
            "engine": "code_guard",
            "reason": (
                "AST analysis and heuristic scan found no known dangerous constructs. "
                "This is a heuristic result — novel or deeply obfuscated attack "
                "patterns may not be detected."
            ),
            "analysis": "ast+regex",
        }

    def _build_verdict(
        self,
        trace_id: str,
        status: VerdictStatus,
        reason: str | None,
        engine: str,
        message: AgentMessage,
        details: dict[str, Any] | None = None,
    ) -> VerificationVerdict:
        """Build a VerificationVerdict, signing with JWT unless status is UNVERIFIABLE.

        UNVERIFIABLE verdicts intentionally carry no attestation — issuing a
        signed JWT for unverified content would be a false cryptographic claim.
        """
        attestation_jwt = None

        # UNVERIFIABLE — no JWT (no verification ran, issuing one would be false)
        # All other statuses (FORWARDED, BLOCKED, HEURISTIC_PASS) get signed JWTs.
        # HEURISTIC_PASS JWTs declare verdict_status="heuristic_pass" in their
        # claims so downstream consumers know they received a heuristic result,
        # not a deterministic verification proof.
        if status != VerdictStatus.UNVERIFIABLE:
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
                logger.error("Failed to sign attestation: %s", exc)
                raise RuntimeError(
                    "Failed to sign attestation; refusing to return an unsigned verdict"
                ) from exc

            if not attestation_jwt:
                raise RuntimeError(
                    "sign_verdict returned an empty token — refusing to emit unsigned verdict"
                )

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
            status=verdict.status,
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
