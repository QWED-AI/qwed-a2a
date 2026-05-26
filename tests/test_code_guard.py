"""
Tests for CodeGuard heuristic scan — issue #9 (A2A-005).

Covers:
- HEURISTIC_PASS is returned for clean code (not FORWARDED/VERIFIED)
- AST analysis blocks direct dangerous calls
- AST analysis blocks dangerous imports
- Regex heuristics block dynamic/obfuscated access patterns
- All bypass examples from the issue are handled
- JWT is issued for HEURISTIC_PASS with trust_level=heuristic in claims
- VerdictStatus.HEURISTIC_PASS exists and is distinct from FORWARDED
- Telemetry records heuristic_pass
"""

import pytest

from qwed_a2a.interceptor import A2AVerificationInterceptor
from qwed_a2a.protocol.schema import (
    AgentMessage,
    InterceptorConfig,
    PayloadType,
    VerdictStatus,
)
from qwed_a2a.security.trust_boundary import TrustBoundary


# helpers


def _code_message(
    code: str, sender: str = "agent-A", receiver: str = "agent-B"
) -> AgentMessage:
    return AgentMessage(
        sender_agent_id=sender,
        receiver_agent_id=receiver,
        payload_type=PayloadType.CODE_EXECUTION,
        payload={"code": code},
    )


@pytest.fixture
def code_interceptor():
    """Interceptor with code verification and open trust boundary."""
    return A2AVerificationInterceptor(
        config=InterceptorConfig(enable_code_verification=True, block_on_error=True),
        trust_boundary=TrustBoundary(default_allow=True),
    )


# VerdictStatus enum


class TestVerdictStatusEnum:
    def test_heuristic_pass_exists(self):
        assert hasattr(VerdictStatus, "HEURISTIC_PASS")

    def test_heuristic_pass_value(self):
        assert VerdictStatus.HEURISTIC_PASS == "heuristic_pass"

    def test_heuristic_pass_is_not_forwarded(self):
        assert VerdictStatus.HEURISTIC_PASS != VerdictStatus.FORWARDED

    def test_heuristic_pass_is_not_blocked(self):
        assert VerdictStatus.HEURISTIC_PASS != VerdictStatus.BLOCKED

    def test_heuristic_pass_is_not_unverifiable(self):
        assert VerdictStatus.HEURISTIC_PASS != VerdictStatus.UNVERIFIABLE


# Clean code -> HEURISTIC_PASS


class TestCleanCodeReturnsHeuristicPass:
    @pytest.mark.asyncio
    async def test_clean_code_is_heuristic_pass(self, code_interceptor):
        msg = _code_message("x = 1 + 2\nprint(x)")
        verdict = await code_interceptor.intercept(msg, trace_id="t_clean")
        assert verdict.status == VerdictStatus.HEURISTIC_PASS

    @pytest.mark.asyncio
    async def test_clean_code_is_not_forwarded(self, code_interceptor):
        """FORWARDED must never be returned for a code payload."""
        msg = _code_message("def add(a, b): return a + b")
        verdict = await code_interceptor.intercept(msg, trace_id="t_not_forwarded")
        assert verdict.status != VerdictStatus.FORWARDED

    @pytest.mark.asyncio
    async def test_empty_code_is_heuristic_pass(self, code_interceptor):
        msg = _code_message("")
        verdict = await code_interceptor.intercept(msg, trace_id="t_empty")
        assert verdict.status == VerdictStatus.HEURISTIC_PASS

    @pytest.mark.asyncio
    async def test_clean_code_has_reason(self, code_interceptor):
        msg = _code_message("result = [x**2 for x in range(10)]")
        verdict = await code_interceptor.intercept(msg, trace_id="t_reason")
        assert verdict.reason is not None
        assert len(verdict.reason) > 0

    @pytest.mark.asyncio
    async def test_clean_code_has_attestation_jwt(self, code_interceptor):
        """HEURISTIC_PASS must carry a JWT for downstream trust-level inspection."""
        msg = _code_message("import math\nresult = math.sqrt(16)")
        verdict = await code_interceptor.intercept(msg, trace_id="t_jwt")
        assert verdict.attestation_jwt is not None

    @pytest.mark.asyncio
    async def test_heuristic_pass_jwt_declares_correct_verdict(self, code_interceptor):
        """The JWT verdict claim must be 'heuristic_pass', not 'forwarded'."""
        import jwt as pyjwt

        msg = _code_message("x = 42")
        verdict = await code_interceptor.intercept(msg, trace_id="t_jwt_claim")
        assert verdict.attestation_jwt is not None
        raw = pyjwt.decode(verdict.attestation_jwt, options={"verify_signature": False})
        assert raw["qwed_a2a"]["verdict"] == "heuristic_pass"
        assert raw["qwed_a2a"]["engine"] == "code_guard"


# AST analysis — direct dangerous calls


class TestASTDirectCalls:
    @pytest.mark.asyncio
    async def test_eval_direct_call_blocked(self, code_interceptor):
        msg = _code_message('result = eval("1+1")')
        verdict = await code_interceptor.intercept(msg, trace_id="t_eval")
        assert verdict.status == VerdictStatus.BLOCKED

    @pytest.mark.asyncio
    async def test_exec_direct_call_blocked(self, code_interceptor):
        msg = _code_message('exec("import os")')
        verdict = await code_interceptor.intercept(msg, trace_id="t_exec")
        assert verdict.status == VerdictStatus.BLOCKED

    @pytest.mark.asyncio
    async def test_compile_direct_call_blocked(self, code_interceptor):
        msg = _code_message('code = compile("x=1", "<str>", "exec")')
        verdict = await code_interceptor.intercept(msg, trace_id="t_compile")
        assert verdict.status == VerdictStatus.BLOCKED

    @pytest.mark.asyncio
    async def test_dunder_import_direct_call_blocked(self, code_interceptor):
        msg = _code_message('os = __import__("os")')
        verdict = await code_interceptor.intercept(msg, trace_id="t_dunder_import")
        assert verdict.status == VerdictStatus.BLOCKED


# AST analysis — attribute calls


class TestASTAttributeCalls:
    @pytest.mark.asyncio
    async def test_os_system_blocked(self, code_interceptor):
        msg = _code_message("import os\nos.system('id')")
        verdict = await code_interceptor.intercept(msg, trace_id="t_os_system")
        assert verdict.status == VerdictStatus.BLOCKED

    @pytest.mark.asyncio
    async def test_subprocess_run_blocked(self, code_interceptor):
        msg = _code_message("import subprocess\nsubprocess.run(['ls'])")
        verdict = await code_interceptor.intercept(msg, trace_id="t_subprocess_run")
        assert verdict.status == VerdictStatus.BLOCKED

    @pytest.mark.asyncio
    async def test_subprocess_popen_blocked(self, code_interceptor):
        msg = _code_message("import subprocess\nsubprocess.Popen(['id'])")
        verdict = await code_interceptor.intercept(msg, trace_id="t_popen")
        assert verdict.status == VerdictStatus.BLOCKED


# AST analysis — dangerous imports


class TestASTImports:
    @pytest.mark.asyncio
    async def test_import_subprocess_blocked(self, code_interceptor):
        msg = _code_message("import subprocess")
        verdict = await code_interceptor.intercept(msg, trace_id="t_imp_sub")
        assert verdict.status == VerdictStatus.BLOCKED

    @pytest.mark.asyncio
    async def test_from_subprocess_import_blocked(self, code_interceptor):
        msg = _code_message("from subprocess import run")
        verdict = await code_interceptor.intercept(msg, trace_id="t_from_sub")
        assert verdict.status == VerdictStatus.BLOCKED

    @pytest.mark.asyncio
    async def test_import_importlib_blocked(self, code_interceptor):
        msg = _code_message("import importlib")
        verdict = await code_interceptor.intercept(msg, trace_id="t_importlib")
        assert verdict.status == VerdictStatus.BLOCKED

    @pytest.mark.asyncio
    async def test_safe_imports_pass(self, code_interceptor):
        """Non-dangerous imports must not be blocked."""
        msg = _code_message("import math\nimport json\nfrom pathlib import Path")
        verdict = await code_interceptor.intercept(msg, trace_id="t_safe_import")
        assert verdict.status == VerdictStatus.HEURISTIC_PASS


# Bypass scenarios from issue #9


class TestBypassScenarios:
    """
    Bypass examples explicitly listed in issue #9.
    These demonstrate why regex-only scanning is insufficient.
    """

    @pytest.mark.asyncio
    async def test_bypass_1_string_concat_getattr_builtins(self, code_interceptor):
        """
        Bypass 1: getattr(__builtins__, 'ev'+'al')(...) hides function name.
        Caught by regex heuristic for getattr(__builtins__, ...) pattern.
        """
        code = (
            'fn = "ev" + "al"\n'
            "getattr(__builtins__, fn)(\"import os; os.system('rm -rf /')\")"
        )
        msg = _code_message(code)
        verdict = await code_interceptor.intercept(msg, trace_id="t_bypass_1")
        assert verdict.status == VerdictStatus.BLOCKED, (
            f"String-concat eval bypass not caught. Status: {verdict.status}, "
            f"Reason: {verdict.reason}"
        )

    @pytest.mark.asyncio
    async def test_bypass_2_builtins_dict_exec(self, code_interceptor):
        """
        Bypass 2: __builtins__.__dict__['exec'](...) avoids direct exec() call.
        Caught by regex heuristic for __builtins__.__dict__[ pattern.
        """
        code = "__builtins__.__dict__['exec'](\"import os; os.system('id')\")"
        msg = _code_message(code)
        verdict = await code_interceptor.intercept(msg, trace_id="t_bypass_2")
        assert (
            verdict.status == VerdictStatus.BLOCKED
        ), f"builtins dict bypass not caught. Reason: {verdict.reason}"

    @pytest.mark.asyncio
    async def test_bypass_3_exec_with_base64(self, code_interceptor):
        """
        Bypass 3: exec(base64.b64decode(...)) — exec() caught by AST directly.
        """
        import base64

        encoded = base64.b64encode(b"import os; os.system('id')").decode()
        code = f"import base64\nexec(base64.b64decode('{encoded}'))"
        msg = _code_message(code)
        verdict = await code_interceptor.intercept(msg, trace_id="t_bypass_3")
        assert (
            verdict.status == VerdictStatus.BLOCKED
        ), f"exec+base64 bypass not caught. Reason: {verdict.reason}"

    @pytest.mark.asyncio
    async def test_bypass_3b_base64_decode_alone(self, code_interceptor):
        """
        Bypass 3b: base64.b64decode without exec — regex catches b64decode pattern.
        """
        import base64

        encoded = base64.b64encode(b"import os; os.system('id')").decode()
        code = f"import base64\npayload = base64.b64decode('{encoded}')"
        msg = _code_message(code)
        verdict = await code_interceptor.intercept(msg, trace_id="t_bypass_3b")
        assert (
            verdict.status == VerdictStatus.BLOCKED
        ), f"base64.b64decode alone not caught. Reason: {verdict.reason}"

    @pytest.mark.asyncio
    async def test_syntax_error_fails_closed(self, code_interceptor):
        """
        Unparseable code must fail closed — BLOCKED, not HEURISTIC_PASS.
        Cannot analyse what we cannot parse.
        """
        code = "def broken(\nx = @@invalid_syntax!!"
        msg = _code_message(code)
        verdict = await code_interceptor.intercept(msg, trace_id="t_syntax_err")
        assert (
            verdict.status == VerdictStatus.BLOCKED
        ), f"Unparseable code was not blocked. Status: {verdict.status}"


# BLOCKED reason and JWT


class TestBlockedReason:
    @pytest.mark.asyncio
    async def test_ast_block_has_reason(self, code_interceptor):
        msg = _code_message('eval("x")')
        verdict = await code_interceptor.intercept(msg, trace_id="t_block_reason")
        assert verdict.status == VerdictStatus.BLOCKED
        assert verdict.reason is not None
        assert "QWED BLOCKED" in verdict.reason

    @pytest.mark.asyncio
    async def test_blocked_verdict_has_jwt(self, code_interceptor):
        """BLOCKED verdicts carry a signed JWT as proof of the blocking decision."""
        msg = _code_message('exec("rm -rf /")')
        verdict = await code_interceptor.intercept(msg, trace_id="t_block_jwt")
        assert verdict.attestation_jwt is not None


# Telemetry


class TestHeuristicPassTelemetry:
    @pytest.mark.asyncio
    async def test_heuristic_pass_increments_counter(self, code_interceptor):
        from qwed_a2a.utils.telemetry import get_metrics

        msg = _code_message("x = 1")
        await code_interceptor.intercept(msg, trace_id="t_telemetry_hp")
        metrics = get_metrics()
        assert metrics.total_heuristic_pass >= 1
        assert metrics.total_errors == 0

    @pytest.mark.asyncio
    async def test_heuristic_pass_not_counted_as_error(self, code_interceptor):
        from qwed_a2a.utils.telemetry import get_metrics

        msg = _code_message("y = 2 + 2")
        await code_interceptor.intercept(msg, trace_id="t_telemetry_no_err")
        metrics = get_metrics()
        assert metrics.total_errors == 0
