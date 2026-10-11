"""
Code guard binding resolution (#119).

Both scan layers used to match binding-literally, so a one-token re-binding
of a blocked call (``import os as o; o.system(...)``) received a signed
HEURISTIC_PASS. Receivers are now resolved through import aliases, simple
re-bindings, star imports and getattr. The guard remains a heuristic
blocklist — see the documented residual families — so a clean result stays
HEURISTIC_PASS, never VERIFIED.
"""

import pytest

from qwed_a2a.protocol.schema import AgentMessage, PayloadType, VerdictStatus


def _code(code: str) -> AgentMessage:
    return AgentMessage(
        sender_agent_id="agent-a",
        receiver_agent_id="agent-b",
        payload_type=PayloadType.CODE_EXECUTION,
        payload={"code": code},
    )


# (code, expected threat label)
BYPASSES = [
    # The six primary repro shapes from #119.
    ("import os as o\no.system('id')", "call:os.system()"),
    ("import os\nx = os\nx.system('id')", "call:os.system()"),
    ("from os import *\nsystem('id')", "import:os.*"),
    ("import posix\nposix.system('id')", "call:posix.system()"),
    ("import builtins\nbuiltins.eval('1+1')", "call:builtins.eval()"),
    ("__builtins__.eval('1+1')", "call:__builtins__.eval()"),
    # Same root cause, other bindings.
    ("import os\nx = os\ny = x\ny.system('id')", "call:os.system()"),
    ("import os\ns = os.system\ns('id')", "call:os.system()"),
    ("from posix import system as s\ns('id')", "import:posix.system"),
    ("from os import system as run_it\nrun_it('id')", "import:os.system"),
    ("e = eval\ne('1')", "call:builtins.eval()"),
    ("import posix as p\np.spawnv(0, '/bin/sh', [])", "call:posix.spawnv()"),
    ("import nt\nnt.startfile('x')", "call:nt.startfile()"),
    ("from builtins import *\nexec('1')", "import:builtins.*"),
    # Process execution beyond system/popen.
    ("import os\nos.execv('/bin/sh', ['sh'])", "call:os.execv()"),
    ("import os\nos.posix_spawn('/bin/sh', ['sh'], {})", "call:os.posix_spawn()"),
    # getattr on a dangerous module: constant and runtime-chosen attribute.
    ("import os\ngetattr(os, 'system')('id')", "call:getattr(os, 'system')"),
    (
        "import os\nname = 'sys' + 'tem'\ngetattr(os, name)('id')",
        "call:getattr(os, <dynamic>)",
    ),
    # Non-dunder builtins namespace dict.
    ("import builtins\nbuiltins.__dict__['eval']('1')", "builtins_dict_access"),
]

CLEAN = [
    "import os\nos.path.join('a', 'b')",
    "import os\nprint(os.getcwd())",
    "from os import path\npath.join('a')",
    "import os\ngetattr(os, 'getcwd')()",
    "import builtins\nbuiltins.len([1])",
    "thread.run()",
    "client.call()",
    "x = 1\ny = x\nprint(y)",
    "def f():\n    return 1",
]


@pytest.mark.asyncio
class TestAliasBypassesBlocked:
    @pytest.mark.parametrize(("code", "threat"), BYPASSES)
    async def test_bypass_blocked_with_named_threat(self, interceptor, code, threat):
        v = await interceptor.intercept(_code(code), trace_id="t_alias")
        assert v.status == VerdictStatus.BLOCKED, code
        assert v.engine_used == "code_guard"
        assert threat in v.details["threats"], v.details["threats"]
        assert v.admissible is False

    async def test_literal_control_still_blocked(self, interceptor):
        v = await interceptor.intercept(
            _code("import os\nos.system('id')"), trace_id="t_alias_ctrl"
        )
        assert v.status == VerdictStatus.BLOCKED
        assert "call:os.system()" in v.details["threats"]

    async def test_subprocess_alias_no_regression(self, interceptor):
        v = await interceptor.intercept(
            _code("import subprocess as sp\nsp.run(['id'])"), trace_id="t_alias_sp"
        )
        assert v.status == VerdictStatus.BLOCKED
        assert "import:subprocess" in v.details["threats"]
        assert "call:subprocess.run()" in v.details["threats"]


@pytest.mark.asyncio
class TestBenignUsesStillPass:
    @pytest.mark.parametrize("code", CLEAN)
    async def test_benign_code_heuristic_pass(self, interceptor, code):
        v = await interceptor.intercept(_code(code), trace_id="t_alias_clean")
        assert v.status == VerdictStatus.HEURISTIC_PASS, (code, v.reason)


@pytest.mark.asyncio
class TestResidualFamiliesDocumented:
    """Known blocklist gaps (documented in the code guard and README). These
    pin current behaviour so a change is a deliberate decision; the result
    is still only a non-admissible HEURISTIC_PASS."""

    @pytest.mark.parametrize(
        "code",
        [
            "[eval][0]('1')",  # subscript callee
            "import sys\nsys.modules['os'].system('id')",  # module via sys.modules
            "import os\na, b = os, 1\na.system('id')",  # tuple-unpacking binding
            "import shutil\nshutil.rmtree('/tmp/x')",  # unlisted module
        ],
    )
    async def test_residual_is_heuristic_not_admissible(self, interceptor, code):
        v = await interceptor.intercept(_code(code), trace_id="t_alias_residual")
        assert v.status == VerdictStatus.HEURISTIC_PASS
        assert v.admissible is False
