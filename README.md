<div align="center">
  <img src="assets/logo.svg" alt="QWED Logo" width="80" height="80">
  <h1>QWED A2A</h1>
  <h3>Zero-Trust Verification Interceptor for Agent-to-Agent Communication</h3>

  > **QWED A2A** intercepts every payload between autonomous agents, runs deterministic verification, and either **forwards** or **blocks** the message — with a signed JWT attestation proving the decision.

  <p>
    <b>Agents don't trust each other. QWED verifies for them.</b>
  </p>

  [![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)
  [![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
  [![Tests](https://github.com/QWED-AI/qwed-a2a/actions/workflows/ci.yml/badge.svg)](https://github.com/QWED-AI/qwed-a2a/actions)
  [![GitHub stars](https://img.shields.io/github/stars/QWED-AI/qwed-a2a?style=social)](https://github.com/QWED-AI/qwed-a2a)

  <a href="https://www.nvidia.com/en-us/startups/"><img src="https://img.shields.io/badge/NVIDIA-Inception_Program-76B900?style=for-the-badge&logo=nvidia&logoColor=white" alt="NVIDIA Inception Program" height="28"></a>

  <br>

  <a href="#-quick-start">Quick Start</a> ·
  <a href="#-how-it-works">How It Works</a> ·
  <a href="#-verification-engines">Engines</a> ·
  <a href="#-zero-trust-boundary">Trust Boundary</a> ·
  <a href="#-crypto-attestations">Attestations</a> ·
  <a href="https://docs.qwedai.com/a2a/overview">📖 Full Documentation</a>
</div>

---

## 🎯 What is QWED A2A?

QWED A2A is a **verification interceptor** for Google's [Agent-to-Agent (A2A) protocol](https://google.github.io/A2A/). It sits between autonomous agents and verifies every inter-agent payload before it reaches the recipient.

**This is NOT a domain guard.** Unlike QWED Finance (banking math) or QWED Legal (citations), A2A is **infrastructure-level** — it intercepts ALL agent communication and routes to the right verification engine.

| Without A2A | With A2A |
|-------------|----------|
| Agent sends wrong total → **Propagates** downstream | **Blocked** — math hallucination detected |
| Agent sends `os.system()` code → **Executes** on receiver | **Blocked** — dangerous pattern detected |
| Agent makes contradictory claims → **Accepted** silently | **Blocked** — logical contradiction caught |
| Rogue agent floods messages → **No limit** — DoS possible | **Rate-limited** — token bucket enforced |
| No audit trail → Nothing to prove | **JWT attestation** — cryptographic proof of every decision |

---

## ⚡ Quick Start

### Installation

```bash
# From source (recommended for now)
git clone https://github.com/QWED-AI/qwed-a2a.git
cd qwed-a2a
pip install -e ".[dev]"
```

### Your First Verification

```python
import asyncio
from qwed_a2a.interceptor import A2AVerificationInterceptor
from qwed_a2a.protocol.schema import AgentMessage, PayloadType

interceptor = A2AVerificationInterceptor()

# Trust the communicating agents (Zero-Trust default)
interceptor.trust.trust_agent("procurement-agent")
interceptor.trust.trust_agent("treasury-agent")

message = AgentMessage(
    sender_agent_id="procurement-agent",
    receiver_agent_id="treasury-agent",
    payload_type=PayloadType.FINANCIAL_TRANSACTION,
    payload={
        "data": {
            "claimed_total": 150.00,
            "line_items": [
                {"description": "Widget A", "amount": 50.00, "quantity": 2},
                {"description": "Widget B", "amount": 25.00, "quantity": 2},
            ]
        }
    }
)

async def main():
    verdict = await interceptor.intercept(message, trace_id="demo_001")
    print(f"Status:  {verdict.status.value}")    # forwarded ✅
    print(f"Engine:  {verdict.engine_used}")      # finance_guard
    print(f"JWT:     {verdict.attestation_jwt[:50]}...")

asyncio.run(main())
```

**Output:**
```text
Status:  forwarded ✅
Engine:  finance_guard
JWT:     eyJhbGciOiJFUzI1NiIsInR5cCI6InF3ZWQtYTJhLWF0dGVz...
```

---

## 🔬 How It Works

Every inter-agent message flows through **five deterministic stages**:

```text
┌──────────────────────────────────────────────────────────────────┐
│                    QWED A2A INTERCEPTOR                          │
│                                                                  │
│  Agent A ──▶ [Schema] ──▶ [Trust] ──▶ [Engine] ──▶ [JWT] ──▶ ? │
│               Validate     Boundary    Verify      Sign          │
│                                                                  │
│                                         │                        │
│                              ┌──────────┴──────────┐            │
│                              ▼                      ▼            │
│                        ✅ FORWARDED             ❌ BLOCKED       │
│                        + attestation            + reason         │
│                        → Agent B                → Agent A        │
└──────────────────────────────────────────────────────────────────┘
```

| Stage | Component | What It Does |
|-------|-----------|-------------|
| **0. Schema** *(endpoint layer)* | Pydantic `AgentMessage` | Validates sender/receiver IDs, payload type, timestamp — runs at FastAPI before `intercept()` |
| **1. Trust** | `TrustBoundary` | Blocklists, allowlists, pair blocks, token-bucket rate limiting |
| **2. Bypass** | Trusted agents check | Skips verification for agents in `config.trusted_agents` |
| **3. Engine** | `_route_to_engine()` | Routes to `finance_guard`, `logic_guard`, `code_guard`, or `passthrough` |
| **4. Verdict + JWT** | `A2ACryptoService` | Builds verdict and signs with ES256 JWT (payload hash, trace ID) |

---

## 🛡️ Verification Engines

### 🧮 Finance Guard — Decimal Arithmetic

Recomputes totals from line items using `decimal.Decimal`. Catches math hallucinations.

```python
# Agent claims total is $999.99, but line items add up to $150.00
# → ❌ BLOCKED: "Mathematical hallucination detected: claimed_total=999.99, computed_total=150.00"
```

> **Precision:** `ROUND_HALF_UP` quantized to `0.01`. Floating-point arithmetic is **never** used.

### ⚖️ Logic Guard — Contradiction Detection

Detects logical contradictions using set-based analysis. If a claim is both asserted and negated, the message is blocked.

```python
# Agent says "budget_approved" AND "budget_approved is false"
# → ❌ BLOCKED: "Logical contradiction detected: claims both asserted and negated: ['budget_approved']"
```

> **Determinism:** Contradictions are `sorted()` before output — stable across all environments.

### 🔒 Code Guard — Regex Security Scan

Scans code payloads for dangerous patterns using case-insensitive compiled regex:

| Pattern | Catches |
|---------|---------|
| `eval` | `eval(`, `EVAL (`, dynamic evaluation |
| `exec` | `exec(`, code execution |
| `subprocess` | `subprocess.run`, `import subprocess`, `from subprocess import` |
| `os.system` | `os.system(`, shell command execution |
| `os.popen` | Process spawning via popen |
| `__import__` | Dynamic imports |
| `compile` | Code compilation |
| `importlib` | Runtime module loading |

> **Hardened:** Subprocess regex catches import statements and aliases, not just `subprocess.call()`.

### 📦 Passthrough

Messages with `payload_type` of `GENERAL` or `DATA_QUERY` are forwarded without verification.

---

## 🔐 Zero-Trust Boundary

The `TrustBoundary` enforces **deny-all by default**. No communication is allowed unless explicitly permitted.

```python
from qwed_a2a.security.trust_boundary import TrustBoundary

# Deny all by default
boundary = TrustBoundary()  # default_allow=False

# Explicitly trust specific agents
boundary.trust_agent("procurement-agent")
boundary.trust_agent("treasury-agent")

# Block a rogue agent globally
boundary.block_agent("rogue-agent-007")

# Block a specific pair
boundary.block_pair("agent-A", "agent-B")
```

### Evaluation Order

| Step | Check | On Failure |
|------|-------|------------|
| 1 | Sender on global blocklist? | **BLOCKED** |
| 2 | Receiver on global blocklist? | **BLOCKED** |
| 3 | Pair explicitly blocked? | **BLOCKED** |
| 4 | (Strict mode) Both in allowlist? | **BLOCKED** |
| 5 | Token bucket has tokens? | **RATE LIMITED** |
| ✅ | All passed | **ALLOWED** |

### Token-Bucket Rate Limiting

- **Algorithm:** Token bucket (not fixed-window) — smooth, fair enforcement
- **Eviction:** Cold pairs (no requests for 5 min) are automatically evicted to prevent memory exhaustion
- **Map spray prevention:** Rate-limit state is only allocated **after** allowlist checks pass

---

## 🔏 Crypto Attestations

Every verdict includes a signed **ES256 JWT attestation**:

```json
{
  "iss": "did:qwed:a2a:local",
  "sub": "sha256:e3b0c44298fc1c...",
  "iat": 1711411200,
  "exp": 1711497600,
  "jti": "a2a_trace_001",
  "qwed_a2a": {
    "version": "1.0",
    "verdict": "forwarded",
    "engine": "finance_guard",
    "sender": "procurement-agent",
    "receiver": "treasury-agent"
  }
}
```

| Feature | Details |
|---------|---------|
| **Algorithm** | ECDSA P-256 (ES256) |
| **Tamper detection** | `sub` claim contains SHA-256 hash of original payload |
| **Identity** | DID-based issuer (`did:qwed:a2a:local`) |
| **Expiry** | 24 hours default |
| **Cross-service** | Each instance has its own key pair |

### Graceful Degradation

If `cryptography` and `PyJWT` are not installed, the interceptor operates **without attestations**. Verdicts are still generated, but `attestation_jwt` will be `None`.

---

## 🚀 FastAPI Gateway

QWED A2A includes a ready-to-use HTTP gateway:

```python
from fastapi import FastAPI
from qwed_a2a.protocol.endpoints import router

app = FastAPI(title="QWED A2A Gateway")
app.include_router(router)

# uvicorn main:app --host 0.0.0.0 --port 8000
```

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/a2a/intercept` | POST | Verify agent message — returns verdict + attestation |
| `/a2a/health` | GET | Service health check |
| `/a2a/metrics` | GET | Intercept metrics (forwarded, blocked, errors) |

### cURL Test

```bash
curl -X POST http://localhost:8000/a2a/intercept \
  -H "Content-Type: application/json" \
  -d '{
    "sender_agent_id": "agent-A",
    "receiver_agent_id": "agent-B",
    "payload_type": "general",
    "payload": {"message": "Hello!"}
  }'
```

---

## 🏗️ Architecture

```text
qwed-a2a/
├── src/qwed_a2a/
│   ├── interceptor.py          # Core verification pipeline
│   ├── protocol/
│   │   ├── schema.py           # Pydantic models (AgentMessage, Verdict, Config)
│   │   └── endpoints.py        # FastAPI router with /a2a/intercept
│   ├── security/
│   │   ├── trust_boundary.py   # Zero-trust enforcement + token-bucket rate limiter
│   │   └── crypto.py           # ES256 JWT attestations (A2ACryptoService)
│   └── utils/
│       └── telemetry.py        # Sentry integration + structured logging
├── tests/
│   ├── test_interceptor.py     # Financial, logic, code, general test suites
│   └── conftest.py             # Shared fixtures
├── pyproject.toml
└── LICENSE                     # Apache 2.0
```

---

## ⚙️ Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enable_financial_verification` | `bool` | `True` | Route financial payloads to math verification |
| `enable_logic_verification` | `bool` | `True` | Route logic assertions to contradiction checks |
| `enable_code_verification` | `bool` | `True` | Route code payloads to regex security scanning |
| `block_on_error` | `bool` | `True` | Block on internal engine errors (set `False` for shadow mode) |
| `max_payload_size_bytes` | `int` | `1,048,576` | Maximum payload size (1 MB) |
| `trusted_agents` | `List[str]` | `None` | Agent IDs that bypass verification |

---

## 🧪 Testing

```bash
# Run all tests
pytest tests/ -v

# Run specific test suite
pytest tests/test_interceptor.py::TestInterceptorFinancial -v
pytest tests/test_interceptor.py::TestInterceptorCode -v
pytest tests/test_interceptor.py::TestInterceptorLogic -v
```

All tests use deterministic `trace_id` injection — no randomness, fully reproducible.

---

## 📋 Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `pydantic` | ≥2.5.0 | Schema validation (AgentMessage, Config) |
| `fastapi` | ≥0.104.0 | HTTP gateway for inter-agent routing |
| `cryptography` | ≥41.0.0 | ECDSA P-256 key generation for attestations |
| `PyJWT` | ≥2.8.0 | JWT signing and verification |
| `sentry-sdk` | ≥2.13.0 | Error tracking and telemetry |

---

## 🌐 Part of the QWED Ecosystem

QWED A2A is the infrastructure-level verification gateway in the QWED ecosystem:

| Package | What It Does | Link |
|---------|-------------|------|
| **qwed** | Core verification engines (Math, Logic, SQL, Code) | [GitHub](https://github.com/QWED-AI/qwed-verification) |
| **qwed-a2a** | **This repo** — Agent-to-Agent verification interceptor | — |
| **qwed-finance** | Banking, loans, NPV, ISO 20022 verification | [GitHub](https://github.com/QWED-AI/qwed-finance) |
| **qwed-legal** | Contracts, deadlines, citations, jurisdiction | [GitHub](https://github.com/QWED-AI/qwed-legal) |
| **qwed-tax** | Tax compliance & withholding verification | [GitHub](https://github.com/QWED-AI/qwed-tax) |
| **qwed-infra** | IaC verification (Terraform, IAM, Cost) | [GitHub](https://github.com/QWED-AI/qwed-infra) |
| **qwed-mcp** | Claude Desktop MCP integration | [GitHub](https://github.com/QWED-AI/qwed-mcp) |

📖 [Full Documentation](https://docs.qwedai.com/a2a/overview) · 🎓 [Free Course](https://github.com/QWED-AI/qwed-learning)

---

## 📄 License

Apache 2.0 — See [LICENSE](LICENSE) for details.

---

<div align="center">
  <sub>Built with ❤️ by <a href="https://github.com/QWED-AI">QWED-AI</a></sub>
</div>
