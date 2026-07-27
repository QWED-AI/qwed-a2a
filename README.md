<div align="center">
  <img src="assets/logo.svg" alt="QWED Logo" width="80" height="80">
  <h1>QWED A2A</h1>
  <h3>Zero-Trust Verification Interceptor for Agent-to-Agent Communication</h3>

  > **QWED A2A** intercepts every payload between autonomous agents, runs deterministic verification, and either **forwards** or **blocks** the message — with a signed JWT attestation proving the decision.

  <p>
    <b>Agents don't trust each other. QWED verifies for them.</b>
  </p>

  [![PyPI](https://img.shields.io/pypi/v/qwed-a2a.svg)](https://pypi.org/project/qwed-a2a/)
  [![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)
  [![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
  [![Tests](https://github.com/QWED-AI/qwed-a2a/actions/workflows/ci.yml/badge.svg)](https://github.com/QWED-AI/qwed-a2a/actions)
  [![CodSpeed](https://img.shields.io/endpoint?url=https://codspeed.io/badge.json)](https://app.codspeed.io/QWED-AI/qwed-a2a?utm_source=badge)
  [![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=QWED-AI_qwed-a2a&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=QWED-AI_qwed-a2a)
  [![QWED Security](https://img.shields.io/badge/GitHub_Marketplace-QWED_Security_%E2%9C%93-2ea44f?style=flat&logo=github&logoColor=white)](https://github.com/marketplace/qwed-security)
  [![Snyk](https://img.shields.io/badge/Snyk-Security_Monitored-4C4F4D?logo=snyk&logoColor=white)](https://snyk.io/test/github/QWED-AI/qwed-a2a)
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

### Prerequisites — Signing Key

QWED A2A requires a persistent ECDSA P-256 signing key for audit continuity
(ephemeral per-process keys broke cross-restart verification). Set the key via the
`QWED_A2A_SIGNING_KEY_PEM` environment variable:

```bash
# Generate a new P-256 private key (PKCS#8 format):
openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt > qwed-a2a-key.pem

# Set the environment variable:
export QWED_A2A_SIGNING_KEY_PEM=$(cat qwed-a2a-key.pem)
```

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

Every inter-agent message flows through **four deterministic stages**:

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
| **2. Engine** | `_route_to_engine()` | Routes to `finance_guard`, `logic_guard`, `code_guard`, or returns `unverifiable` |
| **3. Verdict + JWT** | `A2ACryptoService` | Builds verdict and signs with ES256 JWT (payload hash, trace ID). UNVERIFIABLE verdicts carry no JWT |

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

### 🔒 Code Guard — AST + Heuristic Security Scan

Scans code payloads using a **dual-layer approach**:

**Layer 1 — AST structural analysis (primary):** Parses code into an abstract syntax tree and detects direct dangerous constructs structurally:

| Threat | Example |
|--------|---------|
| Dangerous calls | `eval(`, `exec(`, `compile(`, `__import__(` |
| Dangerous receiver methods | `subprocess.run(`, `os.system(`, `os.popen(` |
| Dangerous imports | `import subprocess`, `import importlib`, `import ctypes` |

**Layer 2 — Regex heuristic scan (secondary):** Catches obfuscation patterns that survive AST parsing:

| Pattern | Catches |
|---------|---------|
| `getattr_builtin` | `getattr(__builtins__, ...)` |
| `builtins_dict_access` | `__builtins__.__dict__[` |
| `base64_exec` | `b64decode(` encoded payloads |
| `dynamic_import` | `__import__(` dynamic imports |
| `os_system` | `os.system(` shell execution |
| `os_popen` | `os.popen(` process spawning |

> **Result:** Returns `BLOCKED` if any threat is found (noting which layer detected it), or `HEURISTIC_PASS` if both layers are clean. A `HEURISTIC_PASS` is *not* a deterministic guarantee — it means no known dangerous constructs were found.

### 📦 Passthrough (Unverifiable)

Messages with `payload_type` of `GENERAL` or `DATA_QUERY` have no verification engine. The interceptor returns an **UNVERIFIABLE** verdict — the message is not forwarded, and no JWT attestation is issued. This prevents false cryptographic claims about unverified content.

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
| 4 | (Strict mode) Neither in allowlist? | **BLOCKED** |
| 5 | Token bucket has tokens? | **RATE LIMITED** |
| ✅ | All passed | **ALLOWED** |

### Token-Bucket Rate Limiting

- **Algorithm:** Token bucket (not fixed-window) — smooth, fair enforcement
- **Eviction:** Cold pairs (no requests for 5 min) are automatically evicted to prevent memory exhaustion
- **Map spray prevention:** Rate-limit state is only allocated **after** allowlist checks pass

---

## 🔏 Crypto Attestations

FORWARDED, BLOCKED, and HEURISTIC_PASS verdicts include a signed **ES256 JWT attestation**. UNVERIFIABLE verdicts carry **no JWT** — issuing a signed token for unverified content would be a false cryptographic claim.

```json
{
  "iss": "did:qwed:a2a:local",
  "sub": "sha256:e3b0c44298fc1c...",
  "iat": 1711411200,
  "exp": 1711411500,
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
| **Expiry** | 300 seconds (5 minutes) default — short-lived attestation token validity window |
| **Key persistence** | Ephemeral keys replaced by `QWED_A2A_SIGNING_KEY_PEM` env var for audit continuity |

### Fail-Closed Attestations

`cryptography` and `PyJWT` are required dependencies. If they are unavailable,
the interceptor raises at startup instead of returning unsigned verdicts. Signing
failures also fail closed so `attestation_jwt=None` is never emitted as a normal
verdict.

The signing key is also fail-closed: if `QWED_A2A_SIGNING_KEY_PEM` is not set,
the first call to sign an attestation raises `RuntimeError` rather than silently
falling back to an ephemeral key.

---

## 🚀 FastAPI Gateway

QWED A2A includes a ready-to-use HTTP gateway. Because the interceptor uses a zero-trust default posture, you must whitelist agents via the `QWED_A2A_TRUSTED_AGENTS` environment variable.

```python
from fastapi import FastAPI
from qwed_a2a.protocol.endpoints import router, wellknown_router

app = FastAPI(title="QWED A2A Gateway")
app.include_router(router)
app.include_router(wellknown_router)

# QWED_A2A_TRUSTED_AGENTS="agent-A,agent-B" uvicorn main:app --host 0.0.0.0 --port 8000
```

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/a2a/intercept` | POST | Verify agent message — returns verdict + attestation |
| `/a2a/health` | GET | Service health check |
| `/a2a/metrics` | GET | Intercept metrics (forwarded, blocked, errors) |
| `/.well-known/jwks.json` | GET | Public JWK set for JWT verification |

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
| `trusted_agents` | `List[str]` | `None` | Agent IDs pre-added to the trust boundary allowlist |

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
