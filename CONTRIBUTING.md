# Contributing to QWED A2A

## Required Reading

Before contributing, please read:

- [README.md](README.md) — project overview and architecture
- [SECURITY.md](SECURITY.md) — vulnerability reporting
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — community standards

## Philosophy

QWED A2A is a **zero-trust verification interceptor**. Every change must preserve:

- **Fail-closed** — all error paths block forwarding, never silently degrade
- **Deterministic** — same input always produces same verdict
- **Auditable** — every decision carries a signed JWT attestation

## Development Setup

```bash
git clone https://github.com/QWED-AI/qwed-a2a.git
cd qwed-a2a
pip install -e ".[dev]"
```

Set required environment variables:

```bash
export QWED_A2A_DEPLOYMENT_ID="dev-deployment"
export QWED_A2A_SIGNING_KEY_PEM=$(openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt)
```

If running the FastAPI gateway, also set the trusted agents:

```bash
export QWED_A2A_TRUSTED_AGENTS="agent-A,agent-B"
```

## Running Tests

```bash
pytest tests/ -v
```

## Pull Request Process

1. Create a branch from `main`
2. Make your changes with clear commit messages
3. Ensure all tests pass
4. Update documentation if needed
5. Open a PR with the enforcement checklist filled out

## Code Review Standards

- Each PR requires at least one review
- Enforcement-related changes require verification that no bypass paths exist
- New verification engines must be deterministic

## What NOT to Contribute

- Enterprise features (SSO, RBAC, audit dashboards) belong in a separate repository
- Non-deterministic verification (ML-based scoring, confidence thresholds)
- Changes that weaken fail-closed guarantees
