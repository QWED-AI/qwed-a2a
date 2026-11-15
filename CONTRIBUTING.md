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

## Licence

QWED A2A is licensed under the [Apache License 2.0](./LICENSE), and contributions are accepted under the same licence:

- **Inbound = outbound.** Under section 5 of the licence, a contribution you submit for inclusion is licensed under the Apache License 2.0, with no additional terms, unless you explicitly state otherwise.
- **You keep your copyright.** The licence lets everyone, the maintainer included, use, change and redistribute your contribution. Under section 3 you also grant a patent licence, limited to the patent claims you can license that your contribution necessarily infringes, alone or combined with QWED A2A.
- **Only submit what you have the right to submit:** your own work, or code under a licence that is compatible with Apache-2.0, with its notices kept. Code under the GPL, the AGPL or another licence that is not compatible cannot be accepted.
- **The names are not licensed.** See [TRADEMARKS.md](./TRADEMARKS.md) for using "QWED" and its logo, and [NOTICE](./NOTICE) for the attribution that redistributions keep.
