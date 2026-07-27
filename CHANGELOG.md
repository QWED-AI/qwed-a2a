# Changelog

## [0.2.0] — 2026-07-27

First public release of qwed-a2a.

### Features

- [#59](https://github.com/QWED-AI/qwed-a2a/pull/59) Add CodSpeed continuous performance benchmarking
- [#60](https://github.com/QWED-AI/qwed-a2a/pull/60) Add community files, CI configs, PyPI publish workflow, and badges
- [#1](https://github.com/QWED-AI/qwed-a2a/pull/1) Bootstrap base architecture and security orchestrations
- [#2](https://github.com/QWED-AI/qwed-a2a/pull/2) Implement A2A verification interceptor with crypto, trust boundary, telemetry, and full test suite

### Fixes

#### Security & Trust

- [#20](https://github.com/QWED-AI/qwed-a2a/pull/20) Remove trusted-agent verification bypass (closes #5)
- [#21](https://github.com/QWED-AI/qwed-a2a/pull/21) Fail closed without attestations
- [#25](https://github.com/QWED-AI/qwed-a2a/pull/25) GENERAL/DATA_QUERY passthrough returns UNVERIFIABLE (closes #6)
- [#26](https://github.com/QWED-AI/qwed-a2a/pull/26) JWT replay prevention — validity 24h→5min, jti registry, context binding (closes #8)
- [#27](https://github.com/QWED-AI/qwed-a2a/pull/27) CodeGuard AST+heuristic dual-layer scan (closes #9)
- [#29](https://github.com/QWED-AI/qwed-a2a/pull/29) Replace ephemeral key generation with persistent QWED_A2A_SIGNING_KEY_PEM
- [#30](https://github.com/QWED-AI/qwed-a2a/pull/30) Scoped, expiring, revocable trust entries
- [#32](https://github.com/QWED-AI/qwed-a2a/pull/32) Enforce sender must be trusted for communication
- [#40](https://github.com/QWED-AI/qwed-a2a/pull/40) Empty finance/logic payload returns UNVERIFIABLE (closes #10)
- [#41](https://github.com/QWED-AI/qwed-a2a/pull/41) Add AttestationContext binding to verify_attestation (closes #14)
- [#57](https://github.com/QWED-AI/qwed-a2a/pull/57) Fix 5 materially false claims in README about current code behavior

#### CI & Tooling

- [#4](https://github.com/QWED-AI/qwed-a2a/pull/4) Harden CI/CD pipelines with SHA-pinned GitHub Actions
- [#23](https://github.com/QWED-AI/qwed-a2a/pull/23) Add SonarCloud, Snyk SAST, and Codecov — fix blocking lint
- [#24](https://github.com/QWED-AI/qwed-a2a/pull/24) Add statuses: write permission to sonar.yml for PR decoration
- [#42](https://github.com/QWED-AI/qwed-a2a/pull/42) Remove unused qwed-finance/qwed-ucp, add upper bounds, add lockfile (closes #37)
- [#43](https://github.com/QWED-AI/qwed-a2a/pull/43) Add dependabot.yml for pip and GitHub Actions (closes #36)
- [#58](https://github.com/QWED-AI/qwed-a2a/pull/58) Make Snyk a blocking security gate

### Maintenance

- [#3](https://github.com/QWED-AI/qwed-a2a/pull/3) Add comprehensive README with architecture, engines, and ecosystem overview
- [#44](https://github.com/QWED-AI/qwed-a2a/pull/44) Bump Mergifyio/gha-mergify-ci from 6 to 24
- [#45](https://github.com/QWED-AI/qwed-a2a/pull/45) Bump SonarSource/sonarqube-scan-action from 4.2.1 to 8.2.1
- [#46](https://github.com/QWED-AI/qwed-a2a/pull/46) Bump actions/checkout from 4.1.7 to 7.0.1
- [#47](https://github.com/QWED-AI/qwed-a2a/pull/47) Bump github/codeql-action/init from 3.35.1 to 4.37.3
- [#48](https://github.com/QWED-AI/qwed-a2a/pull/48) Bump github/codeql-action/upload-sarif from 3.35.1 to 4.37.3
- [#49](https://github.com/QWED-AI/qwed-a2a/pull/49) Bump pydantic from 2.12.5 to 2.13.4
- [#50](https://github.com/QWED-AI/qwed-a2a/pull/50) Bump cryptography from 48.0.1 to 49.0.0
- [#51](https://github.com/QWED-AI/qwed-a2a/pull/51) Bump pytest-asyncio from 1.3.0 to 1.4.0
- [#53](https://github.com/QWED-AI/qwed-a2a/pull/53) Bump sentry-sdk from 2.52.0 to 2.66.1
- [#54](https://github.com/QWED-AI/qwed-a2a/pull/54) Bump pygments from 2.19.2 to 2.20.0
- [#55](https://github.com/QWED-AI/qwed-a2a/pull/55) Bump pytest from 9.0.1 to 9.0.3
- [#56](https://github.com/QWED-AI/qwed-a2a/pull/56) Bump idna from 3.11 to 3.15
- [#61](https://github.com/QWED-AI/qwed-a2a/pull/61) Update QWED Security badge in README.md
