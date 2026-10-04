# Changelog

## 0.2.1 — 2026-10-04

### Fixed
- Corrected static capability classification to avoid treating the word `secret` in instruction tags as credential access.
- Added regression coverage for credential false positives.
- Made the deterministic benchmark runner work both as `python benchmarks/run.py` and as a module.
- Corrected the benchmark expectation for the multi-signal URL/network case.

### CI / Release
- CI now validates Python 3.10 and 3.12 with Ruff, 33 tests, the 16-case deterministic benchmark, and distribution builds.
- GitHub Action default ref updated to `v0.2.1`.
- Release metadata is synchronized to `0.2.1`.

## 0.2.0 — 2026-10-04

### Added

- GitHub Code Scanning SARIF 2.1.0 output.
- Stable SARIF fingerprints and optional source locations.
- Deterministic 16-case MCP security benchmark corpus.
- Authorized MCP inventory discovery with bounded concurrency.
- Aggregate JSON and SARIF reporting for multi-server scans.
- Example discovery inventory and regression tests.

### Improved

- Runtime package version aligned with the 0.2.0 release.
- GitHub Action pinned to the v0.2.0 release ref.
- Trusted PyPI publishing workflow using GitHub Actions OIDC.
