# MCP Security Benchmark

`mcpscan` includes a small deterministic benchmark corpus for regression testing.

The corpus is synthetic and contains no real secrets, malware, or exploit payloads. It covers hidden Unicode, tool poisoning, dangerous capabilities, loose schemas, unconstrained risky parameters, and oversized descriptions.

## Regression

Run `pytest -q tests/test_benchmark.py`.

AI-assisted findings are excluded so the suite remains deterministic.

## Adding a case

1. Add the case to `manifest.json`.
2. Add its synthetic fixture to `tests/test_benchmark.py`.
3. Document the expected category.
4. Keep fixtures non-destructive.

For comparisons across versions, record the commit SHA and benchmark manifest version.
