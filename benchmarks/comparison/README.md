# Comparative MCP Security Benchmark

This directory defines a reproducible comparison methodology for MCP security scanners.

## Goal

Measure scanners against the same deterministic corpus instead of comparing marketing claims.

The benchmark separates:

1. Measured results — produced by actually running a scanner.
2. Capability matrix — features documented by the scanner project.
3. Unavailable — a scanner that cannot be installed or executed in the benchmark environment.

An unavailable scanner is **not** scored as zero.

## Corpus

The canonical corpus is `../manifest.json` and currently contains 16 deterministic cases covering hidden Unicode, prompt/tool poisoning, dangerous capabilities, unconstrained inputs, loose schemas, oversized descriptions, resource/prompt poisoning, and multi-signal findings.

## Metrics

For each scanner: case detection, category detection, false-positive rate, runtime, and exact scanner version.

## Reproducibility record

Every run should preserve scanner version/commit, OS/runtime, benchmark commit, command line, stdout/stderr, exit code, runtime, and normalized findings. Do not publish a percentage unless the raw run record is reproducibly available.

## Comparison targets

- mcp-security-scanner: https://github.com/badchars/mcp-security-scanner
- MCPRadar: https://github.com/yatuk/mcpradar
- mcp-scan: https://github.com/rhilgenkamp/mcp-scan
- mcp-scanner: https://github.com/MK-ScorpioSec/mcp-scanner

Their documented capabilities are not benchmark results.

## Baseline

```bash
python benchmarks/run.py
python benchmarks/run.py --json
```

Third-party scanners are not executed automatically because installation and execution semantics differ and some scanners can inspect local configuration or source trees. Add an adapter with explicit installation, version, benchmark command, parser, category mapping, and sandbox requirements before running one.