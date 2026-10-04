# MCP Security Scanner Comparative Research

Date: 2026-10-04

## Scope

This report compares the publicly documented security surface of `mcpscan` with other MCP/agent security scanners. It deliberately separates:

1. **Measured benchmark results** — produced by executing a scanner against the versioned corpus.
2. **Documented capabilities** — claims or features described by the project itself.

Documented capabilities are not treated as benchmark detections.

## Reproducible baseline

`mcpscan` maintains a deterministic 16-case corpus in `benchmarks/manifest.json`.

The release CI executes:

- Ruff on Python 3.10 and 3.12
- 33 automated tests
- the 16-case benchmark
- wheel/sdist builds

The current baseline passes all 16 benchmark cases.

## Public capability comparison

| Scanner | MCP surface scanning | Tool poisoning / prompt injection | Runtime / proxy | Source / SAST | Discovery | Notes |
|---|---:|---:|---:|---:|---:|---|
| mcpscan | Yes | Yes | Read-only discovery | No | Authorized inventory | Deterministic static scanner; SARIF; JSON; aggregate discovery |
| Snyk Agent Scan | Yes | Yes | Yes / connection scanning | Agent/skill ecosystem | Yes | Scans agent components including MCP servers and skills |
| Invariant MCP-Scan | Yes | Yes | Yes / proxy | Policy / guardrails | Yes | Tool shadowing, rug-pull detection, runtime controls |
| MCPRadar | Yes | Yes | Yes | Yes | Yes | Protocol surface, source, configuration and supply-chain analysis |
| mcp-security-scanner | Yes | Yes | Yes | Yes | Yes | Broad runtime, SAST, config, dependency and OWASP checks |
| MK ScorpioSec mcp-scanner | Yes | Yes | Target-oriented | Limited/documented | Config support | CVE, auth, SSRF, credential, input-validation and supply-chain checks |

## What is actually measured

For this repository, the only numerical benchmark claim is the native deterministic corpus result.

No competitor accuracy, false-positive rate, false-negative rate, or runtime number is published here unless the exact scanner version is executed against the exact same corpus through a documented adapter.

This prevents misleading claims such as treating a feature mentioned in a README as proof that a scanner detects every corresponding synthetic case.

## Why the benchmark is intentionally conservative

Different scanners operate at different layers:

- protocol-definition inspection;
- client configuration discovery;
- live server interaction;
- source-code SAST;
- dependency and supply-chain analysis;
- runtime proxy enforcement.

A single 16-case tool-definition corpus cannot fairly score all of these layers. The corpus is therefore a regression benchmark for the static MCP-definition layer, not a universal security score.

## Next benchmark extension

A stronger comparative study should add separate corpora for:

1. protocol-definition poisoning;
2. runtime toxic flows;
3. source-code injection/SSRF;
4. configuration and authentication;
5. dependency/supply-chain risks;
6. tool mutation / rug-pull behavior.

Each corpus should define its own ground truth and scanner adapters.

## Sources

- Snyk Agent Scan: https://github.com/snyk/agent-scan
- Invariant MCP-Scan: https://github.com/invariantlabs-ai/mcp-scan
- MCPRadar: https://github.com/yatuk/mcpradar
- mcp-security-scanner: https://github.com/badchars/mcp-security-scanner
- MCP scanner: https://github.com/MK-ScorpioSec/mcp-scanner
