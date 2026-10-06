# mcpscan

**Security scanner for Model Context Protocol (MCP) servers.**

mcpscan audits the tools, resources and prompts exposed by an MCP server before an AI agent connects to it. It detects tool poisoning, hidden instructions, dangerous capabilities, unconstrained inputs and other agent-facing security risks.

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![MCP](https://img.shields.io/badge/MCP-security-8A63D2)
![CI](https://github.com/nadirzhon/mcpscan/actions/workflows/ci.yml/badge.svg)
![PyPI](https://img.shields.io/pypi/v/mcpsecscan)

## The problem

MCP moves tools directly into an AI agent's context. A tool description is therefore not just documentation — it can become part of the agent's instruction surface.

mcpscan treats that surface as a security boundary.

It looks for:

- **Tool poisoning** — instruction-like content hidden in tool descriptions
- **Invisible text** — zero-width, bidi and Unicode tag characters
- **Dangerous capabilities** — command execution, file mutation, network egress and credential access
- **Unconstrained inputs** — free-form path, command, URL, query and SQL parameters
- **Weak schemas** — permissive object definitions
- **Oversized descriptions** — unusually large descriptions that can hide payloads
- **Tool combinations** — additional reasoning-based risks when AI analysis is enabled

## Install

```bash
pip install mcpsecscan
```

Or run without a local install:

```bash
uvx mcpsecscan <server>
```

Examples:

```bash
uvx mcpsecscan https://example.com/mcp
uvx mcpsecscan "python my_server.py"
uvx mcpsecscan "uvx some-published-mcp"
```

## CI / automation

Machine-readable output is built in:

```bash
mcpscan https://example.com/mcp --json
mcpscan https://example.com/mcp --sarif
mcpscan https://example.com/mcp --fail-on high
```

Use SARIF to integrate findings into GitHub code-scanning workflows.

## Checks

| Check | Severity | Detects |
|---|---|---|
| hidden-text | critical | Zero-width, bidi and tag characters |
| tool-poisoning | high | Instruction-like malicious content |
| dangerous-capability | high/medium | Exec, code, file, network and credential access |
| unconstrained-input | medium | Free-string security-sensitive inputs |
| loose-schema | low | Unrestricted object properties |
| oversized-description | low | Suspiciously large descriptions |

### AI-assisted threat analysis

An optional AI layer can reason about relationships between tools, authorization gaps and subtle injection surfaces:

```bash
export ANTHROPIC_API_KEY=...
uvx --with 'mcpsecscan[ai]' mcpsecscan https://example.com/mcp --ai
```

Deterministic checks remain useful without the AI layer.

## Discovery mode

Organizations can scan an explicit inventory of authorized MCP servers:

```bash
mcpscan --discover examples/inventory.json --json
mcpscan --discover examples/inventory.json --sarif --max-concurrency 4
```

Discovery is explicit and read-only: mcpscan connects only to servers listed in the inventory and does not invoke their tools.

## Example

```text
mcpscan — https://example/mcp
tools: 7  resources: 2  prompts: 1
────────────────────────────────────────────
CRITICAL  hidden-text
HIGH      tool-poisoning
MEDIUM    unconstrained-input

3 findings
```

## Engineering focus

This project demonstrates a practical AI-security workflow:

```
MCP server
   ↓
structured inspection
   ↓
deterministic security checks
   ↓
optional AI threat analysis
   ↓
JSON / Markdown / SARIF
   ↓
CI / security workflow
```

## Research

mcpscan is also used by [State of MCP Security](https://github.com/nadirzhon/state-of-mcp-security), a reproducible study of MCP security posture.

## License

MIT © nadirzhon
