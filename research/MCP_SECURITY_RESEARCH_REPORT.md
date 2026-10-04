# MCP Security Scanning: A Deterministic Benchmark and Defensive Analysis

**Project:** mcpscan  
**Repository:** https://github.com/nadirzhon/mcpscan  
**Status:** Engineering research report  
**Scope:** Defensive analysis of MCP server/tool definitions

## Abstract

Model Context Protocol (MCP) expands the attack surface of AI applications by allowing models and agents to consume externally supplied tools, resources, prompts, and metadata. Security controls therefore need to inspect not only transport-level behavior, but also the semantic and structural properties of tool definitions.

This report presents the engineering design of mcpscan, an MCP security scanner focused on deterministic, explainable static checks. The project combines security-surface detection, deterministic benchmark cases, SARIF output, authorized MCP discovery, and reproducible reporting.

The central research contribution is methodological: security scanners should be evaluated against a versioned, deterministic corpus rather than by undocumented examples or vendor claims.

## 1. Problem

MCP servers expose machine-readable definitions that can influence model behavior. A malicious or compromised definition can combine several risk signals:

- hidden Unicode and bidirectional text;
- prompt or tool poisoning language;
- dangerous shell, filesystem, or network capabilities;
- credential-access behavior;
- weak or unconstrained input schemas;
- unbounded URLs or filesystem paths;
- unusually long descriptions;
- poisoned resources or prompts;
- multiple simultaneous risk signals.

Traditional source-code scanners do not necessarily see these risks because the security-relevant artifact may be a runtime-discovered tool definition rather than application source code.

## 2. Threat Model

The scanner is designed for authorized defensive assessment of MCP servers and inventories.

### In scope

1. A tool definition contains malicious or deceptive natural-language instructions.
2. A tool definition exposes a dangerous capability.
3. A schema leaves security-sensitive parameters insufficiently constrained.
4. Metadata contains hidden or obfuscated characters.
5. A resource or prompt contains poisoning indicators.
6. An organization wants to inventory multiple authorized MCP servers.

### Out of scope

- exploiting discovered vulnerabilities;
- executing MCP tools during discovery;
- credential theft;
- unauthorized server access;
- claiming that a static scanner proves runtime safety.

A finding is evidence of a security surface, not proof that exploitation is possible.

## 3. Scanner Architecture

The project is structured around a deterministic checks layer and multiple reporting/integration surfaces.

### Static checks

`src/mcpscan/checks.py` evaluates MCP security surfaces without executing the target tool.

### Reporting

The scanner supports human-readable CLI output, JSON reports, SARIF 2.1.0, stable SARIF fingerprints, optional source locations, and aggregate discovery reports.

### Authorized discovery

`src/mcpscan/discovery.py` accepts an explicit inventory and connects only to retrieve definitions. It deliberately does not invoke MCP tools.

Discovery supports JSON inventories, named servers, bounded concurrency, per-server failure isolation, JSON aggregation, and SARIF aggregation.

## 4. Deterministic Benchmark

The benchmark contains 16 synthetic cases. Each case is intentionally small and deterministic so that a scanner can be tested without relying on live infrastructure.

| Surface | Examples |
|---|---|
| Unicode obfuscation | zero-width and bidi characters |
| Instruction injection | ignore-previous/system-style instructions |
| Dangerous capabilities | shell, file-write, network access |
| Sensitive access | credential access |
| Input validation | loose schemas, unconstrained paths/URLs |
| Metadata abuse | excessive descriptions |
| MCP-specific poisoning | resource and prompt poisoning |
| Composite behavior | multi-signal tool |

The expected categories are versioned in `benchmarks/manifest.json`.

The benchmark runner reports exact category matching rather than a vague security score.

## 5. Evaluation Methodology

A valid comparative experiment should record scanner name, exact version or commit, benchmark commit, operating system, runtime version, command line, stdout, stderr, exit code, wall-clock runtime, and normalized findings.

Primary metrics:

### Case detection

Number of benchmark cases for which at least one expected category is detected.

### Category detection

Number of expected category labels detected correctly.

### False-positive rate

Unexpected findings relative to the benchmark expected category set.

### Runtime

Wall-clock time required to process the corpus.

No percentage should be published without the corresponding raw run record.

## 6. Comparative Benchmark Design

The repository defines comparison targets including mcp-security-scanner, MCPRadar, mcp-scan, and mcp-scanner.

Documented capabilities are kept separate from measured benchmark results. This prevents a common methodological error: treating a README feature list as empirical evidence.

Third-party scanners differ in installation model, target representation, runtime requirements, and output formats. Therefore each scanner requires an explicit adapter before it can receive a measured score.

An unavailable scanner is recorded as unavailable, not as zero.

## 7. Reproducibility

Run the baseline with:

    python benchmarks/run.py
    python benchmarks/run.py --json

The expected workflow is: pin the benchmark commit, install the exact scanner version, execute the same corpus, capture raw output, normalize findings, map findings to benchmark categories, calculate metrics, and preserve the run record.

## 8. CI and Developer Integration

mcpscan can emit SARIF 2.1.0 and is packaged with a GitHub Action.

The Action can install a selected mcpscan revision, scan an authorized MCP target, emit SARIF, upload the result to GitHub Code Scanning, and fail the workflow at a configured severity threshold.

SARIF findings include stable partial fingerprints so repeated findings can be correlated across runs.

## 9. Limitations

The current benchmark is deliberately synthetic. It does not establish real-world prevalence, exploitability, runtime behavior of arbitrary MCP implementations, absence of false negatives outside the corpus, or comparative superiority over another scanner without an executed comparison.

Natural-language security detection is inherently heuristic. A scanner should therefore be treated as a triage and detection layer, not as a formal proof of safety.

## 10. Research Questions

### RQ1 — Detection stability

Does a scanner produce stable classifications when the same security signal is represented with benign wording variations?

### RQ2 — Obfuscation resistance

How does detection change when malicious instructions use Unicode obfuscation, whitespace manipulation, or equivalent semantic phrasing?

### RQ3 — Multi-signal correlation

Does combining weak indicators improve detection of compound attacks without causing unacceptable false-positive rates?

### RQ4 — Version regression

Do scanner releases preserve detection coverage against the versioned benchmark corpus?

### RQ5 — Comparative coverage

Which MCP-specific security surfaces are covered by different scanners when evaluated against the same normalized corpus?

## 11. Responsible Use

The project is intended for security engineering, authorized assessments, CI/CD security gates, MCP inventory review, and defensive research.

It should only be used against systems and inventories for which the operator has authorization.

## 12. Conclusion

The primary engineering value of mcpscan is the combination of MCP-specific security checks, deterministic test cases, reproducible benchmark execution, SARIF integration, stable finding fingerprints, authorized discovery, and explicit separation between evidence and claims.

The next research milestone is empirical execution of the comparative adapters and publication of raw benchmark runs. Until those runs exist, this report intentionally makes no unsupported claim that mcpscan is better than competing tools.

## Reproducibility Checklist

- [x] Versioned benchmark corpus
- [x] Deterministic benchmark runner
- [x] Automated benchmark tests
- [x] SARIF output
- [x] Stable finding fingerprints
- [x] Authorized discovery mode
- [x] Comparative benchmark methodology
- [ ] Executed third-party comparative runs
- [ ] Published raw comparative results
- [ ] Independent reproduction