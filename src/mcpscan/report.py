"""Severity ordering and report rendering (text + Markdown + JSON + SARIF)."""

from __future__ import annotations

import hashlib
import json

_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
_SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.0", "low": "2.0", "info": "0.0"}

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}
_EMOJI = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟦", "info": "⬜"}


def rank(sev: str) -> int:
    return _RANK.get(sev, 0)


def sort_findings(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: (-rank(f.get("severity", "info")), f.get("target", "")))


def worst(findings: list[dict]) -> str:
    return max((f.get("severity", "info") for f in findings), key=rank, default="info")


def to_json(server: str, findings: list[dict]) -> str:
    return json.dumps({
        "server": server,
        "total": len(findings),
        "worst_severity": worst(findings) if findings else None,
        "findings": sort_findings(findings),
    }, indent=2, ensure_ascii=False)


def _sarif_fingerprint(server: str, finding: dict) -> str:
    """Create a stable identity for a finding across CI runs."""
    identity = "\x1f".join([
        server,
        finding.get("category", "unknown"),
        finding.get("target", ""),
        finding.get("title", ""),
    ])
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _sarif_location(finding: dict) -> dict | None:
    """Map an optional scanner location into a SARIF physical location."""
    location = finding.get("location")
    if not isinstance(location, dict) or not location.get("uri"):
        return None
    region = {}
    for key, sarif_key in (("start_line", "startLine"), ("start_column", "startColumn"),
                           ("end_line", "endLine"), ("end_column", "endColumn")):
        if location.get(key) is not None:
            region[sarif_key] = location[key]
    physical = {"artifactLocation": {"uri": location["uri"]}}
    if region:
        physical["region"] = region
    return {"physicalLocation": physical}


def to_sarif(server: str, findings: list[dict]) -> str:
    """Render findings as SARIF 2.1.0 for GitHub Code Scanning and other tools."""
    rules = {}
    results = []
    for f in sort_findings(findings):
        category = f.get("category", "unknown")
        rule_id = f"MCPSCAN/{category}"
        severity = f.get("severity", "info")
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": category,
            "shortDescription": {"text": f.get("title", category)},
            "helpUri": "https://github.com/nadirzhon/mcpscan#what-the-checks-cover",
            "defaultConfiguration": {"level": _SARIF_LEVEL.get(severity, "note")},
            "properties": {
                "security-severity": _SECURITY_SEVERITY.get(severity, "0.0"),
                "tags": ["security", "mcp", category],
            },
        })
        result = {
            "ruleId": rule_id,
            "ruleIndex": list(rules).index(rule_id),
            "level": _SARIF_LEVEL.get(severity, "note"),
            "message": {"text": (
                f"{f.get('description', '')} Recommendation: {f.get('recommendation', '')}"
            ).strip()},
            "partialFingerprints": {
                "primaryLocationLineHash": _sarif_fingerprint(server, f),
            },
            "properties": {
                "severity": severity,
                "security-severity": _SECURITY_SEVERITY.get(severity, "0.0"),
                "category": category,
                "target": f.get("target", ""),
                "source": f.get("source", "static"),
            },
        }
        location = _sarif_location(f)
        if location:
            result["locations"] = [location]
        results.append(result)
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "mcpscan",
                "informationUri": "https://github.com/nadirzhon/mcpscan",
                "version": "0.2.0",
                "rules": list(rules.values()),
            }},
            "automationDetails": {"id": f"mcpscan/{server}"},
            "results": results,
        }],
    }
    return json.dumps(document, indent=2, ensure_ascii=False)

def to_terminal(server: str, findings: list[dict], surface_counts: dict) -> str:
    lines = [
        "",
        f"  mcpscan — {server}",
        (f"  tools: {surface_counts.get('tools', 0)}  resources: {surface_counts.get('resources', 0)}  "
         f"prompts: {surface_counts.get('prompts', 0)}"),
        "  " + "─" * 52,
    ]
    if not findings:
        lines.append("  ✅ No security issues found in the MCP surface.")
        return "\n".join(lines) + "\n"
    for f in sort_findings(findings):
        sev = f.get("severity", "info")
        lines.append(f"  {_EMOJI.get(sev, '⬜')} [{sev.upper()}] {f.get('title', '')}")
        lines.append(f"     target: {f.get('target', '-')}  ·  {f.get('category', '-')}")
        lines.append(f"     {f.get('description', '')}")
        lines.append(f"     fix: {f.get('recommendation', '')}")
        lines.append("")
    counts = {s: sum(1 for f in findings if f.get("severity") == s) for s in SEVERITY_ORDER}
    summ = "  ".join(f"{_EMOJI[s]} {counts[s]} {s}" for s in reversed(SEVERITY_ORDER) if counts[s])
    lines.append("  " + "─" * 52)
    lines.append(f"  {len(findings)} finding(s): {summ}")
    return "\n".join(lines) + "\n"


def to_markdown(server: str, findings: list[dict], surface_counts: dict) -> str:
    lines = [f"# mcpscan report — `{server}`", "",
             (f"Surface: **{surface_counts.get('tools', 0)}** tools · "
              f"**{surface_counts.get('resources', 0)}** resources · "
              f"**{surface_counts.get('prompts', 0)}** prompts"), ""]
    if not findings:
        lines.append("✅ No security issues found.")
        return "\n".join(lines)
    for f in sort_findings(findings):
        sev = f.get("severity", "info")
        tag = "🤖" if f.get("source") == "ai" else "🔎"
        lines += [f"### {_EMOJI.get(sev, '⬜')} {f.get('title', '')} — {sev.upper()}",
                  f"{tag} `{f.get('target', '-')}` · _{f.get('category', '-')}_", "",
                  f.get("description", ""), "", f"**Fix:** {f.get('recommendation', '')}", ""]
    return "\n".join(lines)
