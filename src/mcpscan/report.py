"""Severity ordering and report rendering (text + Markdown + JSON + SARIF)."""

from __future__ import annotations

import json\n\n_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}

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
