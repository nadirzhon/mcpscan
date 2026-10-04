"""Deterministic security checks for an MCP server's advertised surface.

These run without an LLM and without executing any tool — they inspect the tool,
resource, and prompt *definitions* a server exposes for the failure modes that
are specific to the Model Context Protocol: tool poisoning (hidden instructions
in descriptions), over-broad capabilities, hidden/invisible text, and
under-constrained inputs.
"""

from __future__ import annotations

import re

# --- invisible / hidden text (classic tool-poisoning vector) ------------------
# zero-width, bidi overrides, and the Unicode "tag" block (U+E0000–U+E007F) used
# to smuggle instructions past human review.
_HIDDEN = re.compile(
    "[\u200b\u200c\u200d\u2060\ufeff]"        # zero-width
    "|[\u202a-\u202e\u2066-\u2069]"            # bidi controls
    "|[\U000e0000-\U000e007f]"                   # tag characters
)
# --- injected-instruction phrasing inside a description -----------------------
_INJECTION = re.compile(
    r"(?i)(ignore (all |the )?(previous|prior|above)|disregard (the )?(instructions|above)|"
    r"you must (always|never)|do not (tell|mention|inform) the user|"
    r"</?(system|important|secret|instructions?)>|"
    r"before (using|calling) (any|other) tools?|"
    r"as an ai|system prompt|reveal your|print your (system )?prompt)"
)

# --- capabilities that are dangerous without explicit guardrails ---------------
_DANGEROUS = [
    ("command-execution", re.compile(r"(?i)\b(exec|execute|shell|bash|subprocess|system\(|run.?command|eval|spawn)\b")),
    ("file-write-delete", re.compile(r"(?i)\b(delete|remove|unlink|rmdir|overwrite|write.?file|truncate)\b")),
    ("network-egress", re.compile(r"(?i)\b(fetch|http|request|curl|download|upload|post to|send to)\b")),
    ("credential-access", re.compile(r"(?i)\b(token|password|api.?key|credential|private.?key|\.env)\b")),
    ("code-execution", re.compile(r"(?i)\b(python|node|interpreter|arbitrary code|run.?code)\b")),
]

# schema field names that are risky when accepted as free strings
_RISKY_PARAMS = re.compile(r"(?i)^(cmd|command|path|file|filename|url|uri|query|sql|code|script|host|target)s?$")

_MAX_DESC = 1500  # descriptions far longer than needed are a poisoning smell


def _finding(sev, cat, target, title, desc, rec) -> dict:
    return {"severity": sev, "category": cat, "target": target,
            "title": title, "description": desc, "recommendation": rec, "source": "static"}


def _check_text(target: str, kind: str, text: str) -> list[dict]:
    out: list[dict] = []
    text = text or ""
    if _HIDDEN.search(text):
        out.append(_finding(
            "critical", "hidden-text", target,
            f"Hidden/invisible characters in {kind} description",
            f"The {kind} `{target}` contains zero-width, bidi, or tag characters — a common way to "
            "smuggle instructions into an agent's context invisibly (tool poisoning).",
            "Strip non-printable characters from the description and review who can register this server."))
    if _INJECTION.search(text):
        out.append(_finding(
            "high", "tool-poisoning", target,
            f"Instruction-like text in {kind} description",
            f"The {kind} `{target}` description reads like an instruction to the model "
            "(e.g. 'ignore previous', 'do not tell the user'), which can hijack agent behaviour.",
            "Descriptions should describe what the tool does, not instruct the model. Remove imperative text."))
    if len(text) > _MAX_DESC:
        out.append(_finding(
            "low", "oversized-description", target,
            f"Unusually long {kind} description ({len(text)} chars)",
            f"The {kind} `{target}` has a very long description, which can hide injected instructions "
            "and bloats the agent's context.",
            "Keep descriptions concise; move detail to documentation."))
    return out


def check_tool(tool: dict) -> list[dict]:
    name = tool.get("name", "<unnamed>")
    desc = tool.get("description", "") or ""
    out = _check_text(name, "tool", desc)

    haystack = f"{name} {desc}"
    dangerous = [cat for cat, rx in _DANGEROUS if rx.search(haystack)]
    if dangerous:
        sev = "high" if {"command-execution", "code-execution"} & set(dangerous) else "medium"
        out.append(_finding(
            sev, "dangerous-capability", name,
            f"Powerful capability exposed: {', '.join(dangerous)}",
            f"Tool `{name}` appears to offer {', '.join(dangerous)}. In an agent, a prompt-injected "
            "instruction could invoke it against the operator's intent.",
            "Gate this tool behind an authorization scope or human confirmation; constrain its inputs."))

    schema = tool.get("inputSchema") or tool.get("input_schema") or {}
    props = (schema.get("properties") or {}) if isinstance(schema, dict) else {}
    if isinstance(schema, dict) and props and schema.get("additionalProperties") is not False:
        out.append(_finding(
            "info", "loose-schema", name,
            f"Tool `{name}` input schema allows arbitrary extra properties",
            "The input schema does not set additionalProperties:false, so unexpected fields pass through.",
            "Set additionalProperties:false and mark required fields."))
    for pname, pspec in props.items():
        if (_RISKY_PARAMS.match(pname) and isinstance(pspec, dict)
                and pspec.get("type") == "string"
                and not any(k in pspec for k in ("enum", "pattern", "format"))):
            out.append(_finding(
                "medium", "unconstrained-input", name,
                f"Unconstrained `{pname}` parameter on `{name}`",
                f"`{pname}` is a free-form string with no enum/pattern/format — a natural injection or "
                "traversal surface (paths, commands, URLs, queries).",
                f"Constrain `{pname}` with a pattern/enum, or validate and sandbox it server-side."))
    return out


def check_surface(surface: dict) -> list[dict]:
    """Run all static checks over {tools, resources, prompts}."""
    findings: list[dict] = []
    for tool in surface.get("tools", []):
        findings.extend(check_tool(tool))
    for res in surface.get("resources", []):
        name = res.get("name") or res.get("uri") or "<resource>"
        findings.extend(_check_text(name, "resource", res.get("description", "")))
    for prompt in surface.get("prompts", []):
        name = prompt.get("name", "<prompt>")
        findings.extend(_check_text(name, "prompt", prompt.get("description", "")))
    return findings
