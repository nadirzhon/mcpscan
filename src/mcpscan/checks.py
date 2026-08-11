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
# Разделены на «серьёзные» (реально мутируют/крадут — остаются high) и
# «egress» (сетевой выход — сам по себе не эксплуатируем у read-only инструмента).
_DANGEROUS = [
    ("command-execution", re.compile(r"(?i)\b(exec|execute|shell|bash|subprocess|system\(|run.?command|spawn)\b")),
    ("file-write-delete", re.compile(r"(?i)\b(delete|remove|unlink|rmdir|overwrite|write.?file|truncate)\b")),
    ("network-egress", re.compile(r"(?i)\b(curl|download|upload|post to|send to|exfiltrat)\b")),
    ("credential-access", re.compile(r"(?i)\b(secret|token|password|api.?key|credential|private.?key|\.env)\b")),
    # code-execution: только ЯВНОЕ выполнение кода, а не упоминание языка.
    # («Python» как параметр фильтра примеров — не выполнение и не FP.)
    ("code-execution", re.compile(r"(?i)\b(arbitrary code|run.?code|execute.?code|code.?execution|eval\()\b")),
]

# Реально опасные категории: даже у read-only-инструмента остаются high/medium.
_SERIOUS = {"command-execution", "code-execution", "file-write-delete", "credential-access"}

# Глаголы read-only инструмента (поиск/чтение/справка). Если имя таково и
# из опасного нашёлся только сетевой выход — это дизайн, а не уязвимость → info.
_READONLY_NAME = re.compile(
    r"(?i)\b(search|find|lookup|look_?up|query|get|list|read|browse|fetch|"
    r"retrieve|sample|example|docs?|documentation|reference|describe|status|info)\b")

# schema field names that are a REAL injection/traversal/SSRF surface as free strings
_TRAVERSAL_PARAMS = re.compile(
    r"(?i)^(cmd|command|path|file|filename|url|uri|sql|code|script|host|target|dir|directory|endpoint|redirect)s?$")
# free-text params that are EXPECTED to be unconstrained (search boxes etc.) —
# a free-form `query` on a search tool is design, not a vulnerability.
_SEARCH_PARAMS = re.compile(
    r"(?i)^(query|q|search|keyword|term|text|prompt|input|topic|question|message|content)s?$")

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
        serious = _SERIOUS & set(dangerous)
        read_only = bool(_READONLY_NAME.search(name)) and not serious
        if read_only:
            # поиск/справка/fetch с сетевым выходом — нормальная функция, не баг.
            out.append(_finding(
                "info", "capability-note", name,
                f"Read-only tool with {', '.join(dangerous)} (expected for its function)",
                f"Tool `{name}` looks read-only (search/fetch/docs). Its "
                f"{', '.join(dangerous)} is inherent to that role, not an exploitable flaw. "
                "Noted for surface mapping; verify only if it can reach internal networks (SSRF).",
                "If it fetches user-supplied URLs, restrict egress to an allowlist (SSRF hardening)."))
        else:
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
        if not (isinstance(pspec, dict) and pspec.get("type") == "string"
                and not any(k in pspec for k in ("enum", "pattern", "format"))):
            continue
        if _TRAVERSAL_PARAMS.match(pname):
            out.append(_finding(
                "medium", "unconstrained-input", name,
                f"Unconstrained `{pname}` parameter on `{name}`",
                f"`{pname}` is a free-form string with no enum/pattern/format — a real "
                "traversal / SSRF / injection surface (paths, commands, URLs, SQL).",
                f"Constrain `{pname}` with a pattern/enum, or validate and sandbox it server-side."))
        elif _SEARCH_PARAMS.match(pname):
            out.append(_finding(
                "info", "free-text-input", name,
                f"Free-text `{pname}` on `{name}` (expected for a search/query tool)",
                f"`{pname}` is unconstrained, but a free-form search/query field is normal design, "
                "not a vulnerability. Noted for surface mapping only.",
                "No action needed unless this value is later used to build a path/command/SQL."))
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
