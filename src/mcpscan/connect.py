"""Connect to an MCP server and enumerate its advertised surface.

Read-only: lists tools, resources, and prompts. No tool is ever called — mcpscan
inspects definitions, it does not exercise them.
"""

from __future__ import annotations

import os
import shlex
from pathlib import Path

from fastmcp import Client
from fastmcp.client.transports import StdioTransport


def _make_transport(target: str):
    """Infer the right transport from *target*.

    - http(s) URL  → remote transport (Client handles it)
    - a .py/.js server script → Client handles it
    - anything else → a stdio command, e.g. "uvx some-mcp" or "python server.py --flag"
    """
    t = target.strip()
    if t.startswith(("http://", "https://")) or t.endswith((".py", ".js", ".ts")):
        return t
    parts = shlex.split(t)
    # Route the server subprocess's stderr (banners, logs) to /dev/null so it
    # doesn't pollute the scan output.
    return StdioTransport(command=parts[0], args=parts[1:], log_file=Path(os.devnull))


def _norm_tool(t) -> dict:
    return {
        "name": getattr(t, "name", None),
        "description": getattr(t, "description", "") or "",
        "inputSchema": getattr(t, "inputSchema", None) or getattr(t, "input_schema", None) or {},
    }


def _norm_named(x) -> dict:
    return {
        "name": getattr(x, "name", None),
        "uri": str(getattr(x, "uri", "") or ""),
        "description": getattr(x, "description", "") or "",
    }


async def fetch_surface(target: str) -> dict:
    """Connect to *target* (URL, `command args`, or config path) and return its surface.

    fastmcp's Client infers the transport: an http(s) URL, a path to a server
    script, or a shell command string for a stdio server.
    """
    client = Client(_make_transport(target))
    async with client:
        tools = [_norm_tool(t) for t in await client.list_tools()]
        try:
            resources = [_norm_named(r) for r in await client.list_resources()]
        except Exception:  # noqa: BLE001 - server may not implement resources
            resources = []
        try:
            prompts = [_norm_named(p) for p in await client.list_prompts()]
        except Exception:  # noqa: BLE001 - server may not implement prompts
            prompts = []
    return {"tools": tools, "resources": resources, "prompts": prompts}
