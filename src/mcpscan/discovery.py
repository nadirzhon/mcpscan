"""Authorized MCP inventory discovery and aggregate scanning."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from .checks import check_surface
from .connect import fetch_surface


def load_inventory(path: str) -> list[dict]:
    """Load a JSON inventory containing strings or {name, server} entries."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("servers")
    if not isinstance(data, list) or not data:
        raise ValueError('inventory must contain a non-empty JSON array or {"servers": [...]}')
    entries = []
    seen = set()
    for index, item in enumerate(data, 1):
        if isinstance(item, str):
            server = item.strip()
            name = server
        elif isinstance(item, dict):
            server = str(item.get("server", "")).strip()
            name = str(item.get("name", "")).strip() or server
        else:
            raise ValueError(f"inventory entry {index} must be a string or object")
        if not server:
            raise ValueError(f"inventory entry {index} has no server")
        if name in seen:
            raise ValueError(f"duplicate inventory name: {name}")
        seen.add(name)
        entries.append({"name": name, "server": server})
    return entries


async def scan_inventory(entries: list[dict], max_concurrency: int = 4) -> list[dict]:
    """Scan an explicit inventory concurrently, without calling MCP tools."""
    semaphore = asyncio.Semaphore(max(1, max_concurrency))

    async def scan(entry: dict) -> dict:
        async with semaphore:
            result = {"name": entry["name"], "server": entry["server"]}
            try:
                surface = await fetch_surface(entry["server"])
                result["surface"] = {k: len(surface.get(k, [])) for k in ("tools", "resources", "prompts")}
                result["findings"] = check_surface(surface)
            except Exception as exc:  # noqa: BLE001
                result["findings"] = []
                result["error"] = f"{type(exc).__name__}: {exc}"
            return result

    return await asyncio.gather(*(scan(entry) for entry in entries))
