import json

import pytest

from mcpscan import discovery


def test_load_inventory_supports_strings_and_named_entries(tmp_path):
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps({"servers": [
        "https://one.example/mcp",
        {"name": "local", "server": "python local_server.py"},
    ]}), encoding="utf-8")
    assert discovery.load_inventory(str(path)) == [
        {"name": "https://one.example/mcp", "server": "https://one.example/mcp"},
        {"name": "local", "server": "python local_server.py"},
    ]


def test_load_inventory_rejects_duplicates(tmp_path):
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps([{"name": "same", "server": "a"}, {"name": "same", "server": "b"}]), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate inventory name"):
        discovery.load_inventory(str(path))


@pytest.mark.asyncio
async def test_scan_inventory_is_read_only_and_collects_failures(monkeypatch):
    async def fake_fetch(server):
        if server == "bad":
            raise RuntimeError("connection refused")
        return {"tools": [{"name": "safe", "description": "safe", "inputSchema": {}}], "resources": [], "prompts": []}

    monkeypatch.setattr(discovery, "fetch_surface", fake_fetch)
    scans = await discovery.scan_inventory([
        {"name": "good", "server": "good"},
        {"name": "bad", "server": "bad"},
    ], max_concurrency=2)
    assert scans[0]["surface"]["tools"] == 1
    assert scans[0]["findings"] == []
    assert "connection refused" in scans[1]["error"]


def test_discovery_sarif_has_one_run_per_server():
    from mcpscan.report import to_sarif_discovery
    doc = json.loads(to_sarif_discovery([
        {"name": "one", "server": "one", "findings": []},
        {"name": "two", "server": "two", "findings": [], "error": "failed"},
    ]))
    assert doc["version"] == "2.1.0"
    assert len(doc["runs"]) == 2
    assert doc["runs"][0]["automationDetails"]["id"] == "mcpscan/discovery/one"
    assert doc["runs"][1]["invocations"][0]["executionSuccessful"] is False


def test_discovery_json_aggregates_counts():
    from mcpscan.report import to_discovery_json
    doc = json.loads(to_discovery_json([
        {"name": "one", "server": "one", "findings": [{"severity": "high"}]},
        {"name": "two", "server": "two", "findings": [], "error": "failed"},
    ]))
    assert doc["total_servers"] == 2
    assert doc["successful_servers"] == 1
    assert doc["failed_servers"] == 1
    assert doc["total_findings"] == 1
