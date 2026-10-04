import json
from pathlib import Path


def test_comparison_targets_are_well_formed():
    path = Path(__file__).parents[1] / "benchmarks" / "comparison" / "targets.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["schema_version"] == "1.0"
    assert data["methodology"]["metrics"]
    ids = [item["id"] for item in data["scanners"]]
    assert len(ids) == len(set(ids))
    assert "mcpscan" in ids
    for item in data["scanners"]:
        assert item["repository"]
        assert item["source"].startswith("https://")
        assert item["benchmark_adapter"]
