import json
from pathlib import Path

from benchmarks.cases import CASES
from benchmarks.run import run_benchmark

MANIFEST = json.loads((Path(__file__).parents[1] / "benchmarks" / "manifest.json").read_text())


def test_manifest_is_complete():
    assert {case["id"] for case in MANIFEST["cases"]} == set(CASES)
    assert MANIFEST["schema_version"] == "1.0"


def test_benchmark_cases_match_expected_categories():
    expected = {case["id"]: set(case["expected"]) for case in MANIFEST["cases"]}
    for case_id, surface in CASES.items():
        categories = {f["category"] for f in __import__("mcpscan.checks", fromlist=["check_surface"]).check_surface(surface)}
        assert categories == expected[case_id], case_id


def test_benchmark_has_no_duplicate_ids():
    ids = [case["id"] for case in MANIFEST["cases"]]
    assert len(ids) == len(set(ids))


def test_benchmark_runner_reports_full_match():
    report = run_benchmark()
    assert report["cases"] == 16
    assert report["matched"] == 16
    assert report["accuracy"] == 1.0
