"""Run the public deterministic security benchmark.

Usage:
    python benchmarks/run.py
    python benchmarks/run.py --json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from benchmarks.cases import CASES
from mcpscan.checks import check_surface


def load_manifest() -> dict:
    path = Path(__file__).with_name("manifest.json")
    return json.loads(path.read_text(encoding="utf-8"))


def run_benchmark() -> dict:
    manifest = load_manifest()
    expected = {case["id"]: set(case["expected"]) for case in manifest["cases"]}
    results = []

    for case_id, surface in CASES.items():
        actual = {finding["category"] for finding in check_surface(surface)}
        wanted = expected[case_id]
        results.append(
            {
                "id": case_id,
                "expected": sorted(wanted),
                "actual": sorted(actual),
                "matched": actual == wanted,
            }
        )

    matched = sum(result["matched"] for result in results)
    return {
        "schema_version": manifest["schema_version"],
        "benchmark": manifest["name"],
        "cases": len(results),
        "matched": matched,
        "accuracy": matched / len(results) if results else 1.0,
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the mcpscan deterministic security benchmark."
    )
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    args = parser.parse_args()
    report = run_benchmark()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(
            f"{report['benchmark']}: {report['matched']}/{report['cases']} "
            f"cases matched ({report['accuracy']:.1%})"
        )
        for result in report["results"]:
            status = "PASS" if result["matched"] else "FAIL"
            print(f"{status:4} {result['id']}")
    return 0 if report["matched"] == report["cases"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
