import json

from mcpscan.report import to_sarif


def _finding(**overrides):
    finding = {
        "severity": "high",
        "category": "tool-poisoning",
        "target": "search",
        "title": "Instruction-like text",
        "description": "Model-directed instructions.",
        "recommendation": "Remove imperative instructions.",
        "source": "static",
    }
    finding.update(overrides)
    return finding


def test_sarif_fingerprint_is_stable():
    a = json.loads(to_sarif("example", [_finding()]))
    b = json.loads(to_sarif("example", [_finding()]))
    fp_a = a["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"]
    fp_b = b["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"]
    assert fp_a == fp_b
    assert len(fp_a) == 64


def test_sarif_fingerprint_changes_with_identity():
    a = json.loads(to_sarif("example", [_finding()]))
    b = json.loads(to_sarif("example", [_finding(target="other")]))
    fp_a = a["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"]
    fp_b = b["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"]
    assert fp_a != fp_b


def test_sarif_security_metadata_and_rule_index():
    doc = json.loads(to_sarif("example", [
        _finding(severity="critical"),
        _finding(category="unconstrained-input", target="read_file", severity="medium"),
    ]))
    run = doc["runs"][0]
    assert run["tool"]["driver"]["rules"][0]["properties"]["security-severity"] == "9.5"
    assert run["results"][0]["ruleIndex"] == 0
    assert run["results"][1]["ruleIndex"] == 1
    assert run["results"][1]["properties"]["security-severity"] == "5.0"


def test_sarif_optional_location_is_rendered():
    doc = json.loads(to_sarif("example", [_finding(location={
        "uri": "benchmarks/fixtures.json",
        "start_line": 12,
        "start_column": 3,
        "end_line": 12,
        "end_column": 18,
    })]))
    location = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "benchmarks/fixtures.json"
    assert location["region"]["startLine"] == 12
    assert location["region"]["startColumn"] == 3


def test_sarif_runtime_finding_can_remain_locationless():
    result = json.loads(to_sarif("remote-server", [_finding()]))["runs"][0]["results"][0]
    assert "locations" not in result


def test_sarif_empty_scan_has_no_results():
    assert json.loads(to_sarif("example", []))["runs"][0]["results"] == []
