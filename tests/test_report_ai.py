import json

from mcpscan import report
from mcpscan.ai import SCHEMA, analyze


def _f(sev, target="t", source="static"):
    return {"severity": sev, "target": target, "category": "c", "title": "x",
            "description": "d", "recommendation": "r", "source": source}


def test_worst_and_sort():
    fs = [_f("low"), _f("critical"), _f("medium")]
    assert report.worst(fs) == "critical"
    assert report.sort_findings(fs)[0]["severity"] == "critical"


def test_json_output_shape():
    out = json.loads(report.to_json("srv", [_f("high")]))
    assert out["server"] == "srv"
    assert out["total"] == 1
    assert out["worst_severity"] == "high"


def test_terminal_clean():
    txt = report.to_terminal("srv", [], {"tools": 3, "resources": 0, "prompts": 0})
    assert "No security issues" in txt


# --- AI analysis (mocked client) ---
class _Block:
    def __init__(self, type, text=None):
        self.type, self.text = type, text


class _Resp:
    def __init__(self, content, stop_reason="end_turn"):
        self.content, self.stop_reason = content, stop_reason


class _Msgs:
    def __init__(self, resp):
        self._r = resp
        self.kwargs = None

    def create(self, **kw):
        self.kwargs = kw
        return self._r


class _Client:
    def __init__(self, resp):
        self.messages = _Msgs(resp)


def test_ai_parses_and_tags_source():
    payload = {"findings": [{"target": "run", "severity": "high", "category": "rce",
                             "title": "t", "description": "d", "recommendation": "r"}]}
    c = _Client(_Resp([_Block("text", json.dumps(payload))]))
    out = analyze(c, "claude-opus-5", {"tools": []})
    assert out[0]["source"] == "ai"
    assert c.messages.kwargs["output_config"]["format"]["schema"] is SCHEMA


def test_ai_refusal_returns_empty():
    c = _Client(_Resp([], stop_reason="refusal"))
    assert analyze(c, "claude-opus-5", {"tools": []}) == []


def test_ai_bad_json_returns_empty():
    c = _Client(_Resp([_Block("text", "{oops")]))
    assert analyze(c, "claude-opus-5", {"tools": []}) == []
