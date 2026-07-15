"""LLM call wrappers, with litellm stubbed out (no network, no API key)."""

from types import SimpleNamespace

import urllm
from test_findings import make_fp


def fake_completion_factory(reply: str, calls: list):
    def fake_completion(*, model, messages, temperature):
        calls.append({"model": model, "messages": messages, "temperature": temperature})
        msg = SimpleNamespace(content=reply)
        return SimpleNamespace(choices=[SimpleNamespace(message=msg)])
    return fake_completion


def test_analyze_with_llm_sends_footprint_and_returns_text(monkeypatch):
    calls: list = []
    monkeypatch.setattr(urllm, "completion", fake_completion_factory("REPORT", calls))
    result = urllm.analyze_with_llm(make_fp(), model="test/model")
    assert result == "REPORT"
    assert calls[0]["model"] == "test/model"
    user_msg = calls[0]["messages"][1]["content"]
    assert "x.example" in user_msg  # footprint JSON embedded
    assert "raw_html" not in user_msg  # raw payloads never sent to the LLM


def test_analyze_with_llm_reports_errors_gracefully(monkeypatch):
    def boom(**kwargs):
        raise RuntimeError("no api key")
    monkeypatch.setattr(urllm, "completion", boom)
    result = urllm.analyze_with_llm(make_fp(), model="test/model")
    assert "LLM error" in result and "no api key" in result


def test_deep_dive_receives_initial_analysis(monkeypatch):
    calls: list = []
    monkeypatch.setattr(urllm, "completion", fake_completion_factory("DEEP", calls))
    result = urllm.deep_dive_analysis(make_fp(), "INITIAL-FINDINGS", model="test/model")
    assert result == "DEEP"
    user_msg = calls[0]["messages"][1]["content"]
    assert "INITIAL-FINDINGS" in user_msg
    assert calls[0]["temperature"] == 0.0


def test_deep_dive_reports_errors_gracefully(monkeypatch):
    def boom(**kwargs):
        raise RuntimeError("quota exceeded")
    monkeypatch.setattr(urllm, "completion", boom)
    result = urllm.deep_dive_analysis(make_fp(), "x", model="test/model")
    assert "Deep-dive error" in result


# --- models that reject the temperature parameter (Claude Fable 5, Opus 4.8/4.7, …) ---

def temperature_rejecting_completion(calls: list):
    """Fake litellm that 400s when `temperature` is present, like claude-fable-5."""
    def fake(**kwargs):
        calls.append(kwargs)
        if "temperature" in kwargs:
            raise RuntimeError(
                "litellm.BadRequestError: AnthropicException - "
                '{"type":"error","error":{"type":"invalid_request_error",'
                '"message":"`temperature` is deprecated for this model."}}'
            )
        msg = SimpleNamespace(content="OK")
        return SimpleNamespace(choices=[SimpleNamespace(message=msg)])
    return fake


def test_analyze_retries_without_temperature_when_rejected(monkeypatch):
    calls: list = []
    monkeypatch.setattr(urllm, "completion", temperature_rejecting_completion(calls))
    result = urllm.analyze_with_llm(make_fp(), model="claude-fable-5")
    assert result == "OK"
    assert len(calls) == 2
    assert "temperature" in calls[0] and "temperature" not in calls[1]


def test_deep_dive_retries_without_temperature_when_rejected(monkeypatch):
    calls: list = []
    monkeypatch.setattr(urllm, "completion", temperature_rejecting_completion(calls))
    result = urllm.deep_dive_analysis(make_fp(), "INITIAL", model="claude-fable-5")
    assert result == "OK"
    assert len(calls) == 2 and "temperature" not in calls[1]


def test_unrelated_errors_are_not_retried(monkeypatch):
    calls: list = []
    def boom(**kwargs):
        calls.append(kwargs)
        raise RuntimeError("invalid api key")
    monkeypatch.setattr(urllm, "completion", boom)
    result = urllm.analyze_with_llm(make_fp(), model="test/model")
    assert "LLM error" in result
    assert len(calls) == 1  # no blind retry on non-temperature errors
