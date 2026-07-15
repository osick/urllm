"""In-process main() runs with fetch + LLM stubbed (counts toward coverage)."""

import json

import pytest

import urllm
from test_findings import make_fp


@pytest.fixture()
def stubbed(monkeypatch):
    fp = make_fp(
        third_parties=[urllm.ThirdPartyEntry(domain="google-analytics.com",
                                             category="analytics", is_non_eu=True)],
        tracking_pixels=["pixel.example.com"],
        fingerprinting_signals=["canvas-fingerprint"],
        cookies=[urllm.CookieInfo(name="sid", domain="x.example", path="/",
                                  secure=False, httponly=False, samesite="unset",
                                  expires="session", classification="third-party")],
        consent_mechanisms_detected=["Cookiebot"],
    )
    monkeypatch.setattr(urllm, "fetch_and_parse", lambda url, timeout=15: fp)
    monkeypatch.setattr(urllm, "analyze_with_llm", lambda fp_, model: "ANALYSIS-BODY")
    monkeypatch.setattr(urllm, "deep_dive_analysis", lambda fp_, a, model: "DEEP-DIVE-BODY")
    return fp


def test_full_report_flow_writes_markdown(stubbed, tmp_path):
    out = tmp_path / "report.md"
    with pytest.raises(SystemExit) as exc:
        urllm.main(["https://x.example/", "-o", str(out), "--deep-dive", "-v",
                    "--save-sources", str(tmp_path / "src")])
    assert exc.value.code == 0
    md = out.read_text()
    assert "ANALYSIS-BODY" in md and "DEEP-DIVE-BODY" in md
    assert "Findings Location" in md          # -v section
    assert "Raw data saved to disk" in md     # --save-sources section
    assert (tmp_path / "src").is_dir()


def test_fetch_error_exits_1_inprocess(monkeypatch):
    monkeypatch.setattr(urllm, "fetch_and_parse", lambda url, timeout=15: "HTTP error: boom")
    with pytest.raises(SystemExit) as exc:
        urllm.main(["https://x.example/"])
    assert exc.value.code == 1


def test_json_mode_prints_plain_json(stubbed, capsys):
    with pytest.raises(SystemExit):
        urllm.main(["https://x.example/", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["base_domain"] == "x.example"
