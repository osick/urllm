"""Markdown report generation."""

import urllm
from test_findings import make_fp


def test_footer_links_to_real_repository():
    md = urllm.build_markdown(make_fp(), "analysis text", model="test-model")
    assert "yourname" not in md
    assert "github.com/osick/urllm" in md


def test_report_contains_disclaimer_and_analysis():
    md = urllm.build_markdown(make_fp(), "ANALYSIS-MARKER", model="test-model")
    assert "not constitute legal advice" in md.lower() or "not legal advice" in md.lower()
    assert "ANALYSIS-MARKER" in md


def test_deep_dive_section_included_when_present():
    md = urllm.build_markdown(make_fp(), "a", model="m", deep_dive="DEEP-DIVE-MARKER")
    assert "DEEP-DIVE-MARKER" in md


def test_gdpr_summary_flags_missing_cmp():
    block = urllm._build_gdpr_summary_block(make_fp())
    assert "No Consent Management Platform" in block


def test_gdpr_summary_reports_detected_cmp():
    block = urllm._build_gdpr_summary_block(make_fp(consent_mechanisms_detected=["Cookiebot"]))
    assert "Cookiebot" in block


def test_gdpr_summary_covers_risk_lines():
    cookie = urllm.CookieInfo(name="sid", domain="x.example", path="/", secure=False,
                              httponly=False, samesite="unset", expires="session",
                              classification="third-party")
    form = urllm.FormFingerprint(action="/s", method="POST", is_cross_origin=False,
                                 input_count=1, pii_fields={"email": "email"})
    fp = make_fp(
        is_https=False,
        cookies=[cookie],
        fingerprinting_signals=["canvas-fingerprint"],
        tracking_pixels=["pixel.example.com"],
        missing_security_headers=["content-security-policy"],
        third_parties=[urllm.ThirdPartyEntry(domain="hotjar.com",
                                             category="session-recording", is_non_eu=True)],
        forms=[form],
    )
    block = urllm._build_gdpr_summary_block(fp)
    for expected in ("not served over HTTPS", "Secure", "third-party cookie",
                     "Fingerprinting", "Tracking pixels", "non-EU",
                     "security headers", "PII"):
        assert expected in block, expected


def test_gdpr_summary_mixed_content_line():
    assert "Mixed content" in urllm._build_gdpr_summary_block(make_fp(has_mixed_content=True))


def test_findings_location_block_lists_sources():
    fp = make_fp(
        third_parties=[urllm.ThirdPartyEntry(domain="hotjar.com",
                                             category="session-recording",
                                             is_non_eu=True, source="CSP:script-src")],
        tracking_pixels=["pixel.example.com"],
        fingerprinting_signals=["canvas-fingerprint"],
        cookies=[urllm.CookieInfo(name="sid", domain="x.example", path="/", secure=True,
                                  httponly=True, samesite="Lax", expires="session",
                                  classification="first-party")],
        consent_mechanisms_detected=["Cookiebot"],
    )
    block = urllm._build_findings_location_block(fp)
    assert "CSP:script-src" in block
    assert "pixel.example.com" in block
    assert "canvas-fingerprint" in block
    assert "`sid`" in block
    assert "Cookiebot" in block


def test_findings_location_block_empty():
    assert "No notable findings" in urllm._build_findings_location_block(make_fp())


def test_report_includes_sources_section(tmp_path):
    fake = tmp_path / "page.html"
    fake.write_text("<html></html>")
    md = urllm.build_markdown(make_fp(), "a", model="m",
                              verbose=True, source_paths={"Page HTML": fake})
    assert "Raw data saved to disk" in md
    assert "page.html" in md
    assert "Findings Location" in md
