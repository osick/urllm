"""Deterministic findings engine backing --fail-on (no LLM involved)."""

import urllm


def make_fp(**kw) -> urllm.Footprint:
    base = dict(
        url="https://x.example/", base_domain="x.example", status_code=200,
        title="t", generator="", content_language="en",
        legal_links={"privacy-policy": "/privacy"},
    )
    base.update(kw)
    return urllm.Footprint(**base)


def severities(fp) -> list[str]:
    return [sev for sev, _msg in urllm.deterministic_findings(fp)]


def test_clean_https_page_yields_no_critical_or_high():
    assert not {"critical", "high"} & set(severities(make_fp()))


def test_non_https_is_critical():
    assert "critical" in severities(make_fp(is_https=False))


def test_password_form_over_http_is_critical():
    form = urllm.FormFingerprint(
        action="http://x.example/login", method="POST", is_cross_origin=False,
        input_count=2, has_password_field=True, transmits_over_https=False,
    )
    assert "critical" in severities(make_fp(forms=[form]))


def test_trackers_without_cmp_is_high():
    tp = urllm.ThirdPartyEntry(domain="google-analytics.com", category="analytics", is_non_eu=True)
    assert "high" in severities(make_fp(third_parties=[tp]))


def test_trackers_with_cmp_is_not_high():
    tp = urllm.ThirdPartyEntry(domain="google-analytics.com", category="analytics", is_non_eu=True)
    fp = make_fp(third_parties=[tp], consent_mechanisms_detected=["Cookiebot"])
    assert "high" not in severities(fp)


def test_cdn_only_third_parties_are_not_trackers():
    tp = urllm.ThirdPartyEntry(domain="cdn.jsdelivr.net", category="cdn", is_non_eu=True)
    assert "high" not in severities(make_fp(third_parties=[tp]))


def test_tracking_pixels_without_cmp_is_high():
    assert "high" in severities(make_fp(tracking_pixels=["pixel.example.com"]))


def test_mixed_content_is_high():
    assert "high" in severities(make_fp(has_mixed_content=True))


def test_mixed_content_not_reported_on_plain_http_site():
    # on a non-HTTPS site the mixed-content finding is meaningless
    # (the missing HTTPS itself is already reported as critical)
    findings = urllm.deterministic_findings(make_fp(is_https=False, has_mixed_content=True))
    assert not any("mixed content" in msg.lower() for _sev, msg in findings)


def test_missing_privacy_policy_is_high():
    assert "high" in severities(make_fp(legal_links={}))


def test_insecure_cookie_is_medium():
    cookie = urllm.CookieInfo(
        name="sid", domain="x.example", path="/", secure=False, httponly=False,
        samesite="unset", expires="session", classification="first-party",
    )
    assert "medium" in severities(make_fp(cookies=[cookie]))


def test_fingerprinting_is_medium():
    assert "medium" in severities(make_fp(fingerprinting_signals=["canvas-fingerprint"]))


def test_missing_critical_security_headers_is_medium():
    fp = make_fp(missing_security_headers=["content-security-policy", "strict-transport-security"])
    assert "medium" in severities(fp)


def test_pii_forms_are_low():
    form = urllm.FormFingerprint(
        action="/signup", method="POST", is_cross_origin=False,
        input_count=1, pii_fields={"email": "email"},
    )
    assert "low" in severities(make_fp(forms=[form]))


def test_findings_reach_filters_by_threshold():
    findings = [("critical", "a"), ("medium", "b"), ("low", "c")]
    assert urllm.findings_reach(findings, "high") == [("critical", "a")]
    assert urllm.findings_reach(findings, "medium") == [("critical", "a"), ("medium", "b")]
    assert urllm.findings_reach(findings, "low") == findings
    assert urllm.findings_reach([("low", "c")], "critical") == []
