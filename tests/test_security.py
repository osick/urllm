"""Deterministic security analysis: CSP quality, secrets, SRI, TLS/HSTS, headers, security.txt."""

from datetime import datetime, timezone

from bs4 import BeautifulSoup

import urllm
from test_findings import make_fp


def soup(html: str) -> BeautifulSoup:
    return BeautifulSoup(html, "html.parser")


def severities(fp, **kw) -> list[str]:
    return [s for s, _m in urllm.deterministic_findings(fp, **kw)]


def messages(fp, **kw) -> str:
    return " | ".join(m for _s, m in urllm.deterministic_findings(fp, **kw))


# --- 1. CSP quality analysis ---

def test_csp_unsafe_inline_and_eval_flagged():
    w = urllm.analyze_csp("default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'")
    assert any("unsafe-inline" in x for x in w)
    assert any("unsafe-eval" in x for x in w)


def test_csp_wildcard_script_src_flagged():
    w = urllm.analyze_csp("script-src *")
    assert any("wildcard" in x for x in w)


def test_csp_structural_gaps_flagged():
    w = urllm.analyze_csp("script-src 'self'")  # no object-src/default-src, base-uri, frame-ancestors
    assert any("object-src" in x for x in w)
    assert any("base-uri" in x for x in w)
    assert any("frame-ancestors" in x for x in w)


def test_csp_default_src_covers_object_src():
    w = urllm.analyze_csp("default-src 'self'; base-uri 'self'; frame-ancestors 'none'")
    assert w == []  # default-src fallback + base-uri + frame-ancestors → clean


def test_csp_empty_yields_no_weaknesses():
    assert urllm.analyze_csp("") == []
    assert urllm.analyze_csp("   ") == []


def test_csp_nonce_script_src_is_clean_for_scripts():
    w = urllm.analyze_csp(
        "default-src 'self'; script-src 'nonce-abc123'; base-uri 'self'; "
        "object-src 'none'; frame-ancestors 'none'"
    )
    assert not any(x.startswith("script-src") for x in w)


def test_finding_script_src_weakness_is_high():
    fp = make_fp(csp_weaknesses=["script-src allows 'unsafe-inline'"])
    assert "high" in severities(fp)


def test_finding_report_only_csp_is_medium():
    fp = make_fp(csp_report_only=True)
    sev = severities(fp)
    assert "medium" in sev
    assert "report-only" in messages(fp).lower()


def test_structural_csp_gaps_alone_are_not_high():
    # base-uri / frame-ancestors gaps are LLM-level notes, not a --fail-on high
    fp = make_fp(csp_weaknesses=["no base-uri (base-tag injection possible)"])
    assert "high" not in severities(fp)


# --- 2. Exposed secrets in page source ---
# Secret-looking strings are built by concatenation so no literal secret ever
# lands in the repo (would trip GitHub push-protection).

STRIPE_KEY = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"
AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
GOOGLE_KEY = "AIza" + "0" * 35
GITHUB_TOKEN = "ghp_" + "0" * 36


def test_detect_stripe_secret_key():
    found = urllm._detect_exposed_secrets(f"var k = '{STRIPE_KEY}';")
    assert found and found[0]["type"] == "stripe-secret-key"


def test_detect_multiple_secret_types():
    text = f"{AWS_KEY} {GOOGLE_KEY} {GITHUB_TOKEN}"
    types = {s["type"] for s in urllm._detect_exposed_secrets(text)}
    assert {"aws-access-key-id", "google-api-key", "github-token"} <= types


def test_detect_private_key_block():
    found = urllm._detect_exposed_secrets("-----BEGIN RSA PRIVATE KEY-----\nMII...")
    assert found and found[0]["type"] == "private-key-block"


def test_secret_value_is_redacted():
    found = urllm._detect_exposed_secrets(STRIPE_KEY)
    redacted = found[0]["redacted"]
    assert redacted != STRIPE_KEY
    assert redacted.startswith("sk_live_")
    assert "…" in redacted


def test_no_false_positive_on_clean_text():
    assert urllm._detect_exposed_secrets("just some ordinary homepage text 12345") == []


def test_secrets_deduplicated():
    found = urllm._detect_exposed_secrets(f"{STRIPE_KEY} ... {STRIPE_KEY}")
    assert len(found) == 1


def test_exposed_secret_is_critical_finding():
    fp = make_fp(exposed_secrets=[{"type": "stripe-secret-key", "redacted": "sk_live_4e…"}])
    assert "critical" in severities(fp)
    assert "stripe-secret-key" in messages(fp)


# --- 3. Subresource Integrity ---

def test_missing_sri_on_cross_origin_script():
    s = soup('<script src="https://cdn.example.com/app.js"></script>')
    missing = urllm._find_missing_sri(s, "site.example")
    assert "https://cdn.example.com/app.js" in missing


def test_sri_present_is_not_flagged():
    s = soup('<script src="https://cdn.example.com/app.js" integrity="sha384-x"></script>')
    assert urllm._find_missing_sri(s, "site.example") == []


def test_same_origin_script_not_flagged_for_sri():
    s = soup('<script src="https://site.example/app.js"></script>')
    assert urllm._find_missing_sri(s, "site.example") == []


def test_cross_origin_stylesheet_without_sri_flagged():
    s = soup('<link rel="stylesheet" href="https://cdn.example.com/x.css">')
    assert "https://cdn.example.com/x.css" in urllm._find_missing_sri(s, "site.example")


def test_missing_sri_is_medium_finding():
    fp = make_fp(sri_missing=["https://cdn.example.com/app.js"])
    assert "medium" in severities(fp)


# --- 4. TLS / cert / HSTS grading ---

NOW = datetime(2026, 7, 15, tzinfo=timezone.utc)


def test_parse_cert_expiry_openssl_format():
    dt = urllm._parse_cert_expiry("Jun  1 12:00:00 2031 GMT")
    assert dt is not None and dt.year == 2031


def test_parse_cert_expiry_invalid_returns_none():
    assert urllm._parse_cert_expiry("") is None
    assert urllm._parse_cert_expiry("not a date") is None


def test_weak_tls_version_is_high():
    assert "high" in severities(make_fp(tls_version="TLSv1"), now=NOW)
    assert "high" in severities(make_fp(tls_version="TLSv1.1"), now=NOW)


def test_modern_tls_version_is_ok():
    assert "high" not in severities(make_fp(tls_version="TLSv1.3"), now=NOW)


def test_expired_certificate_is_high():
    fp = make_fp(certificate_expiry="Jun  1 12:00:00 2020 GMT")
    assert "high" in severities(fp, now=NOW)


def test_certificate_expiring_soon_is_medium():
    fp = make_fp(certificate_expiry="Jul 30 12:00:00 2026 GMT")  # 15 days from NOW
    sev = severities(fp, now=NOW)
    assert "medium" in sev and "high" not in sev


def test_certificate_far_future_is_clean():
    fp = make_fp(certificate_expiry="Jun  1 12:00:00 2031 GMT")
    assert not ({"high", "medium"} & set(severities(fp, now=NOW)))


def test_short_hsts_max_age_is_medium():
    fp = make_fp(security_headers={"strict-transport-security": "max-age=3600"})
    assert "medium" in severities(fp, now=NOW)
    assert "hsts" in messages(fp, now=NOW).lower()


def test_long_hsts_max_age_is_ok():
    fp = make_fp(security_headers={"strict-transport-security": "max-age=63072000; includeSubDomains"})
    assert "hsts" not in messages(fp, now=NOW).lower()


# --- 5. Version disclosure headers ---

def test_server_version_disclosure_is_low():
    fp = make_fp(server_header="nginx/1.18.0")
    assert "low" in severities(fp)
    assert "nginx/1.18.0" in messages(fp)


def test_powered_by_version_disclosure_is_low():
    fp = make_fp(powered_by="PHP/7.4.3")
    assert "PHP/7.4.3" in messages(fp)


def test_server_without_version_not_flagged():
    fp = make_fp(server_header="cloudflare")
    assert "cloudflare" not in messages(fp)


# --- 6. security.txt ---

def test_missing_security_txt_is_low():
    fp = make_fp(security_txt_url="")
    assert "low" in severities(fp)
    assert "security.txt" in messages(fp)


def test_present_security_txt_not_flagged():
    fp = make_fp(security_txt_url="https://x.example/.well-known/security.txt")
    assert "security.txt" not in messages(fp)
