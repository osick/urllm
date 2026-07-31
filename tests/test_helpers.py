"""Regression tests for the pure classification/detection helpers."""

from bs4 import BeautifulSoup

import urllm


def soup(html: str) -> BeautifulSoup:
    return BeautifulSoup(html, "html.parser")


# --- third-party classification ---

def test_classify_known_tracker():
    assert urllm._classify_third_party("www.google-analytics.com") == ("analytics", True)


def test_classify_cmp_domain():
    cat, _ = urllm._classify_third_party("consent.cookiebot.com")
    assert cat == "consent-management"


def test_classify_unknown_domain():
    assert urllm._classify_third_party("totally-unknown.example") == ("unknown", False)


def test_classify_eu_friendly_analytics():
    cat, non_eu = urllm._classify_third_party("plausible.io")
    assert cat == "analytics-privacy-friendly"
    assert non_eu is False


# --- PII field classification ---

def test_pii_email_variants():
    for name in ("email", "e-mail", "user_e_mail"):
        assert urllm._classify_pii_field(name) == "email"


def test_pii_german_field_names():
    assert urllm._classify_pii_field("vorname") == "first-name"
    assert urllm._classify_pii_field("geburtsdatum") == "date-of-birth"
    assert urllm._classify_pii_field("iban") == "bank-account"
    assert urllm._classify_pii_field("passwort") == "password"


def test_non_pii_field_returns_none():
    assert urllm._classify_pii_field("search_query") is None


# --- CMP / fingerprinting / storage detection ---

def test_detect_cmp_from_script_src():
    assert "Cookiebot" in urllm._detect_cmp(["https://consent.cookiebot.com/uc.js"], [])


def test_detect_cmp_tcf_api_inline():
    assert "IAB TCF API" in urllm._detect_cmp([], ["window.__tcfapi('ping', 2, cb)"])


def test_detect_cmp_none():
    assert urllm._detect_cmp(["https://cdn.example.com/app.js"], ["var x = 1;"]) == []


def test_detect_fingerprinting_canvas_and_webgl():
    js = ["c.toDataURL();", "el.getContext('webgl');"]
    found = urllm._detect_fingerprinting(js)
    assert "canvas-fingerprint" in found and "webgl-fingerprint" in found


def test_detect_storage_apis():
    js = ["localStorage.setItem('a',1); sessionStorage.x; indexedDB.open('db')"]
    assert urllm._detect_storage_api(js) == ["IndexedDB", "localStorage", "sessionStorage"]


# --- legal links / pixels / mixed content ---

def test_find_legal_links_german():
    s = soup('<a href="/datenschutz">Datenschutz</a><a href="/impressum">Impressum</a>')
    links = urllm._find_legal_links(s)
    assert links["privacy-policy"] == "/datenschutz"
    assert links["impressum"] == "/impressum"


def test_tracking_pixel_1x1_and_noscript():
    s = soup(
        '<img src="https://px.example/p.gif" width="1" height="1">'
        '<noscript><img src="https://fb.example/tr"></noscript>'
        '<img src="https://ok.example/logo.png" width="200" height="50">'
    )
    assert urllm._find_tracking_pixels(s, "site.example") == ["fb.example", "px.example"]


def test_tracking_pixel_hidden_by_style():
    s = soup('<img src="https://px.example/p.gif" style="display: none">')
    assert urllm._find_tracking_pixels(s, "site.example") == ["px.example"]


def test_mixed_content_detection():
    assert urllm._detect_mixed_content(soup('<script src="http://x.example/a.js"></script>'))
    assert not urllm._detect_mixed_content(soup('<script src="https://x.example/a.js"></script>'))


def test_mixed_content_stylesheet_link_counts():
    assert urllm._detect_mixed_content(soup('<link rel="stylesheet" href="http://x.example/a.css">'))


def test_mixed_content_ignores_non_loading_link_rels():
    # RSS alternate, canonical, pingback, dns-prefetch etc. are metadata/navigation,
    # not loaded subresources — an http:// href there is NOT mixed content.
    for rel in ("alternate", "canonical", "pingback", "dns-prefetch", "preconnect", "next"):
        html = f'<link rel="{rel}" href="http://x.example/thing">'
        assert not urllm._detect_mixed_content(soup(html)), rel


def test_mixed_content_rss_alternate_regression():
    # the exact bild.de shape that produced a false-positive "high" finding
    html = '<link rel="alternate" type="application/rss+xml" href="http://www.bild.de/rss.html">'
    assert not urllm._detect_mixed_content(soup(html))


def test_mixed_content_preload_link_counts():
    assert urllm._detect_mixed_content(soup('<link rel="preload" href="http://x.example/f.woff2">'))


# --- CSP domain extraction ---

def test_csp_extracts_bare_and_wildcard_domains():
    csp = "default-src 'self'; script-src 'unsafe-inline' *.jsctool.com https://cdn.example.com"
    got = urllm._extract_csp_domains(csp)
    assert ("jsctool.com", "CSP:script-src") in got
    assert ("cdn.example.com", "CSP:script-src") in got


def test_csp_ignores_keywords_and_schemes():
    csp = "img-src 'self' data: blob: https:; script-src 'nonce-abc123'"
    domains = [d for d, _ in urllm._extract_csp_domains(csp)]
    assert domains == []


# --- TLS probe ---

def test_tls_info_unreachable_host_returns_empty():
    assert urllm._get_tls_info("127.0.0.1", port=1) == {}


def test_tls_info_against_plain_http_returns_empty(http_site):
    # TLS handshake against a non-TLS server must fail gracefully
    url = http_site()
    port = int(url.rsplit(":", 1)[1].rstrip("/"))
    assert urllm._get_tls_info("127.0.0.1", port=port) == {}
