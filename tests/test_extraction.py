"""Regression tests: full fetch_and_parse() pipeline against a rich fixture page."""

import json
from pathlib import Path

import pytest

import urllm

FIXTURE_HTML = (Path(__file__).parent / "fixtures" / "tracker_page.html").read_text()

CSP = "default-src 'self'; script-src 'self' https://allowed-scripts.example.com"


@pytest.fixture()
def footprint(http_site) -> urllm.Footprint:
    url = http_site(html=FIXTURE_HTML, headers=[
        ("Content-Security-Policy", CSP),
        ("X-Content-Type-Options", "nosniff"),
        ("Server", "nginx/1.18.0"),
        ("X-Powered-By", "PHP/7.4.3"),
        ("Set-Cookie", "session_id=abc; Path=/; HttpOnly; SameSite=Lax"),
        ("Set-Cookie", "persistent=1; Path=/; Expires=Wed, 01 Jan 2031 00:00:00 GMT"),
    ])
    fp = urllm.fetch_and_parse(url)
    assert not isinstance(fp, str), fp
    return fp


def test_third_parties_from_script_src(footprint):
    domains = {tp.domain: tp for tp in footprint.third_parties}
    assert "www.googletagmanager.com" in domains
    assert domains["www.googletagmanager.com"].category == "tag-manager"
    assert domains["www.googletagmanager.com"].is_non_eu is True
    assert domains["www.googletagmanager.com"].source == "script-src"


def test_third_parties_from_csp_header(footprint):
    domains = {tp.domain: tp for tp in footprint.third_parties}
    assert "allowed-scripts.example.com" in domains
    assert domains["allowed-scripts.example.com"].source == "CSP:script-src"


def test_cmp_detected(footprint):
    assert "Cookiebot" in footprint.consent_mechanisms_detected


def test_fingerprinting_signals(footprint):
    assert "canvas-fingerprint" in footprint.fingerprinting_signals
    assert "hardware-fingerprint" in footprint.fingerprinting_signals


def test_tracking_pixels(footprint):
    assert "pixel.tracker.example" in footprint.tracking_pixels
    assert "www.facebook.com" in footprint.tracking_pixels  # <noscript> fallback


def test_pii_form_extraction(footprint):
    form = footprint.forms[0]
    assert form.method == "POST"
    assert form.is_cross_origin is True
    assert form.has_password_field is True
    assert "csrf_token" in form.hidden_inputs
    assert "upload" in form.file_inputs
    assert form.pii_fields["email"] == "email"
    assert form.pii_fields["vorname"] == "first-name"
    assert form.pii_fields["iban"] == "bank-account"
    assert form.pii_fields["land"] == "country"      # <select>
    assert form.pii_fields["strasse"] == "address"   # <textarea>


def test_legal_links(footprint):
    assert footprint.legal_links["privacy-policy"] == "/datenschutz"
    assert footprint.legal_links["impressum"] == "/impressum"


def test_mixed_content_flag(footprint):
    assert footprint.has_mixed_content is True


def test_cookie_parsed_with_attributes(footprint):
    cookie = next(c for c in footprint.cookies if c.name == "session_id")
    assert cookie.samesite == "Lax"
    assert cookie.httponly is True
    assert cookie.classification == "first-party"


def test_storage_and_api_endpoints(footprint):
    assert "localStorage" in footprint.storage_api_usage
    assert "/api/v1/user" in footprint.inline_api_endpoints


def test_security_headers_split(footprint):
    assert "content-security-policy" in footprint.security_headers
    assert "x-content-type-options" in footprint.security_headers
    assert "strict-transport-security" in footprint.missing_security_headers


def test_iframes_and_preconnect(footprint):
    assert any(f["domain"] == "www.youtube.com" for f in footprint.third_party_iframes)
    assert "https://fonts.googleapis.com" in footprint.preconnect_hints


def test_structured_data_and_meta(footprint):
    assert "Organization" in footprint.structured_data_types
    assert "WebSite" in footprint.structured_data_types  # JSON-LD list form
    assert footprint.generator == "TestCMS 1.0"
    assert footprint.content_language == "de"


def test_persistent_cookie_expiry_parsed(footprint):
    cookie = next(c for c in footprint.cookies if c.name == "persistent")
    assert cookie.expires.startswith("2031-01-01")


def test_version_disclosure_headers_extracted(footprint):
    assert footprint.server_header == "nginx/1.18.0"
    assert footprint.powered_by == "PHP/7.4.3"


def test_missing_sri_on_cross_origin_scripts(footprint):
    # the fixture's googletagmanager + cookiebot scripts are cross-origin, no integrity
    assert any("googletagmanager.com" in u for u in footprint.sri_missing)
    assert any("cookiebot.com" in u for u in footprint.sri_missing)


def test_csp_weaknesses_extracted(footprint):
    # CSP has no base-uri / frame-ancestors → structural gaps, but scripts are locked down
    assert footprint.csp_report_only is False
    assert any("base-uri" in w for w in footprint.csp_weaknesses)
    assert not any(w.startswith("script-src") for w in footprint.csp_weaknesses)


def test_no_security_txt_when_server_returns_html(footprint):
    # the fixture server answers every path with text/html, so the probe finds no security.txt
    assert footprint.security_txt_url == ""


def test_security_txt_probe_detects_rfc9116_file():
    """A server serving a real text/plain security.txt at the well-known path is detected."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/.well-known/security.txt":
                body = b"Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00z\n"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
            else:
                body = b"<html><body>home</body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/"
        fp = urllm.fetch_and_parse(url)
        assert not isinstance(fp, str), fp
        assert fp.security_txt_url.endswith("/.well-known/security.txt")
    finally:
        server.shutdown()


def test_to_dict_excludes_raw_payloads(footprint):
    d = footprint.to_dict()
    assert "raw_html" not in d and "raw_headers" not in d
    json.dumps(d)  # must be JSON-serializable


def test_fetch_error_returns_string():
    result = urllm.fetch_and_parse("http://127.0.0.1:1/", timeout=2)
    assert isinstance(result, str)
    assert "HTTP error" in result


def test_save_sources_writes_three_files(footprint, tmp_path):
    saved = urllm.save_sources(footprint, tmp_path / "out")
    assert set(saved) == {"Page HTML", "HTTP Headers", "Footprint JSON"}
    for path in saved.values():
        assert path.exists() and path.stat().st_size > 0
    fp_json = json.loads(saved["Footprint JSON"].read_text())
    assert fp_json["base_domain"].startswith("127.0.0.1")
