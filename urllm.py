"""
URLLM — URL technical footprint analyzer with GDPR & security-focused
GenAI reasoning.

Deterministically extracts a web page's technical + privacy footprint and
hands the structured JSON to an LLM for architectural, security, and GDPR
compliance analysis.

Usage:
    uv run urllm.py https://example.com
    uv run urllm.py https://example.com -o report.md
    uv run urllm.py https://example.com -m gpt-4o --json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import ssl
import socket
import sys
import textwrap
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from importlib.metadata import version as _pkg_version
from pathlib import Path
from urllib.parse import urljoin, urlparse

try:
    __version__ = _pkg_version("urllm")
except Exception:
    __version__ = "dev"

import requests
from bs4 import BeautifulSoup, Tag
from litellm import completion
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax

# ---------------------------------------------------------------------------
# Constants & known-entity databases
# ---------------------------------------------------------------------------

# Known tracker / ad-network domains (substring-matched against netloc)
_KNOWN_TRACKERS: dict[str, str] = {
    "google-analytics.com": "analytics",
    "googletagmanager.com": "tag-manager",
    "googlesyndication.com": "ad-network",
    "googleadservices.com": "ad-network",
    "doubleclick.net": "ad-network",
    "facebook.net": "social-tracker",
    "connect.facebook.net": "social-tracker",
    "meta.com": "social-tracker",
    "analytics.tiktok.com": "social-tracker",
    "snap.licdn.com": "social-tracker",
    "linkedin.com": "social-tracker",
    "ads-twitter.com": "social-tracker",
    "platform.twitter.com": "social-widget",
    "hotjar.com": "session-recording",
    "clarity.ms": "session-recording",
    "mouseflow.com": "session-recording",
    "fullstory.com": "session-recording",
    "luckyorange.com": "session-recording",
    "crazyegg.com": "session-recording",
    "segment.io": "analytics",
    "segment.com": "analytics",
    "mixpanel.com": "analytics",
    "amplitude.com": "analytics",
    "heap.io": "analytics",
    "heapanalytics.com": "analytics",
    "plausible.io": "analytics-privacy-friendly",
    "matomo.cloud": "analytics-privacy-friendly",
    "sentry.io": "error-tracking",
    "newrelic.com": "apm",
    "nr-data.net": "apm",
    "datadoghq.com": "apm",
    "intercom.io": "customer-messaging",
    "intercomcdn.com": "customer-messaging",
    "crisp.chat": "customer-messaging",
    "drift.com": "customer-messaging",
    "hubspot.com": "marketing-automation",
    "hs-analytics.net": "marketing-automation",
    "hs-scripts.com": "marketing-automation",
    "marketo.net": "marketing-automation",
    "pardot.com": "marketing-automation",
    "cookiebot.com": "consent-management",
    "cookielaw.org": "consent-management",
    "onetrust.com": "consent-management",
    "usercentrics.eu": "consent-management",
    "didomi.io": "consent-management",
    "quantcast.com": "consent-management",
    "trustarccloud.com": "consent-management",
    "consentmanager.net": "consent-management",
    "iubenda.com": "consent-management",
    "osano.com": "consent-management",
    "cloudflare.com": "cdn",
    "cdnjs.cloudflare.com": "cdn",
    "jsdelivr.net": "cdn",
    "unpkg.com": "cdn",
    "ajax.googleapis.com": "cdn",
    "fonts.googleapis.com": "font-provider",
    "fonts.gstatic.com": "font-provider",
    "use.typekit.net": "font-provider",
    "recaptcha.net": "captcha",
    "hcaptcha.com": "captcha",
    "challenges.cloudflare.com": "captcha",
    "stripe.com": "payment",
    "js.stripe.com": "payment",
    "paypal.com": "payment",
    "braintreegateway.com": "payment",
    "youtube.com": "video-embed",
    "player.vimeo.com": "video-embed",
}

# Domains generally headquartered outside the EU/EEA
_NON_EU_DOMAINS: set[str] = {
    "google-analytics.com", "googletagmanager.com", "googlesyndication.com",
    "doubleclick.net", "google.com", "gstatic.com", "googleapis.com",
    "facebook.net", "facebook.com", "meta.com", "fbcdn.net",
    "tiktok.com", "twitter.com", "ads-twitter.com", "x.com",
    "amplitude.com", "mixpanel.com", "segment.io", "segment.com",
    "heap.io", "heapanalytics.com", "fullstory.com",
    "hotjar.com", "clarity.ms",
    "sentry.io", "newrelic.com", "nr-data.net", "datadoghq.com",
    "hubspot.com", "hs-analytics.net", "hs-scripts.com",
    "intercom.io", "intercomcdn.com", "drift.com",
    "stripe.com", "paypal.com",
    "cloudflare.com", "jsdelivr.net", "unpkg.com",
    "youtube.com", "youtu.be",
}

# CMP identifiers (substring in script src or inline code)
_CMP_MARKERS: dict[str, str] = {
    "cookiebot": "Cookiebot",
    "onetrust": "OneTrust",
    "cookielaw": "OneTrust (CookieLaw)",
    "usercentrics": "Usercentrics",
    "didomi": "Didomi",
    "quantcast": "Quantcast Choice",
    "trustarccloud": "TrustArc",
    "consentmanager": "consentmanager.net",
    "iubenda": "iubenda",
    "osano": "Osano",
    "complianz": "Complianz",
    "borlabs": "Borlabs Cookie",
    "klaro": "Klaro!",
    "termly": "Termly",
    "cookiefirst": "CookieFirst",
    "cookie-script": "Cookie-Script",
    "__tcfapi": "IAB TCF API",
    "CookieConsent": "Generic CookieConsent",
}

# Fingerprinting API patterns in inline JS
_FINGERPRINT_PATTERNS: dict[str, str] = {
    r"\.toDataURL\(": "canvas-fingerprint",
    r"getContext\s*\(\s*['\"]webgl": "webgl-fingerprint",
    r"AudioContext|webkitAudioContext": "audio-fingerprint",
    r"navigator\.plugins": "plugin-enumeration",
    r"navigator\.languages": "language-enumeration",
    r"screen\.(?:width|height|colorDepth)": "screen-fingerprint",
    r"navigator\.hardwareConcurrency": "hardware-fingerprint",
    r"navigator\.deviceMemory": "device-memory-probe",
    r"getBattery": "battery-api-probe",
    r"RTCPeerConnection": "webrtc-leak",
}

# PII-indicating form field name patterns
_PII_FIELD_PATTERNS: dict[str, str] = {
    r"(?:e-?mail|e_mail)": "email",
    r"(?:first.?name|vorname|fname)": "first-name",
    r"(?:last.?name|nachname|lname|surname)": "last-name",
    r"(?:full.?name)": "name",
    r"(?:phone|tel|mobile|telefon|handy)": "phone",
    r"(?:address|street|strasse|straße|addr)": "address",
    r"(?:zip|postal|plz|postleitzahl)": "postal-code",
    r"(?:city|stadt|ort)": "city",
    r"(?:country|land)": "country",
    r"(?:birth|dob|geburts)": "date-of-birth",
    r"(?:ssn|social.?security|steuer.?id)": "government-id",
    r"(?:passport|ausweis|reisepass)": "government-id",
    r"(?:credit.?card|card.?number|karten)": "payment-card",
    r"(?:iban|bank|konto)": "bank-account",
    r"(?:password|passwort|passwd|pwd)": "password",
    r"(?:gender|geschlecht)": "gender",
    r"(?:company|firma|unternehmen|organisation)": "company",
}

# Legal / privacy page link patterns
_LEGAL_LINK_PATTERNS: dict[str, str] = {
    r"privacy|datenschutz": "privacy-policy",
    r"impress|impressum": "impressum",
    r"cookie.?(?:policy|richtlinie|einstellung)": "cookie-policy",
    r"terms|agb|nutzungsbedingung|geschäftsbedingung": "terms-of-service",
    r"legal|rechtlich": "legal-notice",
    r"dsgvo|gdpr|data.?protection": "data-protection-notice",
    r"opt.?out|widerspruch": "opt-out",
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class CookieInfo:
    name: str
    domain: str
    path: str
    secure: bool
    httponly: bool
    samesite: str  # "Strict" | "Lax" | "None" | "unset"
    expires: str  # ISO timestamp or "session"
    classification: str  # "first-party" | "third-party"


@dataclass
class FormFingerprint:
    action: str
    method: str
    is_cross_origin: bool
    input_count: int
    hidden_inputs: list[str] = field(default_factory=list)
    file_inputs: list[str] = field(default_factory=list)
    pii_fields: dict[str, str] = field(default_factory=dict)
    has_password_field: bool = False
    transmits_over_https: bool = True


@dataclass
class ThirdPartyEntry:
    domain: str
    category: str
    is_non_eu: bool
    source: str = "script-src"  # where this domain was discovered


@dataclass
class Footprint:
    """Deterministic technical + privacy footprint extracted from a single URL."""

    # --- Core ---
    url: str
    base_domain: str
    status_code: int
    title: str
    generator: str
    content_language: str

    # --- TLS ---
    is_https: bool = True
    tls_version: str = ""
    certificate_issuer: str = ""
    certificate_expiry: str = ""
    has_mixed_content: bool = False

    # --- Third parties (enriched) ---
    third_parties: list[ThirdPartyEntry] = field(default_factory=list)
    third_party_iframes: list[dict] = field(default_factory=list)
    preconnect_hints: list[str] = field(default_factory=list)

    # --- Scripts & inline ---
    inline_api_endpoints: list[str] = field(default_factory=list)
    total_script_count: int = 0
    total_inline_script_bytes: int = 0

    # --- Forms ---
    forms: list[FormFingerprint] = field(default_factory=list)

    # --- GDPR / Privacy ---
    cookies: list[CookieInfo] = field(default_factory=list)
    consent_mechanisms_detected: list[str] = field(default_factory=list)
    fingerprinting_signals: list[str] = field(default_factory=list)
    storage_api_usage: list[str] = field(default_factory=list)
    tracking_pixels: list[str] = field(default_factory=list)
    legal_links: dict[str, str] = field(default_factory=dict)

    # --- Metadata ---
    stylesheets: list[str] = field(default_factory=list)
    meta_tags: dict[str, str] = field(default_factory=dict)
    security_headers: dict[str, str] = field(default_factory=dict)
    missing_security_headers: list[str] = field(default_factory=list)
    structured_data_types: list[str] = field(default_factory=list)
    open_graph: dict[str, str] = field(default_factory=dict)
    canonical_url: str = ""

    # raw data — excluded from LLM payload, populated during fetch
    raw_html: str = field(default="", repr=False, compare=False)
    raw_headers: dict = field(default_factory=dict, repr=False, compare=False)

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("raw_html", None)
        d.pop("raw_headers", None)
        return d


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _classify_third_party(domain: str) -> tuple[str, bool]:
    domain_lower = domain.lower()
    category = "unknown"
    for pattern, cat in _KNOWN_TRACKERS.items():
        if pattern in domain_lower:
            category = cat
            break
    is_non_eu = any(d in domain_lower for d in _NON_EU_DOMAINS)
    return category, is_non_eu


def _classify_pii_field(field_name: str) -> str | None:
    name_lower = field_name.lower()
    for pattern, pii_type in _PII_FIELD_PATTERNS.items():
        if re.search(pattern, name_lower):
            return pii_type
    return None


def _detect_cmp(script_sources: list[str], inline_scripts: list[str]) -> list[str]:
    found: set[str] = set()
    combined = " ".join(script_sources) + " " + " ".join(inline_scripts)
    combined_lower = combined.lower()
    for marker, name in _CMP_MARKERS.items():
        if marker.lower() in combined_lower:
            found.add(name)
    return sorted(found)


def _detect_fingerprinting(inline_scripts: list[str]) -> list[str]:
    found: set[str] = set()
    combined = " ".join(inline_scripts)
    for pattern, label in _FINGERPRINT_PATTERNS.items():
        if re.search(pattern, combined):
            found.add(label)
    return sorted(found)


def _detect_storage_api(inline_scripts: list[str]) -> list[str]:
    found: set[str] = set()
    combined = " ".join(inline_scripts)
    if re.search(r"localStorage", combined):
        found.add("localStorage")
    if re.search(r"sessionStorage", combined):
        found.add("sessionStorage")
    if re.search(r"indexedDB|IDBDatabase", combined):
        found.add("IndexedDB")
    if re.search(r"caches\.open|CacheStorage", combined):
        found.add("CacheStorage")
    return sorted(found)


def _find_legal_links(soup: BeautifulSoup) -> dict[str, str]:
    links: dict[str, str] = {}
    for a in soup.find_all("a", href=True):
        text = a.get_text(strip=True).lower()
        href = a["href"]
        combined = text + " " + href.lower()
        for pattern, link_type in _LEGAL_LINK_PATTERNS.items():
            if re.search(pattern, combined) and link_type not in links:
                links[link_type] = href
                break
    return links


def _find_tracking_pixels(soup: BeautifulSoup, base_domain: str) -> list[str]:
    pixel_domains: set[str] = set()
    for img in soup.find_all("img"):
        src = img.get("src", "")
        width = img.get("width", "")
        height = img.get("height", "")
        is_tiny = (str(width) in ("0", "1") and str(height) in ("0", "1"))
        style = img.get("style", "").replace(" ", "")
        is_hidden = "display:none" in style or "visibility:hidden" in style
        if (is_tiny or is_hidden) and src.startswith("http"):
            domain = urlparse(src).netloc
            if domain and domain != base_domain:
                pixel_domains.add(domain)
    for ns in soup.find_all("noscript"):
        for img in ns.find_all("img"):
            src = img.get("src", "")
            if src.startswith("http"):
                domain = urlparse(src).netloc
                if domain and domain != base_domain:
                    pixel_domains.add(domain)
    return sorted(pixel_domains)


def _get_tls_info(hostname: str, port: int = 443) -> dict[str, str]:
    info: dict[str, str] = {}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                info["tls_version"] = ssock.version() or ""
                cert = ssock.getpeercert()
                if cert:
                    for rdn in cert.get("issuer", ()):
                        for attr_type, attr_value in rdn:
                            if attr_type == "organizationName":
                                info["certificate_issuer"] = attr_value
                    not_after = cert.get("notAfter", "")
                    if not_after:
                        info["certificate_expiry"] = not_after
    except Exception:
        pass
    return info


def _extract_csp_domains(csp_value: str) -> list[tuple[str, str]]:
    """Parse a CSP header and return (domain, directive) pairs."""
    results: list[tuple[str, str]] = []
    for directive_chunk in csp_value.split(";"):
        parts = directive_chunk.strip().split()
        if not parts:
            continue
        directive_name = parts[0]
        for token in parts[1:]:
            if token.startswith(("'", "blob:", "data:", "http:", "https:")) and not token.startswith("http"):
                continue  # keyword or scheme-only token
            if token.startswith("http://") or token.startswith("https://"):
                parsed = urlparse(token)
                domain = parsed.netloc.lstrip("*.")
                if domain:
                    results.append((domain, f"CSP:{directive_name}"))
            elif "." in token and not token.startswith("'"):
                domain = token.lstrip("*.")
                if domain:
                    results.append((domain, f"CSP:{directive_name}"))
    return results


def _detect_mixed_content(soup: BeautifulSoup) -> bool:
    for tag in soup.find_all(["script", "link", "img", "iframe", "source", "video", "audio"]):
        src = tag.get("src") or tag.get("href") or ""
        if src.startswith("http://"):
            return True
    return False


# ---------------------------------------------------------------------------
# Main extraction
# ---------------------------------------------------------------------------

_INTERESTING_META = {"description", "keywords", "author", "robots", "viewport", "theme-color"}

_SECURITY_HEADERS_ALL = [
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "x-xss-protection",
    "permissions-policy",
    "referrer-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
]

_API_CALL_RE = re.compile(
    r"""(?:fetch|axios\.(?:get|post|put|delete|patch)|XMLHttpRequest\.open)\(\s*["'](.*?)["']""",
    re.IGNORECASE,
)


def fetch_and_parse(url: str, *, timeout: int = 15) -> Footprint | str:
    """Fetch *url* and return a :class:`Footprint`, or an error string."""

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en-US,en;q=0.9,de;q=0.8",
    }

    try:
        session = requests.Session()
        resp = session.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        resp.raise_for_status()
    except requests.RequestException as exc:
        return f"HTTP error: {exc}"

    soup = BeautifulSoup(resp.text, "html.parser")
    parsed = urlparse(resp.url)
    base_domain = parsed.netloc
    is_https = parsed.scheme == "https"

    # --- TLS ---
    tls_info: dict[str, str] = {}
    if is_https:
        tls_info = _get_tls_info(parsed.hostname or base_domain)

    # --- Title ---
    title_tag = soup.find("title")
    title = title_tag.get_text(strip=True) if title_tag else ""

    # --- Generator ---
    gen_tag = soup.find("meta", attrs={"name": "generator"})
    generator = gen_tag["content"] if gen_tag and gen_tag.get("content") else "Unknown"

    # --- Language ---
    html_tag = soup.find("html")
    lang = (html_tag.get("lang", "") if isinstance(html_tag, Tag) else "") or ""

    # --- Meta tags ---
    meta_tags: dict[str, str] = {}
    for meta in soup.find_all("meta"):
        name = (meta.get("name") or meta.get("property") or "").lower()
        content = meta.get("content", "")
        if name in _INTERESTING_META and content:
            meta_tags[name] = content[:300]

    # --- Open Graph ---
    og: dict[str, str] = {}
    for meta in soup.find_all("meta", attrs={"property": re.compile(r"^og:")}):
        key = meta.get("property", "")[3:]
        if val := meta.get("content"):
            og[key] = val[:300]

    # --- Canonical ---
    canon_tag = soup.find("link", rel="canonical")
    canonical = (canon_tag.get("href", "") if canon_tag else "") or ""

    # --- Scripts ---
    scripts = soup.find_all("script")
    script_sources = [s["src"] for s in scripts if s.get("src")]
    third_party_domains: set[str] = set()
    for src in script_sources:
        if src.startswith("http"):
            domain = urlparse(src).netloc
            if domain and domain != base_domain:
                third_party_domains.add(domain)

    inline_scripts = [s.string for s in scripts if s.string]
    total_inline_bytes = sum(len(s) for s in inline_scripts)
    api_endpoints: set[str] = set()
    for text in inline_scripts:
        api_endpoints.update(_API_CALL_RE.findall(text))

    # --- Third parties (enriched) ---
    third_parties: list[ThirdPartyEntry] = []
    for domain in sorted(third_party_domains):
        cat, non_eu = _classify_third_party(domain)
        third_parties.append(ThirdPartyEntry(domain=domain, category=cat, is_non_eu=non_eu, source="script-src"))

    # --- Iframes ---
    iframes: list[dict] = []
    for iframe in soup.find_all("iframe"):
        src = iframe.get("src", "")
        if src.startswith("http"):
            domain = urlparse(src).netloc
            if domain and domain != base_domain:
                iframes.append({"domain": domain, "src_snippet": src[:200]})

    # --- Preconnect / dns-prefetch ---
    preconnect: list[str] = []
    for link in soup.find_all("link", rel=re.compile(r"preconnect|dns-prefetch")):
        href = link.get("href", "")
        if href:
            preconnect.append(href)

    # --- Forms ---
    form_fps: list[FormFingerprint] = []
    for form in soup.find_all("form"):
        action_raw = form.get("action", "")
        full_action = urljoin(resp.url, action_raw) if action_raw else resp.url
        action_parsed = urlparse(full_action)
        action_domain = action_parsed.netloc
        is_cross_origin = bool(action_domain and action_domain != base_domain)
        transmits_https = action_parsed.scheme == "https" if action_raw else is_https

        inputs = [
            {"name": inp.get("name", ""), "type": inp.get("type", "text")}
            for inp in form.find_all("input")
            if inp.get("name")
        ]

        pii_fields: dict[str, str] = {}
        has_pw = False
        for inp in inputs:
            if inp["type"] == "password":
                has_pw = True
            pii_type = _classify_pii_field(inp["name"])
            if pii_type:
                pii_fields[inp["name"]] = pii_type

        for tag_name in ("select", "textarea"):
            for el in form.find_all(tag_name):
                el_name = el.get("name", "")
                if el_name:
                    pii_type = _classify_pii_field(el_name)
                    if pii_type:
                        pii_fields[el_name] = pii_type

        form_fps.append(
            FormFingerprint(
                action=action_raw or "(self)",
                method=form.get("method", "GET").upper(),
                is_cross_origin=is_cross_origin,
                input_count=len(inputs),
                hidden_inputs=[i["name"] for i in inputs if i["type"] == "hidden"],
                file_inputs=[i["name"] for i in inputs if i["type"] == "file"],
                pii_fields=pii_fields,
                has_password_field=has_pw,
                transmits_over_https=transmits_https,
            )
        )

    # --- Stylesheets ---
    stylesheets = [l["href"] for l in soup.find_all("link", rel="stylesheet") if l.get("href")]

    # --- Structured data (JSON-LD) ---
    sd_types: list[str] = []
    for ld in soup.find_all("script", attrs={"type": "application/ld+json"}):
        try:
            data = json.loads(ld.string or "")
            if isinstance(data, dict) and "@type" in data:
                sd_types.append(data["@type"])
            elif isinstance(data, list):
                sd_types.extend(d.get("@type", "") for d in data if isinstance(d, dict))
        except (json.JSONDecodeError, TypeError):
            pass

    # --- Security headers ---
    sec_present: dict[str, str] = {}
    sec_missing: list[str] = []
    for h in _SECURITY_HEADERS_ALL:
        val = resp.headers.get(h)
        if val:
            sec_present[h] = val[:500]
        else:
            sec_missing.append(h)

    # --- Cookies ---
    cookie_infos: list[CookieInfo] = []
    raw_set_cookies = resp.headers.get("set-cookie", "")
    for cookie in session.cookies:
        samesite = "unset"
        for fragment in raw_set_cookies.split("\n"):
            if cookie.name in fragment:
                frag_lower = fragment.lower()
                if "samesite=strict" in frag_lower:
                    samesite = "Strict"
                elif "samesite=lax" in frag_lower:
                    samesite = "Lax"
                elif "samesite=none" in frag_lower:
                    samesite = "None"
                break

        expires_val = "session"
        if cookie.expires:
            try:
                expires_val = datetime.fromtimestamp(cookie.expires, tz=timezone.utc).isoformat()
            except (OSError, ValueError):
                expires_val = str(cookie.expires)

        cookie_domain = cookie.domain or base_domain
        is_third = not (
            cookie_domain == base_domain
            or cookie_domain.lstrip(".") == base_domain
            or base_domain.endswith(cookie_domain.lstrip("."))
        )

        cookie_infos.append(
            CookieInfo(
                name=cookie.name,
                domain=cookie_domain,
                path=cookie.path or "/",
                secure=bool(cookie.secure),
                httponly=(
                    cookie.has_nonstandard_attr("httponly")
                    or cookie.has_nonstandard_attr("HttpOnly")
                ),
                samesite=samesite,
                expires=expires_val,
                classification="third-party" if is_third else "first-party",
            )
        )

    # --- GDPR-specific detections ---
    consent_mechanisms = _detect_cmp(script_sources, inline_scripts)
    fingerprinting = _detect_fingerprinting(inline_scripts)
    storage_usage = _detect_storage_api(inline_scripts)
    tracking_pixels = _find_tracking_pixels(soup, base_domain)
    legal_links = _find_legal_links(soup)
    mixed_content = _detect_mixed_content(soup)

    # --- Augment third parties with CSP-sourced domains ---
    existing_domains = {tp.domain for tp in third_parties}
    csp_value = sec_present.get("content-security-policy", "")
    if csp_value:
        for domain, directive in _extract_csp_domains(csp_value):
            if domain and domain != base_domain and domain not in existing_domains:
                cat, non_eu = _classify_third_party(domain)
                third_parties.append(
                    ThirdPartyEntry(domain=domain, category=cat, is_non_eu=non_eu, source=directive)
                )
                existing_domains.add(domain)

    return Footprint(
        url=resp.url,
        base_domain=base_domain,
        status_code=resp.status_code,
        title=title,
        generator=generator,
        content_language=lang,
        is_https=is_https,
        tls_version=tls_info.get("tls_version", ""),
        certificate_issuer=tls_info.get("certificate_issuer", ""),
        certificate_expiry=tls_info.get("certificate_expiry", ""),
        has_mixed_content=mixed_content,
        third_parties=third_parties,
        third_party_iframes=iframes[:20],
        preconnect_hints=preconnect[:15],
        inline_api_endpoints=sorted(api_endpoints)[:15],
        total_script_count=len(scripts),
        total_inline_script_bytes=total_inline_bytes,
        forms=form_fps,
        cookies=cookie_infos,
        consent_mechanisms_detected=consent_mechanisms,
        fingerprinting_signals=fingerprinting,
        storage_api_usage=storage_usage,
        tracking_pixels=tracking_pixels,
        legal_links=legal_links,
        stylesheets=stylesheets[:15],
        meta_tags=meta_tags,
        security_headers=sec_present,
        missing_security_headers=sec_missing,
        structured_data_types=sd_types,
        open_graph=og,
        canonical_url=canonical,
        raw_html=resp.text,
        raw_headers=dict(resp.headers),
    )


# ---------------------------------------------------------------------------
# LLM analysis
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = textwrap.dedent("""\
    You are a Principal Security Architect **and** GDPR / ePrivacy compliance
    auditor performing a combined technical + regulatory review of a web page,
    based exclusively on its deterministic footprint.

    <rules>
    - Base every claim on evidence in the footprint JSON.
    - Where you infer, mark it explicitly: *(inference)*.
    - Use concise, professional language.  No filler.
    - For GDPR, reference the relevant Articles (e.g., Art. 6, Art. 44, Art. 13).
    - For ePrivacy, reference the Directive 2002/58/EC and its national
      implementations where relevant (e.g. German TTDSG § 25).
    - When rating severity, use: 🔴 Critical | 🟠 High | 🟡 Medium | 🟢 Low.
    - Structure your response with the EXACT Markdown headings below.
    </rules>

    <output_format>
    ## 1. Tech Stack
    Identify frontend framework(s), CSS framework(s), CMS / generator, and any
    bundler or build-tool fingerprints visible in script paths or filenames.

    ## 2. Data Flow & Third-Party Consumers
    Classify each third-party domain from the footprint: ad network, analytics,
    session recording, tag manager, CDN, font provider, payment, social widget,
    consent management, or other.  Highlight anything unusual or unclassified.

    ## 3. GDPR Compliance Assessment

    ### 3.1 Lawful Basis & Consent
    - Is a Consent Management Platform (CMP) detected?  If not, flag as 🔴.
    - Are tracking scripts / cookies loaded BEFORE consent can be given?
      (Check if analytics / ad scripts appear without a detected CMP — this
      implies pre-consent loading.)
    - Evaluate cookie attributes: are `Secure`, `HttpOnly`, `SameSite` set
      properly?  Flag session cookies without `Secure`/`HttpOnly` as 🟠.

    ### 3.2 Data Minimisation & Purpose Limitation (Art. 5)
    - Are forms collecting PII?  Is the collection proportionate to the
      apparent purpose of the page?
    - Flag excessive PII collection (e.g. date-of-birth or government ID
      on a newsletter form) as 🔴.
    - Are there hidden form fields that may indicate covert data collection?

    ### 3.3 International Data Transfers (Art. 44–49)
    - List all third-party domains flagged as non-EU.
    - For each, note the transfer mechanism likely required (SCCs, adequacy
      decision, etc.) and the risk level.
    - Flag heavy reliance on US-based trackers without a detected CMP as 🔴.

    ### 3.4 Transparency & Data Subject Rights (Art. 13–14)
    - Is a Privacy Policy link present?
    - Is an Impressum / legal notice present?  (Mandatory for German sites
      under TMG § 5 / DDG § 5.)
    - Is a Cookie Policy present?
    - Flag any missing required legal page as 🟠 or 🔴 depending on severity.

    ### 3.5 Browser Fingerprinting & Tracking (ePrivacy / TTDSG)
    - List any fingerprinting APIs detected.
    - Evaluate localStorage / sessionStorage usage — is it likely functional
      or tracking?  (Functional storage doesn't require consent; tracking
      does under TTDSG § 25.)
    - Flag tracking pixels found and their likely purpose.

    ## 4. Security Assessment

    ### 4.1 Transport Security
    - HTTPS status, TLS version, certificate validity.
    - Mixed-content issues.
    - HSTS presence and configuration.

    ### 4.2 Security Headers Audit
    For each header in the OWASP recommended set, state present ✅ or
    missing ❌, and note misconfigurations.  Highlight the most impactful
    gaps.

    ### 4.3 Application Security Signals
    - Cross-origin form submissions (CSRF risk).
    - Password fields over non-HTTPS (credential exposure).
    - File upload endpoints (unrestricted upload risk).
    - Inline API endpoints found — are any sensitive or internal?
    - CSP analysis: does it block inline scripts?  Is it report-only?

    ### 4.4 Overall Security Posture
    Rate: 🔴 Critical | 🟠 Weak | 🟡 Adequate | 🟢 Strong.
    One-paragraph justification.

    ## 5. Risk Summary Table
    Produce a Markdown table with columns:
    | # | Finding | Category | Severity | Regulation | Recommendation |

    Include ALL findings from sections 3 and 4, sorted by severity
    (🔴 first).  Max 15 rows.

    ## 6. Key Recommendations
    Top 5 actionable, prioritised recommendations addressing the most
    severe risks first.
    </output_format>
""")


def analyze_with_llm(footprint: Footprint, model: str) -> str:
    """Send the footprint to the configured LLM and return the analysis."""

    user_msg = (
        "Analyze the following deterministic footprint extracted from a live "
        "web page.  Perform both a security review and a GDPR / ePrivacy "
        "compliance audit.\n\n"
        "<footprint>\n"
        f"{json.dumps(footprint.to_dict(), indent=2)}\n"
        "</footprint>"
    )

    try:
        resp = completion(
            model=model,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_msg},
            ],
            temperature=0.2,
        )
        return resp.choices[0].message.content
    except Exception as exc:
        return f"**LLM error:** {exc}"


# ---------------------------------------------------------------------------
# Deep-dive: evidence-grounded re-review of critical/high findings
# ---------------------------------------------------------------------------

_DEEP_DIVE_PROMPT = textwrap.dedent("""\
    You are a senior security auditor performing a SECOND-PASS, adversarial
    review of an AI-generated GDPR & security analysis.

    Your job is NOT to repeat the first analysis — it is to challenge it:
    - Separate confirmed facts from speculation
    - Expose claims that are not supported by the footprint
    - Provide concrete, actionable remediation for what IS confirmed
    - Flag what requires human investigation beyond static analysis

    <rules>
    1. Work through EVERY 🔴 Critical and 🟠 High finding from the initial analysis.
    2. For each finding, apply this strict evidence test:
       - ✅ CONFIRMED   — directly supported by a named footprint field and value
       - ⚠️  INFERRED    — plausible from footprint context but not directly proven
       - ❓ UNVERIFIABLE — cannot be determined from static HTML analysis alone
    3. For CONFIRMED findings: provide a concrete remediation with a specific
       configuration snippet, code example, or step-by-step fix.
    4. For INFERRED findings: state exactly what additional evidence would be
       needed to confirm (e.g., "requires JavaScript execution", "requires
       server-side access", "requires vendor contract review").
    5. For UNVERIFIABLE findings: do not speculate.  State clearly what a human
       investigator should do (manual testing, vendor inquiry, legal review, etc.).
    6. For unknown third-party domains: NEVER guess the vendor's identity or
       jurisdiction.  State: "Identity unverifiable from static analysis —
       requires WHOIS lookup, vendor inquiry, or network traffic analysis."
    7. Do NOT invent regulation references.  Only cite GDPR Articles,
       TTDSG paragraphs, or OWASP entries you can name precisely.
    8. Do NOT hallucinate tool names, version numbers, CVE IDs, or vendor
       documentation URLs.  If you cite a resource, keep it generic
       (e.g., "OWASP CSP cheat sheet") rather than inventing a URL.
    </rules>

    <output_format>
    ## Deep-Dive: Critical & High Findings Review

    > Second-pass evidence audit.
    > Confidence ratings: ✅ Confirmed (direct footprint evidence) |
    > ⚠️ Inferred (circumstantial) | ❓ Unverifiable (static analysis limit)

    For each 🔴/🟠 finding, use this structure:

    ### [Finding title]
    **Severity:** [🔴/🟠] | **Confidence:** [✅/⚠️/❓]

    **Evidence:** Quote the exact footprint field and value that supports or
    undermines this finding.  If no direct evidence exists, say so.

    **Assessment:** One to three sentences: what is actually known, what is
    assumed, and what cannot be determined.

    **Remediation / Next Steps:**
    - For ✅ Confirmed: concrete fix with example config or code.
    - For ⚠️ Inferred or ❓ Unverifiable: specific human investigation steps.

    ---
    </output_format>
""")


def deep_dive_analysis(footprint: Footprint, initial_analysis: str, model: str) -> str:
    """Run a structured adversarial re-review of critical/high findings."""

    user_msg = (
        "Below is the deterministic footprint and the initial AI-generated "
        "analysis.  Perform the second-pass evidence audit as instructed.\n\n"
        "<footprint>\n"
        f"{json.dumps(footprint.to_dict(), indent=2)}\n"
        "</footprint>\n\n"
        "<initial_analysis>\n"
        f"{initial_analysis}\n"
        "</initial_analysis>"
    )

    try:
        resp = completion(
            model=model,
            messages=[
                {"role": "system", "content": _DEEP_DIVE_PROMPT},
                {"role": "user", "content": user_msg},
            ],
            temperature=0.0,  # maximum determinism for factual review
        )
        return resp.choices[0].message.content
    except Exception as exc:
        return f"**Deep-dive error:** {exc}"


# ---------------------------------------------------------------------------
# Markdown export
# ---------------------------------------------------------------------------

def _build_gdpr_summary_block(fp: Footprint) -> str:
    """Build a quick-glance GDPR / security summary for the report header."""
    lines: list[str] = []

    if fp.consent_mechanisms_detected:
        lines.append(f"✅ CMP detected: {', '.join(fp.consent_mechanisms_detected)}")
    else:
        lines.append("❌ **No Consent Management Platform detected**")

    for required, label in [
        ("privacy-policy", "Privacy Policy"),
        ("impressum", "Impressum"),
        ("cookie-policy", "Cookie Policy"),
    ]:
        if required in fp.legal_links:
            lines.append(f"✅ {label} link found")
        else:
            lines.append(f"❌ **{label} link not found**")

    non_eu = [tp for tp in fp.third_parties if tp.is_non_eu]
    if non_eu:
        lines.append(f"⚠️  {len(non_eu)} third-party domain(s) flagged as non-EU")
    else:
        lines.append("✅ No non-EU third-party script domains detected")

    insecure_cookies = [c for c in fp.cookies if not c.secure]
    if insecure_cookies:
        lines.append(f"⚠️  {len(insecure_cookies)} cookie(s) without `Secure` flag")
    tp_cookies = [c for c in fp.cookies if c.classification == "third-party"]
    if tp_cookies:
        lines.append(f"⚠️  {len(tp_cookies)} third-party cookie(s)")

    if fp.fingerprinting_signals:
        lines.append(f"⚠️  Fingerprinting signals: {', '.join(fp.fingerprinting_signals)}")

    if fp.tracking_pixels:
        lines.append(f"⚠️  Tracking pixels from: {', '.join(fp.tracking_pixels[:5])}")

    if not fp.is_https:
        lines.append("❌ **Site is not served over HTTPS**")
    elif fp.has_mixed_content:
        lines.append("⚠️  Mixed content detected (HTTP resources on HTTPS page)")

    critical_missing = [
        h for h in fp.missing_security_headers
        if h in ("content-security-policy", "strict-transport-security", "x-content-type-options")
    ]
    if critical_missing:
        lines.append(f"⚠️  Missing critical security headers: {', '.join(critical_missing)}")

    pii_forms = [f for f in fp.forms if f.pii_fields]
    if pii_forms:
        all_pii = set()
        for f in pii_forms:
            all_pii.update(f.pii_fields.values())
        lines.append(f"⚠️  {len(pii_forms)} form(s) collecting PII: {', '.join(sorted(all_pii))}")

    return "\n".join(f"- {l}" for l in lines)


def _build_findings_location_block(fp: Footprint) -> str:
    """Build a Findings Location section listing where each domain/signal was discovered."""
    lines: list[str] = []

    if fp.third_parties:
        lines.append("### Third-Party Domains")
        lines.append("")
        lines.append("| Domain | Category | Non-EU | Found In |")
        lines.append("|---|---|---|---|")
        for tp in sorted(fp.third_parties, key=lambda t: t.source):
            eu_flag = "⚠️ Yes" if tp.is_non_eu else "No"
            lines.append(f"| `{tp.domain}` | {tp.category} | {eu_flag} | {tp.source} |")
        lines.append("")

    if fp.tracking_pixels:
        lines.append("### Tracking Pixels")
        lines.append("")
        lines.append("Found in `<img>` tags (1×1 or hidden) / `<noscript>` blocks:")
        for domain in fp.tracking_pixels:
            lines.append(f"- `{domain}`")
        lines.append("")

    if fp.fingerprinting_signals:
        lines.append("### Fingerprinting Signals")
        lines.append("")
        lines.append("Detected in inline `<script>` content:")
        for sig in fp.fingerprinting_signals:
            lines.append(f"- {sig}")
        lines.append("")

    if fp.cookies:
        lines.append("### Cookies")
        lines.append("")
        lines.append("Source: `Set-Cookie` response header")
        for c in fp.cookies:
            lines.append(f"- `{c.name}` (domain: `{c.domain}`, {c.classification})")
        lines.append("")

    if fp.consent_mechanisms_detected:
        lines.append("### Consent Mechanisms")
        lines.append("")
        lines.append("Detected in script `src` attributes and inline `<script>` content:")
        for cm in fp.consent_mechanisms_detected:
            lines.append(f"- {cm}")
        lines.append("")

    if not lines:
        return "_No notable findings to locate._"

    return "\n".join(lines)


def save_sources(footprint: Footprint, directory: Path) -> dict[str, Path]:
    """Save all raw sources to *directory* and return a label→Path mapping."""
    directory.mkdir(parents=True, exist_ok=True)
    safe_domain = re.sub(r"[^\w.-]", "_", footprint.base_domain)
    ts_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    prefix = directory / f"{safe_domain}_{ts_str}"

    saved: dict[str, Path] = {}

    # 1. Raw HTML page
    html_path = Path(f"{prefix}_page.html")
    html_path.write_text(footprint.raw_html, encoding="utf-8")
    saved["Page HTML"] = html_path

    # 2. Complete HTTP response headers (untruncated — security_headers in footprint are capped at 500 chars)
    headers_path = Path(f"{prefix}_headers.json")
    headers_path.write_text(
        json.dumps(dict(footprint.raw_headers), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    saved["HTTP Headers"] = headers_path

    # 3. Structured footprint JSON
    footprint_path = Path(f"{prefix}_footprint.json")
    footprint_path.write_text(
        json.dumps(footprint.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    saved["Footprint JSON"] = footprint_path

    return saved


def build_markdown(
    footprint: Footprint,
    analysis: str,
    model: str,
    verbose: bool = False,
    source_paths: dict[str, Path] | None = None,
    deep_dive: str | None = None,
) -> str:
    """Render the full report as a Markdown string."""

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    fp_json = json.dumps(footprint.to_dict(), indent=2)
    summary_block = _build_gdpr_summary_block(footprint)

    tracker_count = sum(
        1 for tp in footprint.third_parties
        if tp.category not in ("cdn", "font-provider", "unknown")
    )
    non_eu_count = sum(1 for tp in footprint.third_parties if tp.is_non_eu)
    pii_form_count = sum(1 for f in footprint.forms if f.pii_fields)

    stats = " | ".join([
        f"**Domain:** `{footprint.base_domain}`",
        f"**HTTP {footprint.status_code}**",
        f"**HTTPS:** {'✅' if footprint.is_https else '❌'}",
        f"**Scripts:** {footprint.total_script_count}",
        f"**3rd parties:** {len(footprint.third_parties)} ({tracker_count} trackers, {non_eu_count} non-EU)",
        f"**Cookies:** {len(footprint.cookies)}",
        f"**PII forms:** {pii_form_count}",
    ])

    verbose_section = ""
    if verbose:
        location_block = _build_findings_location_block(footprint)
        verbose_section = f"\n## Findings Location\n\n{location_block}\n---\n\n"

    sources_section = ""
    if source_paths:
        src_lines = ["## Sources\n", "\nRaw data saved to disk:\n", "\n"]
        for label, path in source_paths.items():
            src_lines.append(f"- **{label}:** [{path.name}]({path.resolve()})\n")
        src_lines.append("\n> **Note:** HTTP Headers file contains the complete, untruncated CSP and all other response headers.\n")
        src_lines.append("\n---\n\n")
        sources_section = "".join(src_lines)

    md = (
        "# URLLM — GDPR & Security Audit Report\n"
        "\n"
        "> [!CAUTION]\n"
        "> **Disclaimer: This is NOT legal advice.** This report is an automated technical analysis\n"
        "> generated with the assistance of a large language model. All findings must be verified\n"
        "> by qualified humans. See full disclaimer at the end of this report.\n"
        "\n"
        f"> **URL:** {footprint.url}\n"
        f"> **Analyzed:** {ts} — **Model:** `{model}`\n"
        "\n"
        "---\n"
        "\n"
        "## Quick Stats\n"
        "\n"
        f"{stats}\n"
        "\n"
        "---\n"
        "\n"
        "## Compliance Quick-Glance\n"
        "\n"
        f"{summary_block}\n"
        "\n"
        "---\n"
        "\n"
        f"{sources_section}"
        f"{verbose_section}"
        "## Deterministic Footprint\n"
        "\n"
        "<details>\n"
        f"<summary>Click to expand raw JSON ({len(fp_json):,} chars)</summary>\n"
        "\n"
        "```json\n"
        f"{fp_json}\n"
        "```\n"
        "\n"
        "</details>\n"
        "\n"
        "---\n"
        "\n"
        f"{analysis}\n"
        "\n"
        "---\n"
        "\n"
        + (
            f"{deep_dive}\n"
            "\n"
            "---\n"
            "\n"
            if deep_dive else ""
        )
        + "> [!WARNING]\n"
        "> **This report does not constitute legal advice.**\n"
        "> It is an automated technical assessment generated with the assistance of a large language model.\n"
        "> AI-generated findings may be incomplete, inaccurate, or outdated.\n"
        "> Always verify findings independently and involve qualified legal counsel before making\n"
        "> compliance or regulatory decisions.\n"
        "\n"
        f"*Generated by [URLLM](https://github.com/yourname/urllm) {__version__}*\n"
    )
    return md


def export_markdown(md: str, path: Path) -> None:
    path.write_text(md, encoding="utf-8")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

console = Console()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="urllm",
        description="Analyze a URL's technical footprint for GDPR & security risks with GenAI.",
    )
    parser.add_argument("url", help="Target URL to analyze")
    parser.add_argument(
        "-m", "--model",
        default=os.environ.get("LLM_MODEL", "gemini/gemini-2.5-flash"),
        help="LiteLLM model string (default: $LLM_MODEL or gemini/gemini-2.5-flash)",
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        default=None,
        help="Export full report to a Markdown file",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print raw footprint JSON and exit (skip LLM)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=15,
        help="HTTP timeout in seconds (default: 15)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show findings location details (where each domain/signal was discovered)",
    )
    parser.add_argument(
        "--save-sources",
        type=Path,
        default=None,
        metavar="DIR",
        help="Save all raw sources (HTML, HTTP headers, footprint JSON) to DIR (created if absent)",
    )
    parser.add_argument(
        "--deep-dive",
        action="store_true",
        help=(
            "Run a second evidence-grounded pass that re-examines every 🔴/🟠 "
            "finding: separates confirmed facts from inferences, flags "
            "unverifiable claims, and provides concrete remediation. "
            "Costs one extra LLM call."
        ),
    )
    args = parser.parse_args(argv)

    # --- Step 1: Deterministic extraction ---
    console.print(Panel(
        f"[bold]URLLM {__version__}[/bold]  GDPR & Security Audit\n"
        f"Target: [cyan]{args.url}[/cyan]",
        border_style="blue",
    ))

    result = fetch_and_parse(args.url, timeout=args.timeout)

    if isinstance(result, str):
        console.print(f"[red]Error:[/red] {result}")
        sys.exit(1)

    footprint = result

    # --- Optional: save all raw sources ---
    source_paths: dict[str, Path] | None = None
    if args.save_sources:
        source_paths = save_sources(footprint, args.save_sources)
        for label, path in source_paths.items():
            console.print(f"[dim]  {label}: [bold]{path}[/bold][/dim]")

    if args.json:
        console.print(Syntax(json.dumps(footprint.to_dict(), indent=2), "json"))
        sys.exit(0)

    # Quick compliance glance
    console.print("\n[bold]Compliance Quick-Glance[/bold]")
    console.print(_build_gdpr_summary_block(footprint))

    # Verbose: findings location
    if args.verbose:
        console.print("\n[bold]Findings Location[/bold]")
        console.print(_build_findings_location_block(footprint))

    # Full footprint
    console.print("\n[bold]Deterministic Footprint[/bold]")
    console.print(Syntax(json.dumps(footprint.to_dict(), indent=2), "json", theme="monokai"))

    # --- Step 2: LLM analysis ---
    console.print(f"\n[dim]Querying [bold]{args.model}[/bold] for GDPR & security analysis …[/dim]\n")
    analysis = analyze_with_llm(footprint, model=args.model)
    console.print(Panel(analysis, title="GDPR & Security Analysis", border_style="green"))

    # --- Step 2b: Optional deep-dive second pass ---
    deep_dive_result: str | None = None
    if args.deep_dive:
        console.print(
            f"\n[dim]Running deep-dive evidence review with [bold]{args.model}[/bold] …[/dim]\n"
        )
        deep_dive_result = deep_dive_analysis(footprint, analysis, model=args.model)
        console.print(Panel(
            deep_dive_result,
            title="Deep-Dive: Critical & High Findings Review",
            border_style="yellow",
        ))

    # --- Step 3: Optional Markdown export ---
    if args.output:
        md = build_markdown(
            footprint, analysis, model=args.model,
            verbose=args.verbose, source_paths=source_paths,
            deep_dive=deep_dive_result,
        )
        export_markdown(md, args.output)
        console.print(f"\n[green]Report saved to [bold]{args.output}[/bold][/green]")


if __name__ == "__main__":
    main()
