        # URLLM — GDPR & Security Audit Report

        > **URL:** https://openclaw.ai/
        > **Analyzed:** 2026-03-17 23:27 UTC — **Model:** `anthropic/claude-sonnet-4-6`

        ---

        ## Quick Stats

        **Domain:** `openclaw.ai` | **HTTP 200** | **HTTPS:** ✅ | **Scripts:** 4 | **3rd parties:** 0 (0 trackers, 0 non-EU) | **Cookies:** 0 | **PII forms:** 1

        ---

        ## Compliance Quick-Glance

        - ❌ **No Consent Management Platform detected**
- ❌ **Privacy Policy link not found**
- ✅ Impressum link found
- ❌ **Cookie Policy link not found**
- ✅ No non-EU third-party script domains detected
- ⚠️  Missing critical security headers: content-security-policy, x-content-type-options
- ⚠️  1 form(s) collecting PII: email

        ---

        ## Deterministic Footprint

        <details>
        <summary>Click to expand raw JSON (2,440 chars)</summary>

        ```json
        {
  "url": "https://openclaw.ai/",
  "base_domain": "openclaw.ai",
  "status_code": 200,
  "title": "OpenClaw \u2014 Personal AI Assistant",
  "generator": "Unknown",
  "content_language": "en",
  "is_https": true,
  "tls_version": "TLSv1.3",
  "certificate_issuer": "Let's Encrypt",
  "certificate_expiry": "Apr 29 14:01:37 2026 GMT",
  "has_mixed_content": false,
  "third_parties": [],
  "third_party_iframes": [],
  "preconnect_hints": [
    "https://api.fontshare.com",
    "https://cdn.fontshare.com"
  ],
  "inline_api_endpoints": [],
  "total_script_count": 4,
  "total_inline_script_bytes": 3811,
  "forms": [
    {
      "action": "https://buttondown.com/api/emails/embed-subscribe/steipete",
      "method": "POST",
      "is_cross_origin": true,
      "input_count": 2,
      "hidden_inputs": [
        "tag"
      ],
      "file_inputs": [],
      "pii_fields": {
        "email": "email"
      },
      "has_password_field": false,
      "transmits_over_https": true
    }
  ],
  "cookies": [],
  "consent_mechanisms_detected": [],
  "fingerprinting_signals": [],
  "storage_api_usage": [
    "localStorage"
  ],
  "tracking_pixels": [],
  "legal_links": {
    "impressum": "https://x.com/AryehDubois/status/2011742378655432791"
  },
  "stylesheets": [
    "https://api.fontshare.com/v2/css?f[]=clash-display@700,600,500&f[]=satoshi@400,500,700&display=swap",
    "/assets/_slug_.CwMxruYy.css",
    "/assets/index.CH_OG-ax.css"
  ],
  "meta_tags": {
    "viewport": "width=device-width, initial-scale=1",
    "description": "OpenClaw \u2014 The AI that actually does things. Your personal assistant on any platform."
  },
  "security_headers": {
    "strict-transport-security": "max-age=63072000"
  },
  "missing_security_headers": [
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "x-xss-protection",
    "permissions-policy",
    "referrer-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy"
  ],
  "structured_data_types": [],
  "open_graph": {
    "title": "OpenClaw \u2014 Personal AI Assistant",
    "description": "OpenClaw \u2014 The AI that actually does things. Your personal assistant on any platform.",
    "type": "website",
    "url": "https://openclaw.ai/",
    "image": "https://openclaw.ai/og-image.png",
    "image:width": "1200",
    "image:height": "630"
  },
  "canonical_url": "https://openclaw.ai/"
}
        ```

        </details>

        ---

        ## 1. Tech Stack

| Layer | Evidence | Detail |
|---|---|---|
| Frontend Framework | Hashed asset filenames (`_slug_.CwMxruYy.css`, `index.CH_OG-ax.css`) | Vite build output *(inference)*; likely a SPA (React/Vue/Svelte) |
| CSS Framework | Custom stylesheets only; no Tailwind/Bootstrap fingerprint detected | Unknown utility framework |
| Font Provider | `api.fontshare.com`, `cdn.fontshare.com` | Fontshare (Indian Type Foundry CDN) — Clash Display + Satoshi |
| CMS / Generator | `"generator": "Unknown"` | No CMS meta tag; likely statically generated or Vite SPA |
| Bundler | Vite content-hash filenames | Vite *(inference)* |
| Email / Newsletter | `buttondown.com` | Buttondown email subscription service |

Total script count is 4 with 3,811 bytes of inline script — modest footprint consistent with a lightweight landing page.

---

## 2. Data Flow & Third-Party Consumers

| Domain | Classification | Notes |
|---|---|---|
| `api.fontshare.com` | Font provider (CDN) | Serves CSS font manifest; IP of visitor exposed to ITF servers |
| `cdn.fontshare.com` | Font provider (CDN) | Serves actual font files; same privacy implication |
| `buttondown.com` | Email marketing / newsletter SaaS | Receives `email` PII + hidden `tag` field via cross-origin POST |

**Notable observations:**
- **No ad networks, analytics platforms, session recorders, or tag managers detected.** This is an unusually clean third-party footprint.
- **No tracking pixels detected.**
- **No third-party iframes.**
- Buttondown is a US-based SaaS *(inference — company incorporated in the US)*; this is the sole PII processor identified.
- The `tag` hidden field in the Buttondown form warrants scrutiny (see §3.2).

---

## 3. GDPR Compliance Assessment

### 3.1 Lawful Basis & Consent

| Check | Result |
|---|---|
| CMP detected | ❌ None |
| Pre-consent tracking scripts | N/A — no tracking scripts detected |
| Cookies set | None observed |

- 🟡 **No CMP detected.** However, given the absence of tracking cookies, analytics, and ad scripts, the practical risk is reduced. The sole consent-relevant activity is the voluntary newsletter subscription (legitimate basis: **Art. 6(1)(a)** — consent via explicit form submission). No pre-consent loading of trackers is evidenced.
- `localStorage` is used (see §3.5); without a CMP, any non-functional storage use would be unlawful under TTDSG § 25.
- **Cookie attributes:** No cookies are set, so no misconfiguration risk here.

### 3.2 Data Minimisation & Purpose Limitation (Art. 5)

- The newsletter form collects **one PII field: `email`**. This is proportionate for a subscription form. ✅
- **Hidden field `tag`:** Value not visible in the footprint. This field is submitted silently to Buttondown alongside the user's email. Its purpose is likely subscriber segmentation/tagging within Buttondown *(inference)*, which is a common and functional use. However, **users are not informed of this field's existence or purpose**, which may violate Art. 13 transparency requirements. 🟡
- No excessive PII (DOB, government ID, phone) detected. ✅
- No file upload endpoints. ✅

### 3.3 International Data Transfers (Art. 44–49)

| Third Party | Likely Jurisdiction | Transfer Mechanism Required | Risk |
|---|---|---|---|
| `buttondown.com` | USA *(inference)* | SCCs or adequacy decision (US not fully adequate post-Schrems II; US-EU DPF may apply if enrolled) | 🟠 High |
| `api.fontshare.com` / `cdn.fontshare.com` | India (ITF) *(inference)* | SCCs required (India lacks EU adequacy decision) | 🟡 Medium |

- 🟠 **Buttondown (US):** Email addresses are transferred to a US processor. No evidence of a Data Processing Agreement (DPA) link, SCCs, or DPF enrollment disclosure on the page. Under Art. 44–46, a valid transfer mechanism must exist and be documented.
- 🟡 **Fontshare (India):** Visitor IPs are exposed to Indian servers on every page load. India does not have an EU adequacy decision. SCCs would be required. This is a common but frequently overlooked transfer.
- No heavy reliance on US trackers; the single US data flow is the newsletter processor.

### 3.4 Transparency & Data Subject Rights (Art. 13–14)

| Required Element | Status | Notes |
|---|---|---|
| Privacy Policy | ❌ Not detected | No link found in footprint |
| Cookie Policy | ❌ Not detected | No link found |
| Impressum / Legal Notice | ⚠️ Anomalous | Points to an **X (Twitter) post** (`x.com/AryehDubois/status/...`) — not a proper legal page |
| Data Subject Rights mechanism | ❌ Not detected | No contact/rights request mechanism visible |

- 🔴 **No Privacy Policy detected.** Collecting email addresses without an accessible Privacy Policy violates Art. 13 (information to be provided at time of collection). This is a critical gap.
- 🔴 **Impressum links to a social media post.** Under German TMG § 5 / DDG § 5 (and broadly under EU transparency requirements), an Impressum must be a stable, directly accessible legal notice containing operator identity, address, and contact details. A tweet does not satisfy this requirement.
- 🟠 **No Cookie Policy.** While no cookies are currently set, `localStorage` is used and font providers receive visitor data.
- 🟠 **No data subject rights contact mechanism** (Art. 15–22 rights: access, erasure, portability, etc.).

### 3.5 Browser Fingerprinting & Tracking (ePrivacy / TTDSG)

| Signal | Detail |
|---|---|
| Fingerprinting APIs | None detected ✅ |
| `localStorage` usage | Detected — purpose unknown |
| `sessionStorage` | Not detected |
| Tracking pixels | None detected ✅ |

- 🟡 **`localStorage` usage detected.** Without source inspection, the purpose cannot be confirmed. If used for functional state (e.g., UI preferences, SPA routing state), no consent is required under TTDSG § 25(2). If used for any tracking or cross-session identification purpose, consent is required and no CMP exists to collect it. *(inference — functional use is more likely given the absence of analytics)*
- No fingerprinting APIs (Canvas, WebGL, AudioContext, etc.) detected. ✅
- No tracking pixels. ✅

---

## 4. Security Assessment

### 4.1 Transport Security

| Check | Status | Detail |
|---|---|---|
| HTTPS | ✅ | Enforced |
| TLS Version | ✅ | TLSv1.3 |
| Certificate Issuer | ✅ | Let's Encrypt (valid) |
| Certificate Expiry | ✅ | Apr 29, 2026 — ~15 months remaining |
| Mixed Content | ✅ | None detected |
| HSTS | ✅ Partial | `max-age=63072000` (2 years) present; **no `includeSubDomains`; no `preload`** |

- HSTS is present and the max-age meets OWASP recommendations (≥1 year). However, absence of `includeSubDomains` leaves subdomains unprotected, and absence of `preload` means first-visit TOFU (Trust On First Use) attacks remain theoretically possible.

### 4.2 Security Headers Audit

| Header | Status | Impact of Absence |
|---|---|---|
| `Strict-Transport-Security` | ✅ Present | — |
| `Content-Security-Policy` | ❌ Missing | 🔴 No XSS mitigation; inline scripts uncontrolled |
| `X-Content-Type-Options` | ❌ Missing | 🟠 MIME-sniffing attacks possible |
| `X-Frame-Options` | ❌ Missing | 🟠 Clickjacking risk |
| `Referrer-Policy` | ❌ Missing | 🟡 Referrer data leakage to third parties |
| `Permissions-Policy` | ❌ Missing | 🟡 No restriction on browser feature access |
| `X-XSS-Protection` | ❌ Missing | 🟢 Legacy header; low impact on modern browsers |
| `Cross-Origin-Opener-Policy` | ❌ Missing | 🟡 Cross-origin isolation not enforced |
| `Cross-Origin-Embedder-Policy` | ❌ Missing | 🟡 Required for `SharedArrayBuffer` isolation |
| `Cross-Origin-Resource-Policy` | ❌ Missing | 🟡 Resources embeddable cross-origin |

**Most impactful gaps:** CSP absence is the highest-risk missing header given 3,811 bytes of inline script and external font loading. `X-Frame-Options` absence enables clickjacking on the subscription form.

### 4.3 Application Security Signals

| Signal | Detail | Risk |
|---|---|---|
| Cross-origin form submission | POST to `https://buttondown.com/api/emails/embed-subscribe/steipete` | 🟡 Standard for embedded newsletter widgets; HTTPS enforced; CSRF risk is low as no session cookie exists on this origin |
| Password fields over non-HTTPS | None detected | ✅ |
| File upload endpoints | None detected | ✅ |
| Inline API endpoints | None detected | ✅ |
| CSP | Absent | 🔴 3,811 bytes of inline script execute without restriction; no `script-src` directive |
| Inline script volume | 3,811 bytes | Moderate; without CSP, any injected script would execute freely |

- **CSRF:** The Buttondown form posts cross-origin but carries no session state on `openclaw.ai`; practical CSRF risk is low. However, the hidden `tag` field could be manipulated client-side to alter subscriber segmentation *(inference)*.
- **No sensitive internal API endpoints exposed.** ✅

### 4.4 Overall Security Posture

**Rating: 🟠 Weak**

The transport layer is well-configured (TLS 1.3, HSTS, no mixed content, valid certificate). However, the near-total absence of HTTP security headers — most critically Content-Security-Policy — leaves the application without meaningful browser-enforced defenses against XSS and clickjacking. With 3,811 bytes of inline script executing without a CSP, any successful injection (e.g., via a supply-chain compromise of the Fontshare CDN or a future script addition) would have unrestricted access to the DOM and the newsletter form's PII. The attack surface is currently small (static landing page, no auth), which mitigates immediate risk, but the header posture is inadequate for a production service handling personal data.

---

## 5. Risk Summary Table

| # | Finding | Category | Severity | Regulation | Recommendation |
|---|---|---|---|---|---|
| 1 | No Privacy Policy present | Transparency | 🔴 Critical | GDPR Art. 13, 14 | Publish a Privacy Policy; link it from the subscription form |
| 2 | Impressum links to a tweet, not a legal page | Legal Notice | 🔴 Critical | TMG/DDG § 5, GDPR Art. 13 | Create a proper Impressum page with operator identity, address, and contact |
| 3 | Content-Security-Policy absent | Security | 🔴 Critical | — | Implement a strict CSP; use nonces for inline scripts |
| 4 | Email PII transferred to US (Buttondown) without disclosed transfer mechanism | Int'l Transfer | 🟠 High | GDPR Art. 44–46 | Confirm DPF enrollment or execute SCCs; document in Privacy Policy |
| 5 | No CMP present; localStorage used without disclosed purpose | Consent | 🟠 High | TTDSG § 25, GDPR Art. 6 | Audit localStorage use; add CMP if non-functional; disclose in Privacy Policy |
| 6 | `X-Frame-Options` missing — clickjacking on subscription form | Security | 🟠 High | — | Add `X-Frame-Options: DENY` or CSP `frame-ancestors 'none'` |
| 7 | `X-Content-Type-Options` missing | Security | 🟠 High | — | Add `X-Content-Type-Options: nosniff` |
| 8 | Fontshare (India) receives visitor IPs; no adequacy decision | Int'l Transfer | 🟡 Medium | GDPR Art. 44–46 | Execute SCCs with ITF; disclose in Privacy Policy; consider self-hosting fonts |
| 9 | Hidden `tag` field in newsletter form not disclosed to users | Transparency / Data Min. | 🟡 Medium | GDPR Art. 13, Art. 5(1)(a) | Disclose tagging purpose in form copy or Privacy Policy |
| 10 | No data subject rights contact mechanism | Rights | 🟡 Medium | GDPR Art. 15–22 | Provide a contact email/form for DSR requests |
| 11 | No Cookie / Storage Policy | Transparency | 🟡 Medium | ePrivacy Dir. Art. 5(3), TTDSG § 25 | Document all storage use in a Cookie/Storage Policy |
| 12 | HSTS missing `includeSubDomains` and `preload` | Security | 🟡 Medium | — | Update to `max-age=63072000; includeSubDomains; preload` and submit to preload list |
| 13 | `Referrer-Policy` missing — referrer data leaks to Fontshare/Buttondown | Security / Privacy | 🟡 Medium | GDPR Art. 5(1)(c) | Add `Referrer-Policy: strict-origin-when-cross-origin` |
| 14 | `Permissions-Policy` missing | Security | 🟡 Medium | — | Add restrictive Permissions-Policy to limit camera/mic/geolocation access |
| 15 | No `Cross-Origin-Opener-Policy` / `Cross-Origin-Resource-Policy` | Security | 🟡 Medium | — | Add COOP/CORP headers for cross-origin isolation |

---

## 6. Key Recommendations

**1. 🔴 Publish a Privacy Policy and fix the Impressum immediately**
The absence of a Privacy Policy while collecting email addresses is a clear Art. 13 violation. The tweet-based Impressum does not satisfy TMG/DDG § 5. Create a dedicated `/privacy` page disclosing: data controller identity, purposes, legal bases, Buttondown as processor (with transfer mechanism), Fontshare data flows, localStorage use, and data subject rights contact. Create a proper `/impressum` with full legal details.

**2. 🔴 Implement a Content-Security-Policy**
Deploy a CSP header with `script-src` using nonces or hashes for inline scripts, explicit allowlisting of `cdn.fontshare.com` for fonts, and `frame-ancestors 'none'`. This single header addresses XSS, clickjacking, and unauthorized resource loading simultaneously. Given the Vite build pipeline, nonce injection can be handled at the server/edge layer.

**3. 🟠 Establish and disclose the Buttondown data transfer mechanism**
Verify whether Buttondown is enrolled in the EU-US Data Privacy Framework (DPF). If so, document this in the Privacy Policy. If not, execute Standard Contractual Clauses (Art. 46(2)(c)) and conduct a Transfer Impact Assessment. Ensure a Data Processing Agreement is in place per Art. 28.

**4. 🟠 Audit and disclose localStorage usage; add CMP if required**
Inspect all inline scripts to determine what is written to `localStorage`. If purely functional (SPA state, theme preference), document this in the Privacy Policy and no consent gate is needed. If any cross-session tracking identifier is stored, implement a CMP before that storage write occurs, per TTDSG § 25.

**5.

        ---

        *Generated by [URLLM](https://github.com/yourname/urllm) v0.3.0 — This report is automated and does not constitute legal advice.*
