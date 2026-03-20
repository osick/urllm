# URLLM

**Point it at any URL. Get a grounded GDPR & security audit in seconds.**

URLLM deterministically extracts a web page's full technical and privacy fingerprint — scripts, cookies, CSP, third-party domains, PII forms, fingerprinting signals, tracking pixels, security headers — then hands the structured data to an LLM for a rigorous compliance and security review. No guessing. No raw HTML dumped into a prompt.

```
$ urllm https://example-shop.com --deep-dive -o report.md --save-sources ./sources/
```
```
╭──────────────────────────────────────────────╮
│ URLLM v0.4.0  GDPR & Security Audit          │
│ Target: https://example-shop.com             │
╰──────────────────────────────────────────────╯

Compliance Quick-Glance
- ❌ No Consent Management Platform detected
- ✅ Privacy Policy link found
- ⚠️  3 cookie(s) without Secure flag
- ⚠️  Tracking pixels from: pixel.tracker.example
- ⚠️  2 third-party domain(s) flagged as non-EU

  Page HTML:      sources/example-shop.com_page.html
  HTTP Headers:   sources/example-shop.com_headers.json   ← full untruncated CSP here
  Footprint JSON: sources/example-shop.com_footprint.json

Querying gemini/gemini-2.5-flash …
Running deep-dive evidence review …

Report saved to report.md
```

---

## Why URLLM?

Most "AI website audits" dump raw HTML into a prompt and hope for the best. URLLM is different:

- **Deterministic first** — extraction is pure Python, reproducible, no hallucinations about what the page contains
- **LLM second** — the model reasons over structured JSON, not markup soup
- **Grounded citations** — every finding references an actual footprint field
- **Anti-hallucination deep-dive** — a second adversarial pass stress-tests the initial findings, separates confirmed facts from inferences, and flags what can't be determined from static analysis

# IMPORTANT 
urllm **MUST NOT be used as legal advice** — This is a automated technical assessment aid supported by genAI. Involve qualified legal counsel for compliance decisions.

---

## Install

```bash
# Run instantly with uv (no pip, no venv)
uv run urllm.py https://example.com

# Or install as a persistent CLI tool
uv tool install .
urllm https://example.com
```

> **uv** is a fast Python package manager. Install it with:
> `curl -LsSf https://astral.sh/uv/install.sh | sh`

---

## Usage

```
urllm <URL> [OPTIONS]

  -m, --model MODEL      LiteLLM model string
                         (default: $LLM_MODEL or gemini/gemini-2.5-flash)
  -o, --output FILE      Write full audit report to a Markdown file
  -v, --verbose          Show where each finding was discovered
                         (which header, tag, or script it came from)
  --deep-dive            Run a second adversarial pass on every 🔴/🟠 finding:
                         evidence-grounded, confidence-rated, concrete fixes
  --save-sources DIR     Save raw page HTML, full HTTP headers, and footprint
                         JSON to DIR (created if absent)
  --json                 Print raw footprint JSON and exit (no LLM call needed)
  --timeout SECONDS      HTTP timeout (default: 15)
```

### Examples

```bash
# Quick audit — console output only
urllm https://example.com

# Full report with Claude, deep-dive review, and all sources saved
urllm https://example.com \
  -m anthropic/claude-sonnet-4-6 \
  -o audit.md \
  --deep-dive \
  --save-sources ./sources/

# Show exactly where each domain was found (script tag, CSP header, etc.)
urllm https://example.com -v

# Footprint only — no LLM, no API key needed
urllm https://example.com --json

# Pipe JSON into jq — find all non-EU third parties
urllm https://example.com --json 2>/dev/null \
  | jq '.third_parties[] | select(.is_non_eu)'

# Use any LiteLLM-supported model
urllm https://example.com -m gpt-4o
urllm https://example.com -m ollama/llama3.2
```

---

## What gets extracted

### Third parties & CSP

URLLM finds third-party domains from **four sources**, each tracked separately:

| Source | Example |
|---|---|
| `<script src="...">` | `analytics.google.com` via script-src |
| `<iframe src="...">` | `www.youtube.com` via iframe embed |
| `<link rel="preconnect">` | `fonts.googleapis.com` via dns-prefetch |
| **CSP header** | `www.jsctool.com` via `CSP:script-src` |

The CSP source is the most valuable — it reveals domains that are *allowed to run scripts* even if they're not in the current page load. With `--verbose`, each domain shows its exact source in the report.

### GDPR & privacy signals

| Signal | What's checked |
|---|---|
| **Cookies** | `Secure`, `HttpOnly`, `SameSite`, expiry, first/third-party |
| **Consent platforms** | 18+ CMPs: Cookiebot, OneTrust, Usercentrics, Didomi, IAB TCF, … |
| **Tracking pixels** | 1×1 images and `<noscript>` fallback beacons |
| **Fingerprinting** | Canvas, WebGL, AudioContext, WebRTC, battery API, hardware probes |
| **Client-side storage** | localStorage, sessionStorage, IndexedDB, CacheStorage |
| **PII in forms** | Email, phone, name, address, DOB, government ID, payment card, … |
| **Legal links** | Privacy policy, Impressum, cookie policy, terms, opt-out notice |

### Security signals

| Signal | What's checked |
|---|---|
| **TLS** | Version, certificate issuer, expiry |
| **Security headers** | 10 OWASP headers: CSP, HSTS, X-Frame-Options, Referrer-Policy, COOP, COEP, CORP, … |
| **CSP quality** | `unsafe-inline`, `unsafe-eval`, missing nonces — decorative vs. effective CSPs |
| **Mixed content** | HTTP resources on HTTPS pages |
| **Form security** | Cross-origin submissions, password fields, file uploads |

---

## Audit report structure

The LLM produces a structured six-section report:

1. **Tech Stack** — frameworks, CMS, bundler fingerprints from script/CSS paths
2. **Data Flow & Third-Party Consumers** — every domain classified by role
3. **GDPR Compliance Assessment**
   - Lawful basis & consent (CMP, pre-consent loading, cookie attributes)
   - Data minimisation (PII forms, hidden fields)
   - International transfers (Art. 44–49, SCCs, adequacy)
   - Transparency (Privacy Policy, Impressum, Cookie Policy)
   - Fingerprinting & tracking (ePrivacy / TTDSG § 25)
4. **Security Assessment**
   - Transport security (TLS, HSTS, mixed content)
   - Security headers per-header ✅/❌
   - Application security (CSRF, CSP effectiveness, credential exposure)
   - Overall posture rating 🔴/🟠/🟡/🟢
5. **Risk Summary Table** — all findings sorted by severity
6. **Key Recommendations** — top 5, prioritised

### With `--deep-dive`

A second adversarial pass re-examines every 🔴 Critical and 🟠 High finding:

| Rating | Meaning | LLM must provide |
|---|---|---|
| ✅ Confirmed | Direct footprint field + value | Concrete fix with config/code example |
| ⚠️ Inferred | Plausible but not proven | What additional evidence would confirm it |
| ❓ Unverifiable | Can't determine from static HTML | Specific human investigation steps |

Unknown domains like `jsctool.com` are forbidden from speculation — the model must state "requires WHOIS lookup / network traffic analysis" rather than guessing.

---

## Regulatory coverage

| Framework | Scope |
|---|---|
| **GDPR** (EU 2016/679) | Art. 5, 6, 13–14, 44–49 |
| **ePrivacy Directive** (2002/58/EC) | Cookie consent, tracking |
| **TTDSG** (Germany) | § 25 — consent for non-essential device storage |
| **TMG / DDG** (Germany) | § 5 — Impressum obligation |

---

## Configuration

```bash
export GEMINI_API_KEY="..."       # default provider (Gemini Flash)
export ANTHROPIC_API_KEY="..."    # for anthropic/* models
export OPENAI_API_KEY="..."       # for openai/* models

export LLM_MODEL="anthropic/claude-sonnet-4-6"   # override default model
```

Any provider supported by [LiteLLM](https://docs.litellm.ai/docs/providers) works — including local Ollama models.

---

## Limitations

- **Static analysis only** — server-rendered HTML only. JavaScript-heavy SPAs will be partially visible. Pair with a headless browser for full SPA coverage.
- **Server-side cookies only** — cookies set via `document.cookie` after page load are not captured.
- **Curated tracker database** — ~80 known domains covering the most common EU-market trackers. Unknown domains are flagged as `"unknown"` for LLM classification.
- **Not legal advice** — this is a technical assessment aid. Involve qualified legal counsel for compliance decisions.

---

## License

MIT
