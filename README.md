# URLLM

**Deterministic URL footprint extraction + GenAI-powered GDPR & security audit.**

URLLM fetches a web page, extracts a structured technical and privacy fingerprint, and hands the result to an LLM for a combined security review and GDPR/ePrivacy compliance audit — grounding the AI analysis in factual, reproducible data rather than raw HTML.

## Quick Start

```bash
# Install uv if you don't have it
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone and run — uv handles the virtualenv and dependencies automatically
git clone https://github.com/yourname/urllm.git
cd urllm
uv run urllm.py https://example.com
```

No `pip install`, no `venv` — `uv run` resolves everything from `pyproject.toml` on the fly.

## Usage

```
uv run urllm.py <URL> [OPTIONS]

Options:
  -m, --model MODEL    LiteLLM model string (default: gemini/gemini-2.5-flash)
  -o, --output FILE    Export full audit report to Markdown
  --json               Print raw footprint JSON and exit (skip LLM call)
  --timeout SECONDS    HTTP timeout (default: 15)
```

### Examples

```bash
# Default: Gemini Flash analysis, console output
uv run urllm.py https://spiegel.de

# Use Claude, export to Markdown
uv run urllm.py https://bahn.de -m claude-3-5-sonnet-20241022 -o bahn-audit.md

# Use GPT-4o
uv run urllm.py https://example.com -m gpt-4o

# Just extract the footprint (no LLM call, no API key needed)
uv run urllm.py https://example.com --json

# Pipe JSON footprint into jq for quick filtering
uv run urllm.py https://example.com --json 2>/dev/null | jq '.third_parties[] | select(.is_non_eu)'
```

### Install as a CLI tool

```bash
uv tool install .
urllm https://example.com
```

## What Gets Extracted

### Technical Signals

| Signal | Detail |
|--------|--------|
| **Meta & generator** | CMS / framework generator tag, language, title |
| **Third-party script domains** | Classified: ad network, analytics, session recording, CDN, etc. |
| **Non-EU flag** | Each third party is flagged if headquartered outside the EU/EEA |
| **Inline API endpoints** | `fetch()` / `axios` calls found in inline JS |
| **Stylesheets** | External CSS references |
| **Structured data** | JSON-LD `@type` values |
| **Open Graph** | OG meta tags for social/sharing metadata |
| **Third-party iframes** | Embedded content (YouTube, social widgets, etc.) |
| **Preconnect hints** | `dns-prefetch` / `preconnect` links revealing hidden connections |

### GDPR & Privacy Signals

| Signal | Detail |
|--------|--------|
| **Cookies** | Name, domain, `Secure`, `HttpOnly`, `SameSite`, expiry, first/third-party classification |
| **Consent Management Platform** | Detects 18+ CMPs: Cookiebot, OneTrust, Usercentrics, Didomi, IAB TCF API, etc. |
| **Tracking pixels** | 1×1 images and noscript fallback tracking images |
| **Browser fingerprinting** | Canvas, WebGL, AudioContext, WebRTC, battery API, hardware probes |
| **Client-side storage** | localStorage, sessionStorage, IndexedDB, CacheStorage usage |
| **PII collection** | Form fields classified: email, phone, name, address, DOB, government ID, payment card, etc. |
| **Legal links** | Privacy policy, Impressum, cookie policy, terms, opt-out, DSGVO notice |

### Security Signals

| Signal | Detail |
|--------|--------|
| **TLS** | Version, certificate issuer, certificate expiry |
| **Mixed content** | HTTP resources loaded on HTTPS pages |
| **Security headers** | 10 OWASP headers checked: CSP, HSTS, X-Frame-Options, Referrer-Policy, COOP, COEP, CORP, etc. |
| **Form security** | Cross-origin submissions, password fields, file uploads, HTTPS transmission |

## LLM Output Structure

The prompt produces a structured audit report with six sections:

1. **Tech Stack** — frameworks, CSS, CMS, bundler fingerprints
2. **Data Flow & Third-Party Consumers** — classified by role
3. **GDPR Compliance Assessment**
   - 3.1 Lawful Basis & Consent (CMP detection, pre-consent loading)
   - 3.2 Data Minimisation (PII proportionality, hidden fields)
   - 3.3 International Data Transfers (Art. 44–49, SCCs)
   - 3.4 Transparency (Privacy Policy, Impressum, Cookie Policy)
   - 3.5 Fingerprinting & Tracking (ePrivacy / TTDSG § 25)
4. **Security Assessment**
   - 4.1 Transport Security (TLS, HSTS, mixed content)
   - 4.2 Security Headers Audit (per-header ✅/❌)
   - 4.3 Application Security (CSRF, credential exposure, CSP)
   - 4.4 Overall Posture Rating
5. **Risk Summary Table** — all findings ranked by severity (🔴🟠🟡🟢)
6. **Key Recommendations** — top 5, prioritised

## Regulatory Coverage

The analysis references these frameworks where applicable:

| Framework | Scope |
|-----------|-------|
| **GDPR** (EU 2016/679) | Art. 5, 6, 13–14, 44–49 |
| **ePrivacy Directive** (2002/58/EC) | Cookie consent, tracking |
| **TTDSG** (Germany) | § 25 — consent for non-essential storage |
| **TMG / DDG** (Germany) | § 5 — Impressum obligation |

## Configuration

Set your API key for the provider you want to use:

```bash
export GEMINI_API_KEY="..."       # default provider
export ANTHROPIC_API_KEY="..."    # for claude-* models
export OPENAI_API_KEY="..."       # for gpt-* models
```

Override the default model globally:

```bash
export LLM_MODEL="claude-3-5-sonnet-20241022"
```

See [LiteLLM supported providers](https://docs.litellm.ai/docs/providers) for the full list.

## Project Structure

```
urllm/
├── pyproject.toml   # uv / PEP 621 project metadata
├── urllm.py         # single-file application
└── README.md
```

## Limitations

- **Static analysis only**: URLLM fetches the server-rendered HTML. JavaScript-rendered content (SPAs) will only be partially visible. For full SPA analysis, consider pairing with a headless browser.
- **Cookie detection is server-side**: Cookies set via JavaScript are not captured (the `requests` library doesn't execute JS). The inline-JS analysis detects `document.cookie` patterns but cannot enumerate actual values.
- **Tracker database is curated, not exhaustive**: The ~80 known domains cover the most common trackers in the EU market. Unknown domains are flagged as `"unknown"` for LLM classification.
- **Not legal advice**: The generated report is a technical assessment aid. Always involve qualified legal counsel for compliance decisions.

## License

MIT
