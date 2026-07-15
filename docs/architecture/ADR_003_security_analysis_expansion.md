# ADR 003: Security-analysis expansion (v0.6.0)

Date: 2026-07-15 | Status: Accepted

## Context

URLLM's primary direction is shifting toward **security** (compliance features
stay as-is, frozen — see [[urllm-design-philosophy]]). The existing `--fail-on`
gate was mostly compliance-driven; several README-advertised security checks
(notably "CSP quality: decorative vs. effective") were only performed by the
LLM, not deterministically.

## Decision

Add six passive, deterministic security detections — no active probing, one
extra pair of GETs at most — each feeding the keyless `--fail-on` gate:

1. **CSP quality** (`analyze_csp`): parses the CSP header for `unsafe-inline`,
   `unsafe-eval`, wildcard script sources, and missing `object-src` /
   `base-uri` / `frame-ancestors`; detects Report-Only deployment. Script-src
   weaknesses → **high**; Report-Only → **medium**. Structural gaps are
   footprint-level notes for the LLM, not `--fail-on` findings (noise control).
2. **Exposed secrets** (`_detect_exposed_secrets`): high-confidence prefix
   patterns only (Stripe/AWS/Google/GitHub/Slack/OpenAI keys, PEM blocks) to
   keep false positives near zero. Matches are **redacted** in output. → **critical**.
3. **Subresource Integrity** (`_find_missing_sri`): cross-origin script/style
   without `integrity`. → **medium**.
4. **TLS/HSTS/cert grading**: weak TLS (< 1.2) and expired cert → high;
   cert expiring < 30 days and short HSTS `max-age` → medium. Uses existing
   footprint fields; no new collection.
5. **Version disclosure**: `Server` / `X-Powered-By` version strings → **low**.
6. **security.txt** (`_probe_security_txt`): RFC 9116 probe (content-type
   `text/plain` + `Contact:`). Absent → **low**.

## Consequences

- `deterministic_findings()` gained a keyword-only `now` parameter (defaults to
  `datetime.now(UTC)`) so certificate-expiry math is deterministically testable.
- `--fail-on` is now a genuine security gate, not primarily a compliance gate,
  and still needs no API key.
- New footprint fields (`csp_weaknesses`, `csp_report_only`, `exposed_secrets`,
  `sri_missing`, `server_header`, `powered_by`, `security_txt_url`) flow into the
  LLM payload automatically; the system prompt §4.3 references them explicitly.
- Secret-looking strings never appear as literals in the repo (tests build them
  by concatenation) to avoid tripping GitHub push-protection.
- Kept out per KISS: active scanning, subdomain enumeration, DNS/SPF/DMARC,
  and CVE lookups (would add network/database dependencies).
