# ADR 002: Testing strategy — local HTTP fixture server, stubbed LLM

Date: 2026-07-15 | Status: Accepted

## Context

The repo had no tests. The extraction pipeline's whole value proposition is
determinism, which regressions silently destroy. Tests must run offline
(no external sites — flaky, mutable) and without API keys (no LLM calls).

## Decision

- **Real HTTP, local server**: the `http_site` fixture (tests/conftest.py)
  spins up a `ThreadingHTTPServer` on `127.0.0.1` with per-test configurable
  HTML, headers, and cookies. `fetch_and_parse()` is exercised through real
  `requests` traffic — no mocking of the HTTP layer, so header merging and
  cookie-jar behavior are tested as they occur in production.
- **Fixture page** (`tests/fixtures/tracker_page.html`) plants one instance of
  every extractable signal (CMP, fingerprinting JS, pixels incl. `<noscript>`,
  German PII field names, hidden/file inputs, CSP domains, JSON-LD, iframe,
  preconnect, mixed content) and serves as the regression baseline.
- **LLM boundary is the only stub**: `litellm.completion` is monkeypatched in
  `tests/test_llm.py` / `test_main_inprocess.py`; everything below it runs real.
- **CLI contract tests** run the script as a subprocess
  (`tests/test_cli.py`) to pin stdout purity, pipeability, and exit codes.
- **Coverage target ≥ 80%** via `pytest-cov` (currently ~96%). Remaining
  uncovered lines are TLS certificate internals (need a real CA-signed cert)
  and the requests raw-header fallback branch.

## Consequences

- `uv run pytest` is self-contained: offline, keyless, deterministic.
- The fixture page is the contract: new extraction features should add their
  signal there plus an assertion, keeping one canonical regression artifact.
- TDD applies to changes: tests for the SameSite-per-cookie fix, stdout
  purity, `--fail-on`, "passwort ≠ city" PII classification, and
  first-party-cookie-with-port classification were written first and observed
  failing before the fixes.
