# ADR 001: Deterministic findings engine and CLI exit-code contract

Date: 2026-07-15 | Status: Accepted

## Context

URLLM should be usable as a CI/CD compliance gate ("fail the pipeline if the
staging site has a critical issue"). The LLM analysis cannot drive an exit code:
it is non-deterministic, needs an API key, and its severity ratings are prose.
Separately, `--json` mode printed the rich-formatted banner and footprint to
stdout, where rich's 80-column wrapping corrupted the JSON — the documented
`| jq` pipeline did not work.

## Decision

1. **Deterministic findings engine** (`deterministic_findings()`): a pure
   function mapping a `Footprint` to `(severity, message)` pairs using fixed
   rules (severities: `low < medium < high < critical`). It never calls the
   LLM, so results are reproducible and free.
2. **`--fail-on SEVERITY` flag**: exits `2` when any deterministic finding is
   at or above the threshold, after all requested output is produced.
3. **Exit-code contract**: `0` success, `1` operational error (fetch failure),
   `2` fail-on threshold reached. (argparse also uses `2` for usage errors;
   these are distinguishable by the `usage:` prefix on stderr.)
4. **stdout purity in `--json` mode**: stdout carries only the plain
   `json.dumps` footprint; the banner and all status output go to stderr.
   Interactive (non-JSON) mode keeps rich output on stdout.

## Consequences

- `urllm URL --json | jq …` works as documented; `--fail-on` enables
  pipeline gating without an LLM.
- The severity rules are code, not model output — changes to them are
  reviewable and covered by unit tests (`tests/test_findings.py`).
- Mixed-content is only reported on HTTPS pages (on plain-HTTP sites the
  missing HTTPS itself is already the critical finding).
- LLM severity ratings (🔴/🟠/…) remain report-only and never affect exit codes.
