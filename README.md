# URLLM

Deterministic URL footprint extraction + GenAI architectural analysis.

URLLM fetches a web page, extracts a structured technical fingerprint (scripts, forms, third-party data sinks, security headers, structured data, Open Graph metadata), and hands the result to an LLM for security & architecture review — grounding the AI analysis in factual, reproducible data rather than raw HTML.

## Quick Start

```bash
# Install uv if you don't have it
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone and run — uv handles the virtualenv and dependencies automatically
git clone https://github.com/yourname/urllm.git
cd urllm
uv run urllm.py https://news.ycombinator.com
```

No `pip install`, no `venv` — `uv run` resolves everything from `pyproject.toml` on the fly.

## Usage

```
uv run urllm.py <URL> [OPTIONS]

Options:
  -m, --model MODEL    LiteLLM model string (default: gemini/gemini-2.5-flash)
  -o, --output FILE    Export full report to Markdown
  --json               Print raw footprint JSON and exit (skip LLM call)
  --timeout SECONDS    HTTP timeout (default: 15)
```

### Examples

```bash
# Default: Gemini Flash analysis, console output
uv run urllm.py https://example.com

# Use Claude, export to Markdown
uv run urllm.py https://example.com -m claude-3-5-sonnet-20241022 -o report.md

# Use GPT-4o
uv run urllm.py https://example.com -m gpt-4o

# Just extract the footprint (no LLM call, no API key needed)
uv run urllm.py https://example.com --json
```

### Install as a CLI tool

```bash
uv tool install .
urllm https://example.com
```

## What Gets Extracted

| Signal | Detail |
|--------|--------|
| **Meta & generator** | CMS / framework generator tag, language, title |
| **Third-party script domains** | Ad networks, analytics, tag managers, CDNs |
| **Inline API endpoints** | `fetch()` / `axios` calls found in inline JS |
| **Forms** | Action, method, cross-origin flag, hidden & file inputs |
| **Stylesheets** | External CSS references |
| **Security headers** | CSP, HSTS, X-Frame-Options, Referrer-Policy, etc. |
| **Structured data** | JSON-LD `@type` values |
| **Open Graph** | OG meta tags for social/sharing metadata |

Everything is deterministic and reproducible — the LLM never sees the raw HTML, only the structured JSON footprint.

## LLM Output Structure

The prompt is engineered to produce five sections:

1. **Tech Stack** — frameworks, CSS, CMS, bundler fingerprints
2. **Data Flow & Third-Party Consumers** — classified by role (analytics, ads, CDN, etc.)
3. **Security & Privacy Assessment** — header audit, cross-origin risks, posture rating
4. **SDLC & Infrastructure Inference** — deployment model, CI/CD hints, backend clues
5. **Key Recommendations** — max 5, prioritised

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

## License

MIT
