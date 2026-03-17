"""
URLLM — URL technical footprint analyzer with GenAI architectural reasoning.

Deterministically extracts a web page's technical footprint (scripts, forms,
third-party data sinks, meta tags, structured data) and feeds the result to an
LLM for architectural analysis.  Outputs to console and optionally to Markdown.

Usage:
    uv run urllm.py https://example.com
    uv run urllm.py https://example.com --output report.md
    uv run urllm.py https://example.com --model gpt-4o --output report.md
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import textwrap
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup, Tag
from litellm import completion
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class FormFingerprint:
    action: str
    method: str
    is_cross_origin: bool
    input_count: int
    hidden_inputs: list[str] = field(default_factory=list)
    file_inputs: list[str] = field(default_factory=list)


@dataclass
class Footprint:
    """Deterministic technical footprint extracted from a single URL."""

    url: str
    base_domain: str
    status_code: int
    title: str
    generator: str
    content_language: str
    third_party_script_domains: list[str] = field(default_factory=list)
    inline_api_endpoints: list[str] = field(default_factory=list)
    forms: list[FormFingerprint] = field(default_factory=list)
    stylesheets: list[str] = field(default_factory=list)
    meta_tags: dict[str, str] = field(default_factory=dict)
    security_headers: dict[str, str] = field(default_factory=dict)
    structured_data_types: list[str] = field(default_factory=list)
    open_graph: dict[str, str] = field(default_factory=dict)
    canonical_url: str = ""
    total_script_count: int = 0
    total_inline_script_bytes: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Deterministic extraction
# ---------------------------------------------------------------------------

_INTERESTING_META = {"description", "keywords", "author", "robots", "viewport", "theme-color"}
_SECURITY_HEADERS = {
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "x-xss-protection",
    "permissions-policy",
    "referrer-policy",
}

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
        "Accept-Language": "en-US,en;q=0.9",
    }

    try:
        resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        resp.raise_for_status()
    except requests.RequestException as exc:
        return f"HTTP error: {exc}"

    soup = BeautifulSoup(resp.text, "html.parser")
    parsed = urlparse(resp.url)  # use final URL after redirects
    base_domain = parsed.netloc

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
    third_party: set[str] = set()
    for src in script_sources:
        if src.startswith("http"):
            domain = urlparse(src).netloc
            if domain and domain != base_domain:
                third_party.add(domain)

    inline_scripts = [s.string for s in scripts if s.string]
    total_inline_bytes = sum(len(s) for s in inline_scripts)
    api_endpoints: set[str] = set()
    for text in inline_scripts:
        api_endpoints.update(_API_CALL_RE.findall(text))

    # --- Forms ---
    form_fps: list[FormFingerprint] = []
    for form in soup.find_all("form"):
        action_raw = form.get("action", "")
        full_action = urljoin(resp.url, action_raw) if action_raw else resp.url
        action_domain = urlparse(full_action).netloc
        inputs = [
            {"name": inp.get("name"), "type": inp.get("type", "text")}
            for inp in form.find_all("input")
            if inp.get("name")
        ]
        form_fps.append(
            FormFingerprint(
                action=action_raw or "(self)",
                method=form.get("method", "GET").upper(),
                is_cross_origin=bool(action_domain and action_domain != base_domain),
                input_count=len(inputs),
                hidden_inputs=[i["name"] for i in inputs if i["type"] == "hidden"],
                file_inputs=[i["name"] for i in inputs if i["type"] == "file"],
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
    sec_headers: dict[str, str] = {}
    for h in _SECURITY_HEADERS:
        if val := resp.headers.get(h):
            sec_headers[h] = val[:500]

    return Footprint(
        url=resp.url,
        base_domain=base_domain,
        status_code=resp.status_code,
        title=title,
        generator=generator,
        content_language=lang,
        third_party_script_domains=sorted(third_party)[:25],
        inline_api_endpoints=sorted(api_endpoints)[:15],
        forms=form_fps,
        stylesheets=stylesheets[:15],
        meta_tags=meta_tags,
        security_headers=sec_headers,
        structured_data_types=sd_types,
        open_graph=og,
        canonical_url=canonical,
        total_script_count=len(scripts),
        total_inline_script_bytes=total_inline_bytes,
    )


# ---------------------------------------------------------------------------
# LLM analysis
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = textwrap.dedent("""\
    You are a Principal Security & Software Architect performing a technical
    review of a web page based on its deterministic footprint.

    <rules>
    - Base every claim on evidence present in the footprint JSON.
    - Where you infer, mark it explicitly as inference.
    - Use concise, professional language.  No filler.
    - Structure your response with the exact Markdown headings listed below.
    </rules>

    <output_format>
    ## Tech Stack
    Identify frontend framework(s), CSS framework(s), CMS / generator, and any
    bundler or build-tool fingerprints visible in script paths or filenames.

    ## Data Flow & Third-Party Consumers
    Classify each third-party domain: ad network, analytics, tag manager, CDN,
    font provider, social widget, or other.  Highlight anything unusual.

    ## Security & Privacy Assessment
    - Evaluate present/missing security headers against OWASP best practices.
    - Flag cross-origin form submissions, excessive hidden inputs, file-upload
      endpoints, and suspicious inline API calls.
    - Rate overall security posture: Strong / Adequate / Weak / Critical.

    ## SDLC & Infrastructure Inference
    Based on the above evidence, infer the likely deployment model (static host,
    PaaS, containerised, traditional server), CI/CD indicators, and backend
    language/framework hints.

    ## Key Recommendations
    Actionable, prioritised list (max 5 items).
    </output_format>
""")


def analyze_with_llm(footprint: Footprint, model: str) -> str:
    """Send the footprint to the configured LLM and return the analysis."""

    user_msg = (
        "Analyze the following deterministic footprint extracted from a live web page.\n\n"
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
# Markdown export
# ---------------------------------------------------------------------------

def build_markdown(footprint: Footprint, analysis: str, model: str) -> str:
    """Render the full report as a Markdown string."""

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    fp_json = json.dumps(footprint.to_dict(), indent=2)

    # Build a quick stats line
    stats_parts = [
        f"**Domain:** `{footprint.base_domain}`",
        f"**HTTP {footprint.status_code}**",
        f"**Scripts:** {footprint.total_script_count} ({footprint.total_inline_script_bytes:,} bytes inline)",
        f"**Third-party domains:** {len(footprint.third_party_script_domains)}",
        f"**Forms:** {len(footprint.forms)}",
    ]
    if footprint.generator != "Unknown":
        stats_parts.append(f"**Generator:** {footprint.generator}")

    md = textwrap.dedent(f"""\
# URLLM Report

**URL:** {footprint.url}
**Analyzed:** {ts} — **Model:** `{model}`

---

## Quick Stats

{" | ".join(stats_parts)}

---

## Deterministic Footprint

<details>
<summary>Click to expand raw JSON</summary>

```json
{fp_json}
```

</details>

---

{analysis}

---

*Generated by [URLLM](https://github.com/yourname/urllm) v0.2.0*""")
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
        description="Analyze a URL's technical footprint with GenAI reasoning.",
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
    args = parser.parse_args(argv)

    # --- Step 1: Deterministic extraction ---
    console.print(Panel(f"[bold]URLLM[/bold]  Analyzing [cyan]{args.url}[/cyan]"))

    result = fetch_and_parse(args.url, timeout=args.timeout)

    if isinstance(result, str):
        console.print(f"[red]Error:[/red] {result}")
        sys.exit(1)

    footprint = result

    if args.json:
        console.print(Syntax(json.dumps(footprint.to_dict(), indent=2), "json"))
        sys.exit(0)

    # Show extracted data
    console.print("\n[bold]Deterministic Footprint[/bold]")
    console.print(Syntax(json.dumps(footprint.to_dict(), indent=2), "json", theme="monokai"))

    # --- Step 2: LLM analysis ---
    console.print(f"\n[dim]Querying [bold]{args.model}[/bold] …[/dim]\n")
    analysis = analyze_with_llm(footprint, model=args.model)
    console.print(Panel(analysis, title="Architecture Analysis", border_style="green"))

    # --- Step 3: Optional Markdown export ---
    if args.output:
        md = build_markdown(footprint, analysis, model=args.model)
        export_markdown(md, args.output)
        console.print(f"\n[green]Report saved to [bold]{args.output}[/bold][/green]")


if __name__ == "__main__":
    main()
