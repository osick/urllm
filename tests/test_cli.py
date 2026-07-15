"""End-to-end CLI contract: --json must be pipeable, --fail-on must gate exit codes."""

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

# A CSP long enough that any 80-column wrapping of stdout would corrupt the JSON.
LONG_CSP = "default-src 'self'; script-src " + " ".join(
    f"https://cdn{i:02d}.long-domain-name.example.com" for i in range(12)
)

TRACKER_HTML = """<html lang="en"><head><title>t</title>
<script src="https://www.googletagmanager.com/gtag/js?id=G-X"></script>
</head><body><a href="/privacy">Privacy Policy</a></body></html>"""


def run_cli(*argv: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(REPO / "urllm.py"), *argv],
        capture_output=True, text=True, timeout=60,
    )


def test_json_stdout_is_pure_parseable_json(http_site):
    url = http_site(html=TRACKER_HTML, headers=[("Content-Security-Policy", LONG_CSP)])
    proc = run_cli(url, "--json")
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)  # no banner, no line-wrapping
    assert data["url"].startswith("http://127.0.0.1")
    # the untruncated-in-footprint CSP header must survive piping intact
    assert data["security_headers"]["content-security-policy"].startswith("default-src")


def test_json_mode_status_output_goes_to_stderr(http_site):
    url = http_site(html=TRACKER_HTML)
    proc = run_cli(url, "--json")
    assert "URLLM" in proc.stderr  # banner still visible, just not on stdout


def test_json_pipes_into_jq_like_consumers(http_site):
    url = http_site(html=TRACKER_HTML)
    proc = run_cli(url, "--json")
    domains = [tp["domain"] for tp in json.loads(proc.stdout)["third_parties"]]
    assert "www.googletagmanager.com" in domains


def test_exit_0_without_fail_on(http_site):
    url = http_site(html=TRACKER_HTML)
    assert run_cli(url, "--json").returncode == 0


def test_fail_on_exits_2_when_threshold_reached(http_site):
    # plain-HTTP site → deterministic critical finding
    url = http_site(html=TRACKER_HTML)
    proc = run_cli(url, "--json", "--fail-on", "critical")
    assert "usage:" not in proc.stderr  # must not be an argparse error
    assert proc.returncode == 2
    assert "fail-on" in proc.stderr.lower()
    assert "[critical]" in proc.stderr  # severity label must not be eaten as rich markup


def test_fail_on_high_also_triggered_by_critical(http_site):
    url = http_site(html=TRACKER_HTML)
    proc = run_cli(url, "--json", "--fail-on", "high")
    assert "usage:" not in proc.stderr
    assert proc.returncode == 2


def test_fail_on_exit_0_when_below_threshold(monkeypatch):
    import pytest
    import urllm
    from test_findings import make_fp

    monkeypatch.setattr(urllm, "fetch_and_parse", lambda url, timeout=15: make_fp())
    with pytest.raises(SystemExit) as exc:
        urllm.main(["https://x.example/", "--json", "--fail-on", "high"])
    assert exc.value.code == 0


def test_fetch_error_exits_1():
    proc = run_cli("http://127.0.0.1:1/", "--json", "--timeout", "2")
    assert proc.returncode == 1
