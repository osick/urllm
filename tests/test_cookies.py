"""Per-cookie attribute parsing from Set-Cookie headers."""

import urllm


def test_samesite_attributed_to_the_correct_cookie(http_site):
    # Two cookies with *different* SameSite values: each must keep its own.
    url = http_site(headers=[
        ("Set-Cookie", "alpha=1; Path=/; SameSite=None"),
        ("Set-Cookie", "beta=2; Path=/; SameSite=Strict; HttpOnly"),
    ])
    fp = urllm.fetch_and_parse(url)
    assert not isinstance(fp, str), fp
    samesite = {c.name: c.samesite for c in fp.cookies}
    assert samesite == {"alpha": "None", "beta": "Strict"}


def test_samesite_lax_detected(http_site):
    url = http_site(headers=[("Set-Cookie", "gamma=3; Path=/; SameSite=Lax")])
    fp = urllm.fetch_and_parse(url)
    assert fp.cookies[0].samesite == "Lax"


def test_samesite_unset_when_absent(http_site):
    url = http_site(headers=[("Set-Cookie", "delta=4; Path=/")])
    fp = urllm.fetch_and_parse(url)
    assert fp.cookies[0].samesite == "unset"


def test_httponly_and_secure_flags(http_site):
    url = http_site(headers=[
        ("Set-Cookie", "alpha=1; Path=/; SameSite=None"),
        ("Set-Cookie", "beta=2; Path=/; SameSite=Strict; HttpOnly"),
    ])
    fp = urllm.fetch_and_parse(url)
    flags = {c.name: c.httponly for c in fp.cookies}
    assert flags == {"alpha": False, "beta": True}
