"""Tests for authradar.core.parsing."""

from __future__ import annotations

from authradar.core.parsing import parse_html

_HTML = """<html><head><title>Hi</title>
<meta name="csrf-token" content="abc">
<script src="/a.js"></script><script>var x = 1;</script></head>
<body>
<a href="/login">l</a>
<a href="https://other.example/x">o</a>
<a href="#frag">f</a>
<a href="mailto:[email protected]">m</a>
<form action="/login" method="POST" id="lf">
  <input name="user" type="text">
  <input name="pw" type="password" required maxlength="64">
  <input type="submit" value="go">
</form>
</body></html>"""


def test_parse_extracts_title_meta_scripts() -> None:
    page = parse_html("http://t.example/p", _HTML)
    assert page.title == "Hi"
    assert page.meta.get("csrf-token") == "abc"
    assert "http://t.example/a.js" in page.script_srcs
    assert any("var x = 1" in script for script in page.inline_scripts)


def test_parse_resolves_and_filters_links() -> None:
    page = parse_html("http://t.example/p", _HTML)
    assert "http://t.example/login" in page.links
    assert "https://other.example/x" in page.links
    assert all("#" not in link for link in page.links)
    assert all(not link.startswith("mailto:") for link in page.links)


def test_parse_form_details() -> None:
    page = parse_html("http://t.example/p", _HTML)
    assert len(page.forms) == 1
    form = page.forms[0]
    assert form.method == "post"
    assert form.action == "http://t.example/login"
    assert form.form_id == "lf"
    assert form.has_password
    assert "user" in form.input_names
    password = form.input_by_type("password")
    assert password is not None
    assert password.required
    assert password.max_length == 64


def test_parse_empty_and_relative_action() -> None:
    assert parse_html("http://t.example", "").forms == ()
    page = parse_html("http://t.example/x", "<form><input name='a'></form>")
    assert page.forms[0].action == "http://t.example/x"
    assert page.forms[0].method == "get"
