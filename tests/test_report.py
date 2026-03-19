"""Tests for report rendering."""

from __future__ import annotations

import json
from pathlib import Path

from patchtriage.report import generate_html, generate_markdown


def test_markdown_report_includes_security_triage_framing():
    with open(Path("targets/open_source/diff_triaged.json")) as f:
        diff_data = json.load(f)

    markdown = generate_markdown(diff_data, top_n=3)

    assert "# PatchTriage Security Patch Triage Report" in markdown
    assert "Which changed functions deserve immediate reverse-engineering attention?" in markdown
    assert "_parse_http_request" in markdown
    assert "[SEC-LIKELY]" in markdown


def test_html_report_wraps_rendered_markdown():
    html = generate_html("# Title\n\n- item")
    assert "<h1>Title</h1>" in html
    assert "<li>item</li>" in html
    assert "<html" in html.lower()
