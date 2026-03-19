"""CLI smoke tests for report and evaluation commands."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_cli_evaluate_command_runs():
    result = subprocess.run(
        [sys.executable, "-m", "patchtriage.cli", "evaluate", "examples/example_corpus.json"],
        capture_output=True,
        text=True,
        check=True,
    )

    assert "PatchTriage Evaluation" in result.stdout
    assert "Match recall: 1.0" in result.stdout


def test_cli_report_command_writes_outputs(tmp_path):
    output = tmp_path / "report.md"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "patchtriage.cli",
            "report",
            "targets/open_source/diff.json",
            "-o",
            str(output),
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    assert output.exists()
    text = output.read_text()
    assert "PatchTriage Security Patch Triage Report" in text
    assert "_parse_http_request" in text
    assert "Running triage heuristics..." in result.stdout
