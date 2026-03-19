"""Tests for auxiliary scripts."""

from __future__ import annotations

import subprocess


def test_real_world_script_has_valid_shell_syntax():
    subprocess.run(
        ["bash", "-n", "scripts/run_jq_real_world.sh"],
        check=True,
    )
