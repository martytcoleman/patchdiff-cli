"""LLM-powered explanations and vulnerability classification for diff results.

Supports multiple providers (OpenAI, Grok/xAI) with automatic fallback.
Loads API keys from .env file or environment variables.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path


def _load_env():
    """Load .env from project root if python-dotenv is available."""
    try:
        from dotenv import load_dotenv
        # Walk up from this file to find .env
        for parent in [Path.cwd()] + list(Path.cwd().parents):
            env_file = parent / ".env"
            if env_file.exists():
                load_dotenv(env_file)
                return
    except ImportError:
        pass


# ── Prompt templates ──────────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are an expert binary patch analyst specializing in security vulnerability \
triage. You analyze structured evidence extracted from binary diffs — you never \
see raw disassembly, only high-level signals (API changes, string changes, \
control-flow deltas, etc.).

Rules:
1. Base your analysis ONLY on the provided evidence. Do not speculate beyond it.
2. If evidence is insufficient, say so explicitly.
3. Be precise about vulnerability classes (CWE numbers when confident).
4. Distinguish between "fix confirmed" vs "fix likely" vs "insufficient evidence"."""

FUNC_PROMPT_TEMPLATE = """\
Analyze this binary function patch and provide a structured assessment.

## Function: `{name}`
## Triage label: {triage_label}
## Heuristic rationale: {rationale}

## Change evidence:
- Size: {size_a} → {size_b} bytes ({size_delta_pct:+.1f}%)
- Basic blocks: {blocks_a} → {blocks_b} ({blocks_delta:+d})
- Instructions: {instr_a} → {instr_b} ({instr_delta:+d})
- Comparisons added: {compare_delta:+d}
- Branches added: {branch_delta:+d}
- External calls added: {ext_calls_added}
- External calls removed: {ext_calls_removed}
- Internal calls added: {calls_added}
- Internal calls removed: {calls_removed}
- Strings added: {strings_added}
- Strings removed: {strings_removed}
- Constants added: {constants_added}

Respond with this exact JSON structure (no markdown fences):
{{
  "summary": "2-4 sentence explanation of what changed and why it matters",
  "vuln_class": "CWE ID if identifiable (e.g. CWE-120), else null",
  "vuln_name": "vulnerability class name (e.g. Buffer Overflow), else null",
  "fix_confidence": "confirmed | likely | possible | insufficient_evidence",
  "category": "one of: input_validation | memory_safety | integer_safety | format_string | path_traversal | auth | crypto | error_handling | resource_mgmt | feature_change | refactor | unknown",
  "attack_surface": "brief description of what an attacker could exploit before the fix, or null",
  "severity_estimate": "critical | high | medium | low | info"
}}"""

REPORT_PROMPT_TEMPLATE = """\
You are writing the executive summary for a binary patch triage report.

## Binary diff overview:
- Binary A: {binary_a}
- Binary B: {binary_b}
- Total matched functions: {total_matches}
- Functions only in A (removed): {num_unmatched_a}
- Functions only in B (added): {num_unmatched_b}

## Top changed functions (ranked by interestingness):
{top_functions_summary}

Write a concise executive summary (3-5 paragraphs) covering:
1. Overall patch scope and character
2. Security-critical changes found (with specific function names and vuln classes)
3. Notable non-security changes
4. Assessment of patch quality / completeness
5. Recommendations for further manual review

Respond in plain text (no JSON), using markdown formatting."""


# ── Provider abstraction ──────────────────────────────────────────────────────

def _get_client(provider: str | None, api_key: str | None):
    """Return (client, model_name) for the given provider."""
    from openai import OpenAI

    _load_env()

    if provider == "grok" or (provider is None and os.environ.get("GROK_API_KEY")):
        key = api_key or os.environ.get("GROK_API_KEY", "")
        if key:
            client = OpenAI(api_key=key, base_url="https://api.x.ai/v1")
            return client, "grok-3-mini-fast"

    if provider == "openai" or provider is None:
        key = api_key or os.environ.get("OPENAI_API_KEY", "")
        if key:
            client = OpenAI(api_key=key)
            return client, "gpt-4o-mini"

    return None, None


def _chat(client, model: str, system: str, user: str, temperature: float = 0.2) -> str:
    """Send a chat completion request."""
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        temperature=temperature,
        max_tokens=800,
    )
    return response.choices[0].message.content.strip()


def _parse_json_response(text: str) -> dict | None:
    """Extract JSON from LLM response, handling markdown fences."""
    # Strip markdown code fences if present
    cleaned = re.sub(r"^```(?:json)?\s*\n?", "", text, flags=re.MULTILINE)
    cleaned = re.sub(r"\n?```\s*$", "", cleaned, flags=re.MULTILINE)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        # Try to find JSON object in the text
        match = re.search(r"\{[\s\S]*\}", text)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass
    return None


# ── Core functions ────────────────────────────────────────────────────────────

def _build_func_prompt(func_diff: dict) -> str:
    """Build a detailed prompt for a single function diff."""
    signals = func_diff.get("signals", {})

    def _fmt_consts(consts):
        return [hex(c) if isinstance(c, int) else str(c) for c in (consts or [])[:15]]

    return FUNC_PROMPT_TEMPLATE.format(
        name=func_diff.get("name_a", "?"),
        triage_label=func_diff.get("triage_label", "unknown"),
        rationale="; ".join(func_diff.get("triage_rationale", ["none"])),
        size_a=signals.get("size_a", 0),
        size_b=signals.get("size_b", 0),
        size_delta_pct=signals.get("size_delta_pct", 0),
        blocks_a=signals.get("blocks_a", 0),
        blocks_b=signals.get("blocks_b", 0),
        blocks_delta=signals.get("blocks_delta", 0),
        instr_a=signals.get("instr_a", 0),
        instr_b=signals.get("instr_b", 0),
        instr_delta=signals.get("instr_delta", 0),
        compare_delta=signals.get("compare_delta", 0),
        branch_delta=signals.get("branch_delta", 0),
        ext_calls_added=signals.get("ext_calls_added", []),
        ext_calls_removed=signals.get("ext_calls_removed", []),
        calls_added=signals.get("calls_added", []),
        calls_removed=signals.get("calls_removed", []),
        strings_added=signals.get("strings_added", [])[:15],
        strings_removed=signals.get("strings_removed", [])[:15],
        constants_added=_fmt_consts(signals.get("constants_added", [])),
    )


def explain_top_functions(diff_data: dict, top_n: int = 10,
                          provider: str | None = None,
                          api_key: str | None = None) -> dict:
    """Add LLM explanations to the top N most interesting functions.

    Supports providers: "openai", "grok" (auto-detected from env if not specified).
    Returns the modified diff_data.
    """
    try:
        from openai import OpenAI
    except ImportError:
        print("Error: openai package not installed. Run: pip install 'patchtriage[llm]'",
              file=sys.stderr)
        return diff_data

    client, model = _get_client(provider, api_key)
    if not client:
        print("Error: no API key found. Set OPENAI_API_KEY or GROK_API_KEY in .env or environment.",
              file=sys.stderr)
        return diff_data

    print(f"Using LLM provider: {model}")

    funcs = diff_data.get("functions", [])
    interesting = [f for f in funcs if f.get("interestingness", 0) > 0][:top_n]

    print(f"Generating LLM explanations for {len(interesting)} functions...")

    for i, func in enumerate(interesting):
        fname = func.get("name_a", "?")
        print(f"  [{i+1}/{len(interesting)}] {fname}...", end=" ", flush=True)
        prompt = _build_func_prompt(func)
        try:
            raw = _chat(client, model, SYSTEM_PROMPT, prompt)
            parsed = _parse_json_response(raw)
            if parsed:
                func["llm_summary"] = parsed.get("summary", raw)
                func["llm_category"] = parsed.get("category", "unknown")
                func["llm_vuln_class"] = parsed.get("vuln_class")
                func["llm_vuln_name"] = parsed.get("vuln_name")
                func["llm_fix_confidence"] = parsed.get("fix_confidence", "insufficient_evidence")
                func["llm_attack_surface"] = parsed.get("attack_surface")
                func["llm_severity"] = parsed.get("severity_estimate", "info")
                print(f"[{parsed.get('severity_estimate', '?')}] {parsed.get('vuln_class', '-')}")
            else:
                func["llm_summary"] = raw
                func["llm_category"] = "unknown"
                print("[parse error]")
        except Exception as e:
            func["llm_summary"] = f"LLM error: {e}"
            func["llm_category"] = "error"
            print(f"[error: {e}]")

    return diff_data


def generate_executive_summary(diff_data: dict,
                               provider: str | None = None,
                               api_key: str | None = None) -> str:
    """Generate an LLM-powered executive summary of the entire diff."""
    try:
        from openai import OpenAI
    except ImportError:
        return ""

    client, model = _get_client(provider, api_key)
    if not client:
        return ""

    # Build top functions summary
    funcs = diff_data.get("functions", [])
    interesting = [f for f in funcs if f.get("interestingness", 0) > 0][:15]

    lines = []
    for f in interesting:
        label = f.get("triage_label", "?")
        vuln = f.get("llm_vuln_class") or "-"
        summary = f.get("llm_summary", "no LLM analysis")[:200]
        lines.append(f"- `{f['name_a']}` [{label}] {vuln}: {summary}")

    unmatched_b = diff_data.get("unmatched_b", [])
    if unmatched_b:
        lines.append(f"\nNew functions added: {', '.join(f'`{n}`' for n in unmatched_b[:10])}")

    prompt = REPORT_PROMPT_TEMPLATE.format(
        binary_a=diff_data.get("binary_a", "N/A"),
        binary_b=diff_data.get("binary_b", "N/A"),
        total_matches=diff_data.get("total_matches", 0),
        num_unmatched_a=len(diff_data.get("unmatched_a", [])),
        num_unmatched_b=len(diff_data.get("unmatched_b", [])),
        top_functions_summary="\n".join(lines),
    )

    print("Generating executive summary...")
    try:
        return _chat(client, model, SYSTEM_PROMPT, prompt, temperature=0.3)
    except Exception as e:
        print(f"Executive summary error: {e}", file=sys.stderr)
        return ""
