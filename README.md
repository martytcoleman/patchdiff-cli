# PatchTriage — Binary Security Patch Triage CLI

A command-line tool for triaging binary patches to answer one question quickly:

> After a patch lands, which changed functions deserve immediate reverse-engineering attention?

PatchTriage compares two versions of a binary, matches functions across versions, ranks the most important changes, and highlights likely security fixes with evidence-backed heuristics. Optional LLM summaries are available, but they are secondary to the extracted evidence and ranking.

## Architecture Overview

```
Binary A ──> [Ghidra Headless] ──> features_A.json ─┐
                                                      ├──> diff.json ──> report.md
Binary B ──> [Ghidra Headless] ──> features_B.json ─┘
```

### Pipeline Stages

| Stage | Command | Description |
|-------|---------|-------------|
| **Extract** | `patchtriage extract` | Runs Ghidra headless analysis to extract per-function features (mnemonic histograms, strings, imports, constants, CFG metrics) into JSON |
| **Diff** | internal pipeline | Matches functions across versions using multi-signal similarity scoring with optional stripped-mode matching, then computes change signals for each matched pair |
| **Report** | `patchtriage report` | Applies triage heuristics to flag security-relevant changes and generates a ranked Markdown report |
| **Evaluate** | `patchtriage evaluate` | Runs a small fixture corpus and reports matching / ranking quality |
| **Explain** | optional | Adds LLM-generated summaries for the top changed functions |

## Requirements

- **Python 3.10+**
- **Ghidra** (for feature extraction) — set `GHIDRA_INSTALL_DIR` env var or install to `~/ghidra_*/`
- **numpy**, **scipy** (installed automatically)
- (Optional) **openai** package for LLM explanations: `pip install patchtriage[llm]`

## Installation

```bash
git clone <repo-url>
cd patchdiff-cli
pip install -e .
```

## Usage

### Fastest End-to-End Path

```bash
patchtriage run ./binaries/program_v1 ./binaries/program_v2 -o out --html
```

For stripped binaries:

```bash
patchtriage run ./binaries/program_v1 ./binaries/program_v2 -o out --stripped --html
```

### Step 1: Extract Features

```bash
patchtriage extract ./binaries/program_v1 -o features_v1.json
patchtriage extract ./binaries/program_v2 -o features_v2.json
```

This runs Ghidra's `analyzeHeadless` with a custom Jython script (`ghidra_scripts/extract_features.py`) that extracts per-function:

- **Mnemonic histogram** — instruction frequency distribution
- **Mnemonic bigrams** — consecutive instruction pair frequencies
- **Referenced strings** — string constants used by the function
- **Called functions** — both external imports and internal calls (with `is_external` flag)
- **Constants** — scalar operand values (filtering out trivial 0/1)
- **CFG metrics** — basic block count, instruction count, function body size
- **Caller list** — which functions call this one

### Step 2: Diff and Match Functions

```bash
patchtriage diff features_v1.json features_v2.json -o diff.json
```

**Matching algorithm:**

1. **Pass 1 — Name matching:** Functions with non-auto-generated names (i.e., not `FUN_XXXX`) are matched by exact name. This handles symbol-preserved binaries and known library functions.

2. **Pass 2 — Similarity matching:** Remaining functions are matched using a weighted multi-signal similarity score:

   | Signal | Weight | Method |
   |--------|--------|--------|
   | Normalized strings | 0.12 | Jaccard similarity |
   | String categories | 0.08 | Jaccard similarity |
   | External calls | 0.10 | Jaccard similarity |
   | All calls | 0.08 | Jaccard similarity |
   | Mnemonic histogram | 0.14 | Cosine similarity |
   | Instruction groups | 0.08 | Cosine similarity |
   | Mnemonic bigrams | 0.05 | Jaccard on bigram sets |
   | API families | 0.06 | Jaccard similarity |
   | Constant buckets | 0.04 | Jaccard similarity |
   | Callgraph context | 0.05 | Ratio similarity |
   | Size / blocks | 0.05 | min/max penalty |

3. **Blocking:** Only functions within 3x size ratio are compared, with extra blocking from API-family overlap where available.

4. **Assignment:** Candidate matches are solved with bipartite assignment rather than a greedy pass. Matches where the top alternatives are within 0.05 score are flagged as "uncertain."

5. **Stripped mode:** `patchtriage run --stripped ...` ignores function names entirely and relies on structural and contextual signals.

**Change analysis** then computes per-match:
- Size/block/instruction deltas
- Added/removed strings, external calls, internal calls, constants
- Compare/branch instruction density changes (proxy for new validation checks)
- **Interestingness score** — weighted combination of all change signals

### Step 3: Generate Report

```bash
patchtriage report diff.json --html
```

Applies **triage heuristics** and generates a ranked Markdown report (and optional HTML).

**Triage heuristics:**

| Heuristic | What it detects | Label assigned |
|-----------|----------------|----------------|
| Unsafe API swap | `strcpy`->`strncpy`, `sprintf`->`snprintf`, etc. | `security_fix_likely` |
| Stack protection | New `__stack_chk_fail` / `__fortify_fail` calls | `security_fix_likely` |
| Bounds constants + checks | New power-of-2 constants with new comparisons | `security_fix_possible` |
| Error strings | New strings containing "error", "overflow", "invalid", etc. | `security_fix_possible` |
| New validation paths | Simultaneous block + compare + branch growth | `behavior_change` |
| Large size change only | >30% size change with no security signals | `refactor` |

Each function receives:
- **triage_label**: `security_fix_likely`, `security_fix_possible`, `behavior_change`, `refactor`, `unchanged`, or `unknown`
- **rationale**: Bullet-point explanations for the label
- **confidence**: 0.0–1.0 score based on accumulated heuristic evidence

### Step 4: LLM-Powered Vulnerability Analysis

```bash
# Configure API keys in .env (supports both providers)
echo 'GROK_API_KEY=xai-...' >> .env
echo 'OPENAI_API_KEY=sk-...' >> .env

# Run with auto-detected provider (prefers Grok if both keys present)
patchtriage explain diff.json --top 10 --html

# Or specify provider explicitly
patchtriage explain diff.json --provider grok --top 10
patchtriage explain diff.json --provider openai --top 10
```

LLM support is optional. The core deliverable is the evidence-backed triage output. When enabled, the LLM receives **structured evidence only** (no raw disassembly) and produces:

**Per-function analysis:**
- 2-4 sentence natural-language summary of what changed and why it matters
- **CWE classification** (e.g., CWE-120 Buffer Overflow) when identifiable
- **Fix confidence**: `confirmed` / `likely` / `possible` / `insufficient_evidence`
- **Severity estimate**: critical / high / medium / low / info
- **Attack surface** description (what an attacker could exploit pre-patch)
- **Category**: `input_validation`, `memory_safety`, `integer_safety`, `format_string`, `path_traversal`, `auth`, `crypto`, `error_handling`, `resource_mgmt`, `feature_change`, `refactor`, `unknown`

**Executive summary:**
- Multi-paragraph overview of the entire patch
- Security-critical changes with specific function names and vuln classes
- Assessment of patch quality and completeness
- Recommendations for further manual review

**Supported LLM providers:**

| Provider | Model | Env Variable | Notes |
|----------|-------|-------------|-------|
| Grok (xAI) | grok-3-mini-fast | `GROK_API_KEY` | Fast, good at security analysis |
| OpenAI | gpt-4o-mini | `OPENAI_API_KEY` | Widely available |

**Guardrails:**
- System prompt constrains the LLM to only use provided evidence
- If evidence is insufficient, the LLM is instructed to say so explicitly
- JSON schema enforced on responses with robust parsing (handles markdown fences)
- API keys loaded from `.env` via python-dotenv (never hardcoded)

## Output Files

| File | Description |
|------|-------------|
| `features_*.json` | Per-function feature vectors for a binary |
| `diff.json` | Matched functions with change signals and interestingness scores |
| `diff_triaged.json` | Diff data enriched with triage labels and rationale |
| `diff_report.md` | Human-readable ranked report |
| `diff_report.html` | HTML version of the report |
| `diff_explained.md` | Full report with LLM analysis, CWE classifications, and executive summary |
| `diff_explained.json` | Enriched JSON with all LLM fields for programmatic use |

## Evaluation

PatchTriage includes a small fixture-driven evaluation path so changes can be tested without running Ghidra:

```bash
patchtriage evaluate examples/example_corpus.json
pytest -q
```

Suggested evaluation modes:

- symbol-preserved binaries
- stripped binaries
- recompiled binaries with different optimization settings

Suggested metrics:

- function match precision / recall
- top-k hit rate for known security-relevant functions
- analyst triage reduction: how many functions need review versus total changed

## Optional Real-World Case: jq 1.7 -> 1.7.1

`jq` is a small C command-line JSON processor with official release binaries and a documented security-fix release. The official jq site states that `jq 1.7.1` was released on December 13, 2023 and includes fixes for `CVE-2023-50246` and `CVE-2023-50268`.

If you want a real-world patch-triage run outside the default fast test suite:

```bash
scripts/run_jq_real_world.sh
```

This script:

- downloads official `jq 1.7` and `jq 1.7.1` release binaries for the current OS/architecture
- runs `patchtriage run --stripped` on the pair
- writes reports under `tmp/jq-real-world/`

Notes:

- This is intentionally optional and not part of the default `pytest` suite.
- It requires network access and a working Ghidra installation.
- The download URL pattern is inferred from jq's official release layout on GitHub releases.

## CLI Summary

You do not need custom scripts to use PatchTriage:

- `patchtriage run <bin_a> <bin_b>`: full extract + diff + triage + report
- `patchtriage extract <bin>`: extract features once for reuse
- `patchtriage diff <features_a> <features_b>`: match and analyze without rerunning Ghidra
- `patchtriage report <diff.json>`: regenerate triage/report views from saved diff data
- `patchtriage evaluate <corpus.json>`: run fixture-based evaluation

## JSON Schemas

### features.json

```json
{
  "binary": "/path/to/binary",
  "arch": "x86",
  "num_functions": 150,
  "functions": [
    {
      "name": "parse_input",
      "entry": "0x00401000",
      "size": 256,
      "instr_count": 85,
      "block_count": 12,
      "mnemonic_hist": {"mov": 20, "call": 5, "cmp": 3, "je": 2, ...},
      "mnemonic_bigrams": {"mov,mov": 8, "cmp,je": 2, ...},
      "strings": ["Invalid input", "buffer overflow"],
      "constants": [256, 1024, 65535],
      "called_functions": [
        {"name": "strlen", "is_external": true},
        {"name": "validate", "is_external": false}
      ],
      "callers": ["main"]
    }
  ]
}
```

### diff.json

```json
{
  "binary_a": "/path/to/v1",
  "binary_b": "/path/to/v2",
  "total_matches": 120,
  "unmatched_a": ["removed_func"],
  "unmatched_b": ["new_func"],
  "functions": [
    {
      "name_a": "parse_input",
      "name_b": "parse_input",
      "entry_a": "0x00401000",
      "entry_b": "0x00401100",
      "match_score": 0.92,
      "match_method": "name_exact",
      "uncertain": false,
      "interestingness": 8.5,
      "triage_label": "security_fix_likely",
      "triage_rationale": ["Replaced unsafe `sprintf` with `snprintf`"],
      "triage_confidence": 0.75,
      "signals": {
        "size_a": 256, "size_b": 280, "size_delta": 24, "size_delta_pct": 9.4,
        "blocks_a": 12, "blocks_b": 15, "blocks_delta": 3,
        "instr_a": 85, "instr_b": 95, "instr_delta": 10,
        "strings_added": ["buffer too large"],
        "strings_removed": [],
        "ext_calls_added": ["snprintf"],
        "ext_calls_removed": ["sprintf"],
        "compare_delta": 2,
        "branch_delta": 3
      }
    }
  ]
}
```

## Project Structure

```
patchdiff-cli/
├── README.md
├── pyproject.toml
├── ghidra_scripts/
│   └── extract_features.py      # Ghidra Jython script for feature extraction
├── patchtriage/
│   ├── __init__.py
│   ├── cli.py                    # CLI entry point (argparse)
│   ├── extract.py                # Ghidra headless runner
│   ├── matcher.py                # Function matching (name + similarity)
│   ├── analyzer.py               # Change signal computation + interestingness
│   ├── triage.py                 # Security-focused triage heuristics
│   ├── report.py                 # Markdown/HTML report generation
│   └── llm_explain.py            # Optional LLM summary generation
├── tests/
│   ├── test_matcher.py
│   └── test_triage.py
└── examples/                     # Example outputs (populated during evaluation)
```

## Approach & Design Decisions

### Why not just use BinDiff/Diaphora directly?

Existing tools focus on producing exhaustive function diffs. PatchTriage adds:
1. **Automated triage** — rule-based classification of changes as security-relevant, behavioral, or cosmetic
2. **Interestingness ranking** — surfaces the most important changes first instead of flat lists
3. **Evidence-based rationale** — explains *why* a change is flagged, not just *that* it differs
4. **LLM integration** — optional natural-language summaries grounded in extracted evidence
5. **CLI-native workflow** — fully scriptable, JSON-in/JSON-out pipeline

### Matching algorithm tradeoffs

- **Greedy assignment** instead of Hungarian algorithm: simpler, fast enough for typical binary sizes (<10K functions), and the "uncertain" flag catches ambiguous cases
- **Size blocking** (3x ratio): eliminates ~90% of candidate pairs without missing real matches (functions rarely change by more than 3x across versions)
- **Weighted multi-signal**: no single feature dominates; string + call similarity catches semantic similarity even when instruction sequences change due to compiler differences

### Triage heuristic design

Heuristics are intentionally **conservative and explainable**:
- Each heuristic produces a rationale string so results can be verified in Ghidra
- Confidence scores are calibrated so `security_fix_likely` requires multiple converging signals
- False positive rate is prioritized over recall — better to miss a subtle fix than cry wolf

## Evaluation: Real Binary Results

### Open-Source Target: mini_server v1 -> v2 (ARM64 macOS, clang -O1)

A deliberately vulnerable HTTP request parser (v1) was patched with security fixes (v2), compiled with `clang -O1` on ARM64, and analyzed through the full pipeline.

**Extraction:** Ghidra 12.0 via pyghidra extracted 9 functions from v1 and 10 from v2.

**Matching:** 8/9 functions matched (1 removed: `_log_request`), 2 new in v2 (`_parse_content_length`, `_validate_path`).

**Triage results (all correct):**

| Function | Label | Key Findings |
|----------|-------|--------------|
| `_parse_http_request` | SEC-LIKELY | `strcpy`->`strncpy`, +13 blocks, +6 cmp, 5 new error strings |
| `_parse_request_line` | SEC-LIKELY | `strcpy_chk`->`strncpy`, path traversal check, +7 blocks |
| `_url_decode` | SEC-POSSIBLE | `__stack_chk_fail` added, output buffer bounds check |
| `_parse_header_line` | SEC-POSSIBLE | `strcpy`->`strncpy` (bounded header copy) |
| `_format_log_entry` | SEC-POSSIBLE | `sprintf`->`snprintf` |
| `_print_request` | SEC-POSSIBLE | `__sprintf_chk`->`snprintf` |
| `entry` (main) | REFACTOR | -47.6% size (inlined url_decode test removed) |
| `_free_request` | UNCHANGED | No changes detected |

All security-relevant patches were correctly surfaced and ranked above non-security changes. The tool identified unsafe API replacements even through macOS symbol mangling (`___strcpy_chk` -> `_strncpy`).

## Limitations

- **Inlining / LTO**: Aggressive inlining can split or merge functions across versions, breaking 1:1 matching
- **Heavy optimization changes**: Compiling v1 at `-O0` and v2 at `-O2` produces pervasive instruction differences that swamp real semantic changes
- **Stripped binaries with no strings**: Without symbols or strings, matching relies heavily on mnemonic histograms and CFG structure, reducing accuracy
- **Function split/merge**: If a function is split into two (or two merged into one), the current matcher cannot represent this
- **Ghidra analysis quality**: Feature extraction quality depends on Ghidra's auto-analysis; obfuscated or packed binaries may produce poor results
- **LLM hallucination**: The LLM is constrained to provided evidence but may still over-interpret sparse signals

## Running Tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## License

MIT
