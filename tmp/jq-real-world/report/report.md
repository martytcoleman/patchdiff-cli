# PatchTriage Security Patch Triage Report

**Generated:** 2026-03-19 12:51:18
**Binary A:** `/Users/marty/patchdiff-cli/tmp/jq-real-world/jq-1.7-macos-arm64`
**Binary B:** `/Users/marty/patchdiff-cli/tmp/jq-real-world/jq-1.7.1-macos-arm64`
**Primary question:** Which changed functions deserve immediate reverse-engineering attention?

## Summary

| Metric | Value |
|--------|-------|
| Matched functions | 1449 |
| Unmatched in A | 1 |
| Unmatched in B | 0 |

### Triage Breakdown

| Label | Count |
|-------|-------|
| **[SEC-POSSIBLE]** | 1 |
| [BEHAVIOR] | 48 |
| [REFACTOR] | 9 |
| [UNCHANGED] | 1391 |

## Top 15 Changed Functions

### 1. `FUN_10005f1d8` **[SEC-POSSIBLE]**
  Matched to: `FUN_10002a924`

- **Interestingness:** 14.0
- **Match score:** 0.3521 (similarity_bipartite)
- **Match uncertain** (close alternatives exist)
- **Triage confidence:** 0.31
- **Size:** 40 -> 72 (+80.0%)
- **Blocks:** 1 -> 3 (+2)
- **Instructions:** 10 -> 18 (+8)

**Heuristic Rationale:**
- Added stack protection (`stack_chk_fail`)

  Ext calls added: `___stack_chk_fail`
  Ext calls removed: `___assert_rtn`
  Strings removed: ['ctx->digits <= DEC_NUBMER_DOUBLE_PRECISION', 'jv.c', 'tsd_dec_ctx_get']

---

### 2. `entry` [BEHAVIOR]

- **Interestingness:** 15.3
- **Match score:** 0.7662 (similarity_bipartite)
- **Triage confidence:** 0.0
- **Size:** 6404 -> 6108 (-4.6%)
- **Blocks:** 228 -> 217 (-11)
- **Instructions:** 1601 -> 1527 (-74)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence

  Strings added: ['1.7.1', 'jq_init']
  Strings removed: ['1.7', 'For listing the command options, use %s --help.\n', 'jq - commandline JSON processor [version %s]\n\nUsage:\t%s [options] <jq filter> [file...]\n\t%s [options] --args <jq filter> [strings...]\n\t%s [options] --jsonargs <jq filter> [JSON_TEXTS...]\n\njq is a tool for processing JSON inputs, applying the given filter to\nits JSON text inputs and producing the filter\'s results as JSON on\nstandard output.\n\nThe simplest filter is ., which copies jq\'s input to its output\nunmodified except for formatting. For more advanced filters see\nthe jq(1) manpage ("man jq") and/or https://jqlang.github.io/jq/.\n\nExample:\n\n\t$ echo \'{"foo": 0}\' | jq .\n\t{\n\t  "foo": 0\n\t}\n\n']

---

### 3. `FUN_100003218` [BEHAVIOR]
  Matched to: `FUN_1000030a8`

- **Interestingness:** 12.8
- **Match score:** 0.6112 (similarity_bipartite)
- **Match uncertain** (close alternatives exist)
- **Triage confidence:** 0.0
- **Size:** 736 -> 792 (+7.6%)
- **Blocks:** 26 -> 25 (-1)
- **Instructions:** 184 -> 198 (+14)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence

  Strings added: ['%s (%s) and %s (%s) %s']
  String categories added: ['format']

---

### 4. `FUN_100003608` [BEHAVIOR]
  Matched to: `FUN_1000034a0`

- **Interestingness:** 12.0
- **Match score:** 0.6192 (similarity_bipartite)
- **Match uncertain** (close alternatives exist)
- **Triage confidence:** 0.0
- **Size:** 580 -> 680 (+17.2%)
- **Blocks:** 19 -> 19 (+0)
- **Instructions:** 145 -> 170 (+25)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence

  Strings added: ['%s (%s) and %s (%s) %s']
  String categories added: ['format']

---

### 5. `FUN_10000384c` [BEHAVIOR]
  Matched to: `FUN_100003748`

- **Interestingness:** 12.0
- **Match score:** 0.618 (similarity_bipartite)
- **Match uncertain** (close alternatives exist)
- **Triage confidence:** 0.0
- **Size:** 652 -> 704 (+8.0%)
- **Blocks:** 21 -> 21 (+0)
- **Instructions:** 163 -> 176 (+13)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence

  Strings added: ['%s (%s) and %s (%s) %s']
  String categories added: ['format']

---

### 6. `FUN_10000c478` [BEHAVIOR]
  Matched to: `FUN_10000c5d0`

- **Interestingness:** 5.2
- **Match score:** 0.7615 (similarity_bipartite)
- **Triage confidence:** 0.0
- **Size:** 3768 -> 3608 (-4.2%)
- **Blocks:** 87 -> 91 (+4)
- **Instructions:** 942 -> 902 (-40)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 7. `FUN_100020ef0` [BEHAVIOR]
  Matched to: `FUN_100020fd4`

- **Interestingness:** 4.2
- **Match score:** 0.7656 (similarity_bipartite)
- **Triage confidence:** 0.0
- **Size:** 1164 -> 1100 (-5.5%)
- **Blocks:** 81 -> 77 (-4)
- **Instructions:** 291 -> 275 (-16)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 8. `FUN_10000b44c` [BEHAVIOR]
  Matched to: `FUN_10000b668`

- **Interestingness:** 3.6
- **Match score:** 0.7743 (similarity_bipartite)
- **Triage confidence:** 0.0
- **Size:** 3076 -> 2912 (-5.3%)
- **Blocks:** 95 -> 97 (+2)
- **Instructions:** 769 -> 728 (-41)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 9. `FUN_10000728c` [BEHAVIOR]
  Matched to: `FUN_10000743c`

- **Interestingness:** 3.5
- **Match score:** 0.7576 (similarity_bipartite)
- **Match uncertain** (close alternatives exist)
- **Triage confidence:** 0.0
- **Size:** 656 -> 572 (-12.8%)
- **Blocks:** 11 -> 12 (+1)
- **Instructions:** 164 -> 143 (-21)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 10. `FUN_100009f30` [BEHAVIOR]
  Matched to: `FUN_10000a034`

- **Interestingness:** 3.0
- **Match score:** 0.7657 (similarity_bipartite)
- **Match uncertain** (close alternatives exist)
- **Triage confidence:** 0.0
- **Size:** 284 -> 308 (+8.5%)
- **Blocks:** 5 -> 6 (+1)
- **Instructions:** 71 -> 77 (+6)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 11. `FUN_10000a04c` [BEHAVIOR]
  Matched to: `FUN_10000a168`

- **Interestingness:** 3.0
- **Match score:** 0.7655 (similarity_bipartite)
- **Match uncertain** (close alternatives exist)
- **Triage confidence:** 0.0
- **Size:** 284 -> 308 (+8.5%)
- **Blocks:** 5 -> 6 (+1)
- **Instructions:** 71 -> 77 (+6)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 12. `FUN_10001d164` [BEHAVIOR]
  Matched to: `FUN_10001d288`

- **Interestingness:** 3.0
- **Match score:** 0.7627 (similarity_bipartite)
- **Triage confidence:** 0.0
- **Size:** 216 -> 220 (+1.9%)
- **Blocks:** 12 -> 12 (+0)
- **Instructions:** 54 -> 55 (+1)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 13. `FUN_10002a5f4` [BEHAVIOR]
  Matched to: `FUN_10002a6c8`

- **Interestingness:** 3.0
- **Match score:** 0.7502 (similarity_bipartite)
- **Triage confidence:** 0.0
- **Size:** 688 -> 604 (-12.2%)
- **Blocks:** 25 -> 25 (+0)
- **Instructions:** 172 -> 151 (-21)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 14. `FUN_100004a1c` [BEHAVIOR]
  Matched to: `FUN_100004a9c`

- **Interestingness:** 2.7
- **Match score:** 0.7676 (similarity_bipartite)
- **Triage confidence:** 0.0
- **Size:** 460 -> 436 (-5.2%)
- **Blocks:** 9 -> 9 (+0)
- **Instructions:** 115 -> 109 (-6)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 15. `FUN_100005278` [BEHAVIOR]
  Matched to: `FUN_10000536c`

- **Interestingness:** 2.7
- **Match score:** 0.7676 (similarity_bipartite)
- **Triage confidence:** 0.0
- **Size:** 460 -> 436 (-5.2%)
- **Blocks:** 9 -> 9 (+0)
- **Instructions:** 115 -> 109 (-6)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

## Unmatched Functions

### Removed from A (1)
- `FUN_10005f00c`
