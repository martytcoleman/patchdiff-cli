# PatchTriage Security Patch Triage Report

**Generated:** 2026-03-19 16:38:11
**Binary A:** `/Users/marty/patchdiff-cli/corpus/yq/yq-v4.48.2-darwin-arm64`
**Binary B:** `/Users/marty/patchdiff-cli/corpus/yq/yq-v4.49.1-darwin-arm64`
**Primary question:** Which changed functions deserve immediate reverse-engineering attention?

## Summary

| Metric | Value |
|--------|-------|
| Matched functions | 11154 |
| Unmatched in A | 1 |
| Unmatched in B | 2 |

### Triage Breakdown

| Label | Count |
|-------|-------|
| [BEHAVIOR] | 1 |
| [REFACTOR] | 1 |
| [UNCHANGED] | 11152 |

## Security Review Queue

1. `__binary__` [BEHAVIOR] (score 2.0)

## Collapsed Families

- `github.com/mikefarah/yq/v4/pkg/yqlib.(*tomlDecoder).processTable` represents 10 similar `unchanged` changes

## Top 3 Changed Functions

### 1. `__binary__` [BEHAVIOR]

- **Interestingness:** 2.0
- **Match score:** 1.0492 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** allocator, formatter, io, memory_heavy
- **Size:** 10997522 -> 10997522 (+0.0%)
- **Blocks:** 1 -> 1 (+0)
- **Instructions:** 12000 -> 12000 (+0)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence

  Strings added: 'Go build ID: "q2hY0YtN-3sB8ybJE-Jt/lTAkhEBRMc6ciKECGT99/v4LxqxBLF5Kp8ufaXZSy/i1U1wlGtqa...'
  Strings removed: 'Go build ID: "7NfQnVov7nuquJ1DYlcE/mmjmINSqlEl56kMYIaaJ/v4LxqxBLF5Kp8ufaXZSy/PIt4LaME_5...'

---

### 2. `github.com/mikefarah/yq/v4/pkg/yqlib.init.stringValue.func60` [REFACTOR]

- **Interestingness:** 1.6
- **Match score:** 0.9646 (name_exact)
- **Triage confidence:** 0.0
- **Size:** 2688 -> 2112 (-21.4%)
- **Blocks:** 1 -> 1 (+0)
- **Instructions:** 672 -> 528 (-144)

**Heuristic Rationale:**
- Large structural change without semantic evidence


---

### 3. `github.com/mikefarah/yq/v4/pkg/yqlib.(*tomlDecoder).processTable` [UNCHANGED]

**Collapsed similar changes:** 9
**Examples:** `github.com/mikefarah/yq/v4/pkg/yqlib.(*tomlDecoder).processArrayTable`, `github.com/mikefarah/yq/v4/pkg/yqlib.envOperator`, `github.com/mikefarah/yq/v4/pkg/yqlib.envsubstOperator`, `github.com/mikefarah/yq/v4/pkg/yqlib.loadStringOperator`, `github.com/mikefarah/yq/v4/pkg/yqlib.loadOperator`

- **Interestingness:** 1.6
- **Match score:** 0.9688 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** codec, dispatcher, parser
- **Size:** 3776 -> 3968 (+5.1%)
- **Blocks:** 1 -> 1 (+0)
- **Instructions:** 944 -> 992 (+48)

**Review Signals:**
- structure blocks +0, instr +48


---

## Unmatched Functions

### New in B (2)
- `github.com/mikefarah/yq/v4/pkg/yqlib.getPathToUse`
- `github.com/mikefarah/yq/v4/pkg/yqlib.processEscapeCharacters`

### Removed from A (1)
- `strings.ReplaceAll`
