# PatchTriage Security Patch Triage Report

**Generated:** 2026-03-20 10:27:30
**Binary A:** `/Users/marty/patchdiff-cli/corpus/zstd/zstd-1.5.5/programs/zstd`
**Binary B:** `/Users/marty/patchdiff-cli/corpus/zstd/zstd-1.5.7/programs/zstd`
**Primary question:** Which changed functions deserve immediate reverse-engineering attention?

## Summary

| Metric | Value |
|--------|-------|
| Matched functions | 1132 |
| Unmatched in A | 2 |
| Unmatched in B | 29 |

### Triage Breakdown

| Label | Count |
|-------|-------|
| **[SEC-POSSIBLE]** | 3 |
| [BEHAVIOR] | 89 |
| [REFACTOR] | 16 |
| [UNCHANGED] | 1024 |

## Security Review Queue

1. `_ZSTD_compressBlock_doubleFast` **[SEC-POSSIBLE]** (score 31.5)
2. `_ZSTDMT_freeCCtx` **[SEC-POSSIBLE]** (score 16.7)
3. `_ZSTD_compressSeqStore_singleBlock` **[SEC-POSSIBLE]** (score 14.7)
4. `_HUF_decompress4X2_usingDTable_internal` [BEHAVIOR] (score 50.8)
5. `_main` [BEHAVIOR] (score 45.9)
6. `_ZSTD_compressBlock_opt2` [BEHAVIOR] (score 37.5)
7. `_ZSTD_compressBlock_fast_dictMatchState` [BEHAVIOR] (score 34.6)
8. `_ZSTD_compressContinue_internal` [BEHAVIOR] (score 29.6)
9. `_ZSTD_compressSuperBlock` [BEHAVIOR] (score 21.3)
10. `_ZSTD_decompressMultiFrame` [BEHAVIOR] (score 21.1)

## Collapsed Families

- `_ZSTD_XXH64` represents 14 similar `unchanged` changes

## Top 30 Changed Functions

### 1. `_ZSTD_compressBlock_doubleFast` **[SEC-POSSIBLE]**

- **Interestingness:** 31.5
- **Match score:** 0.8229 (name_exact)
- **Triage confidence:** 0.31
- **Inferred roles:** codec
- **Size:** 11536 -> 11716 (+1.6%)
- **Blocks:** 521 -> 491 (-30)
- **Instructions:** 2884 -> 2929 (+45)

**Heuristic Rationale:**
- Added stack protection (`stack_chk_fail`)

  Ext calls added: `___stack_chk_fail`

---

### 2. `_ZSTDMT_freeCCtx` **[SEC-POSSIBLE]**

- **Interestingness:** 16.7
- **Match score:** 1.0029 (name_exact)
- **Triage confidence:** 0.25
- **Inferred roles:** allocator, codec, memory_heavy
- **Size:** 600 -> 332 (-44.7%)
- **Blocks:** 40 -> 25 (-15)
- **Instructions:** 150 -> 83 (-67)

**Heuristic Rationale:**
- Large size change (-44.7%) without clear security signals
- Function shrunk significantly and related function(s) added in B: _ZSTDMT_freeCCtxPool — possible extract-and-harden refactor


---

### 3. `_ZSTD_compressSeqStore_singleBlock` **[SEC-POSSIBLE]**

- **Interestingness:** 14.7
- **Match score:** 0.9297 (name_exact)
- **Triage confidence:** 0.34
- **Inferred roles:** allocator, codec, memory_heavy
- **Size:** 764 -> 820 (+7.3%)
- **Blocks:** 29 -> 31 (+2)
- **Instructions:** 191 -> 205 (+14)

**Heuristic Rationale:**
- Added bounds constant(s) ['0x80'] with 5 new comparison(s)
- Control-flow and comparison growth suggests new guard or parser logic

  Ext calls removed: `___stack_chk_fail`

---

### 4. `_HUF_decompress4X2_usingDTable_internal` [BEHAVIOR]

- **Interestingness:** 50.8
- **Match score:** 1.0347 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** codec
- **Size:** 6696 -> 7044 (+5.2%)
- **Blocks:** 176 -> 201 (+25)
- **Instructions:** 1674 -> 1761 (+87)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 5. `_main` [BEHAVIOR]

- **Interestingness:** 45.9
- **Match score:** 1.0378 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** dispatcher, formatter, io
- **Size:** 12440 -> 12824 (+3.1%)
- **Blocks:** 578 -> 592 (+14)
- **Instructions:** 3110 -> 3206 (+96)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 6. `_ZSTD_compressBlock_opt2` [BEHAVIOR]

- **Interestingness:** 37.5
- **Match score:** 1.0336 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** codec
- **Size:** 3660 -> 4340 (+18.6%)
- **Blocks:** 97 -> 108 (+11)
- **Instructions:** 915 -> 1085 (+170)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 7. `_ZSTD_compressBlock_fast_dictMatchState` [BEHAVIOR]

- **Interestingness:** 34.6
- **Match score:** 1.0375 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** codec
- **Size:** 9912 -> 10252 (+3.4%)
- **Blocks:** 377 -> 393 (+16)
- **Instructions:** 2478 -> 2563 (+85)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 8. `_ZSTD_compressContinue_internal` [BEHAVIOR]

- **Interestingness:** 29.6
- **Match score:** 1.0294 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** allocator, codec, memory_heavy
- **Size:** 2144 -> 2360 (+10.1%)
- **Blocks:** 66 -> 72 (+6)
- **Instructions:** 536 -> 590 (+54)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 9. `_BMK_benchCLevel` [REFACTOR]
  Matched to: `_BMK_benchCLevels`

- **Interestingness:** 27.1
- **Match score:** 0.8506 (similarity_bipartite)
- **Triage confidence:** 0.0
- **Inferred roles:** benchmark, formatter, io
- **Size:** 332 -> 472 (+42.2%)
- **Blocks:** 12 -> 22 (+10)
- **Instructions:** 83 -> 118 (+35)

**Heuristic Rationale:**
- Large size change (42.2%) without clear security signals


---

### 10. `_ZSTD_compressSuperBlock` [BEHAVIOR]

- **Interestingness:** 21.3
- **Match score:** 1.0039 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** allocator, codec, memory_heavy
- **Size:** 3120 -> 2844 (-8.8%)
- **Blocks:** 104 -> 93 (-11)
- **Instructions:** 780 -> 711 (-69)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 11. `_ZSTD_decompressMultiFrame` [BEHAVIOR]

- **Interestingness:** 21.1
- **Match score:** 1.0369 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** allocator, codec, memory_heavy
- **Size:** 1904 -> 2028 (+6.5%)
- **Blocks:** 68 -> 72 (+4)
- **Instructions:** 476 -> 507 (+31)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 12. `_ZSTD_compressSequences` [REFACTOR]

- **Interestingness:** 18.5
- **Match score:** 1.0234 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** allocator, codec, memory_heavy
- **Size:** 860 -> 1056 (+22.8%)
- **Blocks:** 33 -> 36 (+3)
- **Instructions:** 215 -> 264 (+49)

**Heuristic Rationale:**
- Large size change (22.8%) without clear security signals


---

### 13. `_FSE_decompress_wksp_bmi2` [BEHAVIOR]

- **Interestingness:** 18.2
- **Match score:** 1.0351 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** codec
- **Size:** 1484 -> 1716 (+15.6%)
- **Blocks:** 56 -> 62 (+6)
- **Instructions:** 371 -> 429 (+58)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 14. `_ZSTDMT_initCStream_internal` [BEHAVIOR]

- **Interestingness:** 17.9
- **Match score:** 1.035 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** allocator, codec, io, memory_heavy
- **Size:** 2352 -> 2516 (+7.0%)
- **Blocks:** 90 -> 96 (+6)
- **Instructions:** 588 -> 629 (+41)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 15. `_FIO_createDResources` [BEHAVIOR]

- **Interestingness:** 17.8
- **Match score:** 1.039 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** formatter, io
- **Size:** 1272 -> 1388 (+9.1%)
- **Blocks:** 75 -> 82 (+7)
- **Instructions:** 318 -> 347 (+29)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 16. `_ZSTD_compressBlock_internal` [REFACTOR]

- **Interestingness:** 17.0
- **Match score:** 1.0079 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** codec
- **Size:** 296 -> 384 (+29.7%)
- **Blocks:** 10 -> 15 (+5)
- **Instructions:** 74 -> 96 (+22)

**Heuristic Rationale:**
- Large size change (29.7%) without clear security signals


---

### 17. `_ZSTD_decodeLiteralsBlock` [BEHAVIOR]

- **Interestingness:** 16.4
- **Match score:** 1.0209 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** allocator, codec, control_heavy, memory_heavy, parser
- **Size:** 1168 -> 1356 (+16.1%)
- **Blocks:** 47 -> 56 (+9)
- **Instructions:** 292 -> 339 (+47)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 18. `_ZSTDMT_createCCtx_advanced` [REFACTOR]

- **Interestingness:** 14.9
- **Match score:** 0.9746 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** allocator, codec, io, memory_heavy
- **Size:** 700 -> 484 (-30.9%)
- **Blocks:** 29 -> 19 (-10)
- **Instructions:** 175 -> 121 (-54)

**Heuristic Rationale:**
- Large size change (-30.9%) without clear security signals

  Ext calls removed: `_free`

---

### 19. `_ZSTD_resetCCtx_internal` [BEHAVIOR]

- **Interestingness:** 14.4
- **Match score:** 1.0443 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** allocator, codec, memory_heavy
- **Size:** 3096 -> 3012 (-2.7%)
- **Blocks:** 87 -> 86 (-1)
- **Instructions:** 774 -> 753 (-21)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 20. `_ZSTD_decompressSequencesLong` [BEHAVIOR]

- **Interestingness:** 14.2
- **Match score:** 1.0357 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** allocator, codec, memory_heavy
- **Size:** 6296 -> 6436 (+2.2%)
- **Blocks:** 236 -> 243 (+7)
- **Instructions:** 1574 -> 1609 (+35)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 21. `_ZSTD_DCtx_setParameter` [REFACTOR]

- **Interestingness:** 12.5
- **Match score:** 1.024 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** codec
- **Size:** 284 -> 344 (+21.1%)
- **Blocks:** 28 -> 33 (+5)
- **Instructions:** 71 -> 86 (+15)

**Heuristic Rationale:**
- Large size change (21.1%) without clear security signals


---

### 22. `_FIO_decompressSrcFile` [BEHAVIOR]

- **Interestingness:** 11.4
- **Match score:** 1.0349 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** codec, formatter, io
- **Size:** 3452 -> 3196 (-7.4%)
- **Blocks:** 165 -> 154 (-11)
- **Instructions:** 863 -> 799 (-64)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 23. `_HUF_compress_internal` [REFACTOR]

- **Interestingness:** 10.9
- **Match score:** 0.9172 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** allocator, codec, memory_heavy
- **Size:** 1548 -> 1204 (-22.2%)
- **Blocks:** 45 -> 37 (-8)
- **Instructions:** 387 -> 301 (-86)

**Heuristic Rationale:**
- Large size change (-22.2%) without clear security signals

  Ext calls removed: `_bzero`

---

### 24. `_ZSTD_CCtx_setParameter` [REFACTOR]

- **Interestingness:** 10.9
- **Match score:** 1.0247 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** codec
- **Size:** 188 -> 228 (+21.3%)
- **Blocks:** 16 -> 19 (+3)
- **Instructions:** 47 -> 57 (+10)

**Heuristic Rationale:**
- Large size change (21.3%) without clear security signals


---

### 25. `_ZSTDMT_expandBufferPool` [BEHAVIOR]
  Matched to: `_ZSTDMT_createBufferPool`

- **Interestingness:** 10.8
- **Match score:** 0.7438 (similarity_bipartite)
- **Triage confidence:** 0.0
- **Inferred roles:** allocator, codec, io, memory_heavy
- **Size:** 316 -> 324 (+2.5%)
- **Blocks:** 17 -> 14 (-3)
- **Instructions:** 79 -> 81 (+2)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence

  Ext calls removed: `_pthread_mutex_destroy`, `_pthread_mutex_lock`, `_pthread_mutex_unlock`

---

### 26. `_ZSTDMT_compressStream_generic` [BEHAVIOR]

- **Interestingness:** 10.1
- **Match score:** 1.0421 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** allocator, codec, io, memory_heavy
- **Size:** 2640 -> 2732 (+3.5%)
- **Blocks:** 74 -> 76 (+2)
- **Instructions:** 660 -> 683 (+23)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 27. `_FIO_createCResources` [BEHAVIOR]

- **Interestingness:** 10.1
- **Match score:** 1.0493 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** formatter, io
- **Size:** 5268 -> 5296 (+0.5%)
- **Blocks:** 288 -> 290 (+2)
- **Instructions:** 1317 -> 1324 (+7)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 28. `_local_initCCtx` [BEHAVIOR]

- **Interestingness:** 9.5
- **Match score:** 1.0462 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** formatter, io
- **Size:** 1608 -> 1688 (+5.0%)
- **Blocks:** 101 -> 106 (+5)
- **Instructions:** 402 -> 422 (+20)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 29. `_ZSTD_ldm_adjustParameters` [REFACTOR]

- **Interestingness:** 9.5
- **Match score:** 0.9779 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** codec
- **Size:** 124 -> 212 (+71.0%)
- **Blocks:** 2 -> 4 (+2)
- **Instructions:** 31 -> 53 (+22)

**Heuristic Rationale:**
- Large size change (71.0%) without clear security signals


---

### 30. `_ZSTD_copyBlockSequences` [BEHAVIOR]

- **Interestingness:** 9.3
- **Match score:** 0.9953 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** codec
- **Size:** 368 -> 400 (+8.7%)
- **Blocks:** 11 -> 15 (+4)
- **Instructions:** 92 -> 100 (+8)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

## Unmatched Functions

### New in B (29)
- `_HIST_add`
- `_HUF_readCTableHeader`
- `_ZSTD_convertBlockSequences`
- `_ZSTD_get1BlockSummary`
- `_ZSTD_compressSequencesAndLiterals`
- `_ZSTD_compressSequencesAndLiterals_internal`
- `_ZSTD_CCtxParams_registerSequenceProducer`
- `_ZSTD_transferSequences_wBlockDelim`
- `_ZSTD_transferSequences_noDelim`
- `_ZSTD_compressSubBlock`
- `_ZSTD_splitBlock`
- `_ZSTD_recordFingerprint_43`
- `_ZSTD_recordFingerprint_11`
- `_ZSTD_recordFingerprint_5`
- `_ZSTD_recordFingerprint_1`
- `_ZSTDMT_freeBufferPool`
- `_ZSTDMT_freeCCtxPool`
- `_ZSTD_decodeLiteralsBlock_wrapper`
- `_formatString_u`
- `_LOREM_genBlock`
- `_LOREM_genBuffer`
- `_generateWord`
- `_formatString_u.cold.1`
- `_formatString_u.cold.2`
- `_FIO_decompressSrcFile.cold.5`
- `_LOREM_genBlock.cold.1`
- `_LOREM_genBlock.cold.2`
- `_LOREM_genBlock.cold.3`
- `_generateWord.cold.1`

### Removed from A (2)
- `_ZSTD_copySequencesToSeqStoreExplicitBlockDelim`
- `_ZSTD_copySequencesToSeqStoreNoBlockDelim`
