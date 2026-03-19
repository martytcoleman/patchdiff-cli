# PatchTriage Security Patch Triage Report

**Generated:** 2026-03-19 16:37:52
**Binary A:** `/Users/marty/patchdiff-cli/corpus/openssh/sshd-9.7p1-darwin-arm64`
**Binary B:** `/Users/marty/patchdiff-cli/corpus/openssh/sshd-9.8p1-darwin-arm64`
**Primary question:** Which changed functions deserve immediate reverse-engineering attention?

## Summary

| Metric | Value |
|--------|-------|
| Matched functions | 681 |
| Unmatched in A | 561 |
| Unmatched in B | 26 |

### Triage Breakdown

| Label | Count |
|-------|-------|
| **[SEC-LIKELY]** | 3 |
| **[SEC-POSSIBLE]** | 3 |
| [BEHAVIOR] | 9 |
| [REFACTOR] | 8 |
| [UNCHANGED] | 658 |

## Security Review Queue

1. `_server_accept_loop` **[SEC-POSSIBLE]** (score 139.2)
2. `_process_server_config_line_depth` **[SEC-LIKELY]** (score 106.9)
3. `_main` **[SEC-POSSIBLE]** (score 101.1)
4. `_send_rexec_state` **[SEC-LIKELY]** (score 77.9)
5. `_permitopen_port` **[SEC-LIKELY]** (score 22.3)
6. `_child_close_fds` **[SEC-POSSIBLE]** (score 15.2)
7. `_fill_default_server_options` [BEHAVIOR] (score 46.2)
8. `_dump_config` [BEHAVIOR] (score 29.0)
9. `_convtime` [BEHAVIOR] (score 25.1)
10. `_addr_pton_cidr` [BEHAVIOR] (score 9.7)

## Top 30 Changed Functions

### 1. `_server_accept_loop` **[SEC-POSSIBLE]**

- **Interestingness:** 139.2
- **Match score:** 0.9911 (name_exact)
- **Triage confidence:** 0.28
- **Inferred roles:** allocator, io, memory_heavy
- **Size:** 3316 -> 4728 (+42.6%)
- **Blocks:** 192 -> 242 (+50)
- **Instructions:** 829 -> 1182 (+353)

**Heuristic Rationale:**
- Control-flow and comparison growth suggests new guard or parser logic
- Added 50 blocks, 27 cmp(s), 58 branch(es) — possible new validation paths

  Ext calls added: `_getpeername`, `_waitpid`
  Ext calls removed: `_getpid`

---

### 2. `_process_server_config_line_depth` **[SEC-LIKELY]**

- **Interestingness:** 106.9
- **Match score:** 1.0229 (name_exact)
- **Triage confidence:** 0.53
- **Inferred roles:** allocator, dispatcher, memory_heavy
- **Size:** 10272 -> 11320 (+10.2%)
- **Blocks:** 282 -> 311 (+29)
- **Instructions:** 2568 -> 2830 (+262)

**Heuristic Rationale:**
- Added bounds constant(s) ['0x40'] with 6 new comparison(s)
- Control-flow and comparison growth suggests new guard or parser logic
- Added 29 blocks, 6 cmp(s), 59 branch(es) — possible new validation paths

  Ext calls added: `_strncmp`

---

### 3. `_main` **[SEC-POSSIBLE]**

- **Interestingness:** 101.1
- **Match score:** 0.9728 (name_exact)
- **Triage confidence:** 0.25
- **Inferred roles:** allocator, dispatcher, formatter, io, memory_heavy
- **Size:** 6560 -> 5176 (-21.1%)
- **Blocks:** 302 -> 241 (-61)
- **Instructions:** 1640 -> 1294 (-346)

**Heuristic Rationale:**
- Added bounds constant(s) ['0x20'] with 3 new comparison(s)

  Ext calls added: `_open`, `_snprintf`, `_socketpair`
  Ext calls removed: `_alarm`, `_fcntl`, `_setsockopt`, `_strlen`
  API families added: ['network']

---

### 4. `_send_rexec_state` **[SEC-LIKELY]**

- **Interestingness:** 77.9
- **Match score:** 0.7224 (name_exact)
- **Triage confidence:** 0.84
- **Inferred roles:** io
- **Size:** 412 -> 996 (+141.7%)
- **Blocks:** 19 -> 48 (+29)
- **Instructions:** 103 -> 249 (+146)

**Heuristic Rationale:**
- Added stack protection (`stack_chk_fail`)
- Added bounds constant(s) ['0x80', '0xffff'] with 3 new comparison(s)
- Control-flow and comparison growth suggests new guard or parser logic
- Added 29 blocks, 3 cmp(s), 41 branch(es) — possible new validation paths

  Ext calls added: `___error`, `___stack_chk_fail`, `_setsockopt`, `_strerror`
  API families added: ['string']

---

### 5. `_permitopen_port` **[SEC-LIKELY]**

- **Interestingness:** 22.3
- **Match score:** 0.6881 (name_exact)
- **Triage confidence:** 0.66
- **Inferred roles:** io
- **Size:** 64 -> 188 (+193.8%)
- **Blocks:** 5 -> 7 (+2)
- **Instructions:** 16 -> 47 (+31)

**Heuristic Rationale:**
- Added stack protection (`stack_chk_fail`)
- Added bounds constant(s) ['0x20', '0xffff'] with 1 new comparison(s)
- Control-flow and comparison growth suggests new guard or parser logic

  Ext calls added: `___stack_chk_fail`, `_getservbyname`, `_strtonum`
  API families added: ['string']

---

### 6. `_child_close_fds` **[SEC-POSSIBLE]**
  Matched to: `_child_close`

- **Interestingness:** 15.2
- **Match score:** 0.575 (similarity_bipartite)
- **Triage confidence:** 0.25
- **Inferred roles:** allocator, io, memory_heavy
- **Size:** 140 -> 272 (+94.3%)
- **Blocks:** 13 -> 10 (-3)
- **Instructions:** 35 -> 68 (+33)

**Heuristic Rationale:**
- Added bounds constant(s) ['0x40'] with 1 new comparison(s)

  Ext calls added: `_free`
  Ext calls removed: `_endpwent`
  API families added: ['memory']

---

### 7. `_fill_default_server_options` [BEHAVIOR]

- **Interestingness:** 46.2
- **Match score:** 1.0392 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** allocator, memory_heavy
- **Size:** 2368 -> 2652 (+12.0%)
- **Blocks:** 115 -> 129 (+14)
- **Instructions:** 592 -> 663 (+71)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 8. `_dump_config` [BEHAVIOR]

- **Interestingness:** 29.0
- **Match score:** 1.0444 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** allocator, formatter, memory_heavy
- **Size:** 5388 -> 5640 (+4.7%)
- **Blocks:** 218 -> 224 (+6)
- **Instructions:** 1347 -> 1410 (+63)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 9. `_convtime` [BEHAVIOR]

- **Interestingness:** 25.1
- **Match score:** 0.7772 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** allocator, memory_heavy
- **Size:** 412 -> 472 (+14.6%)
- **Blocks:** 25 -> 30 (+5)
- **Instructions:** 103 -> 118 (+15)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence

  Ext calls added: `_free`, `_strdup`, `_strtonum`
  Ext calls removed: `___error`, `_strtol`
  API families added: ['memory']

---

### 10. `_auth2_methods_valid` [REFACTOR]

- **Interestingness:** 19.5
- **Match score:** 1.0011 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** allocator, memory_heavy, validator
- **Size:** 400 -> 560 (+40.0%)
- **Blocks:** 12 -> 20 (+8)
- **Instructions:** 100 -> 140 (+40)

**Heuristic Rationale:**
- Large size change (40.0%) without clear security signals


---

### 11. `_cleanup_exit` [REFACTOR]

- **Interestingness:** 18.3
- **Match score:** 0.6686 (name_exact)
- **Triage confidence:** 0.0
- **Size:** 264 -> 12 (-95.5%)
- **Blocks:** 13 -> 2 (-11)
- **Instructions:** 66 -> 3 (-63)

**Heuristic Rationale:**
- Large size change (-95.5%) without clear security signals

  Ext calls removed: `___error`, `_kill`, `_strerror`

---

### 12. `_main_sigchld_handler` [REFACTOR]

- **Interestingness:** 17.0
- **Match score:** 0.6191 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** dispatcher
- **Size:** 152 -> 24 (-84.2%)
- **Blocks:** 11 -> 2 (-9)
- **Instructions:** 38 -> 6 (-32)

**Heuristic Rationale:**
- Large size change (-84.2%) without clear security signals

  Ext calls removed: `___error`, `___stack_chk_fail`, `_waitpid`

---

### 13. `_close_startup_pipes` [REFACTOR]

- **Interestingness:** 14.1
- **Match score:** 0.7715 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** allocator, io, memory_heavy
- **Size:** 104 -> 260 (+150.0%)
- **Blocks:** 6 -> 10 (+4)
- **Instructions:** 26 -> 65 (+39)

**Heuristic Rationale:**
- Large size change (150.0%) without clear security signals

  Ext calls added: `_free`
  API families added: ['memory']

---

### 14. `_addr_pton_cidr` [BEHAVIOR]

- **Interestingness:** 9.7
- **Match score:** 0.9491 (name_exact)
- **Triage confidence:** 0.0
- **Size:** 400 -> 368 (-8.0%)
- **Blocks:** 20 -> 18 (-2)
- **Instructions:** 100 -> 92 (-8)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence

  Ext calls added: `_strtonum`
  Ext calls removed: `_strtoul`

---

### 15. `_copy_set_server_options` [BEHAVIOR]

- **Interestingness:** 9.5
- **Match score:** 1.0488 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** allocator, memory_heavy
- **Size:** 2984 -> 3016 (+1.1%)
- **Blocks:** 163 -> 165 (+2)
- **Instructions:** 746 -> 754 (+8)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 16. `_srclimit_init` [REFACTOR]

- **Interestingness:** 8.5
- **Match score:** 1.0211 (name_exact)
- **Triage confidence:** 0.0
- **Size:** 336 -> 488 (+45.2%)
- **Blocks:** 12 -> 13 (+1)
- **Instructions:** 84 -> 122 (+38)

**Heuristic Rationale:**
- Large size change (45.2%) without clear security signals


---

### 17. `_ssh_msg_send` [REFACTOR]

- **Interestingness:** 7.5
- **Match score:** 1.0221 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** io
- **Size:** 324 -> 396 (+22.2%)
- **Blocks:** 15 -> 19 (+4)
- **Instructions:** 81 -> 99 (+18)

**Heuristic Rationale:**
- Large size change (22.2%) without clear security signals


---

### 18. `_parse_ipqos` [BEHAVIOR]

- **Interestingness:** 6.8
- **Match score:** 0.9432 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** control_heavy, parser
- **Size:** 212 -> 204 (-3.8%)
- **Blocks:** 8 -> 8 (+0)
- **Instructions:** 53 -> 51 (-2)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence

  Ext calls added: `_strtonum`
  Ext calls removed: `_strtol`

---

### 19. `_initialize_server_options` [BEHAVIOR]

- **Interestingness:** 5.5
- **Match score:** 1.0484 (name_exact)
- **Triage confidence:** 0.0
- **Size:** 360 -> 384 (+6.7%)
- **Blocks:** 3 -> 3 (+0)
- **Instructions:** 90 -> 96 (+6)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 20. `_srclimit_check_allow` [BEHAVIOR]

- **Interestingness:** 5.4
- **Match score:** 1.0355 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** control_heavy, validator
- **Size:** 728 -> 736 (+1.1%)
- **Blocks:** 25 -> 25 (+0)
- **Instructions:** 182 -> 184 (+2)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 21. `_server_listen` [BEHAVIOR]

- **Interestingness:** 3.3
- **Match score:** 1.0475 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** allocator, io, memory_heavy
- **Size:** 972 -> 976 (+0.4%)
- **Blocks:** 47 -> 47 (+0)
- **Instructions:** 243 -> 244 (+1)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 22. `_sigterm_handler` [REFACTOR]

- **Interestingness:** 1.1
- **Match score:** 1.0192 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** dispatcher
- **Size:** 40 -> 20 (-50.0%)
- **Blocks:** 3 -> 2 (-1)
- **Instructions:** 10 -> 5 (-5)

**Heuristic Rationale:**
- Large size change (-50.0%) without clear security signals


---

### 23. `_accumulate_host_timing_secret` [UNCHANGED]

- **Interestingness:** 1.1
- **Match score:** 1.05 (name_exact)
- **Triage confidence:** 0.0
- **Size:** 508 -> 508 (+0.0%)
- **Blocks:** 21 -> 21 (+0)
- **Instructions:** 127 -> 127 (+0)


---

### 24. `_assemble_algorithms` [UNCHANGED]

- **Interestingness:** 1.1
- **Match score:** 1.05 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** allocator, memory_heavy
- **Size:** 684 -> 684 (+0.0%)
- **Blocks:** 35 -> 35 (+0)
- **Instructions:** 171 -> 171 (+0)


---

### 25. `_load_server_config` [UNCHANGED]

- **Interestingness:** 1.1
- **Match score:** 1.05 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** allocator, control_heavy, io, memory_heavy, parser
- **Size:** 484 -> 484 (+0.0%)
- **Blocks:** 26 -> 26 (+0)
- **Instructions:** 121 -> 121 (+0)


---

### 26. `_parse_server_config_depth` [UNCHANGED]

- **Interestingness:** 1.1
- **Match score:** 1.05 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** allocator, control_heavy, memory_heavy, parser
- **Size:** 468 -> 468 (+0.0%)
- **Blocks:** 18 -> 18 (+0)
- **Instructions:** 117 -> 117 (+0)


---

### 27. `_match_cfg_line` [UNCHANGED]

- **Interestingness:** 1.1
- **Match score:** 1.05 (name_exact)
- **Triage confidence:** 0.0
- **Size:** 1788 -> 1788 (+0.0%)
- **Blocks:** 59 -> 59 (+0)
- **Instructions:** 447 -> 447 (+0)


---

### 28. `_srclimit_done` [UNCHANGED]

- **Interestingness:** 1.1
- **Match score:** 1.05 (name_exact)
- **Triage confidence:** 0.0
- **Size:** 176 -> 176 (+0.0%)
- **Blocks:** 7 -> 7 (+0)
- **Instructions:** 44 -> 44 (+0)


---

### 29. `_log_init` [UNCHANGED]

- **Interestingness:** 1.1
- **Match score:** 1.05 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** formatter, io, logger
- **Size:** 220 -> 220 (+0.0%)
- **Blocks:** 7 -> 7 (+0)
- **Instructions:** 55 -> 55 (+0)


---

### 30. `_do_log` [UNCHANGED]

- **Interestingness:** 1.1
- **Match score:** 1.05 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** formatter, io, logger
- **Size:** 652 -> 652 (+0.0%)
- **Blocks:** 28 -> 28 (+0)
- **Instructions:** 163 -> 163 (+0)


---

## Unmatched Functions

### New in B (26)
- `_siginfo_handler`
- `_srclimit_penalty_check_allow`
- `_expire_penalties`
- `_srclimit_penalise`
- `_penalties_by_expiry_RB_INSERT`
- `_srclimit_early_expire_penalties`
- `_penalties_by_expiry_RB_REMOVE`
- `_srclimit_penalty_info`
- `_srclimit_penalty_info_for_tree`
- `_expire_penalties_from_tree`
- `_penalties_by_addr_RB_REMOVE`
- `_srclimit_early_expire_penalties_from_tree`
- `_verify_host_key_dns`
- `_export_dns_rr`
- `_signal_is_crash`
- `_kex_name_valid`
- `_kex_type_from_name`
- `_kex_hash_from_name`
- `_kex_nid_from_name`
- `_kex_has_any_alg`
- `_getrrsetbyname`
- `_free_dns_response`
- `_freerrset`
- `_parse_dns_rrsection`
- `_free_dns_query`
- `_free_dns_rr`

### Removed from A (561)
- `_destroy_sensitive_data`
- `_demote_sensitive_data`
- `_get_hostkey_public_by_type`
- `_get_hostkey_private_by_type`
- `_get_hostkey_by_index`
- `_get_hostkey_public_by_index`
- `_get_hostkey_index`
- `_recv_rexec_state`
- `_server_accept_inetd`
- `_check_ip_options`
- `_grace_alarm_handler`
- `_privsep_preauth`
- `_do_ssh2_kex`
- `_privsep_postauth`
- `_notify_hostkeys`
- `_sshd_hostkey_sign`
- `_append_hostkey_type`
- `_auth_rhosts2`
- `_check_rhosts_file`
- `_auth_password`
- `_sys_auth_passwd`
- `_platform_privileged_uidswap`
- `_platform_setusercontext`
- `_platform_setusercontext_post_groups`
- `_platform_krb5_get_principal_name`
- `_platform_locked_account`
- `_get_last_login_time`
- `_record_login`
- `_record_logout`
- `_process_permitopen`
- `_process_permitopen_list`
- `_process_channel_timeouts`
- `_get_connection_info`
- `_server_loop2`
- `_sigchld_handler`
- `_sigterm_handler`
- `_server_input_channel_open`
- `_server_input_channel_req`
- `_server_input_global_request`
- `_server_input_keep_alive`
- `_allowed_user`
- `_auth_get_canonical_hostname`
- `_auth_log`
- `_auth_maxtries_exceeded`
- `_auth_root_allowed`
- `_expand_authorized_keys`
- `_authorized_principals_file`
- `_check_key_in_hostfiles`
- `_auth_debug_add`
- `_getpwnamallow`
