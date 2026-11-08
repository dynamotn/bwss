# M4 test map

Every test whose code M4 Part B replaced or removed, and the test that covers it now. Nothing was deleted without a row here. `dybw-core 8c4b303` is the pinned core revision (`Cargo.toml`); `B9` is the commit that deletes `src/bw/`; `pre-M4` is a bwss test older than Part B.

The 68 tests of `src/bw/` went with the code: the core's own tests were ported from them in M2 (most keep their names); the few that test bwss glue are ported into bwss under their original names.

## `src/bw/api.rs` (19)

| Old test | Covered now by | Commit |
|---|---|---|
| `a_body_cut_short_is_a_network_error` | bwss `core_ports/http.rs` `http_reports_a_network_error_without_the_url` (a transport failure is a network error) and dybw-core `api/client_tests.rs` `network_failures_carry_the_port_text` | 60ccdd5, dybw-core 8c4b303 |
| `a_body_that_is_not_utf8_is_read_lossily` | dybw-core `api/client_tests.rs` `server_text_is_joined_cleaned_and_clipped` (the server text is read with `from_utf8_lossy`, `api/client.rs`) | dybw-core 8c4b303 |
| `a_client_that_cannot_be_built_is_a_network_error` | no counterpart needed: `HttpPort::new` builds its reqwest client from constants only; its error path stays (`core_ports/http.rs`), its success is covered by every `core_ports/http.rs` test | 60ccdd5 |
| `a_sync_without_a_profile_is_refused` | dybw-core `api/client_tests.rs` `sync_needs_a_profile_id` | dybw-core 8c4b303 |
| `api_key_debug_is_redacted` | dybw-core `api/client_tests.rs` `api_key_debug_is_redacted` | dybw-core 8c4b303 |
| `identity_origins_follow_the_server` | dybw-core `api/client_tests.rs` `resolve_urls` and `origins_are_scheme_host_and_port` (bwss now calls `origin_of(&resolve_server_urls(..)?.identity)`); bwss `migrate.rs` `a_new_profile_carries_the_account_settings_credentials_and_device` checks the bound origin end to end | dybw-core 8c4b303 |
| `normalizes_empty_keys_unchanged` | dybw-core `api/client_tests.rs` `normalize_keys_lowercases_first_letter_recursively` | dybw-core 8c4b303 |
| `normalizes_pascal_case` | dybw-core `api/client_tests.rs` `normalize_keys_lowercases_first_letter_recursively`; vector `read/pascal-case` | dybw-core 8c4b303 |
| `origins_are_scheme_host_and_port` | dybw-core `api/client_tests.rs` `origins_are_scheme_host_and_port` | dybw-core 8c4b303 |
| `out_of_date_detection` | dybw-core `api/client_tests.rs` `errors_shaped` (`is_out_of_date`, `is_transient`) | dybw-core 8c4b303 |
| `prelogin_reads_both_kdf_kinds_and_refuses_others` | dybw-core `api/client_tests.rs` `prelogin_parses_both_kdfs` | dybw-core 8c4b303 |
| `response_bodies_are_capped_while_they_are_read` | bwss `core_ports/http.rs` `http_stops_at_max_body`; dybw-core `api/client_tests.rs` `responses_over_the_limit_are_refused`, `get_cipher_over_16_mib_is_too_large`, `sync_up_to_256_mib_is_read` | 60ccdd5, dybw-core 8c4b303 |
| `server_error_text_loses_control_characters_and_escapes` | dybw-core `api/client_tests.rs` `server_text_is_joined_cleaned_and_clipped` | dybw-core 8c4b303 |
| `server_urls` | dybw-core `api/client_tests.rs` `resolve_urls` | dybw-core 8c4b303 |
| `the_api_key_is_never_sent_to_another_origin` | dybw-core `api/client_tests.rs` `api_key_bound_to_origin`, `a_bad_identity_url_sends_nothing` | dybw-core 8c4b303 |
| `the_body_buffer_is_reserved_modestly_and_grown_into_wiped_copies` | bwss `core_ports/http.rs` `http_grows_the_body_across_chunks_and_puts` (the same reserve-and-grow code moved into `HttpPort::send`) | 60ccdd5 |
| `token_response_yields_token_and_ttl` | dybw-core `api/client_tests.rs` `login_sends_client_credentials`, `login_refuses_answers_without_a_token`, `a_short_lived_token_lasts_a_minute`, `the_token_is_renewed_a_minute_before_it_expires` | dybw-core 8c4b303 |
| `validation_errors_are_part_of_the_server_text` | dybw-core `api/client_tests.rs` `server_text_is_joined_cleaned_and_clipped` | dybw-core 8c4b303 |
| `writing_before_a_sync_is_transient` | dybw-core `api/client_tests.rs` `writes_name_their_owner_and_encode_ids` (`NotSynced`) and `errors_shaped` (`NotSynced` is transient) | dybw-core 8c4b303 |

## `src/bw/crypto.rs` (11)

| Old test | Covered now by | Commit |
|---|---|---|
| `argon2id_known_answers` | dybw-core `crypto/tests.rs` `master_keys_match_kat` | dybw-core 8c4b303 |
| `argon2id_refuses_what_the_algorithm_rejects` | dybw-core `crypto/tests.rs` `native_argon2_reports_bad_parameters`; bwss `core_ports/kdf.rs` `argon2_rejects_bad_parameters` | dybw-core 8c4b303, 60ccdd5 |
| `decrypt_str_rejects_invalid_utf8_and_keeps_valid_text` | dybw-core `crypto/tests.rs` `round_trip` | dybw-core 8c4b303 |
| `derived_keys_are_separate` | dybw-core `crypto/rsa_mark_tests.rs` `bwss_subkeys_known_answers` (ADR 0023 purposes) | dybw-core 8c4b303 |
| `enc_strings_known_answers_and_round_trip` | dybw-core `crypto/tests.rs` `enc_strings_match_kat`, `round_trip` | dybw-core 8c4b303 |
| `kdf_bounds` | dybw-core `crypto/tests.rs` `kdf_bounds` | dybw-core 8c4b303 |
| `keys_of_the_wrong_length_are_refused` | dybw-core `crypto/tests.rs` `malformed_and_unsupported_inputs` (`from_bytes(&[0; 63])`) | dybw-core 8c4b303 |
| `pbkdf2_known_answers` | dybw-core `crypto/tests.rs` `master_keys_match_kat` | dybw-core 8c4b303 |
| `rejects_tampering_and_unauthenticated_types` | dybw-core `crypto/tests.rs` `malformed_and_unsupported_inputs`, `bad_padding_is_decrypt_error`, `key_hmac` | dybw-core 8c4b303 |
| `symmetric_key_debug_hides_the_key_bytes` | dybw-core `crypto/tests.rs` `debug_and_errors_are_redacted` | dybw-core 8c4b303 |
| `value_mark_depends_on_key_id_and_value` | dybw-core `crypto/rsa_mark_tests.rs` `marks_match_kat`, `marks_on_cose_keys_and_subkeys` | dybw-core 8c4b303 |

## `src/bw/fields.rs` (5)

| Old test | Covered now by | Commit |
|---|---|---|
| `encoding_classes` | dybw-core `vault/scan_tests.rs` `what_is_skipped_or_uninspectable`; vectors `read/encoding-blank`, `read/encoding-padded`, `read/encoding-unknown` | dybw-core 8c4b303 |
| `location_classes` | dybw-core `vault/scan_tests.rs` `what_is_skipped_or_uninspectable`; vectors `read/location-blank`, `read/location-padded`, `read/location-unknown` | dybw-core 8c4b303 |
| `names_only_are_decrypted` | dybw-core `vault/scan_tests.rs` `field_primitives`, `unmarked_values_never_decrypted` | dybw-core 8c4b303 |
| `no_fields_key_is_no_fields` | dybw-core `vault/scan_tests.rs` `field_primitives`; vector `read/value-source/fields-null` | dybw-core 8c4b303 |
| `null_names_and_values` | dybw-core `vault/scan_tests.rs` `field_primitives` | dybw-core 8c4b303 |

## `src/bw/items.rs` (1)

| Old test | Covered now by | Commit |
|---|---|---|
| `dates_round_trip_and_items_use_their_own_key` | bwss `backend/bitwarden.rs` `dates_round_trip_and_items_use_their_own_key` (ported: `parse_date` moved there; the item key is the core's `fields::item_key`) | B9 |

## `src/bw/scan.rs` (10)

| Old test | Covered now by | Commit |
|---|---|---|
| `blank_marker_reads_nothing_else` | dybw-core `vault/scan_tests.rs` `blank_marker_reads_nothing_else` | dybw-core 8c4b303 |
| `blob_encrypted_ciphers_are_uninspectable_not_unmarked` | dybw-core `vault/scan_tests.rs` `blob_ciphers_are_held_not_unmarked`; bwss `backend/tests.rs` `a_cipher_that_turns_blob_encrypted_is_held_not_deleted_or_recreated` | dybw-core 8c4b303, f9f14bf |
| `collection_values_normalize` | bwss `model.rs` `collection_values_normalize` (ported: `normalize_collection` moved there) | B9 |
| `distinct_ids_all_win_and_losers_are_sorted_by_id` | dybw-core `vault/scan_tests.rs` `distinct_ids_all_win_and_losers_are_sorted_by_id` | dybw-core 8c4b303 |
| `duplicate_fields_first_wins` | dybw-core `vault/scan_tests.rs` `duplicate_fields_first_wins` | dybw-core 8c4b303 |
| `duplicates_resolve_the_same_way_in_any_order` | dybw-core `vault/scan_tests.rs` `duplicates_resolve_the_same_way_in_any_order` | dybw-core 8c4b303 |
| `label_attributes_and_defaults` | bwss `backend/bitwarden.rs` `label_attributes_and_defaults` (ported onto `build`/`to_marked`, derived attributes on) | B9 |
| `secret_comes_from_the_first_present_source` | dybw-core `vault/scan_tests.rs` `secret_comes_from_the_first_present_source` | dybw-core 8c4b303 |
| `unmarked_items_stay_encrypted` | dybw-core `vault/scan_tests.rs` `unmarked_values_never_decrypted` | dybw-core 8c4b303 |
| `what_is_skipped_or_uninspectable` | dybw-core `vault/scan_tests.rs` `what_is_skipped_or_uninspectable` | dybw-core 8c4b303 |

## `src/bw/write.rs` (22)

| Old test | Covered now by | Commit |
|---|---|---|
| `a_fitting_value_clears_the_stale_notes_copy` | dybw-core `vault/write_tests.rs` `a_fitting_value_clears_the_stale_notes_copy` | dybw-core 8c4b303 |
| `a_padded_mark_is_a_mark_when_writing` | dybw-core `vault/write_tests.rs` `a_padded_mark_is_a_mark_when_writing` | dybw-core 8c4b303 |
| `a_value_re_encrypted_elsewhere_is_not_a_conflict` | dybw-core `vault/write_tests.rs` `a_value_re_encrypted_elsewhere_is_not_a_conflict` | dybw-core 8c4b303 |
| `acl_merges_as_a_union` | dybw-core `vault/write_tests.rs` `acl_merges_as_a_union`, `append_lines_union_keeps_order`; vectors `write/acl-union-*` | dybw-core 8c4b303 |
| `binary_secrets_only_go_into_bwss_storage` | dybw-core `vault/write_tests.rs` `binary_secrets_only_go_into_tool_storage` | dybw-core 8c4b303 |
| `clearing_the_stale_copy_drops_every_location_mark` | dybw-core `vault/write_tests.rs` `clearing_the_stale_copy_drops_every_location_mark` | dybw-core 8c4b303 |
| `foreign_content_decides_the_trash` | dybw-core `vault/write_tests.rs` `foreign_content_decides_the_trash` | dybw-core 8c4b303 |
| `new_items_are_personal_secure_notes` | dybw-core `vault/write_tests.rs` `new_items_are_personal_secure_notes` | dybw-core 8c4b303 |
| `oversize_bwss_field_values_never_reach_the_server` | dybw-core `vault/write_tests.rs` `oversize_tool_field_values_never_reach_the_server` | dybw-core 8c4b303 |
| `oversize_field_value_moves_to_empty_notes_or_fails` | dybw-core `vault/write_tests.rs` `oversize_field_value_moves_to_empty_notes_or_fails` | dybw-core 8c4b303 |
| `patch_changes_the_first_duplicate_and_removes_every_copy` | dybw-core `vault/write_tests.rs` `patch_changes_the_first_duplicate_and_removes_every_copy` | dybw-core 8c4b303 |
| `registry_notes_hold_json_in_their_notes` | bwss `backend/tests.rs` `collections_live_in_the_registry_note`, `a_collection_too_large_for_the_registry_note_is_rejected` (the registry note is now a core `NewItem` with a note body) | pre-M4, kept |
| `response_only_keys_are_stripped_and_history_always_sent` | dybw-core `vault/write_tests.rs` `response_only_keys_are_stripped_and_history_always_sent` | dybw-core 8c4b303 |
| `retry_checks_abort_on_the_fresh_copy` | dybw-core `vault/write_tests.rs` `retry_checks_abort_on_the_fresh_copy` | dybw-core 8c4b303 |
| `set_and_remove_replace_the_attribute_set` | dybw-core `vault/write_tests.rs` `set_and_remove_replace_the_attribute_set` | dybw-core 8c4b303 |
| `strip_clears_the_notes_for_a_padded_mark_only` | dybw-core `vault/write_tests.rs` `strip_clears_the_notes_for_a_padded_mark_only` | dybw-core 8c4b303 |
| `strip_refuses_trashed_and_unreadable_items` | dybw-core `vault/write_tests.rs` `strip_refuses_trashed_and_unreadable_items` | dybw-core 8c4b303 |
| `strip_removes_bwss_fields_and_bwss_notes_only` | dybw-core `vault/write_tests.rs` `strip_removes_tool_fields_and_tool_notes_only` | dybw-core 8c4b303 |
| `unreadable_items_are_never_reported_bare` | dybw-core `vault/write_tests.rs` `unreadable_items_are_never_reported_bare` | dybw-core 8c4b303 |
| `write_back_to_field_and_notes_leaves_the_rest` | dybw-core `vault/write_tests.rs` `write_back_to_field_and_notes_leaves_the_rest` | dybw-core 8c4b303 |
| `write_back_to_login_password_keeps_history` | dybw-core `vault/write_tests.rs` `write_back_to_login_password_keeps_history` | dybw-core 8c4b303 |
| `write_back_to_null_login_password` | dybw-core `vault/write_tests.rs` `write_back_to_null_login_password` | dybw-core 8c4b303 |

## Renamed or removed outside `src/bw/`

| File | Old test | Now | Commit |
|---|---|---|---|
| `src/backend/bitwarden.rs` | `the_queue_is_sealed_with_a_key_of_its_own_as_format_3` | renamed `the_queue_is_sealed_with_a_key_of_its_own_as_format_4` (queue format 4, B6) | fcdc258 |
| `src/backend/runner.rs` | `value_sources_map_to_the_cores` (added in Part B) | removed with the mapping it tested: bwss now keeps the core's `ValueSource` itself; `backend/ops.rs` `value_sources_keep_their_old_names_in_the_file` still checks the queue's old names map to the core's | B9 |
| `src/backend/tests.rs` | `a_write_racing_a_cose_unlock_is_refused` (added in B3) | renamed `a_write_racing_a_cose_unlock_waits_for_it_and_is_sent`: the COSE write guard went away in B5 | facb226 |
| `src/backend/tests.rs` | `collection_changes_queue_behind_item_changes` (added in B5) | renamed `collection_changes_queue_only_behind_collection_changes` (the per-item queueing ruling) | e37e0c3 |
| `src/backend/tests.rs` | `records_and_questions_that_cannot_be_kept_ask_again` (added in B5) | renamed `write_records_that_cannot_be_kept_ask_again` (the questions file is gone) | e37e0c3 |
| `src/config.rs` | `derived_attributes_in_the_index_are_device_state` | renamed `derived_attributes_are_device_state` (`bwss derive`, B7) | 3dcb554 |
| `src/main.rs` | `turning_derived_attributes_on_says_what_becomes_guessable` | renamed `turning_derived_attributes_on_says_what_becomes_visible` (B7) | 3dcb554 |
| `src/vectors.rs` | `only_read_and_write_scenarios` | replaced by `only_read_write_and_sync_scenarios` and the new `sync_scenarios`: the sync vector now runs (bwss plans nothing on a sync) | B9 |
| `src/vectors.rs` | `reasons_map_to_shared_codes` | removed with `reason_code`: skip reasons come from the core's `SkipReason::code()`, checked by `read_scenarios` over every skip vector | B9 |
| `tests/e2e/test_config.py` | `test_derived_attributes_in_the_index_need_a_confirmation_on_a_terminal` | renamed `test_derived_attributes_need_a_confirmation_on_a_terminal` (B7) | 3dcb554 |
