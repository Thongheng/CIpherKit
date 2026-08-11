from __future__ import print_function

import unittest

from core.key_finder import (
    compare_generated_hash, format_hash_comparison, strip_hash_comparison,
    should_render_hash_output, find_key_orders,
)
from core.key_finder import DEFAULT_TOKEN_LEN, fetch_all_frida_candidates, extract_gap_value


class KeyOrderSearchTests(unittest.TestCase):
    def test_finds_orders_without_mutating_input(self):
        fields = {"first": "ab", "second": "cd"}
        matches, visited, capped = find_key_orders(fields, "abcd")

        self.assertEqual([("first", "second")], matches)
        self.assertGreater(visited, 0)
        self.assertFalse(capped)
        self.assertEqual({"first": "ab", "second": "cd"}, fields)

    def test_reports_cap_for_large_search(self):
        fields = dict(("k%d" % i, "a") for i in range(10))
        matches, visited, capped = find_key_orders(fields, "aaaaaaaaab", max_visited=20)

        self.assertEqual([], matches)
        self.assertEqual(20, visited)
        self.assertTrue(capped)

    def test_detects_token_suffix_and_ignores_hash_field(self):
        fields = {
            "aba_id": "4001205",
            "ts": "1784273912798",
            "hash": "38367028E861EF49ECC13DD9BB11F3948CD89AD1"
        }
        known = "40012051784273912798zQA/B2uxc7Jr4Kf0+SqM+5XXXnPdyUwAlUCb4Go0W1uMvOrHobhJPWyivtLe2caF"
        matches, _, _ = find_key_orders(fields, known)
        self.assertEqual([("aba_id", "ts", "token")], matches)

    def test_detects_token_suffix_for_base64_segment(self):
        fields = {
            "aba_id": "1435349",
            "pin": "123456",
            "ts": "1784273912798"
        }
        known = "14353491784273912798123456y2rNlFOX/fNiLJXieYmHTnJfZjZJWtTm6SeYrVEHzaM="
        matches, _, _ = find_key_orders(fields, known)
        self.assertEqual([("aba_id", "ts", "pin", "token")], matches)

    def test_short_middle_gap_not_labelled_as_token(self):
        # "9999" is only 4 chars — below TOKEN_MIN_LEN — so the DFS yields no match.
        # batch_mapper will show "Requires Custom Data" for this endpoint.
        fields = {
            "otp_id": "f268246f-34d5-4b3a-a308-9969119cc9da",
            "type": "0",
            "aba_id": "8000371",
            "ts": "1786069442137"
        }
        known = "f268246f-34d5-4b3a-a308-9969119cc9da99991786069442137"
        matches, _, _ = find_key_orders(fields, known)
        self.assertEqual([], matches)

    def test_rejects_partial_string_mismatch(self):
        fields = {
            "aba_id": "4001205",
            "ts": "1784273912798",
        }
        # String with unmatched prefix before body values
        known = "UNMATCHED_PREFIX_40012051784273912798"
        matches, _, _ = find_key_orders(fields, known)
        self.assertEqual([], matches)

    def test_nested_array_single_digit_fields_dont_block_token_suffix(self):
        fields = {
            "account": "007445788",
            "limits[0].limit": "100000.0",
            "limits[0].type": "8",
            "limits[1].limit": "100000.0",
            "limits[1].type": "2",
            "pin": "7B38CD4D25F9CE0BBDF221307A40B7DAE89E1711",
            "aba_id": "8000371",
            "ts": "1786336006202"
        }
        known = "800037117863360062027B38CD4D25F9CE0BBDF221307A40B7DAE89E1711VC+RX0HxZVZ8MmE4rzAvfKNCmnWSlbFrgbA6kcs/6LZIbnLiWtyGYh2iF/Tm8/tg"
        matches, _, _ = find_key_orders(fields, known)
        self.assertIn(("aba_id", "ts", "pin", "token"), matches)

class TokenLenAwareRecoveryTests(unittest.TestCase):
    def test_peels_exact_suffix_deterministically(self):
        fields = {"aba_id": "4001205", "ts": "1784273912798"}
        known = "40012051784273912798zQA/B2uxc7Jr4Kf0+SqM+5XXXnPdyUwAlUCb4Go0W1uMvOrHobhJPWyivtLe2caF"
        matches, _, _ = find_key_orders(fields, known, token_len=DEFAULT_TOKEN_LEN)
        self.assertEqual([("aba_id", "ts", "token")], matches)

    def test_recovers_token_shorter_than_generic_heuristic_minimum(self):
        # An 8-char token is below the generic 16-char token-shape heuristic, so the
        # heuristic path finds nothing — but a known token_len recovers it deterministically.
        fields = {"aba_id": "4001205", "ts": "1784273912798"}
        known = "40012051784273912798AbC12345"
        no_len_matches, _, _ = find_key_orders(fields, known)
        self.assertEqual([], no_len_matches)

        with_len_matches, _, _ = find_key_orders(fields, known, token_len=8)
        self.assertEqual([("aba_id", "ts", "token")], with_len_matches)

    def test_rejects_when_prefix_doesnt_reconstruct(self):
        fields = {"aba_id": "4001205", "ts": "1784273912798"}
        known = "UNEXPECTED_PREFIX_40012051784273912798AbC12345"
        matches, _, _ = find_key_orders(fields, known, token_len=8)
        self.assertEqual([], matches)

    def test_short_known_string_falls_back_to_heuristic_path(self):
        # known is not even longer than token_len, so peeling is skipped entirely.
        fields = {"aba_id": "12"}
        matches, _, _ = find_key_orders(fields, "12", token_len=DEFAULT_TOKEN_LEN)
        self.assertEqual([("aba_id",)], matches)

    def test_falls_back_to_heuristic_when_endpoint_token_isnt_the_configured_length(self):
        # Real token here is 50 chars, not DEFAULT_TOKEN_LEN (64), so peeling the
        # last 64 chars misaligns everything and finds nothing — but the shape
        # heuristic (>=16 chars) still recovers it over the full string, so
        # passing token_len must not find LESS than omitting it would.
        fields = {"aba_id": "4001205", "ts": "1784273912798"}
        real_token = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWX"
        known = "40012051784273912798" + real_token
        matches, _, _ = find_key_orders(fields, known, token_len=DEFAULT_TOKEN_LEN)
        self.assertEqual([("aba_id", "ts", "token")], matches)


class ExtractGapValueTests(unittest.TestCase):
    def test_extracts_trailing_token_using_known_order(self):
        fields = {"aba_id": "4001205", "ts": "1784273912798"}
        known = "40012051784273912798zQA/B2uxc7Jr4Kf0+SqM+5XXXnPdyUwAlUCb4Go0W1uMvOrHobhJPWyivtLe2caF"
        value = extract_gap_value(fields, known, ["aba_id", "ts", "token"], "token")
        self.assertEqual("zQA/B2uxc7Jr4Kf0+SqM+5XXXnPdyUwAlUCb4Go0W1uMvOrHobhJPWyivtLe2caF", value)

    def test_extracts_gap_in_the_middle_bounded_by_next_key(self):
        fields = {"aba_id": "4001205", "ts": "1784273912798"}
        known = "4001205SECRETVALUE1784273912798"
        value = extract_gap_value(fields, known, ["aba_id", "token", "ts"], "token")
        self.assertEqual("SECRETVALUE", value)

    def test_returns_none_when_known_fields_dont_reconstruct(self):
        fields = {"aba_id": "4001205", "ts": "WRONG_TS"}
        known = "40012051784273912798sometoken"
        value = extract_gap_value(fields, known, ["aba_id", "ts", "token"], "token")
        self.assertIsNone(value)

    def test_returns_none_when_gap_key_not_in_key_order(self):
        fields = {"aba_id": "4001205"}
        value = extract_gap_value(fields, "4001205token", ["aba_id"], "token")
        self.assertIsNone(value)

    def test_returns_none_for_empty_known_string(self):
        self.assertIsNone(extract_gap_value({"a": "1"}, "", ["a", "token"], "token"))


class FetchFridaCandidatesTests(unittest.TestCase):
    def test_prefers_exact_ts_match_over_mismatched_substring(self):
        import os, tempfile, json

        temp_log = tempfile.mktemp()
        with open(temp_log, "w") as f:
            # log_ts explicitly disagrees, even though target_ts appears inside raw_string
            f.write(json.dumps({"ts": "999", "raw_string": "9991784273912798garbage"}) + "\n")
            # log_ts exactly matches target_ts
            f.write(json.dumps({"ts": "1784273912798", "raw_string": "1784273912798realtoken"}) + "\n")

        try:
            candidates = fetch_all_frida_candidates(ts_val="1784273912798", log_path=temp_log)
            raws = [c[0] for c in candidates]
            self.assertEqual(["1784273912798realtoken"], raws)
        finally:
            if os.path.exists(temp_log):
                os.remove(temp_log)


class CompareGeneratedHashTests(unittest.TestCase):
    def test_compares_case_insensitively(self):
        self.assertEqual("valid", compare_generated_hash("ABCD", {"hash": "abcd"}, "hash"))

    def test_reports_invalid_hash(self):
        self.assertEqual("invalid", compare_generated_hash("new", {"signature": "old"}, "signature"))

    def test_reports_absent_reference_hash(self):
        self.assertEqual("missing", compare_generated_hash("new", {"id": "1"}, "hash"))

    def test_reports_error_result_without_comparing(self):
        self.assertEqual("error", compare_generated_hash("Error: failed", {"hash": "failed"}, "hash"))

    def test_formats_match_inside_hash_output(self):
        self.assertEqual("abcd (Match)", format_hash_comparison("abcd", "valid"))

    def test_formats_not_match_inside_hash_output(self):
        self.assertEqual("abcd (Not Match)", format_hash_comparison("abcd", "invalid"))

    def test_missing_reference_keeps_plain_hash(self):
        self.assertEqual("abcd", format_hash_comparison("abcd", "missing"))

    def test_strips_stale_comparison_suffix(self):
        self.assertEqual("abcd", strip_hash_comparison("abcd (Match)"))
        self.assertEqual("abcd", strip_hash_comparison("abcd (Not Match)"))

    def test_comparison_forces_hash_output_even_in_crypto_mode(self):
        self.assertTrue(should_render_hash_output(True, True))
        self.assertFalse(should_render_hash_output(False, True))


class FetchFridaHookTests(unittest.TestCase):
    def test_fetches_hook_by_timestamp(self):
        import os, tempfile, json
        from core.key_finder import fetch_frida_hook

        temp_log = tempfile.mktemp()
        with open(temp_log, "w") as f:
            f.write(json.dumps({"ts": "1784273912798", "raw_string": "40012051784273912798zQA/B2uxc7Jr4Kf0"}) + "\n")

        try:
            raw, matched_ts, mode = fetch_frida_hook("1784273912798", log_path=temp_log)
            self.assertEqual("40012051784273912798zQA/B2uxc7Jr4Kf0", raw)
            self.assertEqual("1784273912798", matched_ts)
            self.assertEqual("timestamp", mode)
        finally:
            if os.path.exists(temp_log):
                os.remove(temp_log)


if __name__ == "__main__":
    unittest.main()

