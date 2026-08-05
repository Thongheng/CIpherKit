from __future__ import print_function

import unittest

from core.key_finder import (
    compare_generated_hash, format_hash_comparison, strip_hash_comparison,
    should_render_hash_output, find_key_orders,
)


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

    def test_detects_secret_suffix(self):
        fields = {
            "aba_id": "1435349",
            "pin": "123456",
            "ts": "1784273912798"
        }
        known = "14353491784273912798123456y2rNlFOX/fNiLJXieYmHTnJfZjZJWtTm6SeYrVEHzaM="
        matches, _, _ = find_key_orders(fields, known)
        self.assertEqual([("aba_id", "ts", "pin", "secret")], matches)

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

