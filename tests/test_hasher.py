from __future__ import print_function

import unittest

from core.hasher import build_flat_payload, resolve_key_order, compute_hash


class BuildFlatPayloadTests(unittest.TestCase):
    def test_flattens_nested_payload_and_merges_custom_data(self):
        payload = {"aba_id": "4001205", "ts": "1784273912798"}
        flat = build_flat_payload(payload, {"token": "abc123"})
        self.assertEqual(
            {"aba_id": "4001205", "ts": "1784273912798", "token": "abc123"}, flat
        )

    def test_custom_data_overrides_body_value(self):
        payload = {"amount": "10"}
        flat = build_flat_payload(payload, {"amount": "999"})
        self.assertEqual("999", flat["amount"])

    def test_non_dict_payload_returns_empty(self):
        self.assertEqual({}, build_flat_payload("not-a-dict"))


class ResolveKeyOrderTests(unittest.TestCase):
    def test_explicit_order_is_split_and_trimmed(self):
        order = resolve_key_order({}, "aba_id, ts , token")
        self.assertEqual(["aba_id", "ts", "token"], order)

    def test_falls_back_to_non_ignored_flat_keys(self):
        flat = {"aba_id": "1", "hash": "deadbeef", "signature": "x"}
        order = resolve_key_order(flat, "")
        self.assertEqual(["aba_id"], order)


class ComputeHashTests(unittest.TestCase):
    def test_matches_known_aba_style_signature(self):
        # Same body/token fixture as tests/test_key_finder.py's token-suffix
        # test; locks the exact concatenation + SHA-1 digest as ground truth.
        payload = {"aba_id": "4001205", "ts": "1784273912798"}
        custom_data = {"token": "zQA/B2uxc7Jr4Kf0+SqM+5XXXnPdyUwAlUCb4Go0W1uMvOrHobhJPWyivtLe2caF"}
        digest, raw_string, debug_log = compute_hash(
            payload, "aba_id, ts, token", custom_data
        )
        self.assertEqual(
            "40012051784273912798zQA/B2uxc7Jr4Kf0+SqM+5XXXnPdyUwAlUCb4Go0W1uMvOrHobhJPWyivtLe2caF",
            raw_string,
        )
        self.assertEqual("FE89EE4060DB78C917C2ADE4BCA4F03DFCA0B70F", digest)
        self.assertIn("Algorithm: sha1", debug_log)

    def test_amount_and_commission_formatted_to_two_decimals(self):
        payload = {"amount": 12, "commission": "3.5"}
        digest, raw_string, _ = compute_hash(payload, "amount, commission")
        self.assertEqual("12.003.50", raw_string)

    def test_default_key_order_excludes_hash_like_fields(self):
        payload = {"aba_id": "1", "hash": "deadbeef"}
        digest, raw_string, _ = compute_hash(payload)
        self.assertEqual("1", raw_string)

    def test_algorithm_name_is_case_and_dash_insensitive(self):
        payload = {"a": "x"}
        sha1_digest, _, _ = compute_hash(payload, algorithm="SHA-1")
        sha256_digest, _, _ = compute_hash(payload, algorithm="sha256")
        self.assertNotEqual(sha1_digest, sha256_digest)
        self.assertEqual(40, len(sha1_digest))
        self.assertEqual(64, len(sha256_digest))

    def test_unknown_algorithm_falls_back_to_sha1(self):
        payload = {"a": "x"}
        fallback_digest, _, _ = compute_hash(payload, algorithm="rot13")
        sha1_digest, _, _ = compute_hash(payload, algorithm="sha1")
        self.assertEqual(sha1_digest, fallback_digest)


if __name__ == "__main__":
    unittest.main()
