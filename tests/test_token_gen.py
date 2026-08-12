from __future__ import print_function

import unittest

from core.token_gen import (
    compute_login_hash, compute_second_hash, generate_token, generate_fresh_login,
)


# Known (hash, token) pairs from the reference token_gen.py's self-test, all
# generated with this exact 32-char secret — locks generate_token()'s AES-CBC
# derivation (key/IV/padding) against ground truth.
_KNOWN_SECRET = "y2rNlFOX/fNiLJXieYmHTnJfZjZJWtTm"
_TRIPLES = [
    ("42E2EDDBA02B83ED4DB638460E9B35AFACC2C651", "h0j2kihUnw61YJBmWueQkDalMyW7mIMzxCVKpMaqYmf1TMugSm5IQf/JGxANCYQ+"),
    ("F0FA2B5EC710503399C510C2D2EDB813E7C98CB9", "TltVjjNLRDM+QQ2bM/PZPhj6I6CpY+baJ43dZD4iAWYgU+5gmVgfyRZ/gHjyou7N"),
    ("41AB27F7223951753A2B958DC372B9A57D54A94A", "1h490r7EdVDMkum/MewZo8WTpnDiusZlbrwANLf2Y4HSU/yn/9/w+EWttJJO3meE"),
    ("720AC2B04884E9B98CFA84A61836172CFBE60584", "d+gUXnfuYhc8kQqhY7qapfixBUowkYH+jyTh7b3jWu+3C7Bq7DvxW/IEf34jvL9J"),
]


class GenerateTokenTests(unittest.TestCase):
    def test_matches_known_vectors(self):
        for hash_hex, expected_token in _TRIPLES:
            self.assertEqual(expected_token, generate_token(hash_hex, _KNOWN_SECRET))

    def test_is_case_insensitive_on_hash_input(self):
        hash_hex, expected_token = _TRIPLES[0]
        self.assertEqual(expected_token, generate_token(hash_hex.lower(), _KNOWN_SECRET))

    def test_truncates_secret_longer_than_32_chars(self):
        hash_hex, expected_token = _TRIPLES[0]
        longer_secret = _KNOWN_SECRET + "EXTRA_SUFFIX_IGNORED"
        self.assertEqual(expected_token, generate_token(hash_hex, longer_secret))


class ComputeHashTests(unittest.TestCase):
    def test_login_hash_concatenates_all_fields_including_secret(self):
        h = compute_login_hash("8000371", "ab4eff18b8758049", "1786440826282",
                                "7B38CD4D25F9CE0BBDF221307A40B7DAE89E1711", "SECRET123")
        self.assertEqual(40, len(h))
        self.assertTrue(h.isupper() or h.isdigit())

    def test_second_hash_excludes_secret(self):
        aba_id, device_id, ts, pin_hash = "8000371", "ab4eff18b8758049", "1786440826282", "7B38CD4D25F9CE0BBDF221307A40B7DAE89E1711"
        h1 = compute_second_hash(aba_id, device_id, ts, pin_hash)
        h2 = compute_login_hash(aba_id, device_id, ts, pin_hash, "")
        self.assertEqual(h1, h2)

    def test_different_secret_changes_login_hash_but_not_second_hash(self):
        aba_id, device_id, ts, pin_hash = "8000371", "ab4eff18b8758049", "1786440826282", "7B38CD4D25F9CE0BBDF221307A40B7DAE89E1711"
        h_a = compute_login_hash(aba_id, device_id, ts, pin_hash, "secretA")
        h_b = compute_login_hash(aba_id, device_id, ts, pin_hash, "secretB")
        self.assertNotEqual(h_a, h_b)
        self.assertEqual(
            compute_second_hash(aba_id, device_id, ts, pin_hash),
            compute_second_hash(aba_id, device_id, ts, pin_hash),
        )


class GenerateFreshLoginTests(unittest.TestCase):
    def test_returns_hash_second_hash_and_matching_token(self):
        hash_val, second_hash, token = generate_fresh_login(
            "8000371", "ab4eff18b8758049", "1786440826282",
            "7B38CD4D25F9CE0BBDF221307A40B7DAE89E1711", _KNOWN_SECRET
        )
        self.assertEqual(40, len(hash_val))
        self.assertEqual(40, len(second_hash))
        self.assertEqual(generate_token(hash_val, _KNOWN_SECRET), token)


if __name__ == "__main__":
    unittest.main()
