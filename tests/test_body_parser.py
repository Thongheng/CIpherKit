from __future__ import print_function

import unittest

from core.body_parser import parse_body, serialize_body


class UrlEncodedSerializationTests(unittest.TestCase):
    def test_encodes_changed_and_added_values_without_corrupting_existing_pairs(self):
        original = "name=A%26B&note=hello+world&dup=1&dup=2"
        data = parse_body(original, "application/x-www-form-urlencoded")
        data["note"] = "hello earth"
        data["hash"] = "x+y&z"

        result = serialize_body(data, original, "application/x-www-form-urlencoded")

        self.assertIn("name=A%26B", result)
        self.assertIn("note=hello+earth", result)
        self.assertIn("dup=1&dup=2", result)
        self.assertIn("hash=x%2By%26z", result)


class MultipartSerializationTests(unittest.TestCase):
    def test_preserves_file_part_headers_and_body_when_adding_hash(self):
        original = (
            "--b\r\n"
            "Content-Disposition: form-data; name=\"upload\"; filename=\"a.txt\"\r\n"
            "Content-Type: text/plain\r\n\r\n"
            "hello file\r\n"
            "--b\r\n"
            "Content-Disposition: form-data; name=\"note\"\r\n\r\n"
            "old note\r\n"
            "--b--\r\n"
        )
        data = parse_body(original, "multipart/form-data; boundary=b")
        data["note"] = "new note"
        data["hash"] = "abc123"

        result = serialize_body(data, original, "multipart/form-data; boundary=b")

        self.assertIn('name="upload"; filename="a.txt"', result)
        self.assertIn("Content-Type: text/plain", result)
        self.assertIn("hello file", result)
        self.assertIn('name="note"\r\n\r\nnew note', result)
        self.assertIn('name="hash"\r\n\r\nabc123', result)
        self.assertEqual(1, result.count("--b--"))

    def test_preserves_boundary_like_bytes_inside_file_content(self):
        original = (
            "--b\r\n"
            "Content-Disposition: form-data; name=\"upload\"; filename=\"a.bin\"\r\n"
            "Content-Type: application/octet-stream\r\n\r\n"
            "prefix--b--suffix\r\n"
            "--b--\r\n"
        )
        data = parse_body(original, "multipart/form-data; boundary=b")
        data["hash"] = "abc123"

        result = serialize_body(data, original, "multipart/form-data; boundary=b")

        self.assertIn("prefix--b--suffix", result)
        self.assertTrue(result.endswith("--b--\r\n"))


    def test_parse_and_serialize_user_multipart_request(self):
        original = (
            "--5b3f12fa-03cf-4fb7-ae17-6686841b16a6\r\n"
            'Content-Disposition: form-data; name="ipf_code"\r\n'
            "Content-Transfer-Encoding: binary\r\n"
            "Content-Type: multipart/form-data; charset=utf-8\r\n"
            "Content-Length: 0\r\n\r\n\r\n"
            "--5b3f12fa-03cf-4fb7-ae17-6686841b16a6\r\n"
            'Content-Disposition: form-data; name="trx_id"\r\n'
            "Content-Transfer-Encoding: binary\r\n"
            "Content-Type: multipart/form-data; charset=utf-8\r\n"
            "Content-Length: 36\r\n\r\n"
            "c089053f-b5ce-48f8-a3ec-cfa6afab1d2c\r\n"
            "--5b3f12fa-03cf-4fb7-ae17-6686841b16a6\r\n"
            'Content-Disposition: form-data; name="hash"\r\n'
            "Content-Transfer-Encoding: binary\r\n"
            "Content-Type: multipart/form-data; charset=utf-8\r\n"
            "Content-Length: 40\r\n\r\n"
            "6F38EB165620C2C403E592BBAFB4F4AB5FCF0823\r\n"
            "--5b3f12fa-03cf-4fb7-ae17-6686841b16a6\r\n"
            'Content-Disposition: form-data; name="selfie_face"; filename="1785995692869.jpeg"\r\n'
            "Content-Type: image/jpeg\r\n"
            "Content-Length: 253456\r\n\r\n"
            "BINARY_DATA_IMAGE\r\n"
            "--5b3f12fa-03cf-4fb7-ae17-6686841b16a6--\r\n"
        )
        ct = "multipart/form-data; boundary=5b3f12fa-03cf-4fb7-ae17-6686841b16a6"
        data = parse_body(original, ct)

        self.assertEqual("c089053f-b5ce-48f8-a3ec-cfa6afab1d2c", data.get("trx_id"))
        self.assertEqual("6F38EB165620C2C403E592BBAFB4F4AB5FCF0823", data.get("hash"))

        data["hash"] = "NEW_HASH_VAL_123456789012345678901234567890"
        serialized = serialize_body(data, original, ct)

        self.assertIn("NEW_HASH_VAL_123456789012345678901234567890", serialized)
        self.assertIn('filename="1785995692869.jpeg"', serialized)
        self.assertIn("BINARY_DATA_IMAGE", serialized)

    def test_multipart_payload_with_binary_data_and_equals(self):
        original = (
            "--bbec4099-f0df-48f4-a729-8807080de149\r\n"
            'Content-Disposition: form-data; name="trx_id"\r\n\r\n'
            "12e22e86-ce5a-4bc4-9223-18d4779c1f3c\r\n"
            "--bbec4099-f0df-48f4-a729-8807080de149\r\n"
            'Content-Disposition: form-data; name="aba_id"\r\n\r\n'
            "0\r\n"
            "--bbec4099-f0df-48f4-a729-8807080de149\r\n"
            'Content-Disposition: form-data; name="hash"\r\n\r\n'
            "E98DEEB8E861867F75C9592A1A2E83C58BBB486D\r\n"
            "--bbec4099-f0df-48f4-a729-8807080de149\r\n"
            'Content-Disposition: form-data; name="ts"\r\n\r\n'
            "1786009402765\r\n"
            "--bbec4099-f0df-48f4-a729-8807080de149\r\n"
            'Content-Disposition: form-data; name="selfie_face"; filename="1786009402854.jpeg"\r\n'
            "Content-Type: image/jpeg\r\n\r\n"
            "BINARY_DATA=123&test=456=789\r\n"
            "--bbec4099-f0df-48f4-a729-8807080de149--\r\n"
        )
        ct = "multipart/form-data; boundary=bbec4099-f0df-48f4-a729-8807080de149"
        data = parse_body(original, ct)

        self.assertEqual("12e22e86-ce5a-4bc4-9223-18d4779c1f3c", data.get("trx_id"))
        self.assertEqual("1786009402765", data.get("ts"))
        self.assertEqual("E98DEEB8E861867F75C9592A1A2E83C58BBB486D", data.get("hash"))


if __name__ == "__main__":
    unittest.main()
