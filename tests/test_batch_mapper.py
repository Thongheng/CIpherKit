from __future__ import print_function
import unittest
import json
import os
import tempfile

from core.batch_mapper import matches_url_filter, matches_method_filter, process_http_item, scan_proxy_history


class DummyHttpRequestResponse(object):
    def __init__(self, request_bytes, url_str="https://mdev.ababank.com/api/v3/pay", method="POST"):
        self._request_bytes = request_bytes
        self._url_str = url_str
        self._method = method

    def getRequest(self):
        return self._request_bytes


class DummyHelpers(object):
    def analyzeRequest(self, http_item):
        class DummyRequestInfo(object):
            def __init__(self, item):
                self._item = item
            def getHeaders(self):
                return ["POST /api/v3/pay HTTP/1.1", "Host: mdev.ababank.com", "Content-Type: application/json"]
            def getMethod(self):
                return self._item._method
            def getUrl(self):
                class DummyURL(object):
                    def __init__(self, s): self._s = s
                    def __str__(self): return self._s
                    def getPath(self): return "/api/v3/pay"
                    def getHost(self): return "mdev.ababank.com"
                return DummyURL(self._item._url_str)
            def getBodyOffset(self):
                req_str = DummyHelpers().bytesToString(self._item.getRequest())
                if "\r\n\r\n" in req_str:
                    return req_str.index("\r\n\r\n") + 4
                return 0
        return DummyRequestInfo(http_item)

    def bytesToString(self, bytes_data):
        if isinstance(bytes_data, str):
            return bytes_data
        if isinstance(bytes_data, bytearray):
            return bytes_data.decode("utf-8", "ignore")
        return str(bytes_data)


class DummyCallbacks(object):
    def __init__(self, history_items):
        self._history = history_items
    def getProxyHistory(self):
        return self._history
    def getHelpers(self):
        return DummyHelpers()


class BatchMapperTests(unittest.TestCase):
    def test_url_filter_wildcard_and_regex(self):
        self.assertTrue(matches_url_filter("https://mdev.ababank.com/api/v3/pay", "*ababank*"))
        self.assertTrue(matches_url_filter("https://mdev.ababank.com/api/v3/pay", "/api/v3/.*"))
        self.assertFalse(matches_url_filter("https://otherdomain.com/api/v1", "*ababank*"))

    def test_method_filter(self):
        self.assertTrue(matches_method_filter("POST", "POST, PUT"))
        self.assertTrue(matches_method_filter("PUT", "POST, PUT"))
        self.assertFalse(matches_method_filter("GET", "POST, PUT"))
        self.assertTrue(matches_method_filter("GET", "ALL"))

    def test_process_http_item_matches_frida_log(self):
        temp_log = tempfile.mktemp()
        ts_val = "1784085966056"
        raw_str = "40012051784085966056sa7Xb6EYGGm5pvP1MwPBkw6Dlk4mMWvmnaSHSQiClfyzvjpw+RQt5E+hei80wEhL"

        with open(temp_log, "w") as f:
            f.write(json.dumps({"ts": ts_val, "raw_string": raw_str}) + "\n")

        body_json = json.dumps({
            "aba_id": "4001205",
            "ts": ts_val,
            "token": "sa7Xb6EYGGm5pvP1MwPBkw6Dlk4mMWvmnaSHSQiClfyzvjpw+RQt5E+hei80wEhL"
        })
        raw_req = "POST /api/v3/pay HTTP/1.1\r\nHost: mdev.ababank.com\r\nContent-Type: application/json\r\n\r\n" + body_json
        dummy_item = DummyHttpRequestResponse(raw_req)
        helpers = DummyHelpers()

        try:
            res = process_http_item(helpers, dummy_item, log_path=temp_log)
            self.assertEqual("MATCHED", res["status"])
            self.assertEqual("/api/v3/pay", res["url_path"])
            self.assertEqual("aba_id, ts, token", res["sign_order"])
            self.assertEqual(ts_val, res["ts"])
        finally:
            if os.path.exists(temp_log):
                os.remove(temp_log)

    def test_scan_proxy_history(self):
        temp_log = tempfile.mktemp()
        ts_val = "1784085966056"
        raw_str = "40012051784085966056sa7Xb6EYGGm5pvP1MwPBkw6Dlk4mMWvmnaSHSQiClfyzvjpw+RQt5E+hei80wEhL"

        with open(temp_log, "w") as f:
            f.write(raw_str + "\n")

        body_json = json.dumps({
            "aba_id": "4001205",
            "ts": ts_val,
            "token": "sa7Xb6EYGGm5pvP1MwPBkw6Dlk4mMWvmnaSHSQiClfyzvjpw+RQt5E+hei80wEhL"
        })
        raw_req = "POST /api/v3/pay HTTP/1.1\r\nHost: mdev.ababank.com\r\nContent-Type: application/json\r\n\r\n" + body_json
        dummy_item = DummyHttpRequestResponse(raw_req)

        callbacks = DummyCallbacks([dummy_item])
        helpers = DummyHelpers()

        try:
            results = scan_proxy_history(callbacks, helpers, url_filter="*ababank*", method_filter="POST", log_path=temp_log)
            self.assertEqual(1, len(results))
            self.assertEqual("MATCHED", results[0]["status"])
            self.assertEqual("aba_id, ts, token", results[0]["sign_order"])
        finally:
            if os.path.exists(temp_log):
                os.remove(temp_log)

    def test_scan_proxy_history_deduplicates_and_takes_latest(self):
        req_old = "POST /api/v3/pay HTTP/1.1\r\nHost: mdev.ababank.com\r\n\r\n{\"old\": \"data\"}"
        req_new = "POST /api/v3/pay HTTP/1.1\r\nHost: mdev.ababank.com\r\n\r\n{\"new\": \"data\"}"
        item_old = DummyHttpRequestResponse(req_old)
        item_new = DummyHttpRequestResponse(req_new)

        # History order: [item_old, item_new] (item_new is at index 1, i.e. latest)
        callbacks = DummyCallbacks([item_old, item_new])
        helpers = DummyHelpers()

        results = scan_proxy_history(callbacks, helpers, url_filter="*", method_filter="POST", log_path="/tmp/non_existent.log")
        self.assertEqual(1, len(results))
        # Verify it captured item_new (req_id = 2, newest request)
        self.assertEqual(2, results[0]["req_id"])
        self.assertEqual("data", results[0]["pairs"].get("new"))


if __name__ == "__main__":
    unittest.main()
