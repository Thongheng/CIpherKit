# -*- coding: utf-8 -*-
from __future__ import print_function
import re
from core.body_parser import parse_body, flatten_data
from core.key_finder import fetch_frida_hook, fetch_all_frida_candidates, find_key_orders
from core.utils import _extract_request_path


def matches_url_filter(url_str, filter_str, only_in_scope=False, callbacks=None, http_item=None):
    """
    Check if a URL matches the filter pattern (supports substring, wildcards '*', or regex).
    """
    if only_in_scope and callbacks and http_item:
        try:
            req_info = callbacks.getHelpers().analyzeRequest(http_item)
            url_obj = req_info.getUrl()
            if not callbacks.isInScope(url_obj):
                return False
        except Exception:
            pass

    filter_str = (filter_str or "").strip()
    if not filter_str:
        return True

    # Try regex match first
    try:
        if re.search(filter_str, url_str, re.IGNORECASE):
            return True
    except Exception:
        pass

    # Try wildcard string match
    if "*" in filter_str:
        try:
            wildcard_regex = ".*" + ".*".join([re.escape(part) for part in filter_str.split("*")]) + ".*"
            if re.search(wildcard_regex, url_str, re.IGNORECASE):
                return True
        except Exception:
            pass

    return filter_str.lower() in url_str.lower()



def matches_method_filter(method, method_filter):
    """Check if request method matches the comma-separated method filter (e.g. 'POST, PUT')."""
    method_filter = (method_filter or "").strip()
    if not method_filter or method_filter.upper() == "ALL":
        return True
    allowed = [m.strip().upper() for m in method_filter.split(",") if m.strip()]
    return str(method).upper() in allowed


def get_history_hosts(callbacks, helpers):
    """Scan Burp Proxy History and return a list of unique hostnames."""
    hosts = set()
    try:
        history = callbacks.getProxyHistory()
        if history:
            for item in history:
                if not item:
                    continue
                try:
                    req_info = helpers.analyzeRequest(item)
                    if req_info.getUrl():
                        host = req_info.getUrl().getHost()
                        if host:
                            hosts.add(host)
                except Exception:
                    pass
    except Exception as e:
        print("[CipherKit] Error fetching history hosts: %s" % str(e))

    return ["(All Domains)"] + sorted(list(hosts))


def process_http_item(helpers, http_item, log_path="/tmp/cipherkit_frida.log"):
    """
    Analyze a single IHttpRequestResponse item against Frida logs and return sign order result.
    """
    req_bytes = http_item.getRequest()
    if not req_bytes:
        return None

    req_info = helpers.analyzeRequest(http_item)
    headers = req_info.getHeaders()
    method = req_info.getMethod()
    url_path = _extract_request_path(req_info)
    full_url = str(req_info.getUrl()) if req_info.getUrl() else url_path

    host = ""
    if req_info.getUrl():
        host = str(req_info.getUrl().getHost())
    if not host:
        for h in headers:
            if h.lower().startswith("host:"):
                host = h[5:].strip()
                break

    # Extract Content-Type
    content_type = ""
    for h in headers:
        if h.lower().startswith("content-type:"):
            content_type = h[len("content-type:"):].strip()
            break

    # Extract body bytes
    body_offset = req_info.getBodyOffset()
    body_bytes = req_bytes[body_offset:]
    body_str = helpers.bytesToString(body_bytes)

    if not body_str or not body_str.strip():
        return {
            "status": "NO_BODY",
            "host": host,
            "method": method,
            "url_path": url_path,
            "full_url": full_url,
            "sign_order": "",
            "raw_string": "",
            "ts": "",
            "pairs": {},
            "body_str": body_str,
        }

    # Parse body
    parsed_payload = parse_body(body_str, content_type)
    pairs = flatten_data(parsed_payload) if parsed_payload else {}

    if not pairs:
        return {
            "status": "NO_PARAMS",
            "host": host,
            "method": method,
            "url_path": url_path,
            "full_url": full_url,
            "sign_order": "",
            "raw_string": "",
            "ts": "",
            "pairs": {},
            "body_str": body_str,
        }

    # Find ts timestamp candidate
    ts_val = pairs.get('ts') or pairs.get('timestamp') or pairs.get('time') or pairs.get('req_time')

    # Fetch all candidate Frida hook logs
    candidates = fetch_all_frida_candidates(ts_val=ts_val, values=pairs, log_path=log_path)

    if not candidates:
        return {
            "status": "NO_FRIDA_HOOK",
            "host": host,
            "method": method,
            "url_path": url_path,
            "full_url": full_url,
            "sign_order": "",
            "raw_string": "",
            "ts": str(ts_val) if ts_val else "",
            "pairs": pairs,
            "body_str": body_str,
        }

    # Extract target request hash if available for verification
    request_hash = ""
    for h_field in ("hash", "signature", "sign", "sig", "mac"):
        if h_field in pairs and pairs[h_field]:
            request_hash = str(pairs[h_field]).strip().lower()
            break

    values = dict((k, str(v)) for k, v in pairs.items())

    best_match = None
    fallback_match = None

    import hashlib
    for raw_string, matched_ts, matched_via in candidates:
        matches, visited, capped = find_key_orders(values, raw_string)
        if matches:
            sign_order = ", ".join(matches[0])
            candidate_res = {
                "status": "MATCHED",
                "host": host,
                "method": method,
                "url_path": url_path,
                "full_url": full_url,
                "sign_order": sign_order,
                "raw_string": raw_string,
                "ts": matched_ts or (str(ts_val) if ts_val else ""),
                "pairs": pairs,
                "body_str": body_str,
            }
            if not fallback_match:
                fallback_match = candidate_res

            # Hash verification check if request has a hash field
            if request_hash:
                try:
                    raw_bytes = raw_string.encode('utf-8')
                    sha256_hex = hashlib.sha256(raw_bytes).hexdigest().lower()
                    sha1_hex = hashlib.sha1(raw_bytes).hexdigest().lower()
                    md5_hex = hashlib.md5(raw_bytes).hexdigest().lower()

                    if request_hash in (sha256_hex, sha1_hex, md5_hex):
                        best_match = candidate_res
                        break
                except Exception:
                    pass

    selected = best_match or fallback_match

    if selected:
        return selected

    # If candidates existed but no sign order matched
    first_cand = candidates[0]
    return {
        "status": "NO_SIGN_MATCH",
        "host": host,
        "method": method,
        "url_path": url_path,
        "full_url": full_url,
        "sign_order": "",
        "raw_string": first_cand[0],
        "ts": first_cand[1] or (str(ts_val) if ts_val else ""),
        "pairs": pairs,
        "body_str": body_str,
    }


def scan_proxy_history(callbacks, helpers, domain_filter="(All Domains)", url_filter="", method_filter="POST, PUT",
                       only_in_scope=False, log_path="/tmp/cipherkit_frida.log", max_items=500):
    """
    Scan Burp's Proxy HTTP History, filter items, match against Frida logs,
    and return unique endpoint sign-order mapping results.
    """
    history = callbacks.getProxyHistory()
    if not history:
        return []

    results = []
    seen_endpoints = set()

    domain_filter = (domain_filter or "").strip()
    if domain_filter == "(All Domains)":
        domain_filter = ""

    # Iterate backwards (newest requests first)
    count = 0
    total = len(history)
    for i in range(total - 1, -1, -1):
        if count >= max_items:
            break

        item = history[i]
        if not item:
            continue

        try:
            req_info = helpers.analyzeRequest(item)
            url_str = str(req_info.getUrl()) if req_info.getUrl() else ""
            method = req_info.getMethod()
            host = req_info.getUrl().getHost() if req_info.getUrl() else ""

            # Domain filter check
            if domain_filter and host and domain_filter.lower() not in host.lower():
                continue

            # Method filter check
            if not matches_method_filter(method, method_filter):
                continue
            # URL pattern filter check
            if not matches_url_filter(url_str, url_filter, only_in_scope, callbacks, item):
                continue

            url_path = _extract_request_path(req_info)
            endpoint_key = (host.lower(), method.upper(), url_path)

            # Deduplicate endpoints: take the latest request only (iterating newest to oldest)
            if endpoint_key in seen_endpoints:
                continue
            seen_endpoints.add(endpoint_key)

            # Process single HTTP item
            res = process_http_item(helpers, item, log_path=log_path)
            if res:
                res["req_id"] = i + 1
                results.append(res)
            count += 1
        except Exception as e:
            print("[CipherKit] Batch Mapper error processing request #%d: %s" % (i + 1, str(e)))

    return results

