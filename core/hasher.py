# -*- coding: utf-8 -*-
from __future__ import print_function
import hashlib

from core.body_parser import flatten_data

_IGNORE_KEYS = set(["hash", "signature", "sign", "sig"])
_DECIMAL_FIELDS = set(["amount", "commission"])

_ALGORITHMS = {
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "md5": hashlib.md5,
}


def build_flat_payload(payload, custom_data=None):
    """Flatten a parsed body dict and merge custom_data on top (custom_data wins)."""
    flat = flatten_data(payload) if isinstance(payload, dict) else {}
    if custom_data:
        merged = dict(flat)
        merged.update(custom_data)
        flat = merged
    return flat


def resolve_key_order(flat_payload, key_order_str=None, ignore_keys=None):
    """Turn a comma-separated Sign Order string into an ordered key list,
    falling back to all non-ignored flat_payload keys in their natural order."""
    ignore = ignore_keys if ignore_keys is not None else _IGNORE_KEYS
    if key_order_str and key_order_str.strip():
        return [k.strip() for k in key_order_str.split(",") if k.strip()]
    return [k for k in flat_payload.keys() if k.lower() not in ignore]


def compute_hash(payload, key_order_str=None, custom_data=None, algorithm="sha1"):
    """
    Recompute the app's signature over a parsed request body.

    payload:       parsed body dict (may be nested; flattened internally)
    key_order_str:  comma-separated field order (e.g. "aba_id, ts, token");
                    falls back to all non-hash-like flat keys when empty
    custom_data:    extra key/value pairs merged over the flattened body
                    (e.g. the Frida-recovered token) — these win over body values
    algorithm:      "sha1" (default), "sha256", or "md5" (case/dash-insensitive,
                    e.g. "SHA-1" is accepted)

    Returns (digest_upper, raw_string, debug_log).
    """
    algo_key = (algorithm or "sha1").lower().replace("-", "").replace("_", "").strip()
    hash_fn = _ALGORITHMS.get(algo_key, hashlib.sha1)

    flat_payload = build_flat_payload(payload, custom_data)
    key_order = resolve_key_order(flat_payload, key_order_str)

    debug_lines = ["--- HASHING PROCESS DEBUG ---", "Algorithm: %s" % (algorithm or "SHA-1")]
    debug_lines.append("[1] Using Keys Order: " + str(key_order))
    debug_lines.append("")
    debug_lines.append("[2] Concatenating Values:")

    raw_parts = []
    for k in key_order:
        val = flat_payload.get(k, "")
        if val is None:
            val = ""
        if k in _DECIMAL_FIELDS:
            try:
                val = "{:.2f}".format(float(val))
            except Exception:
                pass
        val = str(val)
        debug_lines.append("    - %s = '%s'" % (k, val))
        raw_parts.append(val)

    raw_string = "".join(raw_parts)
    debug_lines.append("")
    debug_lines.append("[3] Final Concatenated String:")
    debug_lines.append("    -> '%s'" % raw_string)

    digest = hash_fn(raw_string.encode("utf-8")).hexdigest().upper()
    debug_lines.append("")
    debug_lines.append("[4] Result:")
    debug_lines.append("    -> %s" % digest)

    return digest, raw_string, "\n".join(debug_lines)
