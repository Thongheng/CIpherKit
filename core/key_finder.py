# -*- coding: utf-8 -*-
from __future__ import print_function


def find_key_orders(values, known, max_matches=100, max_visited=10000):
    """
    Find field order sequence that constructs the known raw string.
    Supports body parameter matching plus detection of static token/secret/custom suffix/prefix.
    """
    if not known or not values:
        return [], 0, False

    known_str = str(known).strip()
    if not known_str:
        return [], 0, False

    # Filter out hash/signature fields from candidate values
    ignore_keys = set(["hash", "signature", "sign", "sig", "token_hash", "mac"])
    clean_values = {}
    for k, v in values.items():
        if k.lower() in ignore_keys:
            continue
        v_str = str(v).strip() if v is not None else ""
        if v_str:
            clean_values[k] = v_str

    if not clean_values:
        return [], 0, False

    keys = list(clean_values.keys())
    matches = []
    visited = [0]

    def get_token_name(segment):
        if not segment:
            return None
        if segment.endswith("="):
            return "secret"
        return "token"

    def dfs(current_order, remaining_keys, current_pos):
        visited[0] += 1
        if len(matches) >= max_matches or visited[0] >= max_visited:
            return

        if current_pos == len(known_str):
            if current_order:
                matches.append(tuple(current_order))
            return

        matched_any = False
        for key in list(remaining_keys):
            if visited[0] >= max_visited or len(matches) >= max_matches:
                return
            val = clean_values[key]
            if known_str.startswith(val, current_pos):
                matched_any = True
                next_remaining = [k for k in remaining_keys if k != key]
                dfs(current_order + [key], next_remaining, current_pos + len(val))

        if not matched_any and current_order and current_pos < len(known_str):
            remaining_suffix = known_str[current_pos:]
            custom_matched = False
            for key in list(remaining_keys):
                val = clean_values[key]
                if val and val == remaining_suffix:
                    dfs(current_order + [key], [k for k in remaining_keys if k != key], len(known_str))
                    custom_matched = True
                    break

            if not custom_matched and len(remaining_suffix) >= 4:
                token_key = get_token_name(remaining_suffix)
                if token_key and token_key not in current_order:
                    dfs(current_order + [token_key], remaining_keys, len(known_str))

    dfs([], keys, 0)

    unique_matches = []
    seen = set()
    for m in matches:
        if m not in seen:
            seen.add(m)
            unique_matches.append(m)

    capped = len(unique_matches) >= max_matches or visited[0] >= max_visited
    return unique_matches, visited[0], capped


def compare_generated_hash(generated_hash, payload, hash_field):
    """Return valid, invalid, missing, or error for a generated hash."""
    generated = str(generated_hash)
    if generated.startswith("Error"):
        return "error"
    if not isinstance(payload, dict) or hash_field not in payload:
        return "missing"
    reference = payload.get(hash_field)
    if reference is None or not str(reference).strip():
        return "missing"
    if str(reference).strip().lower() == generated.strip().lower():
        return "valid"
    return "invalid"


def format_hash_comparison(generated_hash, comparison):
    """Format comparison feedback inside the hash output value."""
    value = strip_hash_comparison(generated_hash)
    if comparison == "valid":
        return value + " (Match)"
    if comparison == "invalid":
        return value + " (Not Match)"
    return value


def strip_hash_comparison(value):
    """Remove comparison feedback when request data changes."""
    text = str(value)
    for suffix in (" (Not Match)", " (Match)"):
        if text.endswith(suffix):
            return text[:-len(suffix)]
    return text


def should_render_hash_output(compare_requested, crypto_output_mode):
    """A comparison must display its generated hash even from Crypto mode."""
    return bool(compare_requested or not crypto_output_mode)


def fetch_all_frida_candidates(ts_val=None, values=None, log_path="/tmp/cipherkit_frida.log"):
    """
    Search /tmp/cipherkit_frida.log for all hooked unhashed raw string candidates matching
    the provided timestamp (ts_val) or candidate request body values.
    Returns a list of tuples: [(raw_string, matched_ts, matched_via), ...].
    """
    import os, json

    if not os.path.exists(log_path):
        return []

    target_ts = str(ts_val).strip() if ts_val is not None else ""
    val_strs = [str(v).strip() for v in (values.values() if isinstance(values, dict) else []) if v and len(str(v).strip()) >= 4]

    candidates = []
    seen_raws = set()

    try:
        with open(log_path, "r") as f:
            lines = f.readlines()

        # Read from newest to oldest for faster lookup
        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                log_ts = str(data.get("ts", "")).strip()
                raw_str = str(data.get("raw_string", "")).strip()

                if not raw_str or raw_str in seen_raws:
                    continue

                if target_ts and (log_ts == target_ts or target_ts in raw_str):
                    candidates.append((raw_str, log_ts or target_ts, "timestamp"))
                    seen_raws.add(raw_str)
                elif val_strs and sum(1 for v in val_strs if v in raw_str) >= 2:
                    candidates.append((raw_str, log_ts, "parameter_value"))
                    seen_raws.add(raw_str)
            except Exception:
                if target_ts and target_ts in line:
                    if line not in seen_raws:
                        candidates.append((line, target_ts, "text_match"))
                        seen_raws.add(line)

    except Exception as e:
        print("[CipherKit] Error reading Frida log: " + str(e))

    return candidates


def fetch_frida_hook(ts_val=None, values=None, log_path="/tmp/cipherkit_frida.log"):
    """
    Search /tmp/cipherkit_frida.log for a hooked unhashed raw string matching
    the provided timestamp (ts_val) or candidate request body values.
    Returns (raw_string, matched_ts, matched_via) or (None, None, None).
    """
    candidates = fetch_all_frida_candidates(ts_val=ts_val, values=values, log_path=log_path)
    if candidates:
        return candidates[0]
    return None, None, None

