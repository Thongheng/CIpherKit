# -*- coding: utf-8 -*-
from __future__ import print_function

# ABA Mobile's secret token is a fixed-length base64 suffix appended after the
# signed body fields (observed via Frida hook). When callers know this length,
# passing it to find_key_orders()/fetch_all_frida_candidates() lets recovery
# peel the token deterministically instead of guessing it from string shape.
DEFAULT_TOKEN_LEN = 64


def _search_key_orders(clean_values, target_str, max_matches, max_visited, allow_shape_guess):
    """
    Core DFS: find orderings of clean_values that reconstruct target_str exactly.

    allow_shape_guess: when True, unmatched gaps/suffixes >= 16 chars are guessed
    as a synthetic "token" segment (the generic, length-agnostic heuristic). When
    False, only direct field matches are considered — used when the token has
    already been peeled off deterministically, so nothing else should be guessed.
    Returns (unique_matches, visited_count, capped).
    """
    keys = sorted(clean_values.keys(), key=lambda k: len(clean_values[k]), reverse=True)
    matches = []
    visited = [0]

    # Minimum length for an unknown segment to be treated as a static app token.
    # Short gaps (e.g. "9999", 4 chars) are dynamic custom values — NOT tokens.
    _TOKEN_MIN_LEN = 16

    def get_token_name(segment):
        if not segment or len(segment) < _TOKEN_MIN_LEN:
            return None
        return "token"

    def dfs(current_order, remaining_keys, current_pos):
        visited[0] += 1
        if len(matches) >= max_matches or visited[0] >= max_visited:
            return

        if current_pos == len(target_str):
            if current_order:
                matches.append(tuple(current_order))
            return

        # 1. Direct matches at current_pos
        matched_any = False
        for key in list(remaining_keys):
            if visited[0] >= max_visited or len(matches) >= max_matches:
                return
            val = clean_values[key]
            if target_str.startswith(val, current_pos):
                matched_any = True
                next_remaining = [k for k in remaining_keys if k != key]
                dfs(current_order + [key], next_remaining, current_pos + len(val))

        # 2. If no key matches directly at current_pos, explore middle or suffix gaps
        # (only after first body key matched, and only when shape-guessing is allowed).
        if not matched_any and current_order and current_pos < len(target_str) and allow_shape_guess:
            gap_found = False
            for key in list(remaining_keys):
                if visited[0] >= max_visited or len(matches) >= max_matches:
                    return
                val = clean_values[key]
                if not val or len(val) < 2:
                    continue
                find_idx = target_str.find(val, current_pos + 1)
                if find_idx != -1:
                    gap_segment = target_str[current_pos:find_idx]
                    gap_key = get_token_name(gap_segment)
                    if gap_key:
                        gap_found = True
                        next_remaining = [k for k in remaining_keys if k != key]
                        dfs(current_order + [gap_key, key], next_remaining, find_idx + len(val))

            if not gap_found:
                remaining_suffix = target_str[current_pos:]
                # Only treat suffix as a static token when no remaining body key (>= 2 chars)
                # appears anywhere ahead — single digits like '8' would produce false positives inside base64 tokens.
                any_key_ahead = any(
                    clean_values[k] and len(clean_values[k]) >= 2 and clean_values[k] in remaining_suffix
                    for k in remaining_keys
                )
                if not any_key_ahead and len(remaining_suffix) >= 1:
                    token_key = get_token_name(remaining_suffix)
                    if token_key:
                        dfs(current_order + [token_key], remaining_keys, len(target_str))

    dfs([], keys, 0)

    def verify_and_score(m):
        pos = 0
        real_keys = 0
        real_bytes = 0
        gaps = 0
        for idx, k in enumerate(m):
            if k in clean_values:
                val = clean_values[k]
                if not target_str.startswith(val, pos):
                    return False, 0, 0, 0
                pos += len(val)
                real_keys += 1
                real_bytes += len(val)
            else:
                gaps += 1
                next_val = None
                for next_k in m[idx + 1:]:
                    if next_k in clean_values:
                        next_val = clean_values[next_k]
                        break
                if next_val:
                    next_pos = target_str.find(next_val, pos)
                    if next_pos <= pos:
                        return False, 0, 0, 0
                    pos = next_pos
                else:
                    if pos >= len(target_str):
                        return False, 0, 0, 0
                    pos = len(target_str)
        if pos == len(target_str):
            return True, real_keys, real_bytes, gaps
        return False, 0, 0, 0

    valid_scored = []
    seen = set()
    for m in matches:
        if m not in seen:
            seen.add(m)
            valid, real_keys, real_bytes, gaps = verify_and_score(m)
            if valid:
                valid_scored.append((real_keys, real_bytes, -gaps, m))

    valid_scored.sort(key=lambda x: (x[0], x[1], x[2]), reverse=True)
    if valid_scored:
        best_score = (valid_scored[0][0], valid_scored[0][1], valid_scored[0][2])
        unique_matches = [item[3] for item in valid_scored if (item[0], item[1], item[2]) == best_score]
    else:
        unique_matches = []

    capped = len(unique_matches) >= max_matches or visited[0] >= max_visited
    if visited[0] >= max_visited:
        unique_matches = []
    return unique_matches, visited[0], capped


def extract_gap_value(values, known, key_order, gap_key):
    """
    Given an ALREADY-KNOWN key_order (e.g. from a saved endpoint profile) and
    the current body's values, deterministically extract the substring that
    `gap_key` (typically the secret token — not present in the body) occupies
    within `known`. No brute-force search: the order isn't in question, this
    only answers "what value sits in the gap for *this* known string."

    Walks key_order left to right: every other key's value must match `known`
    at its expected position exactly, or this returns None (the key_order/
    values don't actually reconstruct this known string — wrong profile, or
    this request doesn't match). gap_key's span is bounded by the next key
    in key_order that has a real value, or end-of-string if gap_key is last
    (the common case: a trailing secret token).
    """
    known_str = str(known or "").strip()
    order = [str(k).strip() for k in (key_order or []) if str(k).strip()]
    if not known_str or not order or gap_key not in order:
        return None

    clean_values = dict(
        (k, str(v).strip()) for k, v in (values or {}).items() if v is not None
    )

    pos = 0
    gap_value = None
    for idx, key in enumerate(order):
        if key == gap_key:
            next_val = None
            for next_key in order[idx + 1:]:
                if next_key in clean_values and clean_values[next_key]:
                    next_val = clean_values[next_key]
                    break
            if next_val:
                end = known_str.find(next_val, pos)
                if end == -1 or end < pos:
                    return None
            else:
                end = len(known_str)
            gap_value = known_str[pos:end]
            pos = end
        else:
            val = clean_values.get(key, "")
            if not known_str.startswith(val, pos):
                return None
            pos += len(val)

    if pos != len(known_str):
        return None
    return gap_value


def find_key_orders(values, known, max_matches=100, max_visited=10000, token_len=None):
    """
    Find field order sequence that constructs the known raw string.
    Supports body parameter matching plus detection of static token/secret/custom suffix/prefix.

    token_len: if given and `known` is longer than token_len, the trailing
    `token_len` characters are tried first as a deterministically-peeled secret
    token (every match from this path has "token" appended). This avoids the
    generic 16-char-minimum token-shape heuristic misfiring on short body
    values or on custom gaps that aren't actually the token. If peeling finds
    no valid match — e.g. this endpoint's token isn't actually token_len long,
    or has no trailing token at all — this transparently falls back to the
    original shape-guessing search over the full string, so passing token_len
    never finds *less* than omitting it would.
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

    if token_len and len(known_str) > token_len:
        prefix = known_str[:-token_len]
        peeled_matches, peeled_visited, peeled_capped = _search_key_orders(
            clean_values, prefix, max_matches, max_visited, allow_shape_guess=False
        )
        if peeled_matches:
            return [m + ("token",) for m in peeled_matches], peeled_visited, peeled_capped
        # token_len doesn't apply to this endpoint (no trailing token of that exact
        # length) — fall back to the shape-guessing search over the full string.

    return _search_key_orders(clean_values, known_str, max_matches, max_visited, allow_shape_guess=True)


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
    Returns a list of tuples: [(raw_string, matched_ts, matched_via), ...], with exact
    ts matches ordered before substring/value-based matches.
    """
    import os, json

    if not os.path.exists(log_path):
        return []

    target_ts = str(ts_val).strip() if ts_val is not None else ""
    val_strs = [str(v).strip() for v in (values.values() if isinstance(values, dict) else []) if v and len(str(v).strip()) >= 4]

    exact_candidates = []
    fallback_candidates = []
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

                if target_ts and log_ts and log_ts == target_ts:
                    # Exact ts equality — the log itself recorded this ts, so it's authoritative.
                    exact_candidates.append((raw_str, log_ts, "timestamp"))
                    seen_raws.add(raw_str)
                elif target_ts and not log_ts and target_ts in raw_str:
                    # Log line has no ts field, but the target ts appears embedded in the raw string.
                    fallback_candidates.append((raw_str, target_ts, "timestamp"))
                    seen_raws.add(raw_str)
                elif val_strs and sum(1 for v in val_strs if v in raw_str) >= 2:
                    fallback_candidates.append((raw_str, log_ts, "parameter_value"))
                    seen_raws.add(raw_str)
            except Exception:
                if target_ts and target_ts in line:
                    if line not in seen_raws:
                        fallback_candidates.append((line, target_ts, "text_match"))
                        seen_raws.add(line)

    except Exception as e:
        print("[CipherKit] Error reading Frida log: " + str(e))

    return exact_candidates + fallback_candidates


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

