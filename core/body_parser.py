# -*- coding: utf-8 -*-
from __future__ import print_function
import json, re


def _url_decode(value):
    try:
        from java.net import URLDecoder
        return URLDecoder.decode(value, "UTF-8")
    except Exception:
        try:
            from urllib import unquote_plus
        except ImportError:
            from urllib.parse import unquote_plus
        return unquote_plus(value)


def _url_encode(value):
    value = str(value)
    try:
        from java.net import URLEncoder
        return URLEncoder.encode(value, "UTF-8")
    except Exception:
        try:
            from urllib import quote_plus
        except ImportError:
            from urllib.parse import quote_plus
        return quote_plus(value)

def _get_boundary(content_type):
    """Extract the multipart boundary from a Content-Type header value."""
    if not content_type:
        return None
    for part in content_type.split(";"):
        part = part.strip()
        if part.lower().startswith("boundary="):
            return part[len("boundary="):].strip().strip('"')
    return None


def _auto_detect_boundary(body_str):
    """Extract boundary from the first non-empty line of a multipart body.
    The first line is always '--<boundary>', so we strip the leading '--'.
    """
    for line in body_str.splitlines():
        line = line.strip()
        if line.startswith("--") and len(line) > 2:
            return line[2:]  # Strip the leading '--' prefix
    return None


def _try_parse_json(body_str):
    try:
        result = json.loads(body_str)
        if isinstance(result, dict):
            return result
    except:
        pass
    return None


def _try_parse_urlencoded(body_str):
    """Parse application/x-www-form-urlencoded body. Jython-safe."""
    try:
        stripped = body_str.strip()
        # Reject multipart bodies (they start with --boundary)
        if stripped.startswith("--"):
            return None
        result = {}
        for pair in stripped.split("&"):
            pair = pair.strip()
            if not pair:
                continue
            if "=" in pair:
                k, v = pair.split("=", 1)
            else:
                k, v = pair, ""
            try:
                k = _url_decode(k)
                v = _url_decode(v)
            except Exception:
                k = k.replace("+", " ")
                v = v.replace("+", " ")
            if k:
                result[k] = v
        # Only return if we found key=value pairs (not a JSON-looking string)
        if result and not stripped.startswith("{"):
            return result
    except:
        pass
    return None


def _try_parse_multipart(body_str, content_type):
    """Parse multipart/form-data body using a line-by-line state machine."""
    # Try to get boundary from Content-Type header first, then auto-detect from body
    boundary = _get_boundary(content_type)
    if not boundary:
        boundary = _auto_detect_boundary(body_str)
    if not boundary:
        return None
    try:
        result = {}
        delimiter     = "--" + boundary       # e.g. ------geckoform...
        delimiter_end = "--" + boundary + "--" # final boundary

        # Normalise line endings and split into lines
        lines = body_str.replace("\r\n", "\n").replace("\r", "\n").split("\n")

        # States: 'seek' -> looking for boundary, 'headers' -> reading part headers,
        #         'value' -> reading part value
        state       = "seek"
        current_name  = None
        value_lines   = []
        is_large_or_file = False

        for line in lines:
            stripped = line.strip()

            if state == "seek":
                if stripped == delimiter or stripped == delimiter_end:
                    state = "headers"
                    current_name = None
                    value_lines  = []
                    is_large_or_file = False
                continue

            if state == "headers":
                if stripped == "":
                    # Blank line marks end of headers, start of value
                    state = "value"
                else:
                    lower = stripped.lower()
                    if "content-disposition" in lower:
                        if "filename=" in lower:
                            is_large_or_file = True
                        if "name=" in lower:
                            for seg in stripped.split(";"):
                                seg = seg.strip()
                                if seg.lower().startswith("name="):
                                    current_name = seg[5:].strip().strip('"\'')
                    if lower.startswith("content-length:"):
                        try:
                            val_len = int(lower.split("content-length:", 1)[1].strip())
                            if val_len > 500:
                                is_large_or_file = True
                        except Exception:
                            pass
                continue

            if state == "value":
                if stripped == delimiter or stripped == delimiter_end:
                    # Save current field if not a large file / upload
                    if current_name is not None and not is_large_or_file:
                        val_str = "\n".join(value_lines).rstrip("\r\n ")
                        if len(val_str) <= 500:
                            result[current_name] = val_str
                    # Reset for next part
                    current_name = None
                    value_lines  = []
                    is_large_or_file = False
                    if stripped == delimiter_end:
                        state = "seek"  # done
                    else:
                        state = "headers"
                else:
                    if not is_large_or_file:
                        value_lines.append(line)

        # Flush any trailing field (malformed final boundary)
        if state == "value" and current_name is not None and not is_large_or_file:
            val_str = "\n".join(value_lines).rstrip("\r\n ")
            if len(val_str) <= 500:
                result[current_name] = val_str

        if result:
            return result
    except Exception:
        pass
    return None



def parse_body(body_str, content_type=""):
    """
    Parse an HTTP request body into a dict.
    Supports: application/json, application/x-www-form-urlencoded, multipart/form-data.
    Tries all strategies; content_type just controls priority.
    Returns {} if nothing works.
    """
    if not body_str or not body_str.strip():
        return {}

    ct = (content_type or "").lower().split(";")[0].strip()

    # Decide priority order based on declared Content-Type
    if ct == "application/x-www-form-urlencoded":
        strategies = [_try_parse_urlencoded, _try_parse_json,
                      lambda b: _try_parse_multipart(b, content_type)]
    elif ct == "multipart/form-data":
        strategies = [lambda b: _try_parse_multipart(b, content_type),
                      _try_parse_json, _try_parse_urlencoded]
    else:
        # JSON first (default), then try others as fallback
        strategies = [_try_parse_json, _try_parse_urlencoded,
                      lambda b: _try_parse_multipart(b, content_type)]

    for strategy in strategies:
        try:
            result = strategy(body_str)
            if result:
                return result
        except:
            pass

    return {}


def serialize_body(updated_data, original_body, content_type=""):
    """
    Re-encode updated_data back to the same format as the original body.
    Used by Gen & Inject to write the hash back without changing the format.
    """
    ct = (content_type or "").lower().split(";")[0].strip()

    if ct == "application/x-www-form-urlencoded":
        try:
            original_data = _try_parse_urlencoded(original_body) or {}
            changed = set(
                key for key, value in updated_data.items()
                if key not in original_data or str(original_data.get(key)) != str(value)
            )
            emitted = set()
            parts = []
            for raw_pair in original_body.split("&"):
                raw_key = raw_pair.split("=", 1)[0]
                key = _url_decode(raw_key)
                if key in changed:
                    if key not in emitted:
                        parts.append("%s=%s" % (
                            _url_encode(key), _url_encode(updated_data[key])
                        ))
                        emitted.add(key)
                else:
                    parts.append(raw_pair)
                    emitted.add(key)
            for key, value in updated_data.items():
                if key not in emitted:
                    parts.append("%s=%s" % (_url_encode(key), _url_encode(value)))
            return "&".join(parts)
        except:
            pass

    if ct == "multipart/form-data":
        # Auto-detect the boundary from the body when the header is missing.
        boundary = _get_boundary(content_type)
        if not boundary:
            boundary = _auto_detect_boundary(original_body)
        if boundary:
            try:
                delimiter = "--" + boundary
                original_data = _try_parse_multipart(original_body, content_type) or {}
                changed = set(
                    key for key, value in updated_data.items()
                    if key not in original_data or str(original_data.get(key)) != str(value)
                )
                seen = set()
                # A boundary is valid only as a complete line. Splitting on the
                # token itself corrupts file parts containing boundary-like bytes.
                boundary_lines = []
                offset = 0
                for line in original_body.splitlines(True):
                    line_value = line.rstrip("\r\n")
                    if line_value == delimiter or line_value == delimiter + "--":
                        boundary_lines.append((offset, offset + len(line), line_value == delimiter + "--"))
                    offset += len(line)
                if not boundary_lines:
                    raise ValueError("multipart body has no complete boundary lines")

                output = [original_body[:boundary_lines[0][0]]]
                line_end = "\r\n" if "\r\n" in original_body else "\n"

                for index, (boundary_start, boundary_end, is_closing) in enumerate(boundary_lines):
                    output.append(original_body[boundary_start:boundary_end])
                    if is_closing:
                        break

                    part_start = boundary_end
                    part_end = boundary_lines[index + 1][0] if index + 1 < len(boundary_lines) else len(original_body)
                    segment = original_body[part_start:part_end]
                    separator = "\r\n\r\n" if "\r\n\r\n" in segment else "\n\n"
                    if separator not in segment:
                        output.append(segment)
                        continue
                    headers, body_with_suffix = segment.split(separator, 1)
                    match = re.search(r'name=(?:"([^"]*)"|([^;\r\n]+))', headers, re.I)
                    if not match:
                        output.append(segment)
                        continue
                    name = match.group(1) if match.group(1) is not None else match.group(2).strip()
                    seen.add(name)

                    # Never rewrite file parts; preserving their bytes and metadata is safer.
                    is_file = re.search(r'filename=', headers, re.I) is not None
                    if name in changed and not is_file:
                        line_end = "\r\n" if body_with_suffix.endswith("\r\n") else "\n"
                        output.append(
                            headers + separator + str(updated_data[name]) + line_end
                        )
                    else:
                        output.append(segment)

                for key, value in updated_data.items():
                    if key not in seen:
                        output.insert(
                            -1,
                            'Content-Disposition: form-data; name="%s"' % key
                            + line_end + line_end + str(value) + line_end
                        )
                return "".join(output)
            except:
                pass
        else:
            raise ValueError("multipart/form-data body has no boundary; cannot re-serialize safely.")

    # JSON fallback
    try:
        return json.dumps(updated_data, indent=2)
    except:
        return original_body


def flatten_data(data):
    """Recursively flatten dictionary and list values into a flat list of (key, value) pairs,
    matching the original JSON keys without generating extra formats or date components."""
    from collections import OrderedDict
    pairs = OrderedDict()
    
    def process(prefix, val):
        if val is None:
            return
            
        if isinstance(val, dict):
            for k, v in val.items():
                full_key = "%s.%s" % (prefix, k) if prefix else k
                process(full_key, v)
            return
            
        if isinstance(val, (list, tuple)):
            # Convert list of primitives to a joined string
            try:
                if all(not isinstance(x, (dict, list, tuple)) for x in val):
                    flat_str = "".join(str(x) for x in val)
                    if prefix:
                        pairs[prefix] = flat_str
                    else:
                        pairs["list_join"] = flat_str
                else:
                    # If it contains nested dicts/lists, process them
                    for i, item in enumerate(val):
                        idx_key = "%s[%d]" % (prefix, i) if prefix else "%d" % i
                        process(idx_key, item)
            except:
                pass
            return
            
        # Primitive value
        val_str = str(val)
        last_key = prefix.split('.')[-1] if prefix else ""
        if last_key in ('amount', 'commission'):
            try:
                val_str = "{:.2f}".format(float(val))
            except:
                pass
        if prefix:
            pairs[prefix] = val_str
                    
    # Start recursion
    if isinstance(data, dict):
        for k, v in data.items():
            process(k, v)
            
    return pairs




# =============================================================================
# Core Logic: Crypto Engine
