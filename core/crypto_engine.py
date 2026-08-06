# -*- coding: utf-8 -*-
from __future__ import print_function
import json, hashlib, hmac, base64, time, traceback
from javax.crypto import Cipher
from javax.crypto.spec import SecretKeySpec, IvParameterSpec

class CryptoEngine(object):
    @staticmethod
    def execute_snippet(snippet_code, payload, passcode, custom_data=None, key_order=None):
        """
        Execute a snippet.
        custom_data: dict of {key_name: value} from the custom data fields.
        The merge_payload is built by combining custom_data + payload so that
        key_order can reference both custom data keys and payload keys.
        Backward compat: if snippet uses old `api_key` str param, first value is passed.
        If a snippet returns a tuple (hash_str, debug_log), the debug_log is shown in the UI.
        """
        local_scope = {}
        # Warning-2: restrict __builtins__ to safe allowlist — no os.system, file writes, network
        _safe_builtins = {
            "__import__": __import__,
            "abs": abs, "bool": bool, "bytes": bytes, "chr": chr,
            "dict": dict, "divmod": divmod, "enumerate": enumerate,
            "filter": filter, "float": float, "format": format,
            "frozenset": frozenset, "getattr": getattr, "hasattr": hasattr,
            "hash": hash, "hex": hex, "int": int, "isinstance": isinstance,
            "issubclass": issubclass, "iter": iter, "len": len, "list": list,
            "map": map, "max": max, "min": min, "next": next, "oct": oct,
            "ord": ord, "pow": pow, "print": print, "range": range,
            "repr": repr, "reversed": reversed, "round": round,
            "set": set, "slice": slice, "sorted": sorted, "str": str,
            "sum": sum, "tuple": tuple, "type": type, "vars": vars,
            "zip": zip, "ValueError": ValueError, "TypeError": TypeError,
            "KeyError": KeyError, "Exception": Exception, "True": True,
            "False": False, "None": None,
        }
        global_scope = {
            "__builtins__": _safe_builtins,
            "hashlib": hashlib,
            "hmac": hmac,
            "base64": base64,
            "json": json,
            "time": time
        }

        # Build merged context: custom_data keys come first, then payload keys
        if custom_data is None:
            custom_data = {}

        # Merged dict for snippets that want a unified lookup
        merged = {}
        merged.update(custom_data)
        merged.update(payload)

        try:
            exec(snippet_code, global_scope, local_scope)

            if "generate" not in local_scope:
                raise ValueError("Snippet must define a 'generate' function.")

            generate_func = local_scope["generate"]

            # Try new signature: (payload, passcode, custom_data_dict, key_order)
            try:
                res = generate_func(merged, passcode, custom_data, key_order)
            except TypeError as te:
                err_msg = str(te)
                if "argument" in err_msg:
                    # Fallback for old snippets using api_key (single string)
                    api_key = list(custom_data.values())[0] if custom_data else ""
                    try:
                        res = generate_func(merged, passcode, api_key, key_order)
                    except TypeError:
                        res = generate_func(merged, passcode, api_key)
                else:
                    raise te
            
            # Unpack if snippet returns a debug log tuple
            if isinstance(res, tuple) and len(res) == 2:
                return res[0], res[1]
            return res, ""

        except Exception as e:
            return ("Error: %s\n%s" % (str(e), traceback.format_exc()), "")


# =============================================================================
# AES-CBC-128 Encrypt / Decrypt Engine
# Matches the JS crypto.subtle AES-CBC reference implementation:
#   - Key and IV are UTF-8 encoded strings (16 bytes for AES-128)
#   - If IV is blank/None, the KEY bytes are reused as IV (JS default behaviour)
#   - Ciphertext is Base64 (matches btoa/atob in the JS sample)
#   - Padding: PKCS5 (same as PKCS7, the browser default)
# =============================================================================
class AesCbcEngine(object):
    ALGORITHM = "AES/CBC/PKCS5Padding"

    @staticmethod
    def _prepare(key_utf8, iv_utf8):
        """Convert UTF-8 key and IV strings to Java byte arrays."""
        key_bytes = key_utf8.encode("UTF-8")
        if iv_utf8 and iv_utf8.strip():
            iv_bytes = iv_utf8.encode("UTF-8")
        else:
            # JS default: if iv is empty/omitted, reuse the key bytes as IV
            iv_bytes = key_bytes
        # Warning-3: clear byte-count feedback on wrong-length Key/IV
        if len(key_bytes) not in (16, 24, 32):
            raise ValueError(
                "AES Key must be 16, 24, or 32 UTF-8 bytes — got %d byte(s).\n"
                "Tip: for AES-128 use a 16-character ASCII key." % len(key_bytes)
            )
        if len(iv_bytes) != 16:
            raise ValueError(
                "AES IV must be exactly 16 UTF-8 bytes — got %d byte(s).\n"
                "Tip: leave blank to reuse the Key bytes as IV." % len(iv_bytes)
            )
        return key_bytes, iv_bytes

    @staticmethod
    def encrypt(plaintext_str, key_utf8, iv_utf8=None):
        """
        Encrypt plaintext_str with AES-128-CBC, PKCS5 padding.
        Returns Base64-encoded ciphertext string.
        Matches: crypto.subtle.encrypt({name:'AES-CBC', iv:v}, K, encoded)
        """
        try:
            key_bytes, iv_bytes = AesCbcEngine._prepare(key_utf8, iv_utf8 or "")
            secret_key = SecretKeySpec(key_bytes, "AES")
            iv_spec    = IvParameterSpec(iv_bytes)
            cipher     = Cipher.getInstance(AesCbcEngine.ALGORITHM)
            cipher.init(Cipher.ENCRYPT_MODE, secret_key, iv_spec)
            plaintext_bytes = plaintext_str.encode("UTF-8")
            encrypted_bytes = cipher.doFinal(plaintext_bytes)
            return base64.b64encode(bytes(bytearray(encrypted_bytes)))
        except Exception as e:
            raise RuntimeError("AES-CBC encrypt failed: %s" % str(e))

    @staticmethod
    def decrypt(ciphertext_b64, key_utf8, iv_utf8=None):
        """
        Decrypt a Base64 ciphertext string with AES-128-CBC, PKCS5 padding.
        Returns the original plaintext string.
        Matches: crypto.subtle.decrypt({name:'AES-CBC', iv:v}, K, cipherBytes)
        """
        try:
            key_bytes, iv_bytes = AesCbcEngine._prepare(key_utf8, iv_utf8 or "")
            secret_key      = SecretKeySpec(key_bytes, "AES")
            iv_spec         = IvParameterSpec(iv_bytes)
            cipher          = Cipher.getInstance(AesCbcEngine.ALGORITHM)
            cipher.init(Cipher.DECRYPT_MODE, secret_key, iv_spec)
            # Accept both str and bytes for the base64 input
            ciphertext_bytes = base64.b64decode(ciphertext_b64)
            decrypted_bytes  = cipher.doFinal(ciphertext_bytes)
            return bytearray(decrypted_bytes).decode("UTF-8")
        except Exception as e:
            raise RuntimeError("AES-CBC decrypt failed: %s" % str(e))



# =============================================================================
# Extensible Crypto Snippet System
# Works exactly like the hash SnippetManager -- users add new algorithms by
# adding entries to crypto_snippets.json with encrypt_code / decrypt_code.
