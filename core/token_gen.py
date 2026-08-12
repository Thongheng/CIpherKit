# -*- coding: utf-8 -*-
from __future__ import print_function
import hashlib
import base64

# Fixed AES-CBC IV used by the app for token derivation — its raw ASCII bytes
# (16 chars = 16 bytes), not hex-decoded.
_IV = "e60e6337c0710050"


def compute_login_hash(aba_id, device_id, ts, pin_hash, secret):
    """SHA1 hex (uppercase) of aba_id+device_id+ts+pin_hash+secret — login3's 'hash' field."""
    raw = "%s%s%s%s%s" % (aba_id, device_id, ts, pin_hash, secret)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest().upper()


def compute_second_hash(aba_id, device_id, ts, pin_hash):
    """SHA1 hex (uppercase) of aba_id+device_id+ts+pin_hash — login3's 'second_hash' field."""
    raw = "%s%s%s%s" % (aba_id, device_id, ts, pin_hash)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest().upper()


def _pkcs7_pad(data, block_size=16):
    pad_len = block_size - (len(data) % block_size)
    return data + bytes(bytearray([pad_len] * pad_len))


def _aes_cbc_encrypt(plaintext, key, iv):
    """AES-CBC encrypt with PKCS7 padding. Uses javax.crypto under Jython/Burp;
    falls back to the `cryptography` package under plain CPython (dev/tests)."""
    try:
        from javax.crypto import Cipher
        from javax.crypto.spec import SecretKeySpec, IvParameterSpec
        key_spec = SecretKeySpec(bytearray(key), "AES")
        iv_spec = IvParameterSpec(bytearray(iv))
        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, key_spec, iv_spec)
        result = cipher.doFinal(bytearray(plaintext))
        return bytes(bytearray([b & 0xFF for b in result]))
    except ImportError:
        pass

    from cryptography.hazmat.primitives.ciphers import Cipher as CryptoCipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    padded = _pkcs7_pad(plaintext)
    encryptor = CryptoCipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def generate_token(hash_hex, secret):
    """
    AES-CBC-encrypt the (uppercase) hash hex string with a key derived from the
    first 32 characters of `secret` and a fixed IV, base64-encoded. This is the
    same 64-char value ABA Mobile appends as the request-signing 'token'.
    """
    h = hash_hex.strip().upper()
    key = secret[:32] if len(secret) > 32 else secret
    ciphertext = _aes_cbc_encrypt(
        h.encode("utf-8"), key.encode("utf-8"), _IV.encode("utf-8")
    )
    return base64.b64encode(ciphertext).decode("ascii")


def generate_fresh_login(aba_id, device_id, ts, pin_hash, secret):
    """Compute the full login3 payload fields + the resulting session token."""
    hash_val = compute_login_hash(aba_id, device_id, ts, pin_hash, secret)
    second_hash = compute_second_hash(aba_id, device_id, ts, pin_hash)
    token = generate_token(hash_val, secret)
    return hash_val, second_hash, token
