# -*- coding: utf-8 -*-
from __future__ import print_function
import json, os

class SnippetManager(object):
    def __init__(self, filepath):
        self.filepath = filepath
        self.snippets = {}
        self.load_snippets()

    def load_snippets(self):
        if not os.path.exists(self.filepath):
            self.create_default_snippets()
        try:
            with open(self.filepath, 'r') as f:
                self.snippets = json.load(f)
        except Exception as e:
            print("[CipherKit] Error loading snippets: %s" % str(e))
            self.snippets = {}

    def save_snippets(self):
        try:
            with open(self.filepath, 'w') as f:
                json.dump(self.snippets, f, indent=2)
            return True
        except Exception as e:
            print("[CipherKit] Error saving snippets: %s" % str(e))
            return False

    def get_snippet(self, name):
        return self.snippets.get(name)

    def get_all_names(self):
        return list(self.snippets.keys())

    def create_default_snippets(self):
        default_code = (
            "def generate(payload, passcode=None, custom_data=None, key_order=None):\n"
            "    import hashlib\n"
            "\n"
            "    if key_order:\n"
            "        keys_to_sign = key_order\n"
            "    else:\n"
            "        keys_to_sign = [k for k in payload.keys() if k != 'hash']\n"
            "\n"
            "    concat_str = \"\"\n"
            "    for k in keys_to_sign:\n"
            "        val = payload.get(k)\n"
            "        if val is None: val = \"\"\n"
            "        concat_str += str(val)\n"
            "\n"
            "    digest = hashlib.sha1(concat_str.encode('utf-8')).hexdigest()\n"
            "    return digest\n"
        )
        self.snippets["SHA-1"] = {
            "code": default_code,
            "requires_key": False,
            "description": "Plain SHA-1 hash of concatenated payload values."
        }
        self.save_snippets()



# =============================================================================
