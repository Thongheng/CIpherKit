# Deferred: config-driven generalization (Phase 4)

Not started. Saved for later — CipherKit currently only targets ABA Mobile;
this is the follow-up to make it work against other apps via config instead
of code changes.

## Context

CipherKit re-signs ABA Mobile request bodies: `hash = SHA1(concat(ordered
body fields) + secret_token)`, where the token is a fixed-length base64
suffix recovered via a Frida hook. Phases 1–3 (bug fixes, centralizing the
signing algorithm into `core/hasher.py`, and token-length-aware sign-order
recovery in `core/key_finder.py`) are done and merged into the working tree.
This phase was explicitly scoped out of that work since the tool is
ABA-only today and generalizing further wasn't needed yet.

`app_settings.json` already carries `algorithm`, `secret`, and `hash_field`
per app, but several things are still hardcoded in Python instead of read
from that config. This phase moves them over.

## What to move from code into config

- **`ALLOWED_ABA_DOMAINS`** (hardcoded in `core/batch_mapper.py`) → a
  per-app domain list, so Batch Mapper isn't locked to `*.ababank.com`.
- **`"ABA Mobile"` hardcoded app name** (tab titles, Save/Apply labels,
  status text in `HashGenBurp.py` and `ui/batch_tab.py`) → an active-profile
  selector, so multiple apps can coexist and the UI reflects whichever is
  selected.
- **SHA-1 hardcoded as the only algorithm** in `core/hasher.py` call sites →
  read the per-app `algorithm` field (`core/hasher.compute_hash` already
  accepts an `algorithm` param — `performAction` already passes it through;
  `_onGenerate`/`_computeHash` still call it without one).
- **`amount`/`commission` 2-decimal special-casing** (`core/hasher.py`,
  `core/body_parser.flatten_data`) → per-app field-format rules instead of
  a fixed field-name list.
- **Token field name + length** (`DEFAULT_TOKEN_LEN = 64` in
  `core/key_finder.py`, `"token"` as the default custom-data key) → per-app
  `token_len` / token key name / suffix-vs-prefix position, read from
  `app_settings.json` and passed into `find_key_orders(..., token_len=...)`
  and the Frida-fetch call sites instead of the current hardcoded default.

## Suggested approach when picked up

1. Add `token_len`, `token_key`, and a `field_formats` dict to the
   `app_settings.json` schema (alongside the existing `algorithm`,
   `secret`, `hash_field`).
2. Thread the resolved app's config into `compute_hash()` and
   `find_key_orders()` at each call site (`HashGenBurp.py`,
   `ui/editor_tab.py`, `core/batch_mapper.py`) instead of the current
   ABA-flavored defaults.
3. Replace hardcoded `"ABA Mobile"` strings with the currently-selected/
   resolved app name.
4. Replace `ALLOWED_ABA_DOMAINS` with a per-app domain list, falling back
   to "scan all domains" when unset.
5. Verify: existing ABA behavior must be unchanged when the new config
   fields are absent (defaults should reproduce today's ABA-only behavior)
   — add a second synthetic app fixture in tests to prove a non-ABA profile
   works end-to-end through `core/hasher.py` and `core/key_finder.py`.
