# Changelog

All notable changes to the `cpdpm` package. The paper and thesis materials under `paper/` and `docs/` are not versioned here.

## Unreleased (0.1.0a0)

Protocol version 1. First implementation of context-bound authenticated encryption for clinical records.

Added
- `Context` with an injective, NFC-normalised, length-prefixed canonical encoding; lone surrogates and control characters are rejected with `ContextError`.
- Versioned wire header (`CPDM`, protocol 1, suite, key version, nonce) bound as associated data.
- Suites: AES-256-GCM (default) and XChaCha20-Poly1305 (optional extra `xchacha`).
- HKDF-SHA256 per-context keys and a 32-byte key commitment prepended to every plaintext.
- `Keyring` with versioned master keys, `rotate()`, `retire()`, and wrapped import/export through a `KeyWrapper`; `LocalKeyWrapper` for development.
- Argon2id master-key derivation (optional extra `password`); PBKDF2 at 600k iterations as a deprecated migration path.
- `encrypt` / `decrypt` and the `cpdpm1:` text form for JSON stores.
- FHIR field-level encryption (`cpdpm.fhir`) with a path policy, `[*]` array collapsing, an encrypted **manifest** binding the set of encrypted fields (detects deletion, reordering, duplication and per-field replay), and `bind_cleartext=True` to bind unencrypted fields as well; whole-resource mode.
- `cpdpm.stream`: chunked STREAM encryption for large payloads, with truncation, reordering and extension detection.
- Known-answer vectors in `tests/vectors/kat.json`; property-based fuzzing of every parser in `tests/test_fuzz.py`.

Security notes
- Ciphertexts from other schemes, including base64 JSON packages, are rejected with `DecryptionError`.
- See `docs/red-team-2026-09.md` for the self-review findings and their resolutions.
