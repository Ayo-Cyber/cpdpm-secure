# Changelog

All notable changes to the `cpdpm` package. The paper and thesis materials under `paper/` and `docs/` are not versioned here.

## Unreleased (0.1.0a0)

Protocol version 2. First implementation of context-bound authenticated encryption for clinical records.

Added
- `Context` with an injective, NFC-normalised, length-prefixed canonical encoding.
- Versioned wire header (`CPDM`, protocol 2, suite, key version, nonce) bound as associated data.
- Suites: AES-256-GCM (default) and XChaCha20-Poly1305 (optional extra `xchacha`).
- HKDF-SHA256 per-context keys and a 32-byte key commitment prepended to every plaintext.
- `Keyring` with versioned master keys, `rotate()`, `retire()`, and wrapped import/export through a `KeyWrapper`; `LocalKeyWrapper` for development.
- Argon2id master-key derivation (optional extra `password`); PBKDF2 at 600k iterations as a deprecated migration path.
- `encrypt` / `decrypt` and the `cpdpm2:` text form for JSON stores.
- FHIR field-level encryption (`cpdpm.fhir`) with a path policy, `[*]` array collapsing, and a `meta.tag` record of encrypted paths; whole-resource mode.
- Known-answer vectors in `tests/vectors/v2_kat.json`.

Security notes
- Replaces CPDPM v1 (see `legacy/`), whose pre-encryption "polynomial" layer was a public affine map and whose context binding did not function. v1 ciphertexts are not readable by v2 and are rejected with `DecryptionError`.
