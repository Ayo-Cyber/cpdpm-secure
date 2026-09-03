# Red-team review of CPDPM, September 2026

Self-review of the design and code before external eyes see it. Each finding records what was wrong, how it was found, what changed, and whether it becomes a test or a stated limitation. Severity is relative to the threat model in [threat-model.md](threat-model.md).

| # | Finding | Severity | Resolution |
|---|---|---|---|
| 1 | **Field deletion undetected.** Per-field AEAD binds each value to its path, but nothing bound the *set* of values. An insider could delete an encrypted note (for example an allergy) and decryption succeeded with the note silently gone. | High | Fixed. Every encrypted resource now carries an encrypted **manifest**: ordered (path, SHA-256 of ciphertext) entries under `field_path="_manifest"`. Decryption verifies it before releasing any field. Tests: `test_fhir_manifest.py`. |
| 2 | **Partial replay undetected.** Replacing one field's ciphertext with an older ciphertext of the same field, same patient, same path, decrypted cleanly. | High | Fixed by the manifest (digest mismatch). Whole-document replay, manifest included, remains a stated limitation (threat model §8). |
| 3 | **Encrypted-paths tag list was trusted.** `decrypt_resource` read the list of encrypted paths from `meta.tag`, which the adversary controls. It could not expose data (a wrong path fails closed), but it made the tag list part of the trust boundary. | Medium | Fixed. The manifest is authoritative; the tag list is informational only. Test: `test_tag_list_is_informational_only`. |
| 4 | **Clear fields had no integrity.** By design search fields stay readable, but nothing let an application ask for them to be tamper-evident. | Medium | Added `bind_cleartext=True`: the manifest carries a digest of the resource with encrypted values blanked. Off by default because applications legitimately edit clear fields. |
| 5 | **Lone surrogates escaped `ContextError`.** `Context("t\ud800", …)` raised `UnicodeEncodeError` from `.encode()`, violating the one-exception contract. Found by fuzzing. | Low | Fixed: caught and re-raised as `ContextError`; surrogate and control categories rejected explicitly. Test: `test_fuzz.py::test_context_only_raises_context_error`. |
| 6 | **Unassigned code points.** A first fix rejected Unicode category `Cn` too. That would make validity depend on the Unicode version of the running Python, a portability hazard for a canonical encoding. | Low | Reverted to rejecting only `Cc` and `Cs`. NFC itself can still differ across Unicode versions for newly assigned characters; noted as a limitation. |
| 7 | **Path regex accepted a trailing newline.** `re.match` with `$` let `"code.text\n"` parse. Harmless (the newline was later rejected by `Context`) but sloppy. | Low | `fullmatch`. Test: `test_fuzz.py::test_path_parse_only_raises_value_error`. |
| 8 | **No streaming.** A 654 KB bundle is fine in memory; a 600 MB imaging study is not, and one-shot AEAD cannot release verified output incrementally. | Medium (product) | Added `cpdpm.stream`: STREAM construction, chunk nonce `prefix ‖ counter ‖ last`, commitment in the first chunk. Truncation, extension, drop, swap, duplicate all rejected. Tests: `test_stream.py`. |
| 9 | **XChaCha performance depends on PyNaCl's libsodium build.** 35x slower than OpenSSL ChaCha20-Poly1305 on arm64. | Info | Recorded in the evaluation; AES-GCM stays default; `cryptography`-backed ChaCha20-Poly1305 suite is a 0.2 candidate. A GitHub Actions job now measures on x86-64. |

## Reviewed and left as designed

- **Commitment derived from MK and context, not from K_ctx.** K_ctx is a function of (MK, suite, ctx), so committing to (MK, ctx) commits to K_ctx. The standard padding-fix argument applies: a ciphertext valid under two candidate keys would need its first 32 bytes to equal two different commitments simultaneously.
- **Streaming releases plaintext before the stream ends.** Inherent to streaming AEAD; the consumer must discard output on error. Documented in the module.
- **No zeroisation of keys in memory.** Python cannot guarantee it. Out of scope with host compromise.
- **Header parse order leaks nothing secret.** Early exits depend only on public bytes.
- **Nonce collision bound.** 96-bit random per context key; per-context write counts keep it negligible (design §4).

## Fuzzing

`tests/test_fuzz.py` drives every parser that touches untrusted input with Hypothesis: header unpack, blob decrypt, text-form decrypt, `Context` construction over arbitrary text including surrogates and C0 controls, path parsing, the FHIR walker over random JSON, and `decrypt_resource` over random documents. The property in each case is that only the contracted exception type escapes. Findings 5 and 7 came from this.

## Still open

- External review. This document is a self-review and should be read as such.
- Whole-document replay needs application-side versioning; the library cannot see time.
- Length and existence of encrypted fields remain visible.
