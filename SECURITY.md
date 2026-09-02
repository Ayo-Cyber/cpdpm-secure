# Security

## Status

cpdpm is **pre-alpha research software**. It has not been reviewed by a third party. Do not use it to protect real patient data until a review has happened and this file says so.

What it does claim, and the evidence for each claim, is in [docs/threat-model.md](docs/threat-model.md) and [docs/design-v2.md](docs/design-v2.md). What it does not claim is listed in the threat model under "explicitly out of scope" and in the limitations section of the paper outline.

## Design principles that bound the attack surface

- No new primitives. AES-256-GCM and ChaCha20-Poly1305 come from OpenSSL (via `cryptography`) and libsodium (via `PyNaCl`); HKDF and PBKDF2 from `cryptography`; Argon2id from `argon2-cffi`.
- The decrypt path raises one exception type with one fixed message. Nothing about *which* check failed leaves the library.
- Ciphertexts carry no key material and no context. The context must be supplied by the caller from an authenticated source.
- Every check on the decrypt path (header, key version, AEAD tag, key commitment) is exercised by tests that flip each byte of a ciphertext and change each context field.

## Reporting a vulnerability

Email the maintainer at the address on the GitHub profile of the repository owner, or open a GitHub security advisory on this repository (Security tab, "Report a vulnerability"). Please do not open a public issue for anything that could be a vulnerability.

You can expect an acknowledgement within seven days. Because this is a one-person research project, fixes are best-effort; a confirmed report will be described in `CHANGELOG.md` with credit if you want it.

## Known limitations (not vulnerabilities)

- Replay of an old ciphertext *within the same context* is not detected. Applications that need it must version the context or the record.
- Ciphertext length, existence, and which fields are encrypted are visible.
- Security depends on the host that holds the master key. A compromised application host is out of scope.
- The XChaCha20-Poly1305 suite is only as fast as the installed libsodium build.
