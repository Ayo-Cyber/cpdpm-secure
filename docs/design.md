# CPDPM design: context-bound AEAD for clinical records

Status: implemented in `cpdpm/` (context, header, kdf, aead, keys, core, fhir, stream). Protocol version 1.
Companion: [threat-model.md](threat-model.md). The protocol version byte in the header is 1; the package version starts at 0.1.0.

## 1. One-paragraph summary

A record field is encrypted with a standard AEAD under a key derived, through HKDF, from a versioned master key and the record's **context**: tenant, patient, resource type, field path. The same context, canonically encoded, is also passed as associated data together with the header. Decrypting under any other context therefore fails twice over: wrong key, wrong associated data. Nothing is invented at the primitive level. The contribution is the binding discipline, its encoding, its key hierarchy, and the evidence that it stops the attack the threat model describes.

## 2. Design principles

| Principle | Consequence |
|---|---|
| No pre-transform layers, no new primitives | AES-256-GCM or XChaCha20-Poly1305 from audited libraries; one primitive, one key per context |
| Context is an input, not metadata | Canonically encoded, fed to HKDF **and** to the AEAD as associated data; never stored with the ciphertext |
| No key material in the ciphertext | Header carries only version, suite, key version, nonce |
| Password-derived keys are the exception | Argon2id when unavoidable; PBKDF2 at 600k only as a migration path |
| Keys have versions | Rotation without re-encrypting history; retirement is crypto-shredding |
| One failure mode | A single `DecryptionError` with a fixed message; no oracle |

## 3. Context

```python
@dataclass(frozen=True)
class Context:
    tenant: str          # e.g. "org:st-marys"
    patient: str         # e.g. "Patient/8f3a…"
    resource_type: str   # e.g. "Condition"
    field_path: str      # e.g. "code.text", or "*" for whole-resource
    purpose: str = ""    # optional: "clinical", "research", "billing"
```

**Canonical encoding** (no JSON, no ambiguity):

```
canon(ctx) = 0x01
           || u16be(len(tenant))        || utf8(tenant)
           || u16be(len(patient))       || utf8(patient)
           || u16be(len(resource_type)) || utf8(resource_type)
           || u16be(len(field_path))    || utf8(field_path)
           || u16be(len(purpose))       || utf8(purpose)
```

Length-prefixing every field means `("ab","c")` and `("a","bc")` encode differently. Strings are NFC-normalised before encoding. Maximum field length 65,535 bytes. `patient` and `purpose` may be empty; the other three are required (§12).

**Rule the API enforces.** Context comes from the caller at *both* encrypt and decrypt. It is never read from the ciphertext, and the header never stores it. An application that stores context beside the ciphertext and reads it back has undone the binding; the documentation says so in the first paragraph.

## 4. Key hierarchy

```
 KEK  (in KMS, HSM, or a local file for dev)
  |    wraps
  v
 MK[v]  32-byte master data key, version v = 1, 2, 3 …
  |    HKDF-SHA256(ikm = MK[v], salt = none, info = "cpdpm/key" || suite || canon(ctx))
  v
 K_ctx  32-byte per-context key
  |    AEAD(K_ctx, nonce, aad = header || canon(ctx), plaintext)
  v
 ciphertext
```

- **HKDF with empty salt** is acceptable because MK is uniformly random. If MK is password-derived, Argon2id output is used as ikm the same way.
- **Suite in the info string** guarantees an AES-GCM key and a ChaCha key for the same context are independent.
- **Why derive per context at all, if AAD already binds?** Two reasons. Nonce-reuse blast radius shrinks to a single context (G4 in the threat model). And a leaked derived key exposes one patient's one field, not the tenant.

**Nonce.** 96-bit random for AES-GCM, 192-bit random for XChaCha20-Poly1305. With a per-context key, the number of encryptions under one key is the write count of one field of one patient, realistically under 2^20, giving a GCM collision probability below 2^-56. Applications that expect more than 2^32 writes to a single context must use the XChaCha suite; the library warns on suite selection in the docs, not at run time (it cannot count).

## 5. Wire format

```
 offset  size  field
 0       4     magic  "CPDM"
 4       1     protocol version = 0x01
 5       1     suite: 0x01 AES-256-GCM, 0x02 XChaCha20-Poly1305
 6       4     key_version (u32be)
 10      1     nonce_len (12 or 24)
 11      n     nonce
 11+n    …     AEAD ciphertext || 16-byte tag
```

Header (bytes 0 through 11+n) is included in the associated data, so tampering with suite, key version or nonce is detected. For JSON stores the whole blob is base64url with a `cpdpm1:` prefix, so it is never mistaken for another scheme's base64 output.

## 6. Password-derived master keys

For deployments without a KMS, MK may be derived from a passphrase:

- **Argon2id**, memory 64 MiB, iterations 3, parallelism 1, 16-byte random salt, 32-byte output. Parameters are stored beside the wrapped key, never in the ciphertext.
- **PBKDF2-HMAC-SHA256**, 600,000 iterations, only for deployments migrating from PBKDF2-derived keys. Emits a deprecation warning.

## 7. Key commitment (decided: in)

AES-GCM does not commit to its key: an adversary can craft one ciphertext that decrypts validly under two keys. In password settings this enables partitioning-oracle attacks. Proposed mitigation, cheap and standard: prepend to the plaintext a 32-byte commitment `HKDF(MK[v], info="cpdpm/commit" || canon(ctx))` and verify it after decryption in constant time. Cost: 32 bytes per ciphertext, one extra HKDF. Decision: implemented and always on. It is cheap, standard (Albertini et al., "How to abuse and fix authenticated encryption without key commitment"), and removes a whole attack class from the discussion chapter.

## 8. Field-level FHIR encryption

- Caller supplies a **path allow-list** per resource type, e.g. `Condition: ["code.text", "note[*].text"]`, `Patient: ["name", "telecom", "address", "birthDate"]`.
- Each selected value is JSON-serialised, encrypted with `field_path` set to its canonical path (array indices collapsed to `[*]` so a note moving from index 0 to 1 does not break decryption while still binding the field kind), and replaced in place by the string `"cpdpm1:<base64url>"`.
- The list of encrypted paths is recorded in `meta.tag` with system `urn:cpdpm:encrypted-paths`, which is where FHIR permits implementation metadata. The resource stays schema-valid JSON; typed validators will complain about a string where a `CodeableConcept` was, and that is accepted for the thesis. A search-safe variant (leave `code.coding[*].code` clear, encrypt `code.text`) is a configuration, not a code change.
- Whole-resource mode uses `field_path = "*"`.
- **Manifest (structural integrity).** Per-field AEAD binds each value to its path but not the set of values, so field deletion and per-field replay would go unnoticed. Every encrypted resource therefore carries a manifest, `{"v":1,"paths":[…],"entries":[[path, sha256(ciphertext)],…],"clear":digest|null}`, encrypted under `field_path="_manifest"` and stored as a `meta.tag` with system `urn:cpdpm:manifest`. Decryption verifies the manifest before releasing any field; the encrypted-paths tags are informational only. With `bind_cleartext=True`, `clear` is the digest of the resource with encrypted values blanked and cpdpm tags removed, so edits to clear fields are also detected. Whole-document replay (manifest included) is not covered; see threat model §8.

### 8a. Streaming (`cpdpm.stream`)

For payloads too large to hold in memory: STREAM (Hoang, Reyhanitabar, Rogaway, Vizár 2015) over the same per-context AEAD. Header `CPDS ‖ 0x01 ‖ suite ‖ key_version ‖ chunk_size ‖ prefix_len ‖ prefix`; chunk *i* uses nonce `prefix ‖ u32be(i) ‖ last_flag` with the header and canonical context as associated data; the 32-byte commitment is prepended to chunk 0. Truncation, extension, chunk drop, swap and duplication all fail authentication. Output is released per verified chunk, so consumers discard on error.

## 9. Public API

```python
from cpdpm import Context, Keyring, encrypt, decrypt, DecryptionError

keyring = Keyring.from_kms(...)            # or Keyring.from_password(...), Keyring.generate()
ctx = Context(tenant="org:st-marys", patient="Patient/8f3a", resource_type="Condition", field_path="code.text")

blob = encrypt(keyring, ctx, b"Type 2 diabetes mellitus")
plain = decrypt(keyring, ctx, blob)          # raises DecryptionError on any failure

# FHIR
from cpdpm.fhir import encrypt_resource, decrypt_resource
enc = encrypt_resource(keyring, tenant, resource, paths=POLICY["Condition"])
```

Modules: `context.py`, `header.py`, `kdf.py`, `aead.py`, `keys.py`, `core.py`, `fhir.py`, `stream.py`, `errors.py`. Everything raises `DecryptionError` on the decrypt path, with no message beyond a fixed string.

## 10. Security argument (sketch for chapter 4)

Let AEAD be IND-CCA2 and INT-CTXT secure, and HKDF-SHA256 a PRF under uniformly random MK.

1. For distinct contexts c ≠ c′, `canon(c) ≠ canon(c′)` by injectivity of the length-prefixed encoding. Hence the HKDF info strings differ and K_c, K_c′ are computationally independent (PRF).
2. Confidentiality (G1) follows from AEAD confidentiality under each K_c; a multi-key hybrid over at most q contexts loses a factor q.
3. Integrity (G2) follows from INT-CTXT: any change to header, nonce or ciphertext is a forgery.
4. Context binding (G3): a ciphertext for c presented under c′ is decrypted with key K_c′ and aad′ ≠ aad. Success would be a forgery under K_c′ against a challenger who never encrypted under K_c′ with that aad. Bounded by the INT-CTXT advantage.
5. Compartmentalisation (G4): given K_c, recovering MK or K_c′ contradicts PRF security.

The reduction is routine; the chapter's value is stating it precisely for this encoding and then showing the empirical attack in chapter 5.

## 11. Test plan (week 3–6)

- Round-trip for both suites, all field sizes from 0 bytes to 1 MiB.
- Tamper: every byte of header, nonce, ciphertext, tag flipped → `DecryptionError`.
- Wrong context: each of the five fields changed individually → `DecryptionError`.
- Rotation: encrypt under key version 1, rotate to 2; version-1 blobs still decrypt, new blobs carry 2; retire 1 → version-1 blobs fail.
- Encoding injectivity: Hypothesis property that `canon(a) == canon(b)` implies `a == b`.
- Known-answer vectors checked in for both suites with fixed nonce (test-only hook).
- Foreign blob detection: a base64-JSON package from another scheme raises `DecryptionError`, never a decode exception.
- Constant-time: commitment comparison uses `hmac.compare_digest`.

## 12. Decisions

1. **Key commitment: in** (§7). Implemented.
2. **`patient` may be empty** for tenant-level resources such as `Organization` and `Practitioner`. The empty string is length-prefixed like any value, so absence is itself bound: a ciphertext for "no patient" fails under any patient. `tenant`, `resource_type` and `field_path` are required. Implemented in `cpdpm/context.py`.
3. **`purpose` stays in the context** as an optional field. Binding a record to a purpose means it cannot be read for another purpose without re-encryption; that is the intended behaviour for research extracts. Applications that do not want it leave it empty.
4. **XChaCha20-Poly1305 comes from libsodium via PyNaCl** as an optional extra (`cpdpm[xchacha]`), since `cryptography` does not expose it. Hand-implementing HChaCha20 was rejected: no new primitive code in this project.
5. **Argon2id comes from `argon2-cffi`** as an optional extra (`cpdpm[password]`). PBKDF2 at 600k iterations is always available as a migration path and warns.
6. **Context strings are NFC-normalised and reject `\0`, `\n`, `\r`**, so two visually identical identifiers cannot silently be two contexts, and log-injection through a context value is not possible.
7. **AES-256-GCM is the default suite for performance reasons as well as availability.** The evaluation found PyNaCl's bundled libsodium roughly 35x slower than OpenSSL's ChaCha20-Poly1305 on arm64 for the same bytes; XChaCha remains available for deployments that need the 192-bit nonce, and a `cryptography`-backed ChaCha20-Poly1305 (96-bit nonce) suite is a candidate for 0.2.
