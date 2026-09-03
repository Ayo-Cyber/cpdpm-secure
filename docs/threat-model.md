# Threat model

Status: draft 1 (September 2026). For supervisor review.
Companion: [design.md](design.md).

## 1. What is being protected

**Assets**

| Asset | Where it lives | Sensitivity |
|---|---|---|
| Protected health information (PHI) inside clinical records: identifiers, diagnoses, observations, notes | Application database, object storage, message queues, backups | Highest. Regulated under HIPAA (US), GDPR Article 9 (EU), and equivalents. |
| The mapping between a ciphertext and the patient, tenant, and field it belongs to | Database row keys, FHIR resource IDs, JSON paths | High. Corrupting this mapping is the attack this work is about. |
| Key material: key-encryption key (KEK), master data keys (MK), derived per-context keys | KMS or local key file; application memory at run time | Critical. Compromise of a MK exposes every record under it. |

**Not assets of this system.** Access control decisions, user authentication, and audit of who read what are handled by the surrounding application. This library makes those decisions enforceable at the ciphertext, it does not make them.

## 2. System model and trust boundaries

```
 clinician / app user
        |
 [ application host ]  <- trusted: holds MK in memory, runs cpdpm
        |         \
        |          \-- [ KMS ]  <- trusted for KEK; sees wrapped MKs only
        |
 [ database / object store ]  <- UNTRUSTED for integrity and confidentiality
        |
 [ backups, replicas, analytics copies ]  <- UNTRUSTED
```

The application host is the trust anchor. Everything below it in the diagram is assumed hostile: it may read, write, reorder, duplicate, or roll back any byte it stores.

## 3. Adversaries

| ID | Adversary | Capabilities | Goal |
|---|---|---|---|
| A1 | External attacker with a database dump | Read every ciphertext, header, and row key. Offline compute. Knows the scheme. | Recover PHI. |
| A2 | Insider with database write access (DBA, compromised service account, malicious migration) | Everything A1 can do, plus write: move a ciphertext from patient X's row to patient Y's row, from tenant P to tenant Q, from field `note` to field `diagnosis`; replay an old ciphertext over a new one; roll back a table. | Cause the application to decrypt and present the **wrong** patient's data as if it were the right one, without triggering any error. Also: reuse a ciphertext in a context it was never authorised for. |
| A3 | Cloud storage or backup operator | Read access to storage and backups over long periods. | Recover PHI, now or after a future key compromise. |
| A4 | Network attacker between application and storage | Observe, modify, inject traffic to the store. | Same as A2 but transient. |
| A5 | Attacker who obtains a *single* per-context derived key (for example via a debug log) | One derived key. | Decrypt records of *other* patients, tenants, or fields. |

**Explicitly out of scope**

- Compromise of the application host while MK is in memory. Nothing at the storage layer can defend that; it is the job of host hardening and HSM/KMS envelope design.
- Side channels beyond constant-time tag comparison. Timing of AES-GCM is delegated to the underlying library (OpenSSL via `cryptography`).
- Availability. An adversary who deletes the store denies service; the scheme only guarantees that whatever is returned is either correct or rejected.
- Metadata leakage: ciphertext length, existence of a record, write timestamps, which fields are encrypted. Length-hiding padding is a possible future option, not a goal here.
- Authorisation logic. Whether a clinician *should* read a record is decided by the application.

## 4. Security goals

| Goal | Statement | Adversaries addressed |
|---|---|---|
| G1 Confidentiality | An adversary with any number of ciphertexts and adaptive decryption queries on other ciphertexts learns nothing about a plaintext beyond its length. (IND-CCA2, from AEAD security.) | A1, A3, A4 |
| G2 Integrity | Any modification of a ciphertext, its header, or its nonce is detected and rejected before any plaintext is released. | A2, A4 |
| G3 Context binding | A ciphertext produced for context *c* (tenant, patient, resource type, field path, key version) fails to decrypt under any context *c′ ≠ c*. Substitution, replay across contexts, and field swapping are therefore detected. | **A2**, A4 |
| G3a Structural integrity (FHIR layer) | Within one resource, deleting, reordering, duplicating or individually replaying an encrypted field is detected via an encrypted manifest. Optionally, edits to clear fields are detected too. | **A2**, A4 |
| G4 Key compartmentalisation | Per-context keys are derived through a PRF from MK. Disclosure of one derived key does not help recover MK or any other derived key. | A5 |
| G5 Rotation | MKs are versioned. New records use the current version; old records remain decryptable; re-encryption can proceed lazily. A retired version can be destroyed to make its records unreadable (crypto-shredding). | A3 |
| G6 Failure without oracle | Every decryption failure raises one error type carrying no information about *which* check failed. | A1, A2 |

G3 and G3a are the contribution. G1, G2, G4, G5 and G6 are table stakes that shared-key encryption at rest often meets only partially (no binding, no rotation, ad hoc MAC keys).

## 5. The demonstrated attack

The evaluation chapter runs one concrete attack against three schemes.

**Setup.** Two patients, Alice and Bob, each with an encrypted `Condition` resource stored in a table keyed by patient ID and field.

**Attack (A2, record swap).** The adversary copies Bob's ciphertext into Alice's row. The application later reads Alice's row and decrypts under Alice's context.

| Scheme | Outcome |
|---|---|
| AES-256-CBC + HMAC, one shared key | Decrypts cleanly. Clinician sees Bob's condition under Alice's name. **Undetected.** |
| AES-256-GCM with random nonce, no associated data | Decrypts cleanly. **Undetected.** Confidentiality is perfect; binding is absent. |
| CPDPM (this design) | Rejected. The derived key and the associated data both differ. |

Variants also run: cross-tenant move, cross-field move (`note` to `diagnosis`), and replay of a stale ciphertext over a fresh one under a rotated key version.

## 6. Assumptions

1. `cryptography`'s AES-GCM and ChaCha20-Poly1305 are correct AEADs, and HKDF-SHA256 is a PRF.
2. The application supplies the correct context at decrypt time from an authenticated source (the row it is reading, the tenant of the authenticated user), not from the ciphertext itself. If the application trusts a context stored *beside* the ciphertext by the same adversary, G3 collapses. The API is shaped to make this mistake hard: context is a required argument to `decrypt`, and the header carries no context fields.
3. Nonces come from the OS CSPRNG. With 96-bit random GCM nonces under a *per-context* key, the number of encryptions under any single key is bounded by records in one context, which keeps collision probability negligible. See design §4.
4. MK has at least 256 bits of entropy from a CSPRNG or is derived from a password by Argon2id with parameters no weaker than the defaults in design §6.

## 7. Relationship to HIPAA

This is not a compliance claim. The technical safeguards in 45 CFR §164.312 that the design speaks to are encryption of ePHI at rest (§164.312(a)(2)(iv)) and integrity controls (§164.312(c)(1)). A control mapping document is product work for 2027 and is not part of the thesis.

## 8. Open questions for supervisor discussion

- Key commitment is in scope and implemented (design §7); confirm the supervisor is content with the padding-fix argument rather than a committing AEAD mode.
- Replay *within* the same context. Per-field replay inside a resource is now detected by the manifest (G3a). Replay of a *whole* resource, manifest included, by an older version of itself is not: preventing it needs a monotonic version in the context, which is application state. Documented as a limitation.
