# Bibliography seed

Starting points for the week 1–5 reading. These are real, well-known references, listed from memory; **verify every entry against the publisher's page before citing** and fill in pages and DOIs. The critiqued-genre pile (hybrid pre-transform EHR papers) is deliberately empty here: those must be found and read by you, and the table of their claims is part of the thesis work.

## Primitives the construction stands on

- Rogaway, P. "Authenticated-Encryption with Associated-Data." ACM CCS 2002. The AEAD notion and why associated data exists.
- McGrew, D., Viega, J. "The Galois/Counter Mode of Operation (GCM)." NIST SP 800-38D (Dworkin, 2007) is the normative spec.
- Nir, Y., Langley, A. "ChaCha20 and Poly1305 for IETF Protocols." RFC 8439, 2018.
- Arciszewski, S. "XChaCha: eXtended-nonce ChaCha and AEAD_XChaCha20_Poly1305." IRTF CFRG draft (draft-irtf-cfrg-xchacha). Never became an RFC; cite as an Internet-Draft and libsodium's documentation.
- Krawczyk, H., Eronen, P. "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)." RFC 5869, 2010. Krawczyk's CRYPTO 2010 paper "Cryptographic Extraction and Key Derivation: The HKDF Scheme" for the proof.
- McGrew, D. "An Interface and Algorithms for Authenticated Encryption." RFC 5116, 2008.
- Biryukov, A., Dinu, D., Khovratovich, D., Josefsson, S. "Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications." RFC 9106, 2021.
- Bellare, M., Namprempre, C. "Authenticated Encryption: Relations among Notions and Analysis of the Generic Composition Paradigm." ASIACRYPT 2000 / J. Cryptology 2008. For the encrypt-then-MAC argument about v1's construction.

## Key commitment and the attack class it closes

- Albertini, A., Duong, T., Gueron, S., Kölbl, S., Luykx, A., Schmieg, S. "How to Abuse and Fix Authenticated Encryption Without Key Commitment." USENIX Security 2022.
- Len, J., Grubbs, P., Ristenpart, T. "Partitioning Oracle Attacks." USENIX Security 2021.
- Grubbs, P., Lu, J., Ristenpart, T. "Message Franking via Committing Authenticated Encryption." CRYPTO 2017.
- Bellare, M., Hoang, V. T. "Efficient Schemes for Committing Authenticated Encryption." EUROCRYPT 2022.

## Context binding, envelope encryption, and databases

- Google Tink documentation: AEAD primitive and the associated-data guidance ("bind ciphertext to its context"). Cite the developers.google.com/tink pages with access date.
- AWS Key Management Service Developer Guide: "Encryption context." The industry-practice reference for binding key use to context.
- Popa, R. A., Redfield, C. M. S., Zeldovich, N., Balakrishnan, H. "CryptDB: Protecting Confidentiality with Encrypted Query Processing." SOSP 2011. For the database-adversary model and what encrypted storage does and does not protect.
- Grubbs, P., Ristenpart, T., Shmatikov, V. "Why Your Encrypted Database Is Not Secure." HotOS 2017. Snapshot versus persistent adversaries; the insider-with-write model.

## Standards and regulation

- HL7 FHIR R4 (and R5) specification, especially `Resource.meta.tag` and the JSON representation. Cite hl7.org/fhir with version.
- 45 CFR §164.312 (HIPAA Security Rule, technical safeguards): (a)(2)(iv) encryption and decryption; (c)(1) integrity.
- Regulation (EU) 2016/679 (GDPR), Article 9 (special categories, including health data) and Article 32 (security of processing).
- NIST SP 800-57 Part 1 Rev. 5, "Recommendation for Key Management." For rotation and crypto-period vocabulary.

## Tooling cited in the evaluation

- `cryptography` (pyca) documentation for AESGCM, ChaCha20Poly1305, Fernet, HKDF, PBKDF2HMAC.
- Fernet specification (github.com/fernet/spec).
- PyNaCl and libsodium documentation for `crypto_aead_xchacha20poly1305_ietf`.
- pyperf documentation (Stinner) for the benchmarking method.
- Hypothesis (MacIver et al.) for property-based testing; cite the JOSS paper "Hypothesis: A new approach to property-based testing" (2019).
- Kaggle "Stroke Prediction Dataset" (fedesoriano). Public dataset, no direct identifiers; cite with access date and licence.

## The genre under critique (to be filled by you)

Collect a dozen "novel hybrid / polynomial / chaotic-map + AES encryption for EHR" papers from IEEE Access, Journal of Medical Systems, and similar. For each record: venue, year, the pre-transform used, the security claim made, the evidence offered (usually entropy or histogram plots and a speed table), and whether the transform key is public or secret in the described system. That table is chapter 2's contribution and the motivation for chapter 3.
