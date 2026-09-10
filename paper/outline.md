# Outline: thesis and paper

Working title: **Context-bound authenticated encryption for clinical records**

Every claim below names the script and result file it comes from. If a number is not in a JSON under `paper/*/results/`, it does not go in the text.

## Thesis chapters (target ~12,000 words) → paper sections (8–12 pages)

| Ch. | Thesis chapter | Paper section | Evidence |
|---|---|---|---|
| 1 | Introduction and contributions | §1 Introduction | – |
| 2 | Background and related work | §2 Background | reading table (week 1–5) |
| 3 | Why a pre-transform layer is not a security layer | §3 Motivation | `paper/analysis/results/*.json`, fig 3-1, 3-2 |
| 4 | Construction: context-bound AEAD | §4 Design | `docs/design.md`, figs 4-0 to 4-3, table 4-1, `tests/vectors/kat.json` |
| 5 | Evaluation | §5 Evaluation | `paper/evaluation/results/*.json`, fig 5-0, table 5-1, fig 5-1, 5-2 |
| 6 | Discussion and limitations | §6 Discussion | `docs/red-team-2026-09.md` |
| 7 | Conclusion | §7 Conclusion | – |

## Chapter 1: Introduction

- The problem: encryption at rest for clinical records is usually specified as "AES-256" and evaluated by speed. Binding a ciphertext to *whose* record it is, in *which* tenant, in *which* field, is rarely stated as a requirement, so the insider-with-write-access threat goes unaddressed.
- The genre: a body of "hybrid encryption for EHR" papers adds a reversible byte transform in front of AES and claims added security. Chapter 3 shows what such a layer can and cannot add; chapter 4 spends the same engineering effort on binding instead.
- Contributions: (C1) a precise statement, with exhaustive checks, of what a byte-level pre-transform layer contributes (nothing if its key travels, at most 15 bits if it does not, and no diffusion); (C2) a context-bound AEAD construction with an injective context encoding, per-context HKDF keys, key commitment, versioned rotation, a structural-integrity manifest for FHIR resources and a streaming mode, reduced to standard AEAD security; (C3) an empirical demonstration that the construction stops ciphertext substitution where shared-key AES does not, at a cost that is measurable but small against a raw AES-GCM floor; (C4) an open, reproducible artifact.

## Chapter 3: Why a pre-transform layer is not a security layer

The chapter analyses the *pattern*, implemented from its published description, not any deployed system.

| Claim | Source |
|---|---|
| A per-byte affine map has exactly 2^15 distinct transforms, whatever parameters its description carries | `pre_transform.json → effective_keyspace` |
| One flipped input byte changes exactly one output byte: no diffusion | `pre_transform.json → diffusion` |
| The composite `Enc(T_k(m))` is exactly as secure as `Enc` when `T_k` is public or transmitted; secrecy adds at most 15 bits | `pre_transform.json → security_argument` |
| Cost, KDF counted equally: ~1.0x at 1–8 KB, 1.15x at 64 KB, 2.1x at 512 KB, all of it the pure-Python loop | `fair_benchmark.json`, fig 3-1, fig 3-2 |

Argument paragraph: a public bijection applied before an IND-CPA-secure cipher yields a scheme exactly as secure as the cipher. Cite the standard hybrid argument; no new theorem is needed. The point of the chapter is to redirect effort: the same engineering budget buys binding, which changes what an adversary can do.

## Chapter 4: Construction

Sections follow `docs/design.md`: context and canonical encoding (§3, injectivity by length-prefixing, Hypothesis test as evidence, fig 4-1); key hierarchy (§4, fig 4-1); wire format (§5, fig 4-2, table 4-1); key commitment (§7, cite Albertini et al. 2022); FHIR field-level mapping and the manifest (§8, fig 4-3); streaming (§8a, fig 4-2 B); security argument (§10). Fig 4-0 opens the chapter. Known-answer vectors in `tests/vectors/kat.json` are the reference for implementers.

## Chapter 5: Evaluation

**Experiment 1, record swap** (`record_swap.py` → `record_swap.json`, fig 5-0, table 5-1). Three schemes, four manipulations.

| Scheme | Patient swap | Tenant move | Field move | Stale replay |
|---|---|---|---|---|
| AES-256-CBC + HMAC, one shared key | accepted | accepted | accepted | accepted |
| AES-256-GCM, key per tenant, no AAD | accepted | rejected | accepted | accepted |
| CPDPM | rejected | rejected | rejected | rejected |

Honest note for the text: per-tenant keys already stop the tenant move; CPDPM's contribution is the other three columns. Also report the FHIR-layer swap and the manifest's structural detections.

**Experiment 2, cost** (`benchmark.py` → `summarize.py` → `benchmark.json`, fig 5-1, 5-2). Median latency per op, payloads of 1/10/100/1000 observations (726 B to 670 KB), schemes aes-gcm, fernet, tink, cpdpm-gcm, cpdpm-xchacha, plus the field-level path at n=1.

Full pyperf run (2 Sep 2026, macOS arm64, Python 3.14, 8 processes × 3 values, warmup 1). A prior `--fast` run gave the same medians within 3%, so the numbers are stable on this machine; repeat on x86-64 before submission:

| Payload | aes-gcm encrypt | cpdpm-gcm encrypt | ratio | fernet ratio | tink ratio |
|---|---|---|---|---|---|
| 1 obs, 726 B | 2.6 µs | 14.8 µs | 5.6x | 2.9x | 0.33x |
| 10 obs, 6.6 KB | 3.5 µs | 16.0 µs | 4.5x | 6.2x | 0.52x |
| 100 obs, 66 KB | 15.0 µs | 26.3 µs | 1.8x | 10.9x | 0.91x |
| 1000 obs, 654 KB | 96.9 µs | 113.1 µs | 1.17x | 16.2x | 1.12x |

Reading: cpdpm-gcm carries a fixed cost of about 12 µs per operation (two HKDF-SHA256 derivations, a 32-byte commitment, header and context encoding), then tracks raw AES-GCM. At one small record it is 5x the raw floor and still under 15 µs; Fernet, the most common Python "just encrypt it" choice, is slower than CPDPM from 10 observations up. The field-level path (three fields, one observation) costs 110 µs, about 37 µs per field: per-field HKDF is the price of per-field binding. Tink beats raw `cryptography` at small sizes because it caches the cipher object; the raw baseline constructs `AESGCM(key)` per call, which is how application code usually does it.

**XChaCha caveat, must be stated.** cpdpm-xchacha is 110x the floor at 654 KB. A direct check shows PyNaCl's bundled libsodium encrypts 670 KB in 10.1 ms while `cryptography`'s ChaCha20-Poly1305 does it in 0.29 ms and AES-GCM in 0.07 ms on the same machine. The gap is the PyNaCl wheel's libsodium build on arm64 (no SIMD path), not the design. Report it as an implementation artifact, keep AES-GCM as the default suite, and re-measure on x86-64 in the final run.

## Chapter 6: Discussion and limitations

- Replay of a *whole* resource, manifest included, by an older version of itself is not prevented; needs application-side versioning. Per-field replay within a resource is.
- Metadata leakage: lengths, existence, which fields are encrypted.
- The context must come from an authenticated source; the API shape helps but cannot force it.
- No formal verification; the reduction is a sketch; the red-team review is a self-review.
- Threat model excludes host compromise.
- What this says about the hybrid-EHR genre and how reviewers might screen for it.
- Unicode normalisation can differ across Unicode versions for newly assigned characters.

## Figures and tables

| ID | Content | Generator |
|---|---|---|
| fig 3-1 | Pipeline with vs without a pre-transform layer, encrypt/decrypt, 1 KB–512 KB | `paper/analysis/make_figures.py` |
| fig 3-2 | Where a pre-transform pipeline spends its time | `paper/analysis/make_figures.py` |
| table 5-1 | Attack matrix | `paper/evaluation/make_figures.py` |
| fig 5-1 | Latency per scheme and payload size | `paper/evaluation/make_figures.py` |
| fig 5-2 | Overhead over raw AES-GCM vs payload size | `paper/evaluation/make_figures.py` |
| fig 4-0 | Baseline shared-key encryption vs context-bound encryption | `paper/diagrams/fig4-0_baseline_vs_cpdpm.svg` |
| fig 4-1 | Key hierarchy and encryption path | `paper/diagrams/fig4-1_key_hierarchy.svg` |
| fig 4-2 | Wire formats: one-shot blob and stream | `paper/diagrams/fig4-2_wire_format.svg` |
| fig 4-3 | Field-level encryption with the manifest | `paper/diagrams/fig4-3_fhir_manifest.svg` |
| fig 4-4 | System architecture and trust boundary | `paper/diagrams/fig4-4_architecture.svg` |
| fig 5-0 | The record-swap attack, three schemes | `paper/diagrams/fig5-0_record_swap.svg` |
| table 4-1 | Bytes of overhead per ciphertext, measured | `paper/construction/overhead_table.py` |

## Reproduction

`docker build -t cpdpm-paper . && docker run --rm cpdpm-paper` runs the gate, both experiment sets, and regenerates every figure. Pinned results are committed under `paper/*/results/`.
