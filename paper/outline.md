# Outline: thesis and paper

Working title: **Context-bound authenticated encryption for clinical records: a cryptanalytic case study and a construction**

Every claim below names the script and result file it comes from. If a number is not in a JSON under `paper/*/results/`, it does not go in the text.

## Thesis chapters (target ~12,000 words) → paper sections (8–12 pages)

| Ch. | Thesis chapter | Paper section | Evidence |
|---|---|---|---|
| 1 | Introduction and contributions | §1 Introduction | – |
| 2 | Background and related work | §2 Background | reading table (week 1–5) |
| 3 | Analysis of CPDPM v1 | §3 Case study | `paper/analysis/results/*.json`, fig 3-1, 3-2 |
| 4 | Construction: context-bound AEAD | §4 Design | `docs/design-v2.md`, `tests/vectors/v2_kat.json` |
| 5 | Evaluation | §5 Evaluation | `paper/evaluation/results/*.json`, table 5-1, fig 5-1, 5-2 |
| 6 | Discussion and limitations | §6 Discussion | – |
| 7 | Conclusion | §7 Conclusion | – |

## Chapter 1: Introduction

- The problem: encryption at rest for clinical records is usually specified as "AES-256" and evaluated by speed. Binding a ciphertext to *whose* record it is, in *which* tenant, in *which* field, is rarely stated as a requirement, so the insider-with-write-access threat goes unaddressed.
- The genre: "novel hybrid encryption for EHR" papers layer a reversible transform in front of AES and claim added security. We shipped one. We analyse it.
- Contributions: (C1) a rigorous analysis showing a representative pre-transform layer contributes zero bits and that two of its reported measurements were artifacts; (C2) a context-bound AEAD construction with an injective context encoding, per-context HKDF keys, key commitment, and versioned rotation, reduced to standard AEAD security; (C3) an empirical demonstration that the construction stops ciphertext substitution where v1 and plain AES-GCM do not, at a cost that is measurable but small against a raw AES-GCM floor; (C4) an open, reproducible artifact.

## Chapter 3: Analysis of CPDPM v1

| Claim | Source |
|---|---|
| The transform is `T(x,i) = (a·x + b + i + 1) mod 256`; identity holds for all 65,536 (x, i) pairs | `affine_map.json → affine_identity` |
| Prime modulus, degree, exponents, coefficients c2.. have no effect on output | `affine_map.json → unused_key_fields` |
| 32,768 = 2^15 distinct transforms over all keys | `affine_map.json → effective_keyspace` |
| The transform key is shipped in the clear inside the ciphertext package | `affine_map.json → key_in_package` |
| One flipped input byte changes exactly one output byte (no diffusion) | `affine_map.json → diffusion` |
| "Context" keys are not deterministic: 200 distinct keys for one context | `context_key.json → same_context_many_times` |
| Two v1 tests fail on exactly this | `context_key.json → legacy_test_suite` |
| In the client build coefficients are constants 7, 11, 13; transform is key-independent | `client_build.json → keyless_transform` |
| HMAC key is the AES key (client build) | `client_build.json → source_facts.hmac_uses_aes_key` |
| Security-score chart is hard-coded `[85, 95, 90]` | `client_build.json → source_facts.hardcoded_security_scores` |
| Reported 2x overhead is a parity artifact: AES decrypt timed at 0.004 ms vs 21.8 ms | `client_build.json → client_benchmark_as_reported` |
| Fair cost: 1.00x at 1 KB, 3.7x encrypt / 10.6x decrypt at 512 KB, all pure-Python loop | `fair_benchmark.json`, fig 3-1, fig 3-2 |

Argument paragraph: a public bijection applied before an IND-CPA-secure cipher yields a scheme exactly as secure as the cipher (the bijection is a public pre-processing step any adversary can undo or apply). Cite the standard hybrid argument; no new theorem is needed.

## Chapter 4: Construction

Sections follow `docs/design-v2.md`: context and canonical encoding (§3, injectivity proof by length-prefixing, Hypothesis test as evidence); key hierarchy (§4); wire format (§5); key commitment (§7, cite Albertini et al. 2022); FHIR field-level mapping (§8); security argument (§10). Known-answer vectors in `tests/vectors/v2_kat.json` are the reference for implementers.

## Chapter 5: Evaluation

**Experiment 1, record swap** (`record_swap.py` → `record_swap.json`, table 5-1). Three schemes, four manipulations. Expected table:

| Scheme | Patient swap | Tenant move | Field move | Stale replay |
|---|---|---|---|---|
| v1 (shipped) | accepted | accepted | accepted | accepted |
| AES-256-GCM, key per tenant, no AAD | accepted | rejected | accepted | accepted |
| CPDPM v2 | rejected | rejected | rejected | rejected |

Honest note for the text: per-tenant keys already stop the tenant move; v2's contribution is the other three columns. Also report the FHIR-layer swap.

**Experiment 2, cost** (`benchmark.py` → `summarize.py` → `benchmark.json`, fig 5-1, 5-2). Median latency per op, payloads of 1/10/100/1000 observations (726 B to 670 KB), schemes aes-gcm, fernet, tink, v2-gcm, v2-xchacha, plus the field-level path at n=1. Report the v2/aes-gcm ratio at each size and where the fixed cost (two HKDF calls, 32-byte commitment) stops mattering.

## Chapter 6: Discussion and limitations

- Replay *within* a context (old Alice over new Alice) is not prevented; needs application-side versioning. State plainly.
- Metadata leakage: lengths, existence, which fields are encrypted.
- The context must come from an authenticated source; the API shape helps but cannot force it.
- No formal verification; the reduction is a sketch; no third-party review yet.
- Threat model excludes host compromise.
- What this says about the hybrid-EHR genre and how reviewers might screen for it.

## Figures and tables

| ID | Content | Generator |
|---|---|---|
| fig 3-1 | v1 vs transform-free baseline, encrypt/decrypt, 1 KB–512 KB | `paper/analysis/make_figures.py` |
| fig 3-2 | Where v1 encryption time goes | `paper/analysis/make_figures.py` |
| table 5-1 | Attack matrix | `paper/evaluation/make_figures.py` |
| fig 5-1 | Latency per scheme and payload size | `paper/evaluation/make_figures.py` |
| fig 5-2 | Overhead over raw AES-GCM vs payload size | `paper/evaluation/make_figures.py` |

## Reproduction

`docker build -t cpdpm-paper . && docker run --rm cpdpm-paper` runs the gate, both experiment sets, and regenerates every figure. Pinned results are committed under `paper/*/results/`.
