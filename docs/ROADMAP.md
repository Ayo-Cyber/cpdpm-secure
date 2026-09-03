# Sixteen Weeks to Preprint

Plan from Wednesday 2 September to Friday 25 December 2026. The thesis paper is the spine; the Substack post and the product alpha hang off it, so each week's code and writing counts three times.

Assumed effort: 15–20 hours per week, one person. Monday-start weeks; week 0 is the four days from 2 September.

## Status, 3 September 2026

Done, in merged and open pull requests on `github.com/Ayo-Cyber/cpdpm-secure`:

- Foundations: threat model, design doc, venue shortlist, CI, coverage gate, release workflow.
- Chapter 3 analysis of the pre-transform pattern: scripts, pinned results, fig 3-1 and 3-2.
- Construction: `cpdpm/` core, FHIR layer with manifest, streaming; 120 tests, 98% coverage, fuzzing, known-answer vectors.
- Evaluation: attack matrix, full pyperf run, figs 5-0 to 5-2, table 5-1; x86-64 benchmark workflow (run it after merge).
- Explanatory diagrams for chapters 4 and 5, self red-team review, SECURITY and CHANGELOG.

Roughly six weeks of slack now sit in the calendar. Spend it on the reading (weeks 1–5, unchanged), on the writing, and on an external red-team read. The writing is yours; the evidence, figures and outline are ready for it.

Still open before submission: repeat the pyperf run on x86-64, the critiqued-genre table for chapter 2, an external review.

## Under the tree on 25 December

1. **Paper submitted** to the chosen venue, with the arXiv preprint live and citable.
2. **Thesis chapters 1–5 drafted** (introduction, background and related work, analysis of the pre-transform pattern, construction, evaluation), one full supervisor pass done.
3. **Substack post published**, on why binding beats layering for clinical data, linking the preprint.
4. **cpdpm 0.1.0 alpha on PyPI**: the construction from chapter 4 as an installable package, public repo, one-command reproduction of every figure.

## Timeline

| Week | Dates | Block | Milestone |
|---|---|---|---|
| 0–1 | 2 Sep – 13 Sep | Foundations: repo restructure, threat model, design doc, supervisor kickoff, client correction note, arXiv endorser | Supervisor kickoff |
| 1–5 | 7 Sep – 11 Oct | Reading (background, ~4 h/week): hybrid-EHR papers, AEAD, context binding | 40-entry bibliography |
| 2–3 | 14 Sep – 27 Sep | Analysis of the pre-transform pattern: keyspace, diffusion, cost | Chapter 3 draft |
| 3–6 | 21 Sep – 18 Oct | Construction (core): AEAD, HKDF, associated data, versioned header, envelope keys, FHIR fields, tests | tests green; chapter 4 draft |
| 6–8 | 12 Oct – 1 Nov | Evaluation: record-swap attack demo; benchmarks vs AES-GCM, Fernet, Tink | `make figures`; chapter 5 draft |
| 8–11 | 26 Oct – 22 Nov | Writing: chapters 1, 2, 6; cut the paper from the thesis | **Draft 1 to supervisor by Sun 15 Nov** |
| 12–13 | 23 Nov – 6 Dec | Review: supervisor comments, red-team read, Docker reproducibility package, Substack draft | Camera-ready paper; post draft |
| 14–15 | 7 Dec – 20 Dec | Submit (Fri 11 Dec), arXiv (Mon 14 Dec), Substack (16–18 Dec), PyPI 0.1.0a1 (Fri 18 Dec) | Submission, arXiv ID, post URL, `pip install cpdpm` |
| 16 | 21 Dec – 25 Dec | Buffer. Deliberately empty. | 25 Dec |

## Phase detail

### Week 0–1: Foundations (~25 h)

- Structure: `cpdpm/` for the package, `paper/` for experiments and figures, `docs/` for the design record.
- Write `docs/threat-model.md`: assets, adversaries (external attacker with ciphertext, insider with database write access, cloud operator), the demonstrated attack (ciphertext substitution across patients and tenants), out of scope.
- Design document: AEAD choice, HKDF context derivation, associated-data layout, versioned header, envelope keys.
- Supervisor kickoff: agree framing (analysis then construction), venue shortlist, and book review slots for mid-November and early December.
- Request an arXiv cs.CR endorser if needed.

Done when: fresh clone passes all tests with one command; threat model and design doc reviewed; venue shortlist has three names and deadlines.

### Week 1–5: Reading (~20 h, in the background)

- The genre being critiqued: "novel hybrid encryption for EHR" papers adding a substitution, chaotic map, or polynomial layer before AES. Collect a dozen; table their claims and evidence.
- The primitives: AEAD definitions, AES-GCM and ChaCha20-Poly1305, HKDF, nonce-reuse and key-commitment literature.
- Context binding in practice: associated data, envelope encryption in cloud KMS, field-level encryption for FHIR, ciphertext substitution attacks on databases.

Done when: annotated bibliography of ~40 entries; one-page table of critiqued papers.

### Week 2–3: Analysis of the pre-transform pattern (~35 h)

- Implement the pattern from its published descriptions and show, exhaustively, its keyspace (2^15 for a per-byte affine map) and its lack of diffusion.
- Short reduction showing a public or transmitted bijection on plaintext neither strengthens nor weakens the cipher behind it.
- Measure its cost fairly, KDF counted on both sides, and decompose where the time goes.

Done when: chapter 3 draft (~3,000 words), two figures and one table generated by `paper/analysis/` scripts.

### Week 3–6: Construction, the core (~65 h)

- AES-256-GCM default, XChaCha20-Poly1305 as second suite.
- HKDF-SHA256 per-context subkeys from a master key.
- Associated data: tenant, patient ID, resource type, field path, key version.
- Versioned binary header; rotation without re-encrypting history.
- Envelope keys; local KEK backend now, KMS interface stubbed.
- Field-level encryption of FHIR resources with a path allow-list.
- Argon2id for password-derived keys; PBKDF2 only as compatibility path.
- Hypothesis property tests; known-answer vectors; constant-time comparisons; no exception text leaks.
- Written security argument: reduction to AEAD security.

Done when: round-trip, tamper, wrong-context and rotation tests green in CI; chapter 4 draft.

### Week 6–8: Evaluation (~40 h)

- Record-swap attack: encrypt two patients' records with shared-key AES-CBC+HMAC, per-tenant AES-GCM without associated data, and CPDPM. Swap ciphertexts at the storage layer. The baselines decrypt into the wrong patient; CPDPM rejects. This is the paper's central figure.
- Performance: CPDPM vs AES-GCM, Fernet, Tink on the 5,110-row stroke dataset and synthetic FHIR bundles at 1, 10, 100, 1,000 resources. pyperf, medians and intervals, pinned versions.
- Chapter 5 written from the scripts; every number comes from emitted JSON.

Done when: `make figures` regenerates every plot; chapter 5 draft.

### Week 8–11: Writing (~55 h)

- Chapter 1 (introduction, contributions), chapter 2 (background, related work), chapter 6 (discussion, limitations).
- Cut the paper from the thesis: 8–12 pages. Analysis as motivation; construction and attack demo carry the weight.
- Draft 1 to supervisor by Sunday 15 November. This date protects Christmas.

### Week 12–13: Review and reproducibility (~35 h)

- Work supervisor comments; second review slot week of 30 November.
- Red-team read by one cryptographer; fix or narrow claims.
- Dockerfile, pinned lockfile, `make all` from a clean container to every figure.
- Draft the Substack post (1,500–2,000 words).

### Week 14–15: Submit, preprint, publish, package (~30 h)

- Fri 11 Dec: submit. If the venue is a conference, its deadline replaces this date and anchors the plan.
- Mon 14 Dec: arXiv cs.CR preprint.
- Wed 16 – Fri 18 Dec: publish the Substack post with the arXiv link.
- Fri 18 Dec: tag and publish `cpdpm 0.1.0a1` to PyPI from CI. README says alpha, unreviewed, points to the paper.

### Week 16: Buffer

Deliberately empty.

## Effort budget

| Block | Hours |
|---|---|
| Foundations | 25 |
| Reading | 20 |
| Analysis of the pattern | 35 |
| Construction | 65 |
| Evaluation | 40 |
| Writing | 55 |
| Review and reproducibility | 35 |
| Submit, publish, package | 30 |
| **Total** | **~305 (≈ 18 h/week)** |

At 10 hours per week the paper and post still land; move the PyPI alpha to January and drop Tink from the benchmark.

## Risks

| Risk | Likelihood | Move |
|---|---|---|
| Supervisor turnaround slower than two weeks | High | Book both slots in week 0; send chapters as they finish. |
| Conference deadline before 11 Dec | Medium | Decide venue in week 0; its date becomes the anchor. |
| arXiv endorsement delay | Medium | Request in week 0; fallback: supervisor posts as co-author. |
| Tink Python package install trouble | Medium | Substitute PyNaCl (libsodium). |
| Scope creep into product during construction | High | Product backlog in a separate file; anything not needed for the attack demo or benchmark waits until January. |
| Thesis format differs from paper | Low | Get the template in week 0; write chapters into it. |

## After Christmas: product, January–March 2027

Pydantic field annotations, SQLAlchemy column type, FastAPI service in Docker, AWS and GCP KMS backends, hash-chained audit log, HIPAA Safe Harbor de-identification, HIPAA control mapping. Then a third-party code review funded by the first pilot customer or a small grant.
