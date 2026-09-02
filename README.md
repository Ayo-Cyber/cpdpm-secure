# cpdpm

Context-bound authenticated encryption for clinical records.

A record field is encrypted with a standard AEAD (AES-256-GCM or XChaCha20-Poly1305) under a key derived from a versioned master key and the record's **context**: tenant, patient, resource type, field path. The same context is bound as associated data. Moving a ciphertext to another patient, tenant or field makes it undecryptable, so an insider with database write access cannot make the application show the wrong patient's data as if it were the right one.

Nothing is invented at the primitive level. The contribution is the binding discipline, its encoding, the key hierarchy, and the evidence that it stops a concrete attack that plain AES does not.

**Status: pre-alpha.** The protocol v2 core (context binding, key hierarchy, both suites, rotation, key commitment) and the FHIR field-level layer are implemented and tested; the evaluation is next. Unreviewed. Do not use for real data. See the [roadmap](docs/ROADMAP.md).

## Repository

| Path | Purpose |
|---|---|
| [`cpdpm/`](cpdpm/) | The library (protocol v2): `context`, `header`, `kdf`, `aead`, `keys`, `core`, `fhir` |
| [`docs/threat-model.md`](docs/threat-model.md) | Assets, adversaries, goals, and the attack the evaluation demonstrates |
| [`docs/design-v2.md`](docs/design-v2.md) | Context encoding, key hierarchy, wire format, API, security argument, test plan |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | Sixteen-week plan to paper submission, preprint, and 0.1.0 alpha |
| [`paper/`](paper/) | Reproducible experiments and figures |
| [`legacy/`](legacy/) | CPDPM v1 as shipped, frozen. Object of study for the analysis chapter. |
| [`data/`](data/) | Stroke prediction dataset used as realistic record content |

## Develop

```bash
make setup      # fresh .venv with the package and dev tools
make test       # the gate: must pass on a fresh clone
make lint typecheck
```

Legacy v1 has its own instructions in [`legacy/README.md`](legacy/README.md).

## About v1

The first version of this project, delivered to a client in 2025, wrapped AES-256-CBC in a "polynomial transformation" layer. Analysis showed that layer to be a public per-byte affine map contributing no security, that the "contextual" key derivation did not function, and that two of the reported measurements were artifacts. That analysis is chapter 3 of the thesis and the motivation for v2. The code is preserved unchanged in `legacy/`.

## License

MIT. See [LICENSE](LICENSE).
