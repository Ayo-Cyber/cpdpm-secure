# cpdpm

Context-bound authenticated encryption for clinical records.

A record field is encrypted with a standard AEAD (AES-256-GCM or XChaCha20-Poly1305) under a key derived from a versioned master key and the record's **context**: tenant, patient, resource type, field path. The same context is bound as associated data. Moving a ciphertext to another patient, tenant or field makes it undecryptable, so an insider with database write access cannot make the application show the wrong patient's data as if it were the right one.

Nothing is invented at the primitive level. The contribution is the binding discipline, its encoding, the key hierarchy, key commitment, versioned rotation, a manifest that binds the set of encrypted fields in a FHIR resource, and the evidence that all of this stops a concrete attack that plain AES does not.

**Status: pre-alpha.** Protocol version 1 is implemented and tested, including field-level FHIR encryption and a streaming mode for large payloads. Unreviewed. Do not use for real data. See the [roadmap](docs/ROADMAP.md).

## Repository

| Path | Purpose |
|---|---|
| [`cpdpm/`](cpdpm/) | The library: `context`, `header`, `kdf`, `aead`, `keys`, `core`, `fhir`, `stream` |
| [`docs/threat-model.md`](docs/threat-model.md) | Assets, adversaries, goals, and the attack the evaluation demonstrates |
| [`docs/design.md`](docs/design.md) | Context encoding, key hierarchy, wire format, API, security argument, test plan |
| [`docs/red-team-2026-09.md`](docs/red-team-2026-09.md) | Self-review findings, fixes, and what is left as a limitation |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | Sixteen-week plan to paper submission, preprint, and 0.1.0 alpha |
| [`paper/`](paper/) | Reproducible experiments, diagrams and figures |
| [`data/`](data/) | Stroke prediction dataset used as realistic record content |

## Use

```python
from cpdpm import Context, Keyring, encrypt, decrypt

keyring = Keyring.generate()
ctx = Context(tenant="org:st-marys", patient="Patient/8f3a",
              resource_type="Condition", field_path="code.text")

blob = encrypt(keyring, ctx, b"Type 2 diabetes mellitus")
assert decrypt(keyring, ctx, blob) == b"Type 2 diabetes mellitus"
```

The context is supplied by the caller at both encrypt and decrypt time, from an authenticated source such as the row being read. It is never stored with the ciphertext. Field-level FHIR encryption lives in `cpdpm.fhir`, streaming in `cpdpm.stream`.

## Develop

```bash
make setup      # fresh .venv with the package and dev tools
make test       # the gate: must pass on a fresh clone
make lint typecheck coverage
```

## Reproduce the paper

```bash
make all                       # gate, chapter 3 analysis, chapter 5 evaluation, all figures
docker build -t cpdpm-paper . && docker run --rm cpdpm-paper   # same, from a clean container
```

Results land in `paper/*/results/*.json`; figures and tables in `paper/figures/`. The map from claims to result files is [`paper/outline.md`](paper/outline.md).

## License

MIT. See [LICENSE](LICENSE).
