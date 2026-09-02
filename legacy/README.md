# Legacy: CPDPM v1 (frozen)

This folder is the code as it existed on 2 September 2026, including the `client_deliverable/` package handed to the client. It is kept unchanged as the object of study for the analysis chapter of the thesis. **Do not fix anything here.** (One exception, made for the repository's secret scanner: a demo password literal in the notebook was replaced by a plain-words placeholder. Nothing else differs from what shipped.) If a defect matters, document it in `paper/analysis/` and demonstrate it against this code.

## Layout

| Path | What it is |
|---|---|
| `src/` | The library version: `cpdpm_core.py`, `cpdpm_hybrid.py`, `security_analysis.py`, `benchmarks.py`, `synthetic_data.py` |
| `client_deliverable/` | The single-file system shipped to the client, its benchmark script, real-data test, and the two PNG charts that were delivered |
| `healthcare_encryption_client.py` | Earlier copy of the client system without the comparison benchmarks |
| `tests/` | The v1 test suite |
| `notebooks/` | Demo notebook (never executed; no saved outputs) |
| `check_errors.py` | Dependency and import checker |
| `requirements.txt` | Reconstructed dependency list for running v1 |

## Running v1

```bash
make setup legacy-setup      # from the repo root
make legacy-test
```

Expected: 24 passed, 2 failed. The two failures (`test_polynomial_key_generation`, `test_context_key_generation`) are the context-key non-determinism defect and are evidence, not bugs to fix.

The client benchmark needs the dataset in its working directory and already has a copy:

```bash
cd legacy/client_deliverable && ../../.venv/bin/python benchmark_demo.py --quick
```

## Known defects (catalogued for chapter 3)

1. The "polynomial transformation" is a per-byte affine map `(a·x + b + i) mod 256`. Prime modulus, degree and exponents are generated but unused (`src/cpdpm_core.py:113-119`).
2. Effective transform keyspace is 2^15, and the key is stored unencrypted in the ciphertext package (`src/cpdpm_hybrid.py:126`).
3. In the client build the coefficients are the constants 7, 11, 13 (`client_deliverable/cpdpm_healthcare_system.py:99`).
4. Context-derived keys are not deterministic: the context seeds NumPy's RNG but coefficients are drawn from `secrets` (`src/cpdpm_core.py:249-256`).
5. HMAC key is derived from the AES key (library) or *is* the AES key (client build).
6. The security-versus-performance chart uses hard-coded scores (`client_deliverable/test_real_healthcare_data.py:617`).
7. The CPDPM-vs-AES timing ratio counts PBKDF2 on the CPDPM decrypt path only (`client_deliverable/cpdpm_healthcare_system.py:528-537`).
8. The "brute force" and "differential" tests exercise AES with a random IV, not the transform.
