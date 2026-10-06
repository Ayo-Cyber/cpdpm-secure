"""Chapter 5, experiment 3: containing a working-key leak.

The exposure experiment (record_swap.py) says how many cells one leaked working
key opens. This one asks what an operator has to do about it. For each scheme:

  1. write the same corpus (CORPUS_TENANTS x CORPUS_PATIENTS x CORPUS_FIELDS);
  2. leak the key the application used for Alice's note in tenant P;
  3. contain the leak: replace the leaked material (a new shared key, a new
     tenant key, or a new CPDPM master version) and re-encrypt every cell the
     leaked key could open, which is exactly the set that must move before the
     leak is harmless;
  4. check that afterwards the leaked key opens nothing and every cell still
     decrypts for the application.

Reported per scheme: secrets at rest, cells re-encrypted, median wall-clock
time to contain over REPEATS runs, and per-cell cost. The per-cell cost is then
multiplied out to a stated deployment size (SCALE_*) as an extrapolation, so
the text can say "re-encrypt one tenant" in minutes rather than in cells.

What this does not measure: loss of the master key, which under every scheme
means re-encrypting everything; and master rotation under CPDPM, which is the
same whole-corpus job. Only the working-key leak differs between schemes.

Run: python -m paper.evaluation.containment
"""

from __future__ import annotations

import statistics
import time
from typing import Any

from paper.analysis._common import write_result
from paper.evaluation.record_swap import (
    CORPUS_FIELDS,
    CORPUS_PATIENTS,
    CORPUS_TENANTS,
    RESULTS,
    TENANT_P,
    V2,
    AadGCM,
    CbcHmac,
    PlainGCM,
    _opens,
    attempt,
    build_corpus,
)

REPEATS = 15
SCALE_TENANTS = 5
SCALE_PATIENTS = 100_000
SCALE_FIELDS = 10


def contain_once(factory: Any) -> dict[str, Any]:
    scheme = factory()
    cells, stored, alice = build_corpus(scheme)
    leaked = scheme.key_used_for(*alice)
    opened = [c for c in cells if _opens(scheme, leaked, c, stored[c])]

    t0 = time.perf_counter()
    old_decrypt = scheme.rekey(TENANT_P)
    for cell in opened:
        value = old_decrypt(*cell, stored[cell])
        stored[cell] = scheme.encrypt_field(*cell, value)
    elapsed = time.perf_counter() - t0

    opens_after = sum(_opens(scheme, leaked, c, stored[c]) for c in cells)
    readable_after = sum(
        attempt(lambda c=c: scheme.decrypt_field(*c, stored[c]))["outcome"] == "accepted"
        for c in cells
    )
    return {
        "scheme": scheme.name,
        "secrets_at_rest": scheme.secrets_at_rest,
        "corpus_cells": len(cells),
        "cells_reencrypted": len(opened),
        "seconds": elapsed,
        "opens_after": opens_after,
        "readable_after": readable_after,
    }


def contain(factory: Any) -> dict[str, Any]:
    runs = [contain_once(factory) for _ in range(REPEATS)]
    first = runs[0]
    for r in runs:
        assert r["opens_after"] == 0, "containment must leave the leaked key useless"
        assert r["readable_after"] == r["corpus_cells"], "containment must not lose data"
        assert r["cells_reencrypted"] == first["cells_reencrypted"]
    secs = [r["seconds"] for r in runs]
    median = statistics.median(secs)
    n = first["cells_reencrypted"]
    keep = ("scheme", "secrets_at_rest", "corpus_cells", "cells_reencrypted")
    return {
        **{k: first[k] for k in keep},
        "opens_after": first["opens_after"],
        "readable_after": first["readable_after"],
        "repeats": REPEATS,
        "median_ms": median * 1e3,
        "per_cell_us": median / n * 1e6,
        "min_ms": min(secs) * 1e3,
        "max_ms": max(secs) * 1e3,
    }


def scale(per_scheme: dict[str, dict[str, Any]]) -> dict[str, Any]:
    cells_per_tenant = SCALE_PATIENTS * SCALE_FIELDS
    cells_total = SCALE_TENANTS * cells_per_tenant
    out: dict[str, Any] = {
        "tenants": SCALE_TENANTS,
        "patients_per_tenant": SCALE_PATIENTS,
        "fields_per_patient": SCALE_FIELDS,
        "cells_per_tenant": cells_per_tenant,
        "cells_total": cells_total,
        "per_scheme": {},
    }
    corpus_per_tenant = CORPUS_PATIENTS * len(CORPUS_FIELDS)
    for name, r in per_scheme.items():
        # The measured re-encryption set is all cells, one tenant, or one cell;
        # map it onto the stated deployment by the same rule.
        if r["cells_reencrypted"] == r["corpus_cells"]:
            cells = cells_total
        elif r["cells_reencrypted"] == corpus_per_tenant:
            cells = cells_per_tenant
        else:
            cells = r["cells_reencrypted"]
        out["per_scheme"][name] = {
            "cells_reencrypted": cells,
            "seconds": cells * r["per_cell_us"] / 1e6,
        }
    return out


def main() -> None:
    per_scheme = {}
    for factory in (CbcHmac, PlainGCM, AadGCM, V2):
        r = contain(factory)
        per_scheme[r["scheme"]] = r
        print(
            f"{r['scheme']:48s} re-encrypt {r['cells_reencrypted']:4d}/{r['corpus_cells']} cells",
            f"in {r['median_ms']:8.2f} ms ({r['per_cell_us']:.1f} us/cell),",
            f"secrets: {r['secrets_at_rest']}",
        )
    sc = scale(per_scheme)
    for name, r in sc["per_scheme"].items():
        print(f"{name:48s} at scale: {r['cells_reencrypted']:>9,} cells, {r['seconds']:.3f} s")
    write_result(
        "containment",
        {
            "corpus": {
                "tenants": len(CORPUS_TENANTS),
                "patients_per_tenant": CORPUS_PATIENTS,
                "fields_per_patient": len(CORPUS_FIELDS),
            },
            "per_scheme": per_scheme,
            "scale": sc,
        },
        results_dir=RESULTS,
    )


if __name__ == "__main__":
    main()
