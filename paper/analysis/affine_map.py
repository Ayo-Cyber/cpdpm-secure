"""Chapter 3, finding 1: the v1 "polynomial transformation" is a per-byte affine map.

Establishes, by exhaustive check rather than argument:

* T_k(x, i) = (a·x + b + (i+1)) mod 256 with a = c0 | 1 and b = c1, for every
  byte value x and every position i mod 256.
* The prime modulus, degree, exponents and coefficients c2.. have no effect.
* The number of distinct transforms over all keys is 2^15.
* The transform key is stored, unencrypted, inside the ciphertext package.
* A single-byte change in the input changes exactly one output byte.

Run: python -m paper.analysis.affine_map
"""

from __future__ import annotations

import dataclasses
import hashlib
import os

import numpy as np

from paper.analysis._legacy import add_legacy_paths, write_result

add_legacy_paths()

from cpdpm_core import FiniteFieldPolynomial, PolynomialKey  # noqa: E402
from cpdpm_hybrid import CPDPMHybrid  # noqa: E402


def affine_identity(engine: FiniteFieldPolynomial, key: PolynomialKey) -> dict:
    a = key.coefficients[0] | 1
    b = key.coefficients[1]
    checks = 0
    mismatches = 0
    # One input of 256 positions, each holding the same byte x, checks all (x, i) pairs.
    for x in range(256):
        out = engine.polynomial_transform(bytes([x]) * 256, key)
        for i, y in enumerate(out):
            checks += 1
            if y != (a * x + b + (i + 1)) % 256:
                mismatches += 1
    return {"checks": checks, "mismatches": mismatches, "holds": mismatches == 0}


def unused_fields(engine: FiniteFieldPolynomial, key: PolynomialKey) -> dict:
    data = os.urandom(4096)
    ref = engine.polynomial_transform(data, key)
    variants = {
        "prime_modulus": dataclasses.replace(key, prime_modulus=101),
        "degree": dataclasses.replace(key, degree=1),
        "exponents": dataclasses.replace(key, exponents=[0] * len(key.exponents)),
        "coefficients_2_onward": dataclasses.replace(
            key, coefficients=key.coefficients[:2] + [1] * (len(key.coefficients) - 2)
        ),
    }
    return {
        name: {"output_unchanged": engine.polynomial_transform(data, k) == ref}
        for name, k in variants.items()
    }


def effective_keyspace() -> dict:
    """Count distinct transforms over every (c0 mod 256, c1 mod 256) pair."""
    x = np.arange(256, dtype=np.int64)
    pos = np.arange(1, 257, dtype=np.int64)
    seen: set[bytes] = set()
    for c0 in range(256):
        a = c0 | 1
        for c1 in range(256):
            # Transform of the canonical input bytes(range(256)) at positions 0..255.
            out = ((a * x + c1 + pos) % 256).astype(np.uint8).tobytes()
            seen.add(hashlib.blake2b(out, digest_size=16).digest())
    n = len(seen)
    return {
        "candidate_pairs": 256 * 256,
        "distinct_transforms": n,
        "log2_distinct": float(np.log2(n)),
        "theory": "128 odd multipliers x 256 offsets = 32768",
    }


def key_in_package() -> dict:
    hybrid = CPDPMHybrid()
    pkg = hybrid.encrypt(b"PATIENT SSN 123-45-6789", "correct horse battery staple", "patient:001")
    shipped = pkg.get("polynomial_key")
    return {
        "package_fields": sorted(pkg.keys()),
        "polynomial_key_present_in_clear": shipped is not None,
        "polynomial_key_shipped": shipped,
        "consequence": "anyone holding the ciphertext holds the transform key; "
        "the layer's secrecy contribution is 0 bits regardless of its size",
    }


def diffusion(engine: FiniteFieldPolynomial, key: PolynomialKey, trials: int = 1000) -> dict:
    changed = []
    for _ in range(trials):
        data = bytearray(os.urandom(256))
        ref = engine.polynomial_transform(bytes(data), key)
        i = int.from_bytes(os.urandom(1), "big")
        data[i] ^= 1 << (int.from_bytes(os.urandom(1), "big") % 8)
        out = engine.polynomial_transform(bytes(data), key)
        changed.append(sum(1 for p, q in zip(ref, out, strict=True) if p != q))
    return {
        "trials": trials,
        "mean_output_bytes_changed_per_input_byte_flip": float(np.mean(changed)),
        "max": int(max(changed)),
        "reference": "an ideal 256-byte block transform would change ~128 bytes",
    }


def main() -> None:
    engine = FiniteFieldPolynomial()
    key = engine.generate_polynomial_key(degree=5)
    write_result(
        "affine_map",
        {
            "sampled_key": dataclasses.asdict(key),
            "affine_identity": affine_identity(engine, key),
            "unused_key_fields": unused_fields(engine, key),
            "effective_keyspace": effective_keyspace(),
            "key_in_package": key_in_package(),
            "diffusion": diffusion(engine, key),
        },
    )


if __name__ == "__main__":
    main()
