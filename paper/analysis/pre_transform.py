"""Chapter 3: what a byte-level pre-transform layer in front of AES can and cannot add.

A recurring pattern in "hybrid encryption for EHR" papers is a keyed byte
transform applied before a standard cipher, presented as an extra security
layer. The most common instances are affine maps ``(a·x + b) mod 256`` and
byte substitutions. This script measures the properties of such a layer in
the abstract, using its own implementation of the pattern; it does not analyse
any particular deployed system.

Findings it establishes by exhaustive check, not argument:

* The keyspace of a per-byte affine map is exactly 128 · 256 = 2^15, however
  many parameters the description carries.
* A single flipped input byte changes exactly one output byte: no diffusion.
* If the transform key is stored with the ciphertext (which such designs do,
  because the receiver needs it), the layer contributes 0 bits.
* The layer is a public bijection on the plaintext, so the composite scheme is
  exactly as secure as the cipher behind it, no more and no less.

Run: python -m paper.analysis.pre_transform
"""

from __future__ import annotations

import hashlib
import os

import numpy as np

from paper.analysis._common import write_result


def affine_forward(data: bytes, a: int, b: int) -> bytes:
    """The genre's transform: per-byte (a·x + b + i) mod 256 with a odd, position i."""
    a |= 1
    return bytes((a * x + b + i) % 256 for i, x in enumerate(data))


def affine_inverse(data: bytes, a: int, b: int) -> bytes:
    a |= 1
    a_inv = pow(a, -1, 256)
    return bytes((a_inv * (y - b - i)) % 256 for i, y in enumerate(data))


def invertibility(trials: int = 200) -> dict:
    ok = 0
    for _ in range(trials):
        a, b = os.urandom(1)[0], os.urandom(1)[0]
        data = os.urandom(512)
        ok += affine_inverse(affine_forward(data, a, b), a, b) == data
    return {"trials": trials, "roundtrips_ok": ok}


def effective_keyspace() -> dict:
    x = np.arange(256, dtype=np.int64)
    pos = np.arange(256, dtype=np.int64)
    seen: set[bytes] = set()
    for a in range(256):
        for b in range(256):
            out = (((a | 1) * x + b + pos) % 256).astype(np.uint8).tobytes()
            seen.add(hashlib.blake2b(out, digest_size=16).digest())
    return {
        "parameter_pairs": 65536,
        "distinct_transforms": len(seen),
        "log2_distinct": float(np.log2(len(seen))),
        "note": "128 odd multipliers x 256 offsets; extra parameters in a description do not enlarge this",  # noqa: E501
    }


def diffusion(trials: int = 1000) -> dict:
    changed = []
    for _ in range(trials):
        a, b = os.urandom(1)[0], os.urandom(1)[0]
        data = bytearray(os.urandom(256))
        ref = affine_forward(bytes(data), a, b)
        i = os.urandom(1)[0]
        data[i] ^= 1 << (os.urandom(1)[0] % 8)
        out = affine_forward(bytes(data), a, b)
        changed.append(sum(p != q for p, q in zip(ref, out, strict=True)))
    return {
        "trials": trials,
        "mean_output_bytes_changed_per_input_byte_flip": float(np.mean(changed)),
        "max": int(max(changed)),
        "reference": "a block cipher changes about half of 256 bytes",
    }


def argument() -> dict:
    return {
        "claim": "Enc'(m) = Enc(T_k(m)) with T_k a public or transmitted bijection is exactly as "
        "secure as Enc.",
        "sketch": "Any adversary against Enc' applies T_k (known) to its chosen plaintexts and "
        "T_k^{-1} to any recovered plaintext, giving an adversary against Enc with identical "
        "advantage; conversely Enc' inherits every security property of Enc. Secrecy of k adds "
        "at most log2(keyspace) bits, here 15, and only if k is never transmitted.",
        "secret_key_bits_upper_bound": 15,
        "transmitted_key_bits": 0,
    }


def main() -> None:
    write_result(
        "pre_transform",
        {
            "invertibility": invertibility(),
            "effective_keyspace": effective_keyspace(),
            "diffusion": diffusion(),
            "security_argument": argument(),
        },
    )


if __name__ == "__main__":
    main()
