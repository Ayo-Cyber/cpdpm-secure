"""Chapter 3: the cost of a byte-level pre-transform layer, measured fairly.

Compares a password-based AES-256-CBC + HMAC pipeline with and without a
per-byte affine pre-transform, counting the key derivation identically on both
sides and in both directions. Also times each component alone so the source
of any overhead is visible. Medians and interquartile ranges over repeated
runs. Cross-library comparison is chapter 5's job, not this script's.

Run: python -m paper.analysis.fair_benchmark
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time
from collections.abc import Callable

import numpy as np
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.padding import PKCS7

from paper.analysis._common import write_result
from paper.analysis.pre_transform import affine_forward, affine_inverse

SIZES = [1024, 8 * 1024, 64 * 1024, 512 * 1024]
REPS = 15
PASSWORD = "correct horse battery staple"  # noqa: S105  (benchmark input, not a secret)


def kdf(password: bytes, salt: bytes) -> bytes:
    return PBKDF2HMAC(hashes.SHA256(), 32, salt, 100_000).derive(password)


def aes_cbc_hmac_encrypt(key: bytes, data: bytes) -> tuple[bytes, bytes, bytes]:
    iv = os.urandom(16)
    padder = PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct = enc.update(padded) + enc.finalize()
    ikey = hashlib.sha256(key + b"integrity").digest()
    tag = hmac.new(ikey, ct, hashlib.sha256).digest()
    return iv, ct, tag


def aes_cbc_hmac_decrypt(key: bytes, iv: bytes, ct: bytes, tag: bytes) -> bytes:
    ikey = hashlib.sha256(key + b"integrity").digest()
    if not hmac.compare_digest(tag, hmac.new(ikey, ct, hashlib.sha256).digest()):
        raise ValueError("bad tag")
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def pipeline_encrypt(data: bytes, transform: bool) -> dict:
    salt = os.urandom(16)
    key = kdf(PASSWORD.encode(), salt)
    a, b = os.urandom(1)[0], os.urandom(1)[0]
    body = affine_forward(data, a, b) if transform else data
    iv, ct, tag = aes_cbc_hmac_encrypt(key, body)
    return {"salt": salt, "iv": iv, "ct": ct, "tag": tag, "a": a, "b": b, "t": transform}


def pipeline_decrypt(pkg: dict) -> bytes:
    key = kdf(PASSWORD.encode(), pkg["salt"])
    body = aes_cbc_hmac_decrypt(key, pkg["iv"], pkg["ct"], pkg["tag"])
    return affine_inverse(body, pkg["a"], pkg["b"]) if pkg["t"] else body


def timeit(fn: Callable[[], object], reps: int = REPS) -> dict:
    samples = []
    for _ in range(reps):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000.0)
    arr = np.asarray(samples)
    return {
        "n": reps,
        "median_ms": float(np.median(arr)),
        "p25_ms": float(np.percentile(arr, 25)),
        "p75_ms": float(np.percentile(arr, 75)),
        "min_ms": float(arr.min()),
    }


def main() -> None:
    fixed_key = kdf(PASSWORD.encode(), b"\x00" * 16)

    def measure(size: int) -> dict:
        data = os.urandom(size)
        with_t = pipeline_encrypt(data, True)
        without = pipeline_encrypt(data, False)
        r = {
            "with_transform_encrypt": timeit(lambda: pipeline_encrypt(data, True)),
            "with_transform_decrypt": timeit(lambda: pipeline_decrypt(with_t)),
            "baseline_encrypt": timeit(lambda: pipeline_encrypt(data, False)),
            "baseline_decrypt": timeit(lambda: pipeline_decrypt(without)),
            "component_pbkdf2": timeit(lambda: kdf(PASSWORD.encode(), b"\x00" * 16)),
            "component_aes_cbc_hmac_encrypt": timeit(lambda: aes_cbc_hmac_encrypt(fixed_key, data)),
            "component_transform_loop": timeit(lambda: affine_forward(data, 7, 11)),
            "component_inverse_loop": timeit(lambda: affine_inverse(data, 7, 11)),
        }
        r["ratio_encrypt"] = (
            r["with_transform_encrypt"]["median_ms"] / r["baseline_encrypt"]["median_ms"]
        )
        r["ratio_decrypt"] = (
            r["with_transform_decrypt"]["median_ms"] / r["baseline_decrypt"]["median_ms"]
        )
        return r

    per_size = {}
    for size in SIZES:
        per_size[str(size)] = measure(size)
        r = per_size[str(size)]
        print(
            f"{size:>7} B  with/without encrypt {r['ratio_encrypt']:.2f}x  "
            f"decrypt {r['ratio_decrypt']:.2f}x  (pbkdf2 {r['component_pbkdf2']['median_ms']:.1f} ms, "  # noqa: E501
            f"loop {r['component_transform_loop']['median_ms']:.1f} ms)"
        )

    write_result(
        "fair_benchmark",
        {
            "sizes_bytes": SIZES,
            "reps": REPS,
            "pbkdf2_iterations": 100_000,
            "per_size": per_size,
            "note": "same pipeline with and without the pre-transform; KDF counted on both sides "
            "in both directions",
        },
    )


if __name__ == "__main__":
    main()
