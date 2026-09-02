"""Chapter 3, finding 4: the honest cost of the v1 transform.

Measures, with the KDF counted identically on both sides:

* v1 library encrypt / decrypt (PBKDF2 + transform + AES-CBC + HMAC)
* an otherwise identical baseline with the transform removed
* each component alone: PBKDF2, AES-CBC+HMAC, the Python transform loop

Reports medians and interquartile ranges over repeated runs. Not pyperf: this is
a component decomposition, not a cross-library comparison (that is chapter 5).

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

from paper.analysis._legacy import add_legacy_paths, write_result

add_legacy_paths()

from cpdpm_hybrid import CPDPMHybrid  # noqa: E402

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


def baseline_encrypt(data: bytes) -> dict:
    salt = os.urandom(16)
    key = kdf(PASSWORD.encode(), salt)
    iv, ct, tag = aes_cbc_hmac_encrypt(key, data)
    return {"salt": salt, "iv": iv, "ct": ct, "tag": tag}


def baseline_decrypt(pkg: dict) -> bytes:
    key = kdf(PASSWORD.encode(), pkg["salt"])
    return aes_cbc_hmac_decrypt(key, pkg["iv"], pkg["ct"], pkg["tag"])


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
    v1 = CPDPMHybrid()
    poly = v1.cpdpm_core.poly_engine
    poly_key = poly.generate_polynomial_key()
    fixed_key = kdf(PASSWORD.encode(), b"\x00" * 16)

    def measure(size: int) -> dict:
        data = os.urandom(size)
        v1_pkg = v1.encrypt(data, PASSWORD, "patient:001")
        base_pkg = baseline_encrypt(data)
        return {
            "v1_encrypt": timeit(lambda: v1.encrypt(data, PASSWORD, "patient:001")),
            "v1_decrypt": timeit(lambda: v1.decrypt(v1_pkg, PASSWORD)),
            "baseline_encrypt": timeit(lambda: baseline_encrypt(data)),
            "baseline_decrypt": timeit(lambda: baseline_decrypt(base_pkg)),
            "component_pbkdf2": timeit(lambda: kdf(PASSWORD.encode(), b"\x00" * 16)),
            "component_aes_cbc_hmac_encrypt": timeit(lambda: aes_cbc_hmac_encrypt(fixed_key, data)),
            "component_transform_loop": timeit(lambda: poly.polynomial_transform(data, poly_key)),
        }

    per_size = {}
    for size in SIZES:
        per_size[str(size)] = measure(size)
        r = per_size[str(size)]
        r["ratio_v1_over_baseline_encrypt"] = (
            r["v1_encrypt"]["median_ms"] / r["baseline_encrypt"]["median_ms"]
        )
        r["ratio_v1_over_baseline_decrypt"] = (
            r["v1_decrypt"]["median_ms"] / r["baseline_decrypt"]["median_ms"]
        )
        print(
            f"{size:>7} B  v1/base encrypt {r['ratio_v1_over_baseline_encrypt']:.2f}x  "
            f"decrypt {r['ratio_v1_over_baseline_decrypt']:.2f}x  "
            f"(pbkdf2 {r['component_pbkdf2']['median_ms']:.1f} ms, "
            f"loop {r['component_transform_loop']['median_ms']:.1f} ms)"
        )

    write_result(
        "fair_benchmark",
        {
            "sizes_bytes": SIZES,
            "reps": REPS,
            "pbkdf2_iterations": 100_000,
            "per_size": per_size,
            "note": "baseline = v1 with the transform removed; KDF counted on both sides "
            "for both directions",
        },
    )


if __name__ == "__main__":
    main()
