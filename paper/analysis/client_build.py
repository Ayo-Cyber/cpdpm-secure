"""Chapter 3, finding 3: what the client actually received.

* The transform coefficients in the shipped build are the constants 7, 11, 13;
  the transform does not depend on any key at all.
* The AES key is reused as the HMAC key.
* The "security score" scatter plot is drawn from hard-coded constants.
* The reported 2x overhead comes from timing PBKDF2 on the CPDPM decrypt path but
  not on the AES baseline decrypt path.

Run: python -m paper.analysis.client_build
"""

from __future__ import annotations

import os
import re

from paper.analysis._legacy import LEGACY_CLIENT, add_legacy_paths, write_result

add_legacy_paths()

from cpdpm_healthcare_system import HealthcareDataManager, HealthcareEncryption  # noqa: E402


def keyless_transform() -> dict:
    a = HealthcareEncryption(master_password="one")  # noqa: S106
    b = HealthcareEncryption(master_password="two")  # noqa: S106
    data = os.urandom(2048)
    return {
        "poly_coeffs": a.poly_coeffs,
        "transform_identical_across_instances": a._apply_polynomial_transformation(data)
        == b._apply_polynomial_transformation(data),
        "key_material_in_transform_bits": 0,
    }


def _grep(path: str, pattern: str) -> list[dict]:
    text = (LEGACY_CLIENT / path).read_text().splitlines()
    return [
        {"line": i + 1, "text": ln.strip()} for i, ln in enumerate(text) if re.search(pattern, ln)
    ]


def source_facts() -> dict:
    return {
        "hardcoded_security_scores": _grep(
            "test_real_healthcare_data.py", r"security_scores\s*=\s*\["
        ),
        "hmac_uses_aes_key": _grep("cpdpm_healthcare_system.py", r"hmac\.HMAC\(key,"),
        "fixed_coefficients": _grep("cpdpm_healthcare_system.py", r"self\.poly_coeffs\s*="),
    }


def reported_timings(size: int = 1024, reps: int = 5) -> dict:
    """Reproduce the client benchmark's own numbers to show the parity defect."""
    m = HealthcareDataManager()
    cp = [m.benchmark_performance(size) for _ in range(reps)]
    aes = [m.benchmark_aes_comparison(size) for _ in range(reps)]
    med = lambda xs: sorted(xs)[len(xs) // 2]  # noqa: E731
    return {
        "data_size_bytes": size,
        "reps": reps,
        "cpdpm_encrypt_ms_median": med([r["encryption_time_ms"] for r in cp]),
        "cpdpm_decrypt_ms_median": med([r["decryption_time_ms"] for r in cp]),
        "aes_encrypt_ms_median": med([r["encryption_time_ms"] for r in aes]),
        "aes_decrypt_ms_median": med([r["decryption_time_ms"] for r in aes]),
        "explanation": "AES baseline decrypt reuses the derived key (no PBKDF2); "
        "CPDPM decrypt re-derives it. The 'total' ratio therefore counts one PBKDF2 "
        "for AES and two for CPDPM.",
    }


def main() -> None:
    write_result(
        "client_build",
        {
            "keyless_transform": keyless_transform(),
            "source_facts": source_facts(),
            "client_benchmark_as_reported": reported_timings(),
        },
    )


if __name__ == "__main__":
    main()
