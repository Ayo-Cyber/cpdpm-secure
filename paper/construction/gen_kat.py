"""Generate known-answer vectors for protocol v2 into tests/vectors/v2_kat.json.

Fixed master key and fixed nonces make the output reproducible. The test in
``tests/test_kat.py`` checks that decrypting each vector yields the plaintext
and that re-encrypting with the same nonce reproduces the blob byte for byte.
Any change to the encoding, the HKDF info strings, the header, or the
commitment breaks these vectors, which is the point.

Run: python -m paper.construction.gen_kat
"""

from __future__ import annotations

import json
from pathlib import Path

from cpdpm import Context, Keyring, Suite
from cpdpm.core import _encrypt_with_nonce

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "tests" / "vectors" / "v2_kat.json"

MASTER = bytes(range(1, 33))  # test vector key, never a secret; written to JSON as its recipe
CTX = Context(
    tenant="org:st-marys", patient="Patient/8f3a", resource_type="Condition", field_path="code.text"
)
CTX_NO_PATIENT = Context(
    tenant="org:st-marys", patient="", resource_type="Organization", field_path="*"
)

CASES = [
    ("gcm-empty", Suite.AES_256_GCM, CTX, b"", bytes(12)),
    ("gcm-text", Suite.AES_256_GCM, CTX, b"Type 2 diabetes mellitus", bytes(range(12))),
    (
        "gcm-no-patient",
        Suite.AES_256_GCM,
        CTX_NO_PATIENT,
        b"St Mary's Hospital",
        bytes([0xAB] * 12),
    ),
    ("xchacha-text", Suite.XCHACHA20_POLY1305, CTX, b"Type 2 diabetes mellitus", bytes(range(24))),
]


def main() -> None:
    kr = Keyring.from_master(MASTER, version=1)
    vectors = []
    for name, suite, ctx, pt, nonce in CASES:
        blob = _encrypt_with_nonce(kr, ctx, pt, suite, 1, nonce)
        vectors.append(
            {
                "name": name,
                "suite": int(suite),
                "key_version": 1,
                "context": {
                    "tenant": ctx.tenant,
                    "patient": ctx.patient,
                    "resource_type": ctx.resource_type,
                    "field_path": ctx.field_path,
                    "purpose": ctx.purpose,
                },
                "context_canonical_hex": ctx.canonical().hex(),
                "nonce_hex": nonce.hex(),
                "plaintext_hex": pt.hex(),
                "blob_hex": blob.hex(),
            }
        )
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        json.dumps({"master_key": "bytes(range(1, 33))", "vectors": vectors}, indent=2) + "\n"
    )
    print(f"wrote {OUT.relative_to(ROOT)} ({len(vectors)} vectors)")


if __name__ == "__main__":
    main()
