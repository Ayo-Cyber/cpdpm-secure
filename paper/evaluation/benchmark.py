"""Chapter 5, experiment 2: cost of context binding against standard libraries.

pyperf benchmark of encrypt and decrypt for FHIR Bundle payloads of 1, 10, 100
and 1000 observations built from the stroke dataset.

Schemes (all with pre-established keys; no password KDF on the hot path):
  aes-gcm     cryptography AESGCM, random 96-bit nonce, no AAD   (floor)
  fernet      cryptography Fernet (AES-128-CBC + HMAC, base64)
  tink        Google Tink AEAD, AES256_GCM key template
  cpdpm-gcm      cpdpm, AES-256-GCM suite (HKDF per call + commitment + AAD)
  cpdpm-xchacha  cpdpm, XChaCha20-Poly1305 suite

Plus, for the single-observation payload only, the FHIR field-level path with
three encrypted fields, to price per-field HKDF.

Run (pyperf spawns worker processes; pass its flags through):
    python -m paper.evaluation.benchmark -o paper/evaluation/results/bench_pyperf.json
    python -m paper.evaluation.benchmark --fast -o ...   # quick look
"""

from __future__ import annotations

import os
from collections.abc import Callable

import pyperf
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cpdpm import Context, Keyring, Suite, decrypt, encrypt
from cpdpm.fhir import decrypt_resource, encrypt_resource
from paper.evaluation.records import POLICY, bundle_bytes, load_rows, observation

SIZES = [1, 10, 100, 1000]
TENANT = "org:st-marys"
CTX = Context(TENANT, "Patient/9046", "Bundle", "*")


def tink_aead():  # type: ignore[no-untyped-def]
    import tink
    from tink import aead

    aead.register()
    if hasattr(tink, "new_keyset_handle"):
        handle = tink.new_keyset_handle(aead.aead_key_templates.AES256_GCM)
    else:  # pragma: no cover - newer API
        handle = tink.KeysetHandle.generate_new(aead.aead_key_templates.AES256_GCM)
    return handle.primitive(aead.Aead)


def schemes() -> dict[str, tuple[Callable[[bytes], bytes], Callable[[bytes], bytes]]]:
    gcm_key = AESGCM.generate_key(256)

    def gcm_enc(pt: bytes) -> bytes:
        n = os.urandom(12)
        return n + AESGCM(gcm_key).encrypt(n, pt, b"")

    def gcm_dec(ct: bytes) -> bytes:
        return AESGCM(gcm_key).decrypt(ct[:12], ct[12:], b"")

    fernet = Fernet(Fernet.generate_key())
    tink_prim = tink_aead()
    kr = Keyring.generate()

    return {
        "aes-gcm": (gcm_enc, gcm_dec),
        "fernet": (fernet.encrypt, fernet.decrypt),
        "tink": (lambda pt: tink_prim.encrypt(pt, b""), lambda ct: tink_prim.decrypt(ct, b"")),
        "cpdpm-gcm": (
            lambda pt: encrypt(kr, CTX, pt, suite=Suite.AES_256_GCM),
            lambda ct: decrypt(kr, CTX, ct),
        ),
        "cpdpm-xchacha": (
            lambda pt: encrypt(kr, CTX, pt, suite=Suite.XCHACHA20_POLY1305),
            lambda ct: decrypt(kr, CTX, ct),
        ),
    }


def main() -> None:
    runner = pyperf.Runner(processes=8, values=3, warmups=1)
    runner.metadata["payload"] = "FHIR Bundle JSON of N stroke-dataset observations"
    table = schemes()
    payloads = {n: bundle_bytes(n) for n in SIZES}
    for n, pt in payloads.items():
        for name, (enc, dec) in table.items():
            ct = enc(pt)
            runner.bench_func(f"{name}/encrypt/n={n}/bytes={len(pt)}", enc, pt)
            runner.bench_func(f"{name}/decrypt/n={n}/bytes={len(pt)}", dec, ct)

    # Field-level path, one observation, three encrypted fields.
    kr = Keyring.generate()
    obs = observation(load_rows(1)[0])
    enc_doc = encrypt_resource(kr, TENANT, obs, POLICY)
    runner.bench_func(
        "cpdpm-fhir-fields/encrypt/n=1/fields=3", encrypt_resource, kr, TENANT, obs, POLICY
    )
    runner.bench_func(
        "cpdpm-fhir-fields/decrypt/n=1/fields=3",
        lambda: decrypt_resource(kr, TENANT, enc_doc, patient="Patient/9046"),
    )


if __name__ == "__main__":
    main()
