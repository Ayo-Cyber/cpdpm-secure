"""Chapter 5, experiment 1: the record-swap attack (threat model §5).

Three storage-layer manipulations by an adversary with database write access,
applied to three schemes. For each cell we record whether the application,
decrypting for the row it *believes* it is reading, silently gets data
("accepted") or gets an error ("rejected").

Schemes
  cbc-hmac  AES-256-CBC + HMAC-SHA256 under one shared key (typical shared-key design)
  aes-gcm   AES-256-GCM, one key per tenant, random nonce, no associated data
  cpdpm     this work: per-context key + header||context as associated data

Attacks
  patient-swap   Bob's ciphertext stored in Alice's row, decrypted for Alice
  tenant-move    a tenant-P ciphertext stored under tenant Q, decrypted for Q
  field-move     the ciphertext of note[*].text stored in effectiveDateTime
  stale-replay   a ciphertext from before key rotation and retirement, replayed

Run: python -m paper.evaluation.record_swap
"""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cpdpm import Context, DecryptionError, Keyring, decrypt_from_str, encrypt_to_str
from cpdpm.fhir import decrypt_resource, encrypt_resource
from paper.analysis._common import write_result
from paper.evaluation.records import POLICY, load_rows, observation

ROOT = Path(__file__).resolve().parents[2]
RESULTS = Path(__file__).resolve().parent / "results"

TENANT_P, TENANT_Q = "org:st-marys", "org:riverside"


# --- scheme adapters --------------------------------------------------------------
# Each adapter exposes encrypt_field / decrypt_field so every scheme is driven the
# same way: the application encrypts one field of one resource for one patient in
# one tenant, stores the string, and later decrypts what it finds in that cell.


class CbcHmac:
    """Typical shared-key design: AES-256-CBC + HMAC-SHA256 under one shared key, random IV."""

    name = "AES-256-CBC + HMAC, one shared key"

    def __init__(self) -> None:
        self.key = os.urandom(32)
        self.mac_key = os.urandom(32)

    def encrypt_field(self, tenant: str, patient: str, rtype: str, path: str, value: Any) -> str:
        from cryptography.hazmat.primitives import hashes, hmac
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.padding import PKCS7

        iv = os.urandom(16)
        padder = PKCS7(128).padder()
        padded = padder.update(json.dumps(value).encode()) + padder.finalize()
        enc = Cipher(algorithms.AES(self.key), modes.CBC(iv)).encryptor()
        ct = enc.update(padded) + enc.finalize()
        h = hmac.HMAC(self.mac_key, hashes.SHA256())
        h.update(iv + ct)
        return (iv + ct + h.finalize()).hex()

    def decrypt_field(self, tenant: str, patient: str, rtype: str, path: str, text: str) -> Any:
        from cryptography.hazmat.primitives import hashes, hmac
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.padding import PKCS7

        raw = bytes.fromhex(text)
        iv, ct, tag = raw[:16], raw[16:-32], raw[-32:]
        h = hmac.HMAC(self.mac_key, hashes.SHA256())
        h.update(iv + ct)
        h.verify(tag)
        dec = Cipher(algorithms.AES(self.key), modes.CBC(iv)).decryptor()
        padded = dec.update(ct) + dec.finalize()
        unpadder = PKCS7(128).unpadder()
        return json.loads(unpadder.update(padded) + unpadder.finalize())

    def rotate_and_retire(self) -> None:
        # One long-lived key; nothing to retire.
        pass


class PlainGCM:
    name = "AES-256-GCM, key per tenant, no AAD"

    def __init__(self) -> None:
        self.keys = {TENANT_P: os.urandom(32), TENANT_Q: os.urandom(32)}

    def encrypt_field(self, tenant: str, patient: str, rtype: str, path: str, value: Any) -> str:
        nonce = os.urandom(12)
        ct = AESGCM(self.keys[tenant]).encrypt(nonce, json.dumps(value).encode(), b"")
        return (nonce + ct).hex()

    def decrypt_field(self, tenant: str, patient: str, rtype: str, path: str, text: str) -> Any:
        raw = bytes.fromhex(text)
        return json.loads(AESGCM(self.keys[tenant]).decrypt(raw[:12], raw[12:], b""))

    def rotate_and_retire(self) -> None:
        # Typical deployment: one long-lived key per tenant; nothing to retire.
        pass


class V2:
    name = "CPDPM (this work)"

    def __init__(self) -> None:
        self.keyring = Keyring.generate()

    def encrypt_field(self, tenant: str, patient: str, rtype: str, path: str, value: Any) -> str:
        ctx = Context(tenant, patient, rtype, path)
        return encrypt_to_str(self.keyring, ctx, json.dumps(value).encode())

    def decrypt_field(self, tenant: str, patient: str, rtype: str, path: str, text: str) -> Any:
        ctx = Context(tenant, patient, rtype, path)
        return json.loads(decrypt_from_str(self.keyring, ctx, text))

    def rotate_and_retire(self) -> None:
        old = self.keyring.current
        self.keyring.rotate()
        self.keyring.retire(old)


def attempt(fn: Any) -> dict[str, Any]:
    try:
        value = fn()
        return {"outcome": "accepted", "returned": value}
    except Exception as exc:  # any error = the application is told something is wrong
        return {"outcome": "rejected", "error_type": type(exc).__name__}


def run_scheme(scheme: Any) -> dict[str, Any]:
    rows = load_rows(2)
    alice, bob = observation(rows[0]), observation(rows[1])
    alice_pid, bob_pid = alice["subject"]["reference"], bob["subject"]["reference"]
    rtype = "Observation"

    # The application writes each patient's note under its own row and tenant.
    alice_note = scheme.encrypt_field(
        TENANT_P, alice_pid, rtype, "note[*].text", alice["note"][0]["text"]
    )
    bob_note = scheme.encrypt_field(
        TENANT_P, bob_pid, rtype, "note[*].text", bob["note"][0]["text"]
    )
    alice_date = scheme.encrypt_field(
        TENANT_P, alice_pid, rtype, "effectiveDateTime", alice["effectiveDateTime"]
    )

    results: dict[str, Any] = {
        "scheme": scheme.name,
        "control_correct_row": attempt(
            lambda: scheme.decrypt_field(TENANT_P, alice_pid, rtype, "note[*].text", alice_note)
        ),
        # Adversary copies Bob's cell into Alice's row; app decrypts for Alice.
        "patient_swap": attempt(
            lambda: scheme.decrypt_field(TENANT_P, alice_pid, rtype, "note[*].text", bob_note)
        ),
        # Adversary copies a tenant-P cell into tenant Q's table; app decrypts for Q.
        "tenant_move": attempt(
            lambda: scheme.decrypt_field(TENANT_Q, alice_pid, rtype, "note[*].text", alice_note)
        ),
        # Adversary writes the note ciphertext into the effectiveDateTime column.
        "field_move": attempt(
            lambda: scheme.decrypt_field(
                TENANT_P, alice_pid, rtype, "effectiveDateTime", alice_note
            )
        ),
    }
    results["expected_alice_note"] = alice["note"][0]["text"]
    results["bob_note_for_reference"] = bob["note"][0]["text"]

    # Stale replay: keep an old ciphertext, rotate and retire, then present it.
    stale = alice_date
    scheme.rotate_and_retire()
    results["stale_replay_after_retirement"] = attempt(
        lambda: scheme.decrypt_field(TENANT_P, alice_pid, rtype, "effectiveDateTime", stale)
    )
    return results


def fhir_level_demo() -> dict[str, Any]:
    """Same attack through the FHIR layer: Bob's encrypted document in Alice's row."""
    kr = Keyring.generate()
    rows = load_rows(2)
    alice, bob = observation(rows[0]), observation(rows[1])
    bob_doc = encrypt_resource(kr, TENANT_P, bob, POLICY)
    swapped = copy.deepcopy(bob_doc)
    try:
        decrypt_resource(kr, TENANT_P, swapped, patient=alice["subject"]["reference"])
        outcome = "accepted"
    except DecryptionError:
        outcome = "rejected"
    return {"scheme": "CPDPM FHIR layer", "patient_swap": {"outcome": outcome}}


def main() -> None:
    schemes = [CbcHmac(), PlainGCM(), V2()]
    per_scheme = [run_scheme(s) for s in schemes]
    attacks = ["patient_swap", "tenant_move", "field_move", "stale_replay_after_retirement"]
    matrix = {
        r["scheme"]: {a: r[a]["outcome"] for a in attacks}
        | {"control": r["control_correct_row"]["outcome"]}
        for r in per_scheme
    }
    for name, cells in matrix.items():
        print(f"{name:40s}", "  ".join(f"{a}={o}" for a, o in cells.items()))
    write_result(
        "record_swap",
        {"matrix": matrix, "detail": per_scheme, "fhir_layer": fhir_level_demo()},
        results_dir=RESULTS,
    )


if __name__ == "__main__":
    main()
