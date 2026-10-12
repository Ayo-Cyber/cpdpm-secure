"""Chapter 5, experiment 1: the record-swap attack (threat model §5).

Storage-layer manipulations by an adversary with database write access, applied
to four schemes that form a ladder: each adds one thing to the one before. For
each cell we record whether the application, decrypting for the row it
*believes* it is reading, silently gets data ("accepted") or gets an error
("rejected").

Schemes
  cbc-hmac  AES-256-CBC + HMAC-SHA256 under one shared key (typical legacy design)
  aes-gcm   AES-256-GCM, one key per tenant, random nonce, no associated data
  aad-gcm   AES-256-GCM, one key per tenant, the same four context fields bound
            as associated data. This is the strongest thing an application can
            build from the AEAD interface alone, and the baseline CPDPM must be
            judged against: binding without a per-context key.
  cpdpm     this work: per-context key + header||context as associated data

Attacks
  patient-swap   Bob's ciphertext stored in Alice's row, decrypted for Alice
  tenant-move    a tenant-P ciphertext stored under tenant Q, decrypted for Q
  field-move     the ciphertext of note[*].text stored in effectiveDateTime
  stale-replay   a ciphertext from before key rotation and retirement, replayed.
                 Only CPDPM has key versioning; for the baselines this column reports
                 "not applicable" rather than a failed check, because there is no
                 retirement to fail.

Leaked-key exposure
  The swap columns measure binding. They cannot distinguish aad-gcm from cpdpm,
  because associated data alone already rejects every substitution. What the
  per-context key adds is a smaller blast radius, and that is measured directly:
  the key the application used to decrypt one cell (Alice's note) is leaked, and
  we count how many cells of a corpus of CORPUS_TENANTS x CORPUS_PATIENTS x
  CORPUS_FIELDS it decrypts, by attempting the raw AEAD decryption of every cell
  under that key with that cell's own associated data.

Run: python -m paper.evaluation.record_swap
"""

from __future__ import annotations

import base64
import copy
import json
import os
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cpdpm import Context, DecryptionError, Keyring, decrypt_from_str, encrypt_to_str
from cpdpm.core import TEXT_PREFIX
from cpdpm.fhir import decrypt_resource, encrypt_resource
from cpdpm.header import Header, Suite
from cpdpm.kdf import derive_context_key
from paper.analysis._common import write_result
from paper.evaluation.records import POLICY, load_rows, observation

ROOT = Path(__file__).resolve().parents[2]
RESULTS = Path(__file__).resolve().parent / "results"

TENANT_P, TENANT_Q = "org:st-marys", "org:riverside"
CORPUS_TENANTS = (TENANT_P, TENANT_Q)
CORPUS_PATIENTS = 50
CORPUS_FIELDS = ("note[*].text", "effectiveDateTime")


# --- scheme adapters --------------------------------------------------------------
# Each adapter exposes encrypt_field / decrypt_field so every scheme is driven the
# same way: the application encrypts one field of one resource for one patient in
# one tenant, stores the string, and later decrypts what it finds in that cell.


class CbcHmac:
    """Typical shared-key design: AES-256-CBC + HMAC-SHA256 under one shared key, random IV."""

    name = "AES-256-CBC + HMAC, one shared key"
    has_key_versioning = False

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

    secrets_at_rest = "2, shared (cipher, MAC)"

    def rekey(self, tenant: str) -> Any:
        """Replace the leaked material; return a decryptor for ciphertexts written before."""
        old = copy.copy(self)
        self.key, self.mac_key = os.urandom(32), os.urandom(32)
        return old.decrypt_field

    def key_used_for(self, tenant: str, patient: str, rtype: str, path: str) -> bytes:
        return self.key + self.mac_key

    def raw_decrypt(
        self, key: bytes, tenant: str, patient: str, rtype: str, path: str, text: str
    ) -> None:
        """Decrypt one stored cell with a leaked key and nothing else. Raises on failure."""
        from cryptography.hazmat.primitives import hashes, hmac
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.padding import PKCS7

        enc_key, mac_key = key[:32], key[32:]
        raw = bytes.fromhex(text)
        iv, ct, tag = raw[:16], raw[16:-32], raw[-32:]
        h = hmac.HMAC(mac_key, hashes.SHA256())
        h.update(iv + ct)
        h.verify(tag)
        dec = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
        padded = dec.update(ct) + dec.finalize()
        unpadder = PKCS7(128).unpadder()
        unpadder.update(padded) + unpadder.finalize()


class PlainGCM:
    name = "AES-256-GCM, key per tenant, no AAD"
    has_key_versioning = False

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

    secrets_at_rest = "1 per tenant"

    def rekey(self, tenant: str) -> Any:
        old = copy.copy(self)
        old.keys = dict(self.keys)
        self.keys[tenant] = os.urandom(32)
        return old.decrypt_field

    def key_used_for(self, tenant: str, patient: str, rtype: str, path: str) -> bytes:
        return self.keys[tenant]

    def raw_decrypt(
        self, key: bytes, tenant: str, patient: str, rtype: str, path: str, text: str
    ) -> None:
        raw = bytes.fromhex(text)
        AESGCM(key).decrypt(raw[:12], raw[12:], b"")


class AadGCM:
    """AES-256-GCM, one key per tenant, the context bound as associated data.

    The associated data is the same four fields CPDPM binds, joined with a
    delimiter, which is how an application would write it. This is the strongest
    baseline the AEAD interface offers without a key hierarchy, and the one the
    binding claims of this paper have to be measured against.
    """

    name = "AES-256-GCM, key per tenant, context as AAD"
    has_key_versioning = False

    def __init__(self) -> None:
        self.keys = {TENANT_P: os.urandom(32), TENANT_Q: os.urandom(32)}

    @staticmethod
    def aad(tenant: str, patient: str, rtype: str, path: str) -> bytes:
        return "|".join((tenant, patient, rtype, path)).encode()

    def encrypt_field(self, tenant: str, patient: str, rtype: str, path: str, value: Any) -> str:
        nonce = os.urandom(12)
        aad = self.aad(tenant, patient, rtype, path)
        ct = AESGCM(self.keys[tenant]).encrypt(nonce, json.dumps(value).encode(), aad)
        return (nonce + ct).hex()

    def decrypt_field(self, tenant: str, patient: str, rtype: str, path: str, text: str) -> Any:
        raw = bytes.fromhex(text)
        aad = self.aad(tenant, patient, rtype, path)
        return json.loads(AESGCM(self.keys[tenant]).decrypt(raw[:12], raw[12:], aad))

    def rotate_and_retire(self) -> None:
        # One long-lived key per tenant; nothing to retire.
        pass

    secrets_at_rest = "1 per tenant"

    def rekey(self, tenant: str) -> Any:
        old = copy.copy(self)
        old.keys = dict(self.keys)
        self.keys[tenant] = os.urandom(32)
        return old.decrypt_field

    def key_used_for(self, tenant: str, patient: str, rtype: str, path: str) -> bytes:
        return self.keys[tenant]

    def raw_decrypt(
        self, key: bytes, tenant: str, patient: str, rtype: str, path: str, text: str
    ) -> None:
        raw = bytes.fromhex(text)
        AESGCM(key).decrypt(raw[:12], raw[12:], self.aad(tenant, patient, rtype, path))


class V2:
    name = "CPDPM (this work)"
    has_key_versioning = True

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

    secrets_at_rest = "1 per live master version"

    def rekey(self, tenant: str) -> Any:
        # A new master version. The old version stays readable until retired, so
        # cells the leaked key never opened need no immediate re-encryption.
        self.keyring.rotate()
        return self.decrypt_field

    def key_used_for(self, tenant: str, patient: str, rtype: str, path: str) -> bytes:
        # The per-context AEAD key the application derived for this one cell.
        ctx = Context(tenant, patient, rtype, path)
        return derive_context_key(self.keyring.master(self.keyring.current), Suite.AES_256_GCM, ctx)

    def raw_decrypt(
        self, key: bytes, tenant: str, patient: str, rtype: str, path: str, text: str
    ) -> None:
        # The adversary holds a derived key, not the master, so no HKDF: the raw AEAD
        # call with this cell's header and context as associated data.
        b64 = text[len(TEXT_PREFIX) :]
        blob = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4))
        header, offset = Header.unpack(blob)
        ctx = Context(tenant, patient, rtype, path)
        AESGCM(key).decrypt(header.nonce, blob[offset:], blob[:offset] + ctx.canonical())


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
    # A scheme without key versioning has nothing to retire; report the missing
    # capability rather than scoring a check it cannot perform.
    stale = alice_date
    if scheme.has_key_versioning:
        scheme.rotate_and_retire()
        results["stale_replay_after_retirement"] = attempt(
            lambda: scheme.decrypt_field(TENANT_P, alice_pid, rtype, "effectiveDateTime", stale)
        )
    else:
        results["stale_replay_after_retirement"] = {
            "outcome": "n/a",
            "note": "no key versioning, so no retirement to test; the old ciphertext stays valid",
        }
    return results


def _opens(scheme: Any, key: bytes, cell: tuple[str, str, str, str], text: str) -> bool:
    try:
        scheme.raw_decrypt(key, *cell, text)
    except Exception:
        return False
    return True


Cell = tuple[str, str, str, str]


def build_corpus(scheme: Any) -> tuple[list[Cell], dict[Cell, str], Cell]:
    """Write CORPUS_TENANTS x CORPUS_PATIENTS x CORPUS_FIELDS cells under ``scheme``.

    Returns the cell list, the stored ciphertexts, and the cell whose key the
    leak experiments give away (Alice's note in tenant P).
    """
    rows = load_rows(CORPUS_PATIENTS)
    rtype = "Observation"
    cells: list[Cell] = []
    stored: dict[Cell, str] = {}
    for tenant in CORPUS_TENANTS:
        for row in rows:
            obs = observation(row, tenant_hint=tenant)
            pid = obs["subject"]["reference"]
            values = {
                "note[*].text": obs["note"][0]["text"],
                "effectiveDateTime": obs["effectiveDateTime"],
            }
            for path in CORPUS_FIELDS:
                key = (tenant, pid, rtype, path)
                cells.append(key)
                stored[key] = scheme.encrypt_field(*key, values[path])
    alice = (
        TENANT_P,
        observation(rows[0], tenant_hint=TENANT_P)["subject"]["reference"],
        rtype,
        "note[*].text",
    )
    return cells, stored, alice


def leaked_key_exposure(scheme: Any) -> dict[str, Any]:
    """Leak the key the application used for one cell; count the cells it opens.

    The corpus is CORPUS_TENANTS x CORPUS_PATIENTS x CORPUS_FIELDS cells. The key
    for Alice's note in tenant P is leaked. Every cell is then attacked with that
    key alone, using the cell's own associated data (the adversary can read the
    row, so knows the context; what they lack is any other key).
    """
    cells, stored, alice = build_corpus(scheme)
    leaked = scheme.key_used_for(*alice)
    opened = 0
    opened_tenants: set[str] = set()
    opened_patients: set[str] = set()
    for cell in cells:
        if _opens(scheme, leaked, cell, stored[cell]):
            opened += 1
            opened_tenants.add(cell[0])
            opened_patients.add((cell[0], cell[1]))
    assert alice in stored and opened >= 1, "the leaked key must at least open its own cell"
    return {
        "scheme": scheme.name,
        "corpus_cells": len(cells),
        "corpus_tenants": len(CORPUS_TENANTS),
        "corpus_patients_per_tenant": CORPUS_PATIENTS,
        "corpus_fields": list(CORPUS_FIELDS),
        "leaked_key_for": {"tenant": alice[0], "patient": alice[1], "path": alice[3]},
        "cells_opened": opened,
        "tenants_opened": len(opened_tenants),
        "patients_opened": len(opened_patients),
    }


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
    schemes = [CbcHmac(), PlainGCM(), AadGCM(), V2()]
    per_scheme = [run_scheme(s) for s in schemes]
    attacks = ["patient_swap", "tenant_move", "field_move", "stale_replay_after_retirement"]
    matrix = {
        r["scheme"]: {a: r[a]["outcome"] for a in attacks}
        | {"control": r["control_correct_row"]["outcome"]}
        for r in per_scheme
    }
    for name, cells in matrix.items():
        print(f"{name:48s}", "  ".join(f"{a}={o}" for a, o in cells.items()))
    # Fresh instances: the swap run has rotated and retired CPDPM's first key version.
    exposure = [leaked_key_exposure(s) for s in (CbcHmac(), PlainGCM(), AadGCM(), V2())]
    for e in exposure:
        print(
            f"{e['scheme']:48s}",
            f"leaked key opens {e['cells_opened']}/{e['corpus_cells']} cells,",
            f"{e['patients_opened']} patients, {e['tenants_opened']} tenants",
        )
    write_result(
        "record_swap",
        {
            "matrix": matrix,
            "detail": per_scheme,
            "leaked_key_exposure": {e["scheme"]: e for e in exposure},
            "fhir_layer": fhir_level_demo(),
        },
        results_dir=RESULTS,
    )


if __name__ == "__main__":
    main()
