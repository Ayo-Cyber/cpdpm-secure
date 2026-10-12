"""The failure branches a security library cannot leave untested.

Each test here targets a line that an earlier coverage report showed was never
executed: the commitment-mismatch branch of both decrypt paths, the stream
chunk-counter bound, and the FHIR layer's structural rejections.
"""

from __future__ import annotations

import copy
import io
import json
import os

import pytest

from cpdpm import Context, DecryptionError, Keyring, Suite, decrypt, encrypt_to_str
from cpdpm.aead import for_suite
from cpdpm.core import is_cpdpm_text
from cpdpm.fhir import (
    MANIFEST_PATH,
    MANIFEST_SYSTEM,
    WHOLE,
    decrypt_resource,
    decrypt_resource_whole,
    encrypt_resource,
)
from cpdpm.header import Header
from cpdpm.kdf import COMMIT_LEN, derive_commitment, derive_context_key
from cpdpm.stream import _COUNTER_MAX, _nonce, _pack_header, decrypt_stream, encrypt_stream

CTX = Context("org:st-marys", "Patient/8f3a", "Condition", "code.text")
TENANT = "org:st-marys"


def _forge_blob(kr: Keyring, ctx: Context, body: bytes) -> bytes:
    """What an adversary holding the leaked per-context key, but not the master, can make."""
    suite = Suite.AES_256_GCM
    key = derive_context_key(kr.master(kr.current), suite, ctx)
    nonce = os.urandom(suite.nonce_len)
    hdr = Header(suite, kr.current, nonce).pack()
    return hdr + for_suite(suite).encrypt(key, nonce, body, hdr + ctx.canonical())


def test_forged_blob_with_leaked_context_key_is_rejected() -> None:
    kr = Keyring.generate()
    # Wrong commitment: the tag verifies, the commitment does not.
    with pytest.raises(DecryptionError):
        decrypt(kr, CTX, _forge_blob(kr, CTX, os.urandom(COMMIT_LEN) + b"forged"))
    # Body shorter than a commitment.
    with pytest.raises(DecryptionError):
        decrypt(kr, CTX, _forge_blob(kr, CTX, b"short"))
    # Control: the same forgery with the right commitment decrypts, so the
    # rejection above is the commitment check and nothing else.
    commit = derive_commitment(kr.master(kr.current), CTX)
    assert decrypt(kr, CTX, _forge_blob(kr, CTX, commit + b"ok")) == b"ok"


def test_forged_stream_with_leaked_context_key_is_rejected() -> None:
    kr = Keyring.generate()
    suite = Suite.AES_256_GCM
    ctx = Context(TENANT, "Patient/8f3a", "Binary", "*")
    key = derive_context_key(kr.master(kr.current), suite, ctx)
    prefix = os.urandom(suite.nonce_len - 5)
    header = _pack_header(suite, kr.current, 1024, prefix)
    aad = header + ctx.canonical()
    body = os.urandom(COMMIT_LEN) + b"forged stream"
    blob = header + for_suite(suite).encrypt(key, _nonce(prefix, 0, True), body, aad)
    with pytest.raises(DecryptionError):
        decrypt_stream(kr, ctx, io.BytesIO(blob), io.BytesIO())


def test_stream_chunk_counter_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    import cpdpm.stream as stream

    assert _COUNTER_MAX == 0xFFFFFFFF
    monkeypatch.setattr(stream, "_COUNTER_MAX", 1)
    kr = Keyring.generate()
    ctx = Context(TENANT, "Patient/8f3a", "Binary", "*")
    with pytest.raises(ValueError, match="32-bit chunk counter"):
        encrypt_stream(kr, ctx, io.BytesIO(b"x" * 3000), io.BytesIO(), chunk_size=1024)


def test_is_cpdpm_text() -> None:
    kr = Keyring.generate()
    assert is_cpdpm_text(encrypt_to_str(kr, CTX, b"v"))
    assert not is_cpdpm_text("plain")


def _condition() -> dict:
    return {
        "resourceType": "Condition",
        "subject": {"reference": "Patient/8f3a"},
        "code": {"text": "Type 2 diabetes mellitus"},
        "note": [{"text": "stable"}],
    }


def test_fhir_rejects_encrypting_an_already_encrypted_field() -> None:
    kr = Keyring.generate()
    res = _condition()
    res["code"]["text"] = encrypt_to_str(
        kr, Context(TENANT, "Patient/8f3a", "Condition", "code.text"), b"x"
    )
    with pytest.raises(ValueError, match="already encrypted"):
        encrypt_resource(kr, TENANT, res, ["code.text"])


def test_fhir_rejects_recorded_path_replaced_by_plaintext() -> None:
    kr = Keyring.generate()
    doc = encrypt_resource(kr, TENANT, _condition(), ["code.text", "note[*].text"])
    tampered = copy.deepcopy(doc)
    tampered["code"]["text"] = "Type 2 diabetes mellitus"  # adversary writes plaintext back
    with pytest.raises(DecryptionError):
        decrypt_resource(kr, TENANT, tampered, patient="Patient/8f3a")


def test_fhir_rejects_unknown_manifest_version() -> None:
    kr = Keyring.generate()
    doc = encrypt_resource(kr, TENANT, _condition(), ["code.text"])
    tag = next(t for t in doc["meta"]["tag"] if t["system"] == MANIFEST_SYSTEM)
    mctx = Context(TENANT, "Patient/8f3a", "Condition", MANIFEST_PATH)
    manifest = json.loads(__import__("cpdpm").decrypt_from_str(kr, mctx, tag["code"]).decode())
    manifest["v"] = 2
    tag["code"] = encrypt_to_str(
        kr, mctx, json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode()
    )
    with pytest.raises(DecryptionError):
        decrypt_resource(kr, TENANT, doc, patient="Patient/8f3a")


def test_whole_resource_non_json_payload_is_decryption_error() -> None:
    kr = Keyring.generate()
    ctx = Context(TENANT, "Patient/8f3a", "Condition", WHOLE)
    text = encrypt_to_str(kr, ctx, b"not json")
    with pytest.raises(DecryptionError):
        decrypt_resource_whole(kr, TENANT, text, resource_type="Condition", patient="Patient/8f3a")
