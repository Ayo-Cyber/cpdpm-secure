import builtins
import sys

import pytest

from cpdpm import Context, ContextError, DecryptionError, Keyring, SuiteUnavailableError
from cpdpm.aead import XChaCha20Poly1305
from cpdpm.fhir import decrypt_resource, decrypt_resource_whole, encrypt_resource
from cpdpm.header import Header, Suite


def test_context_rejects_non_str() -> None:
    with pytest.raises(ContextError):
        Context("t", 5, "R", "f")  # type: ignore[arg-type]


def test_header_key_version_range() -> None:
    with pytest.raises(ValueError):
        Header(Suite.AES_256_GCM, -1, bytes(12))
    with pytest.raises(ValueError):
        Header(Suite.AES_256_GCM, 1 << 32, bytes(12))


def test_xchacha_unavailable_is_a_clear_error(monkeypatch: pytest.MonkeyPatch) -> None:
    real_import = builtins.__import__

    def fake_import(name: str, *args: object, **kwargs: object) -> object:
        if name == "nacl" or name.startswith("nacl."):
            raise ImportError("no nacl")
        return real_import(name, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.delitem(sys.modules, "nacl", raising=False)
    monkeypatch.delitem(sys.modules, "nacl.bindings", raising=False)
    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(SuiteUnavailableError):
        XChaCha20Poly1305()


def test_fhir_paths_through_non_containers_are_skipped() -> None:
    kr = Keyring.generate()
    res = {
        "resourceType": "Observation",
        "subject": {"reference": "Patient/p"},
        "code": "just-a-string",  # path code.text walks into a non-dict
        "note": {"text": "not a list"},  # note[*].text expects a list
    }
    enc = encrypt_resource(kr, "t", res, ["code.text", "note[*].text"])
    assert enc["code"] == "just-a-string"
    assert enc["note"] == {"text": "not a list"}
    assert not [t for t in enc["meta"]["tag"] if t["system"] == "urn:cpdpm:encrypted-paths"]


def test_fhir_requires_resource_type() -> None:
    kr = Keyring.generate()
    with pytest.raises(ValueError):
        encrypt_resource(kr, "t", {"id": "x"}, ["id"])
    with pytest.raises(DecryptionError):
        decrypt_resource(kr, "t", {"id": "x"}, patient="")


def test_whole_resource_garbage_is_decryption_error() -> None:
    kr = Keyring.generate()
    with pytest.raises(DecryptionError):
        decrypt_resource_whole(kr, "t", "not a blob", resource_type="Condition", patient="")


def test_context_rejects_lone_surrogates_with_context_error() -> None:
    for bad in ("t\ud800", "\udfff", "a\ud83d"):
        with pytest.raises(ContextError):
            Context(bad, "p", "R", "f")
