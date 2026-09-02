import json
import os

import pytest

from cpdpm import Keyring, KeyringError, LocalKeyWrapper


def test_kek_length_enforced() -> None:
    with pytest.raises(KeyringError):
        LocalKeyWrapper(b"short")


def test_unwrap_rejects_tamper_and_wrong_version() -> None:
    w = LocalKeyWrapper(os.urandom(32))
    wrapped = w.wrap(os.urandom(32), version=1)
    with pytest.raises(KeyringError):
        w.unwrap(wrapped, version=2)
    bad = bytearray(wrapped)
    bad[-1] ^= 1
    with pytest.raises(KeyringError):
        w.unwrap(bytes(bad), version=1)
    with pytest.raises(KeyringError):
        w.unwrap(b"", version=1)


def test_from_master_length() -> None:
    with pytest.raises(KeyringError):
        Keyring.from_master(b"short")


def test_retire_rules() -> None:
    kr = Keyring.generate()
    with pytest.raises(KeyringError):
        kr.retire(1)  # current
    with pytest.raises(KeyringError):
        kr.retire(7)  # unknown
    kr.rotate()
    kr.retire(1)
    assert kr.versions == (2,)
    with pytest.raises(KeyringError):
        kr.master(1)


def test_import_rejects_malformed_documents() -> None:
    w = LocalKeyWrapper(os.urandom(32))
    kr = Keyring.generate()
    good = json.loads(kr.export_wrapped(w))
    for doc in (
        "not json",
        json.dumps({**good, "format": "other"}),
        json.dumps({**good, "current": 9}),
        json.dumps({"format": "cpdpm-keyring-1"}),
        json.dumps({**good, "keys": {"1": "!!!"}}),
    ):
        with pytest.raises(KeyringError):
            Keyring.import_wrapped(doc, w)
    with pytest.raises(KeyringError):
        Keyring.import_wrapped(json.dumps(good), LocalKeyWrapper(os.urandom(32)))  # wrong KEK
