import dataclasses
import os

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from cpdpm import (
    Context,
    DecryptionError,
    Keyring,
    LocalKeyWrapper,
    Suite,
    decrypt,
    decrypt_from_str,
    encrypt,
    encrypt_to_str,
)
from cpdpm.header import FIXED_LEN

CTX = Context(
    tenant="org:st-marys", patient="Patient/8f3a", resource_type="Condition", field_path="code.text"
)

try:
    import nacl  # noqa: F401

    SUITES = [Suite.AES_256_GCM, Suite.XCHACHA20_POLY1305]
except ImportError:  # pragma: no cover
    SUITES = [Suite.AES_256_GCM]


@pytest.fixture
def keyring() -> Keyring:
    return Keyring.generate()


@pytest.mark.parametrize("suite", SUITES)
@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 1024, 1 << 20])
def test_roundtrip(keyring: Keyring, suite: Suite, size: int) -> None:
    pt = os.urandom(size)
    blob = encrypt(keyring, CTX, pt, suite=suite)
    assert decrypt(keyring, CTX, blob) == pt
    assert len(blob) == FIXED_LEN + suite.nonce_len + 32 + size + 16


@settings(max_examples=200, deadline=None)
@given(st.binary(max_size=4096))
def test_roundtrip_property(pt: bytes) -> None:
    kr = Keyring.generate()
    assert decrypt(kr, CTX, encrypt(kr, CTX, pt)) == pt


@pytest.mark.parametrize("suite", SUITES)
def test_every_byte_flip_is_rejected(keyring: Keyring, suite: Suite) -> None:
    blob = bytearray(encrypt(keyring, CTX, b"hello", suite=suite))
    for i in range(len(blob)):
        for bit in (0x01, 0x80):
            mutated = bytes(blob[:i] + bytes([blob[i] ^ bit]) + blob[i + 1 :])
            with pytest.raises(DecryptionError):
                decrypt(keyring, CTX, mutated)


def test_truncation_rejected(keyring: Keyring) -> None:
    blob = encrypt(keyring, CTX, b"hello")
    for n in range(len(blob)):
        with pytest.raises(DecryptionError):
            decrypt(keyring, CTX, blob[:n])


@pytest.mark.parametrize(
    "change",
    [
        {"tenant": "org:other"},
        {"patient": "Patient/0000"},
        {"resource_type": "Observation"},
        {"field_path": "note[*].text"},
        {"purpose": "research"},
    ],
)
def test_wrong_context_rejected(keyring: Keyring, change: dict[str, str]) -> None:
    blob = encrypt(keyring, CTX, b"secret")
    other = dataclasses.replace(CTX, **change)
    with pytest.raises(DecryptionError):
        decrypt(keyring, other, blob)


def test_record_swap_is_rejected(keyring: Keyring) -> None:
    """The attack from threat-model §5: Bob's ciphertext moved into Alice's row."""
    alice = dataclasses.replace(CTX, patient="Patient/alice")
    bob = dataclasses.replace(CTX, patient="Patient/bob")
    bob_blob = encrypt(keyring, bob, b"Bob's condition")
    with pytest.raises(DecryptionError):
        decrypt(keyring, alice, bob_blob)


def test_wrong_keyring_rejected(keyring: Keyring) -> None:
    blob = encrypt(keyring, CTX, b"secret")
    with pytest.raises(DecryptionError):
        decrypt(Keyring.generate(), CTX, blob)


def test_rotation_and_retirement(keyring: Keyring) -> None:
    old = encrypt(keyring, CTX, b"old")
    assert keyring.rotate() == 2
    new = encrypt(keyring, CTX, b"new")
    assert new[6:10] == (2).to_bytes(4, "big")
    assert decrypt(keyring, CTX, old) == b"old"
    assert decrypt(keyring, CTX, new) == b"new"
    keyring.retire(1)
    with pytest.raises(DecryptionError):
        decrypt(keyring, CTX, old)
    assert decrypt(keyring, CTX, new) == b"new"


def test_key_version_tamper_rejected(keyring: Keyring) -> None:
    keyring.rotate()
    blob = bytearray(encrypt(keyring, CTX, b"x", key_version=1))
    blob[6:10] = (2).to_bytes(4, "big")
    with pytest.raises(DecryptionError):
        decrypt(keyring, CTX, bytes(blob))


def test_text_form(keyring: Keyring) -> None:
    text = encrypt_to_str(keyring, CTX, b"hello")
    assert text.startswith("cpdpm1:")
    assert decrypt_from_str(keyring, CTX, text) == b"hello"
    with pytest.raises(DecryptionError):
        decrypt_from_str(keyring, CTX, "cpdpm1:!!!not base64!!!")
    with pytest.raises(DecryptionError):
        decrypt_from_str(
            keyring, CTX, "eyJ2ZXJzaW9uIjogIjEuMCJ9"
        )  # a base64 JSON blob from another scheme


def test_garbage_never_leaks_exception_type(keyring: Keyring) -> None:
    for junk in (b"", b"CPDM", os.urandom(3), os.urandom(64), b"\x00" * 100):
        with pytest.raises(DecryptionError) as info:
            decrypt(keyring, CTX, junk)
        assert str(info.value) == "decryption failed"
        assert info.value.__cause__ is None


def test_keyring_wrap_roundtrip(keyring: Keyring) -> None:
    keyring.rotate()
    wrapper = LocalKeyWrapper(os.urandom(32))
    doc = keyring.export_wrapped(wrapper)
    restored = Keyring.import_wrapped(doc, wrapper)
    assert restored.versions == keyring.versions
    assert restored.current == keyring.current
    blob = encrypt(keyring, CTX, b"persisted")
    assert decrypt(restored, CTX, blob) == b"persisted"
