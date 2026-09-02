"""Cipher suites. Both are standard AEADs from audited libraries.

* AES-256-GCM via ``cryptography`` (OpenSSL). 96-bit nonce.
* XChaCha20-Poly1305 via ``PyNaCl`` (libsodium), optional. 192-bit nonce.
"""

from __future__ import annotations

from typing import Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cpdpm.errors import SuiteUnavailableError
from cpdpm.header import Suite


class AEAD(Protocol):
    def encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes: ...

    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes: ...


class AesGcm:
    def encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        return AESGCM(key).encrypt(nonce, plaintext, aad)

    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        try:
            return AESGCM(key).decrypt(nonce, ciphertext, aad)
        except InvalidTag as exc:
            raise ValueError("tag") from exc


class XChaCha20Poly1305:
    def __init__(self) -> None:
        try:
            from nacl import bindings
        except ImportError as exc:
            raise SuiteUnavailableError("PyNaCl is required: pip install cpdpm[xchacha]") from exc
        self._enc = bindings.crypto_aead_xchacha20poly1305_ietf_encrypt
        self._dec = bindings.crypto_aead_xchacha20poly1305_ietf_decrypt

    def encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        return bytes(self._enc(plaintext, aad, nonce, key))

    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        try:
            return bytes(self._dec(ciphertext, aad, nonce, key))
        except Exception as exc:  # nacl raises CryptoError; normalise
            raise ValueError("tag") from exc


def for_suite(suite: Suite) -> AEAD:
    if suite is Suite.AES_256_GCM:
        return AesGcm()
    if suite is Suite.XCHACHA20_POLY1305:
        return XChaCha20Poly1305()
    raise ValueError("unknown suite")  # pragma: no cover
