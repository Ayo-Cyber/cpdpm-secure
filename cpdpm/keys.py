"""Master keys, versions, rotation, and wrapping. See ``docs/design.md`` §4.

A :class:`Keyring` holds one or more 32-byte master data keys indexed by
version. New ciphertexts use ``current``; old versions stay for decryption
until retired. Retiring a version makes every ciphertext under it
unrecoverable (crypto-shredding).

Master keys are wrapped at rest by a :class:`KeyWrapper`. ``LocalKeyWrapper``
uses a 32-byte key-encryption key held by the caller and is meant for
development and tests; a KMS-backed wrapper implements the same two methods.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass, field
from typing import Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cpdpm.errors import KeyringError
from cpdpm.kdf import KEY_LEN


class KeyWrapper(Protocol):
    """Wraps and unwraps master keys. Implement against a KMS in production."""

    def wrap(self, key: bytes, version: int) -> bytes: ...

    def unwrap(self, wrapped: bytes, version: int) -> bytes: ...


class LocalKeyWrapper:
    """AES-256-GCM under a caller-supplied KEK; version is bound as associated data."""

    def __init__(self, kek: bytes) -> None:
        if len(kek) != KEY_LEN:
            raise KeyringError("KEK must be 32 bytes")
        self._kek = kek

    def wrap(self, key: bytes, version: int) -> bytes:
        nonce = os.urandom(12)
        return nonce + AESGCM(self._kek).encrypt(nonce, key, version.to_bytes(4, "big"))

    def unwrap(self, wrapped: bytes, version: int) -> bytes:
        try:
            return AESGCM(self._kek).decrypt(wrapped[:12], wrapped[12:], version.to_bytes(4, "big"))
        except (InvalidTag, ValueError, IndexError) as exc:
            raise KeyringError("cannot unwrap master key") from exc


@dataclass
class Keyring:
    _keys: dict[int, bytes] = field(default_factory=dict)
    current: int = 0

    @classmethod
    def generate(cls) -> Keyring:
        return cls({1: os.urandom(KEY_LEN)}, current=1)

    @classmethod
    def from_master(cls, master: bytes, version: int = 1) -> Keyring:
        if len(master) != KEY_LEN:
            raise KeyringError("master key must be 32 bytes")
        return cls({version: master}, current=version)

    def master(self, version: int) -> bytes:
        try:
            return self._keys[version]
        except KeyError as exc:
            raise KeyringError(f"no master key for version {version}") from exc

    @property
    def versions(self) -> tuple[int, ...]:
        return tuple(sorted(self._keys))

    def rotate(self) -> int:
        """Add a fresh master key as the new current version. Returns the version."""
        new = max(self._keys, default=0) + 1
        self._keys[new] = os.urandom(KEY_LEN)
        self.current = new
        return new

    def retire(self, version: int) -> None:
        """Destroy one version. Ciphertexts under it become unrecoverable."""
        if version == self.current:
            raise KeyringError("cannot retire the current version; rotate first")
        if version not in self._keys:
            raise KeyringError(f"no master key for version {version}")
        del self._keys[version]

    # Persistence via a wrapper -------------------------------------------------

    def export_wrapped(self, wrapper: KeyWrapper) -> str:
        doc = {
            "format": "cpdpm-keyring-1",
            "current": self.current,
            "keys": {
                str(v): base64.urlsafe_b64encode(wrapper.wrap(k, v)).decode()
                for v, k in self._keys.items()
            },
        }
        return json.dumps(doc, sort_keys=True)

    @classmethod
    def import_wrapped(cls, doc: str, wrapper: KeyWrapper) -> Keyring:
        try:
            data = json.loads(doc)
            if data["format"] != "cpdpm-keyring-1":
                raise KeyringError("unknown keyring format")
            keys = {
                int(v): wrapper.unwrap(base64.urlsafe_b64decode(w), int(v))
                for v, w in data["keys"].items()
            }
            current = int(data["current"])
        except (KeyError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise KeyringError("malformed keyring document") from exc
        if current not in keys:
            raise KeyringError("current version missing from keyring")
        return cls(keys, current=current)
