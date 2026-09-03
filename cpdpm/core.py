"""Encrypt and decrypt a value bound to a :class:`~cpdpm.context.Context`.

Layout of a blob::

    header || AEAD( K_ctx, nonce, aad = header || canon(ctx), commit || plaintext )

``K_ctx`` and ``commit`` are derived from the master key for ``header.key_version``
and the caller-supplied context. The context is never stored; the caller must
supply it from an authenticated source at decrypt time (threat model §6.2).
"""

from __future__ import annotations

import base64
import hmac
import os

from cpdpm.aead import for_suite
from cpdpm.context import Context
from cpdpm.errors import DecryptionError
from cpdpm.header import Header, Suite
from cpdpm.kdf import COMMIT_LEN, derive_commitment, derive_context_key
from cpdpm.keys import Keyring

TEXT_PREFIX = "cpdpm1:"


def _encrypt_with_nonce(
    keyring: Keyring, ctx: Context, plaintext: bytes, suite: Suite, version: int, nonce: bytes
) -> bytes:
    master = keyring.master(version)
    header = Header(suite, version, nonce)
    hdr = header.pack()
    key = derive_context_key(master, suite, ctx)
    body = derive_commitment(master, ctx) + plaintext
    return hdr + for_suite(suite).encrypt(key, nonce, body, hdr + ctx.canonical())


def encrypt(
    keyring: Keyring,
    ctx: Context,
    plaintext: bytes,
    *,
    suite: Suite = Suite.AES_256_GCM,
    key_version: int | None = None,
) -> bytes:
    """Encrypt ``plaintext`` for ``ctx`` under the keyring's current (or given) version."""
    version = keyring.current if key_version is None else key_version
    nonce = os.urandom(suite.nonce_len)
    return _encrypt_with_nonce(keyring, ctx, bytes(plaintext), suite, version, nonce)


def decrypt(keyring: Keyring, ctx: Context, blob: bytes) -> bytes:
    """Decrypt ``blob`` for ``ctx``. Raises :class:`DecryptionError` on any failure."""
    try:
        header, offset = Header.unpack(blob)
        master = keyring.master(header.key_version)
        key = derive_context_key(master, header.suite, ctx)
        aad = blob[:offset] + ctx.canonical()
        body = for_suite(header.suite).decrypt(key, header.nonce, blob[offset:], aad)
        expected = derive_commitment(master, ctx)
        if len(body) < COMMIT_LEN or not hmac.compare_digest(body[:COMMIT_LEN], expected):
            raise ValueError("commitment")
        return body[COMMIT_LEN:]
    except Exception:
        raise DecryptionError() from None


def encrypt_to_str(
    keyring: Keyring,
    ctx: Context,
    plaintext: bytes,
    *,
    suite: Suite = Suite.AES_256_GCM,
    key_version: int | None = None,
) -> str:
    """Text form for JSON stores: ``cpdpm1:<base64url>``."""
    blob = encrypt(keyring, ctx, plaintext, suite=suite, key_version=key_version)
    return TEXT_PREFIX + base64.urlsafe_b64encode(blob).rstrip(b"=").decode("ascii")


def decrypt_from_str(keyring: Keyring, ctx: Context, text: str) -> bytes:
    try:
        if not text.startswith(TEXT_PREFIX):
            raise ValueError("prefix")
        b64 = text[len(TEXT_PREFIX) :]
        blob = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4))
    except Exception:
        raise DecryptionError() from None
    return decrypt(keyring, ctx, blob)


def is_cpdpm_text(text: str) -> bool:
    return text.startswith(TEXT_PREFIX)
