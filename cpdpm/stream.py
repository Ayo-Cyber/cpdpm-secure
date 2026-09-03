"""Chunked (streaming) encryption for payloads too large to hold in memory.

Construction: STREAM (Hoang, Reyhanitabar, Rogaway, Vizár, CRYPTO 2015) over the
same per-context AEAD as :mod:`cpdpm.core`. The nonce of chunk *i* is
``prefix || u32be(i) || last_flag``; the associated data is the stream header
plus the canonical context. The 32-byte key commitment is prepended to the
first chunk. Truncation, reordering, dropping, duplicating or extending chunks
all fail authentication.

Wire format::

    0   4   magic "CPDS"
    4   1   protocol version = 0x01
    5   1   suite
    6   4   key_version (u32be)
    10  4   chunk_size (u32be), plaintext bytes per chunk
    14  1   prefix_len (= suite nonce length - 5)
    15  n   nonce prefix
    ...     chunk_0 || chunk_1 || ... each = AEAD ciphertext || 16-byte tag

Decryption releases each chunk after it authenticates, so a consumer that
receives ``DecryptionError`` part-way through must discard everything already
written. That is inherent to streaming AEAD.
"""

from __future__ import annotations

import hmac
import os
from typing import BinaryIO

from cpdpm.aead import for_suite
from cpdpm.context import Context
from cpdpm.errors import DecryptionError
from cpdpm.header import TAG_LEN, Suite
from cpdpm.kdf import COMMIT_LEN, derive_commitment, derive_context_key
from cpdpm.keys import Keyring

MAGIC = b"CPDS"
PROTOCOL_VERSION = 1
FIXED_LEN = 15
DEFAULT_CHUNK = 1 << 20
MAX_CHUNK = 64 << 20
_COUNTER_MAX = 0xFFFFFFFF


def _read_exact(src: BinaryIO, n: int) -> bytes:
    out = bytearray()
    while len(out) < n:
        piece = src.read(n - len(out))
        if not piece:
            break
        out += piece
    return bytes(out)


def _nonce(prefix: bytes, counter: int, last: bool) -> bytes:
    return prefix + counter.to_bytes(4, "big") + (b"\x01" if last else b"\x00")


def _pack_header(suite: Suite, key_version: int, chunk_size: int, prefix: bytes) -> bytes:
    return (
        MAGIC
        + bytes([PROTOCOL_VERSION, int(suite)])
        + key_version.to_bytes(4, "big")
        + chunk_size.to_bytes(4, "big")
        + bytes([len(prefix)])
        + prefix
    )


def encrypt_stream(
    keyring: Keyring,
    ctx: Context,
    src: BinaryIO,
    dst: BinaryIO,
    *,
    suite: Suite = Suite.AES_256_GCM,
    key_version: int | None = None,
    chunk_size: int = DEFAULT_CHUNK,
) -> int:
    """Encrypt ``src`` to ``dst`` in chunks. Returns the number of ciphertext bytes written."""
    if not 1 <= chunk_size <= MAX_CHUNK:
        raise ValueError("chunk_size out of range")
    version = keyring.current if key_version is None else key_version
    master = keyring.master(version)
    prefix = os.urandom(suite.nonce_len - 5)
    header = _pack_header(suite, version, chunk_size, prefix)
    aad = header + ctx.canonical()
    key = derive_context_key(master, suite, ctx)
    commit = derive_commitment(master, ctx)
    aead = for_suite(suite)

    written = dst.write(header)
    buf = _read_exact(src, chunk_size)
    nxt = _read_exact(src, chunk_size)
    counter = 0
    first = True
    while True:
        last = not nxt
        plaintext = (commit if first else b"") + buf
        written += dst.write(aead.encrypt(key, _nonce(prefix, counter, last), plaintext, aad))
        if last:
            return written
        first = False
        counter += 1
        if counter > _COUNTER_MAX:
            raise ValueError("stream too long for a 32-bit chunk counter")
        buf, nxt = nxt, _read_exact(src, chunk_size)


def decrypt_stream(keyring: Keyring, ctx: Context, src: BinaryIO, dst: BinaryIO) -> int:
    """Decrypt ``src`` to ``dst``. Returns plaintext bytes written.

    Raises :class:`DecryptionError` on any failure. Output written before the
    failure must be discarded by the caller.
    """
    try:
        header = _read_exact(src, FIXED_LEN)
        if len(header) != FIXED_LEN or header[:4] != MAGIC or header[4] != PROTOCOL_VERSION:
            raise ValueError("header")
        suite = Suite(header[5])
        version = int.from_bytes(header[6:10], "big")
        chunk_size = int.from_bytes(header[10:14], "big")
        prefix_len = header[14]
        if not 1 <= chunk_size <= MAX_CHUNK or prefix_len != suite.nonce_len - 5:
            raise ValueError("header fields")
        prefix = _read_exact(src, prefix_len)
        if len(prefix) != prefix_len:
            raise ValueError("prefix")
        header += prefix
        aad = header + ctx.canonical()
        master = keyring.master(version)
        key = derive_context_key(master, suite, ctx)
        commit = derive_commitment(master, ctx)
        aead = for_suite(suite)

        first_len = COMMIT_LEN + chunk_size + TAG_LEN
        other_len = chunk_size + TAG_LEN
        buf = _read_exact(src, first_len)
        nxt = _read_exact(src, other_len)
        counter = 0
        first = True
        written = 0
        while True:
            last = not nxt
            plaintext = aead.decrypt(key, _nonce(prefix, counter, last), buf, aad)
            if first:
                if len(plaintext) < COMMIT_LEN or not hmac.compare_digest(
                    plaintext[:COMMIT_LEN], commit
                ):
                    raise ValueError("commitment")
                plaintext = plaintext[COMMIT_LEN:]
                first = False
            written += dst.write(plaintext)
            if last:
                return written
            counter += 1
            buf, nxt = nxt, _read_exact(src, other_len)
    except Exception:
        raise DecryptionError() from None
