"""Wire format header. See ``docs/design-v2.md`` §5.

::

    offset  size  field
    0       4     magic  "CPDM"
    4       1     protocol version = 0x02
    5       1     suite
    6       4     key_version (u32be)
    10      1     nonce_len
    11      n     nonce

The packed header is part of the associated data, so any change to it is a
forgery.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

MAGIC = b"CPDM"
PROTOCOL_VERSION = 2
FIXED_LEN = 11
TAG_LEN = 16


class Suite(IntEnum):
    AES_256_GCM = 0x01
    XCHACHA20_POLY1305 = 0x02

    @property
    def nonce_len(self) -> int:
        return _NONCE_LEN[self]


_NONCE_LEN = {Suite.AES_256_GCM: 12, Suite.XCHACHA20_POLY1305: 24}


@dataclass(frozen=True)
class Header:
    suite: Suite
    key_version: int
    nonce: bytes

    def __post_init__(self) -> None:
        if not 0 <= self.key_version <= 0xFFFFFFFF:
            raise ValueError("key_version out of range")
        if len(self.nonce) != self.suite.nonce_len:
            raise ValueError("nonce length does not match suite")

    def pack(self) -> bytes:
        return (
            MAGIC
            + bytes([PROTOCOL_VERSION, int(self.suite)])
            + self.key_version.to_bytes(4, "big")
            + bytes([len(self.nonce)])
            + self.nonce
        )

    @classmethod
    def unpack(cls, blob: bytes) -> tuple[Header, int]:
        """Parse a header from the start of ``blob``. Returns (header, body_offset).

        Raises ``ValueError`` on any malformation. Callers on the decrypt path
        must convert that to :class:`~cpdpm.errors.DecryptionError`.
        """
        if len(blob) < FIXED_LEN:
            raise ValueError("short header")
        if blob[:4] != MAGIC:
            raise ValueError("bad magic")
        if blob[4] != PROTOCOL_VERSION:
            raise ValueError("unsupported protocol version")
        try:
            suite = Suite(blob[5])
        except ValueError as exc:
            raise ValueError("unknown suite") from exc
        key_version = int.from_bytes(blob[6:10], "big")
        nonce_len = blob[10]
        if nonce_len != suite.nonce_len:
            raise ValueError("nonce length does not match suite")
        end = FIXED_LEN + nonce_len
        if len(blob) < end + TAG_LEN:
            raise ValueError("truncated")
        return cls(suite, key_version, bytes(blob[FIXED_LEN:end])), end
