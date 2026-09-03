"""Key derivation. See ``docs/design.md`` §4, §6, §7.

* Per-context keys and commitments come from HKDF-SHA256 over a uniformly
  random master key. Empty salt is fine for uniformly random input keying
  material; the context and the suite go in ``info``.
* Password-derived master keys use Argon2id (optional dependency
  ``argon2-cffi``). PBKDF2 at 600,000 iterations exists only for migrating deployments
  that already hold PBKDF2-derived keys, and warns on use.
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from cpdpm.context import Context
from cpdpm.errors import SuiteUnavailableError
from cpdpm.header import Suite

KEY_LEN = 32
COMMIT_LEN = 32
_INFO_KEY = b"cpdpm/key"
_INFO_COMMIT = b"cpdpm/commit"
PBKDF2_ITERATIONS = 600_000


def _hkdf(ikm: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(ikm)


def derive_context_key(master: bytes, suite: Suite, ctx: Context) -> bytes:
    """32-byte AEAD key for one (master, suite, context) triple."""
    return _hkdf(master, _INFO_KEY + bytes([int(suite)]) + ctx.canonical(), KEY_LEN)


def derive_commitment(master: bytes, ctx: Context) -> bytes:
    """32-byte key-commitment value prepended to every plaintext (design §7)."""
    return _hkdf(master, _INFO_COMMIT + ctx.canonical(), COMMIT_LEN)


@dataclass(frozen=True)
class Argon2Params:
    memory_kib: int = 64 * 1024
    iterations: int = 3
    parallelism: int = 1


def master_from_password(password: bytes, salt: bytes, params: Argon2Params | None = None) -> bytes:
    """Argon2id. Requires ``pip install cpdpm[password]``."""
    if len(salt) < 16:
        raise ValueError("salt must be at least 16 bytes")
    p = params or Argon2Params()
    try:
        from argon2.low_level import Type, hash_secret_raw
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise SuiteUnavailableError("argon2-cffi is required: pip install cpdpm[password]") from exc
    return hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=p.iterations,
        memory_cost=p.memory_kib,
        parallelism=p.parallelism,
        hash_len=KEY_LEN,
        type=Type.ID,
    )


def master_from_password_pbkdf2(password: bytes, salt: bytes) -> bytes:
    """PBKDF2-HMAC-SHA256 at 600k iterations. Migration path only; prefer Argon2id."""
    warnings.warn(
        "PBKDF2 is a compatibility path; use master_from_password (Argon2id)",
        DeprecationWarning,
        stacklevel=2,
    )
    if len(salt) < 16:
        raise ValueError("salt must be at least 16 bytes")
    return PBKDF2HMAC(hashes.SHA256(), KEY_LEN, salt, PBKDF2_ITERATIONS).derive(password)
