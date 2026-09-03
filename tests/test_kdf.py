import os

import pytest

from cpdpm import Context, Suite
from cpdpm.kdf import (
    Argon2Params,
    derive_commitment,
    derive_context_key,
    master_from_password,
    master_from_password_pbkdf2,
)

CTX = Context("t", "p", "R", "f")


def test_context_key_is_deterministic_and_suite_separated() -> None:
    mk = os.urandom(32)
    a = derive_context_key(mk, Suite.AES_256_GCM, CTX)
    b = derive_context_key(mk, Suite.AES_256_GCM, CTX)
    c = derive_context_key(mk, Suite.XCHACHA20_POLY1305, CTX)
    assert a == b and len(a) == 32
    assert a != c
    assert derive_commitment(mk, CTX) != a
    assert derive_commitment(mk, CTX) == derive_commitment(mk, CTX)


def test_argon2id_master_key() -> None:
    pytest.importorskip("argon2")
    salt = os.urandom(16)
    params = Argon2Params(memory_kib=8 * 1024, iterations=1, parallelism=1)  # fast for tests
    k1 = master_from_password(b"correct horse battery staple", salt, params)  # noqa: S106
    k2 = master_from_password(b"correct horse battery staple", salt, params)  # noqa: S106
    k3 = master_from_password(b"correct horse battery stapler", salt, params)  # noqa: S106
    assert k1 == k2 and len(k1) == 32
    assert k1 != k3
    with pytest.raises(ValueError):
        master_from_password(b"x", b"short", params)


def test_pbkdf2_migration_path_warns() -> None:
    salt = os.urandom(16)
    with pytest.warns(DeprecationWarning):
        k = master_from_password_pbkdf2(b"migrated password", salt)
    assert len(k) == 32
    with pytest.raises(ValueError), pytest.warns(DeprecationWarning):
        master_from_password_pbkdf2(b"x", b"short")
