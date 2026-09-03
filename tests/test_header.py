import pytest

from cpdpm.header import FIXED_LEN, TAG_LEN, Header, Suite


def test_pack_unpack_roundtrip() -> None:
    h = Header(Suite.AES_256_GCM, 7, bytes(range(12)))
    packed = h.pack()
    assert len(packed) == FIXED_LEN + 12
    parsed, offset = Header.unpack(packed + b"\x00" * TAG_LEN)
    assert parsed == h
    assert offset == FIXED_LEN + 12


def test_xchacha_nonce_len() -> None:
    h = Header(Suite.XCHACHA20_POLY1305, 1, bytes(24))
    parsed, offset = Header.unpack(h.pack() + b"\x00" * TAG_LEN)
    assert parsed.suite is Suite.XCHACHA20_POLY1305
    assert offset == FIXED_LEN + 24


def test_wrong_nonce_len_rejected_at_construction() -> None:
    with pytest.raises(ValueError):
        Header(Suite.AES_256_GCM, 1, bytes(24))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b: b[:5],  # short
        lambda b: b"XXXX" + b[4:],  # bad magic
        lambda b: b[:4] + b"\x02" + b[5:],  # wrong protocol version
        lambda b: b[:5] + b"\x09" + b[6:],  # unknown suite
        lambda b: b[:10] + b"\x18" + b[11:],  # nonce_len mismatch for suite
        lambda b: b[: FIXED_LEN + 12 + TAG_LEN - 1],  # truncated before tag
    ],
)
def test_malformed_rejected(mutate) -> None:  # type: ignore[no-untyped-def]
    good = Header(Suite.AES_256_GCM, 1, bytes(12)).pack() + b"\x00" * TAG_LEN
    with pytest.raises(ValueError):
        Header.unpack(mutate(good))
