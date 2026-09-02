import io
import os
from pathlib import Path

import pytest

from cpdpm import Context, DecryptionError, Keyring, Suite
from cpdpm.header import TAG_LEN
from cpdpm.kdf import COMMIT_LEN
from cpdpm.stream import FIXED_LEN, decrypt_stream, encrypt_stream

CTX = Context("org:st-marys", "Patient/8f3a", "Binary", "*")
CHUNK = 1024

try:
    import nacl  # noqa: F401

    SUITES = [Suite.AES_256_GCM, Suite.XCHACHA20_POLY1305]
except ImportError:  # pragma: no cover
    SUITES = [Suite.AES_256_GCM]


def enc(kr: Keyring, data: bytes, suite: Suite = Suite.AES_256_GCM, chunk: int = CHUNK) -> bytes:
    out = io.BytesIO()
    encrypt_stream(kr, CTX, io.BytesIO(data), out, suite=suite, chunk_size=chunk)
    return out.getvalue()


def dec(kr: Keyring, blob: bytes, ctx: Context = CTX) -> bytes:
    out = io.BytesIO()
    decrypt_stream(kr, ctx, io.BytesIO(blob), out)
    return out.getvalue()


@pytest.mark.parametrize("suite", SUITES)
@pytest.mark.parametrize("size", [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK, 3 * CHUNK + 7])
def test_roundtrip(suite: Suite, size: int) -> None:
    kr = Keyring.generate()
    data = os.urandom(size)
    blob = enc(kr, data, suite)
    chunks = max(1, -(-size // CHUNK))
    assert len(blob) == FIXED_LEN + (suite.nonce_len - 5) + COMMIT_LEN + size + chunks * TAG_LEN
    assert dec(kr, blob) == data


def test_file_roundtrip(tmp_path: Path) -> None:
    kr = Keyring.generate()
    src = tmp_path / "scan.bin"
    src.write_bytes(os.urandom(5 * CHUNK + 123))
    with src.open("rb") as f, (tmp_path / "scan.enc").open("wb") as g:
        encrypt_stream(kr, CTX, f, g, chunk_size=CHUNK)
    with (tmp_path / "scan.enc").open("rb") as f, (tmp_path / "scan.out").open("wb") as g:
        decrypt_stream(kr, CTX, f, g)
    assert (tmp_path / "scan.out").read_bytes() == src.read_bytes()


def test_truncation_at_every_length_is_rejected() -> None:
    kr = Keyring.generate()
    blob = enc(kr, os.urandom(2 * CHUNK + 5))
    for n in range(len(blob)):
        with pytest.raises(DecryptionError):
            dec(kr, blob[:n])


def test_extension_is_rejected() -> None:
    kr = Keyring.generate()
    blob = enc(kr, os.urandom(CHUNK))
    for extra in (b"\x00", os.urandom(TAG_LEN), os.urandom(CHUNK + TAG_LEN)):
        with pytest.raises(DecryptionError):
            dec(kr, blob + extra)


def _chunk_bounds(size: int) -> list[tuple[int, int]]:
    """Byte ranges of each ciphertext chunk for an AES-GCM stream of ``size`` plaintext bytes."""
    start = FIXED_LEN + 7
    bounds = []
    remaining = size
    first = True
    while True:
        n = min(CHUNK, remaining)
        length = (COMMIT_LEN if first else 0) + n + TAG_LEN
        bounds.append((start, start + length))
        start += length
        remaining -= n
        first = False
        if remaining <= 0:
            return bounds


def test_chunk_drop_swap_and_duplicate_are_rejected() -> None:
    kr = Keyring.generate()
    data = os.urandom(4 * CHUNK)
    blob = enc(kr, data)
    b = _chunk_bounds(len(data))
    assert len(b) == 4 and b[-1][1] == len(blob)
    c = [blob[s:e] for s, e in b]
    head = blob[: b[0][0]]
    for variant in (
        head + c[0] + c[2] + c[3],  # drop middle chunk
        head + c[0] + c[2] + c[1] + c[3],  # swap two chunks
        head + c[0] + c[1] + c[1] + c[2] + c[3],  # duplicate a chunk
        head + c[0] + c[1] + c[2],  # drop the last chunk
        head + c[1] + c[0] + c[2] + c[3],  # move the first chunk
    ):
        with pytest.raises(DecryptionError):
            dec(kr, variant)


def test_tamper_bits_in_header_and_body() -> None:
    kr = Keyring.generate()
    blob = bytearray(enc(kr, os.urandom(CHUNK + 3)))
    for i in list(range(0, FIXED_LEN + 7)) + [len(blob) // 2, len(blob) - 1]:
        mutated = bytes(blob[:i] + bytes([blob[i] ^ 0x01]) + blob[i + 1 :])
        with pytest.raises(DecryptionError):
            dec(kr, mutated)


def test_wrong_context_and_wrong_key_are_rejected() -> None:
    kr = Keyring.generate()
    blob = enc(kr, os.urandom(10))
    with pytest.raises(DecryptionError):
        dec(kr, blob, Context("org:st-marys", "Patient/other", "Binary", "*"))
    with pytest.raises(DecryptionError):
        dec(Keyring.generate(), blob)


def test_rotation_and_retirement() -> None:
    kr = Keyring.generate()
    old = enc(kr, b"old")
    kr.rotate()
    assert dec(kr, old) == b"old"
    kr.retire(1)
    with pytest.raises(DecryptionError):
        dec(kr, old)


def test_chunk_size_bounds() -> None:
    kr = Keyring.generate()
    with pytest.raises(ValueError):
        encrypt_stream(kr, CTX, io.BytesIO(b""), io.BytesIO(), chunk_size=0)
    with pytest.raises(ValueError):
        encrypt_stream(kr, CTX, io.BytesIO(b""), io.BytesIO(), chunk_size=(64 << 20) + 1)


def test_garbage_is_decryption_error() -> None:
    kr = Keyring.generate()
    for junk in (b"", b"CPDS", os.urandom(14), os.urandom(200)):
        with pytest.raises(DecryptionError):
            dec(kr, junk)
