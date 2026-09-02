"""Known-answer vectors. Regenerate only deliberately: python -m paper.construction.gen_kat"""

import json
from pathlib import Path

import pytest

from cpdpm import Context, Keyring, Suite, decrypt
from cpdpm.core import _encrypt_with_nonce

VECTORS = json.loads((Path(__file__).parent / "vectors" / "v2_kat.json").read_text())
MASTER = bytes(range(1, 33))  # public test-vector key; the JSON stores its recipe, not the bytes


@pytest.mark.parametrize("vec", VECTORS["vectors"], ids=lambda v: v["name"])
def test_known_answer(vec: dict) -> None:  # type: ignore[type-arg]
    if vec["suite"] == Suite.XCHACHA20_POLY1305:
        pytest.importorskip("nacl")
    assert VECTORS["master_key"] == "bytes(range(1, 33))"
    kr = Keyring.from_master(MASTER, version=vec["key_version"])
    ctx = Context(**vec["context"])
    assert ctx.canonical().hex() == vec["context_canonical_hex"]
    blob = bytes.fromhex(vec["blob_hex"])
    pt = bytes.fromhex(vec["plaintext_hex"])
    assert decrypt(kr, ctx, blob) == pt
    regenerated = _encrypt_with_nonce(
        kr, ctx, pt, Suite(vec["suite"]), vec["key_version"], bytes.fromhex(vec["nonce_hex"])
    )
    assert regenerated == blob
