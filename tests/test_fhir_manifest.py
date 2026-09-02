"""Structural integrity of field-level encrypted resources (the manifest)."""

import copy

import pytest

from cpdpm import DecryptionError, Keyring
from cpdpm.fhir import MANIFEST_SYSTEM, TAG_SYSTEM, decrypt_resource, encrypt_resource

TENANT = "org:st-marys"
ALICE = "Patient/alice"
POLICY = ["code.text", "note[*].text"]
RES = {
    "resourceType": "Condition",
    "subject": {"reference": ALICE},
    "code": {"coding": [{"code": "44054006"}], "text": "Type 2 diabetes mellitus"},
    "note": [
        {"text": "Diet controlled"},
        {"text": "Metformin started"},
        {"text": "Allergy: penicillin"},
    ],
}


@pytest.fixture
def kr() -> Keyring:
    return Keyring.generate()


def _manifest_tags(doc: dict) -> list[dict]:  # type: ignore[type-arg]
    return [t for t in doc["meta"]["tag"] if t["system"] == MANIFEST_SYSTEM]


def test_manifest_present_and_roundtrip(kr: Keyring) -> None:
    enc = encrypt_resource(kr, TENANT, RES, POLICY)
    assert len(_manifest_tags(enc)) == 1
    assert decrypt_resource(kr, TENANT, enc, patient=ALICE) == RES


def test_deleting_an_encrypted_note_is_detected(kr: Keyring) -> None:
    enc = encrypt_resource(kr, TENANT, RES, POLICY)
    del enc["note"][2]  # the allergy note disappears
    with pytest.raises(DecryptionError):
        decrypt_resource(kr, TENANT, enc, patient=ALICE)


def test_reordering_encrypted_notes_is_detected(kr: Keyring) -> None:
    enc = encrypt_resource(kr, TENANT, RES, POLICY)
    enc["note"][0], enc["note"][1] = enc["note"][1], enc["note"][0]
    with pytest.raises(DecryptionError):
        decrypt_resource(kr, TENANT, enc, patient=ALICE)


def test_partial_replay_of_one_field_is_detected(kr: Keyring) -> None:
    old = encrypt_resource(kr, TENANT, RES, POLICY)
    new_res = copy.deepcopy(RES)
    new_res["code"]["text"] = "Type 2 diabetes mellitus, in remission"
    new = encrypt_resource(kr, TENANT, new_res, POLICY)
    new["code"]["text"] = old["code"]["text"]  # same patient, same field, older ciphertext
    with pytest.raises(DecryptionError):
        decrypt_resource(kr, TENANT, new, patient=ALICE)


def test_forged_extra_encrypted_element_is_detected(kr: Keyring) -> None:
    enc = encrypt_resource(kr, TENANT, RES, POLICY)
    other = encrypt_resource(kr, TENANT, RES, POLICY)
    enc["note"].append(other["note"][0])  # a genuine ciphertext, wrong document
    with pytest.raises(DecryptionError):
        decrypt_resource(kr, TENANT, enc, patient=ALICE)


def test_missing_or_duplicate_manifest_is_rejected(kr: Keyring) -> None:
    enc = encrypt_resource(kr, TENANT, RES, POLICY)
    no_manifest = copy.deepcopy(enc)
    no_manifest["meta"]["tag"] = [t for t in enc["meta"]["tag"] if t["system"] != MANIFEST_SYSTEM]
    with pytest.raises(DecryptionError):
        decrypt_resource(kr, TENANT, no_manifest, patient=ALICE)
    two = copy.deepcopy(enc)
    two["meta"]["tag"].append(_manifest_tags(enc)[0])
    with pytest.raises(DecryptionError):
        decrypt_resource(kr, TENANT, two, patient=ALICE)


def test_manifest_from_another_patient_is_rejected(kr: Keyring) -> None:
    enc = encrypt_resource(kr, TENANT, RES, POLICY)
    bob = copy.deepcopy(RES)
    bob["subject"] = {"reference": "Patient/bob"}
    bob_enc = encrypt_resource(kr, TENANT, bob, POLICY)
    enc["meta"]["tag"] = [t for t in enc["meta"]["tag"] if t["system"] != MANIFEST_SYSTEM]
    enc["meta"]["tag"].append(_manifest_tags(bob_enc)[0])
    with pytest.raises(DecryptionError):
        decrypt_resource(kr, TENANT, enc, patient=ALICE)


def test_tag_list_is_informational_only(kr: Keyring) -> None:
    """The encrypted-paths tags can be tampered with freely; the manifest is authoritative."""
    enc = encrypt_resource(kr, TENANT, RES, POLICY)
    enc["meta"]["tag"] = [t for t in enc["meta"]["tag"] if t["system"] != TAG_SYSTEM]
    assert decrypt_resource(kr, TENANT, enc, patient=ALICE) == RES


def test_cleartext_edit_allowed_by_default_but_bound_when_asked(kr: Keyring) -> None:
    enc = encrypt_resource(kr, TENANT, RES, POLICY)
    enc["code"]["coding"][0]["code"] = "73211009"  # clear, searchable field edited
    out = decrypt_resource(kr, TENANT, enc, patient=ALICE)
    assert out["code"]["coding"][0]["code"] == "73211009"

    bound = encrypt_resource(kr, TENANT, RES, POLICY, bind_cleartext=True)
    assert decrypt_resource(kr, TENANT, bound, patient=ALICE) == RES
    bound["code"]["coding"][0]["code"] = "73211009"
    with pytest.raises(DecryptionError):
        decrypt_resource(kr, TENANT, bound, patient=ALICE)


def test_bound_cleartext_ignores_foreign_meta_tags_but_not_other_meta(kr: Keyring) -> None:
    res = copy.deepcopy(RES)
    res["meta"] = {"versionId": "1", "tag": [{"system": "urn:other", "code": "x"}]}
    bound = encrypt_resource(kr, TENANT, res, POLICY, bind_cleartext=True)
    assert decrypt_resource(kr, TENANT, bound, patient=ALICE) == res
    bound["meta"]["versionId"] = "2"
    with pytest.raises(DecryptionError):
        decrypt_resource(kr, TENANT, bound, patient=ALICE)


def test_re_encrypting_an_encrypted_resource_is_refused(kr: Keyring) -> None:
    enc = encrypt_resource(kr, TENANT, RES, POLICY)
    with pytest.raises(ValueError):
        encrypt_resource(kr, TENANT, enc, ["subject"])
