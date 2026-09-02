import copy

import pytest

from cpdpm import DecryptionError, Keyring
from cpdpm.fhir import (
    TAG_SYSTEM,
    decrypt_resource,
    decrypt_resource_whole,
    derive_patient,
    encrypt_resource,
    encrypt_resource_whole,
)

TENANT = "org:st-marys"
POLICY = ["code.text", "note[*].text", "onsetDateTime", "evidence[*].detail[*].display"]

CONDITION = {
    "resourceType": "Condition",
    "id": "c1",
    "subject": {"reference": "Patient/alice"},
    "code": {
        "coding": [{"system": "http://snomed.info/sct", "code": "44054006"}],
        "text": "Type 2 diabetes mellitus",
    },
    "onsetDateTime": "2019-03-04",
    "note": [{"text": "Diet controlled"}, {"text": "Metformin started 2021"}],
    "evidence": [{"detail": [{"display": "HbA1c 7.9%"}, {"display": "Fasting glucose 8.1"}]}],
    "meta": {"tag": [{"system": "urn:other", "code": "keep-me"}]},
}


@pytest.fixture
def keyring() -> Keyring:
    return Keyring.generate()


def test_roundtrip_restores_exact_resource(keyring: Keyring) -> None:
    original = copy.deepcopy(CONDITION)
    enc = encrypt_resource(keyring, TENANT, CONDITION, POLICY)
    assert CONDITION == original, "input must not be mutated"
    assert enc["code"]["text"].startswith("cpdpm2:")
    assert all(n["text"].startswith("cpdpm2:") for n in enc["note"])
    assert enc["evidence"][0]["detail"][1]["display"].startswith("cpdpm2:")
    assert enc["code"]["coding"] == CONDITION["code"]["coding"], "unselected fields stay clear"
    recorded = {t["code"] for t in enc["meta"]["tag"] if t["system"] == TAG_SYSTEM}
    assert recorded == set(POLICY)
    assert {"system": "urn:other", "code": "keep-me"} in enc["meta"]["tag"]

    dec = decrypt_resource(keyring, TENANT, enc, patient="Patient/alice")
    assert dec == original


def test_non_string_values_roundtrip(keyring: Keyring) -> None:
    obs = {
        "resourceType": "Observation",
        "subject": {"reference": "Patient/p"},
        "valueQuantity": {"value": 7.9, "unit": "%"},
        "component": [{"valueInteger": 3}, {"valueBoolean": True}],
    }
    enc = encrypt_resource(keyring, TENANT, obs, ["valueQuantity", "component[*]"])
    assert isinstance(enc["valueQuantity"], str)
    assert all(isinstance(c, str) for c in enc["component"])
    assert decrypt_resource(keyring, TENANT, enc, patient="Patient/p") == obs


def test_record_swap_between_patients_rejected(keyring: Keyring) -> None:
    bob = copy.deepcopy(CONDITION)
    bob["subject"] = {"reference": "Patient/bob"}
    bob_enc = encrypt_resource(keyring, TENANT, bob, POLICY)
    # Adversary stores Bob's document in Alice's row; the app decrypts for Alice.
    with pytest.raises(DecryptionError):
        decrypt_resource(keyring, TENANT, bob_enc, patient="Patient/alice")


def test_cross_tenant_rejected(keyring: Keyring) -> None:
    enc = encrypt_resource(keyring, TENANT, CONDITION, POLICY)
    with pytest.raises(DecryptionError):
        decrypt_resource(keyring, "org:other", enc, patient="Patient/alice")


def test_field_move_rejected(keyring: Keyring) -> None:
    """Move the ciphertext of note[*].text into code.text: same patient, wrong field."""
    enc = encrypt_resource(keyring, TENANT, CONDITION, POLICY)
    enc["code"]["text"] = enc["note"][0]["text"]
    with pytest.raises(DecryptionError):
        decrypt_resource(keyring, TENANT, enc, patient="Patient/alice")


def test_resource_type_relabel_rejected(keyring: Keyring) -> None:
    enc = encrypt_resource(keyring, TENANT, CONDITION, POLICY)
    enc["resourceType"] = "Observation"
    with pytest.raises(DecryptionError):
        decrypt_resource(keyring, TENANT, enc, patient="Patient/alice")


def test_tampered_tag_list_cannot_expose_or_confuse(keyring: Keyring) -> None:
    enc = encrypt_resource(keyring, TENANT, CONDITION, POLICY)
    # Adversary rewrites the recorded path list to point at a clear field.
    enc["meta"]["tag"] = [{"system": TAG_SYSTEM, "code": "code.coding[*].code"}]
    with pytest.raises(DecryptionError):
        decrypt_resource(keyring, TENANT, enc, patient="Patient/alice")


def test_missing_paths_are_skipped(keyring: Keyring) -> None:
    minimal = {"resourceType": "Condition", "subject": {"reference": "Patient/x"}}
    enc = encrypt_resource(keyring, TENANT, minimal, POLICY)
    assert enc["meta"]["tag"] == []
    assert decrypt_resource(keyring, TENANT, enc, patient="Patient/x") == minimal


def test_double_encrypt_refused(keyring: Keyring) -> None:
    enc = encrypt_resource(keyring, TENANT, CONDITION, POLICY)
    with pytest.raises(ValueError):
        encrypt_resource(keyring, TENANT, enc, POLICY)


def test_bad_path_rejected(keyring: Keyring) -> None:
    with pytest.raises(ValueError):
        encrypt_resource(keyring, TENANT, CONDITION, ["code[0].text"])


def test_derive_patient() -> None:
    assert derive_patient({"resourceType": "Patient", "id": "9"}) == "Patient/9"
    assert derive_patient(CONDITION) == "Patient/alice"
    assert derive_patient({"resourceType": "Organization", "id": "o"}) == ""


def test_tenant_level_resource(keyring: Keyring) -> None:
    org = {
        "resourceType": "Organization",
        "id": "o1",
        "name": "St Mary's",
        "telecom": [{"value": "x"}],
    }
    enc = encrypt_resource(keyring, TENANT, org, ["name", "telecom[*].value"])
    assert decrypt_resource(keyring, TENANT, enc, patient="") == org
    with pytest.raises(DecryptionError):
        decrypt_resource(keyring, TENANT, enc, patient="Patient/alice")


def test_whole_resource(keyring: Keyring) -> None:
    text = encrypt_resource_whole(keyring, TENANT, CONDITION)
    assert text.startswith("cpdpm2:")
    out = decrypt_resource_whole(
        keyring, TENANT, text, resource_type="Condition", patient="Patient/alice"
    )
    assert out == CONDITION
    with pytest.raises(DecryptionError):
        decrypt_resource_whole(
            keyring, TENANT, text, resource_type="Condition", patient="Patient/bob"
        )
