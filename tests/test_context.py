import pytest
from hypothesis import given
from hypothesis import strategies as st

from cpdpm import Context, ContextError

field = st.text(
    alphabet=st.characters(blacklist_categories=("Cs", "Cc")),
    min_size=1,
    max_size=40,
)
optional = st.text(alphabet=st.characters(blacklist_categories=("Cs", "Cc")), max_size=40)


@given(field, optional, field, field, optional, field, optional, field, field, optional)
def test_canonical_is_injective(t1, p1, r1, f1, u1, t2, p2, r2, f2, u2):  # type: ignore[no-untyped-def]
    a = Context(t1, p1, r1, f1, u1)
    b = Context(t2, p2, r2, f2, u2)
    if a.canonical() == b.canonical():
        assert a == b
    if a == b:
        assert a.canonical() == b.canonical()


def test_shifted_boundaries_encode_differently() -> None:
    a = Context("ab", "c", "R", "f")
    b = Context("a", "bc", "R", "f")
    assert a.canonical() != b.canonical()


def test_empty_patient_is_bound() -> None:
    a = Context("t", "", "Organization", "*")
    b = Context("t", "Patient/1", "Organization", "*")
    assert a.canonical() != b.canonical()


def test_required_fields() -> None:
    for kwargs in (
        {"tenant": ""},
        {"resource_type": ""},
        {"field_path": ""},
    ):
        base = {"tenant": "t", "patient": "p", "resource_type": "R", "field_path": "f"}
        base.update(kwargs)
        with pytest.raises(ContextError):
            Context(**base)


def test_nfc_normalisation() -> None:
    composed = Context("t", "p", "R", "café")
    decomposed = Context("t", "p", "R", "café")
    assert composed == decomposed
    assert composed.canonical() == decomposed.canonical()


def test_control_characters_rejected() -> None:
    with pytest.raises(ContextError):
        Context("t\n", "p", "R", "f")


def test_field_too_long() -> None:
    with pytest.raises(ContextError):
        Context("t" * 70_000, "p", "R", "f")


def test_encoding_layout() -> None:
    c = Context("ab", "", "R", "f", "")
    assert c.canonical() == bytes([0x02, 0, 2, *b"ab", 0, 0, 0, 1, *b"R", 0, 1, *b"f", 0, 0])
