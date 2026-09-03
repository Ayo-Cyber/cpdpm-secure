"""Property-based fuzzing of every parser that touches untrusted input.

The property in each case is the same: the function either succeeds or raises the
one exception type its contract allows. Any other exception is a bug.
"""

from hypothesis import given, settings
from hypothesis import strategies as st

from cpdpm import Context, ContextError, DecryptionError, Keyring, decrypt, decrypt_from_str
from cpdpm.fhir import _parse, _walk, decrypt_resource
from cpdpm.header import Header

KR = Keyring.generate()
CTX = Context("t", "p", "R", "f")

any_text = st.text(
    alphabet=st.one_of(
        st.characters(),
        st.characters(min_codepoint=0xD800, max_codepoint=0xDFFF),  # lone surrogates
        st.characters(min_codepoint=0x00, max_codepoint=0x1F),  # C0 controls
    ),
    max_size=64,
)

json_value = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | st.text(max_size=8),
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=8), children, max_size=4)
    ),
    max_leaves=20,
)


@settings(max_examples=500, deadline=None)
@given(st.binary(max_size=80))
def test_header_unpack_only_raises_value_error(blob: bytes) -> None:
    try:
        Header.unpack(blob)
    except ValueError:
        pass


@settings(max_examples=300, deadline=None)
@given(st.binary(max_size=200))
def test_decrypt_garbage_only_raises_decryption_error(blob: bytes) -> None:
    try:
        decrypt(KR, CTX, blob)
    except DecryptionError as exc:
        assert exc.__cause__ is None


@settings(max_examples=300, deadline=None)
@given(any_text)
def test_decrypt_from_str_garbage_only_raises_decryption_error(text: str) -> None:
    try:
        decrypt_from_str(KR, CTX, text)
    except DecryptionError:
        pass


@settings(max_examples=500, deadline=None)
@given(any_text, any_text, any_text, any_text, any_text)
def test_context_only_raises_context_error(a: str, b: str, c: str, d: str, e: str) -> None:
    try:
        ctx = Context(a, b, c, d, e)
    except ContextError:
        return
    canon = ctx.canonical()
    assert canon[0] == 0x01
    assert canon == Context(a, b, c, d, e).canonical()


@settings(max_examples=500, deadline=None)
@given(any_text)
def test_path_parse_only_raises_value_error(path: str) -> None:
    try:
        segments = _parse(path)
    except ValueError:
        return
    assert segments
    assert all(name for name, _ in segments)


@settings(max_examples=300, deadline=None)
@given(json_value, st.sampled_from(["a", "a.b", "a[*]", "a[*].b", "a.b[*].c"]))
def test_walk_never_raises(doc: object, path: str) -> None:
    for container, key in _walk(doc, _parse(path)):
        _ = container[key]


@settings(max_examples=200, deadline=None)
@given(json_value)
def test_decrypt_resource_garbage_only_raises_decryption_error(doc: object) -> None:
    if not isinstance(doc, dict):
        doc = {"resourceType": "X", "junk": doc}
    try:
        decrypt_resource(KR, "t", doc, patient="")
    except DecryptionError:
        pass
