"""The context a ciphertext is bound to, and its canonical encoding.

See ``docs/design-v2.md`` §3. The encoding is injective: two contexts encode to
the same bytes only if they are equal. That property is what makes the
derived-key and associated-data binding meaningful, and it is tested with a
property-based test in ``tests/test_context.py``.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass

from cpdpm.errors import ContextError

ENCODING_VERSION = 0x02
MAX_FIELD_BYTES = 0xFFFF

_FIELDS = ("tenant", "patient", "resource_type", "field_path", "purpose")
_REQUIRED = ("tenant", "resource_type", "field_path")


@dataclass(frozen=True)
class Context:
    """What a ciphertext belongs to.

    ``tenant``, ``resource_type`` and ``field_path`` are required. ``patient``
    may be empty for tenant-level resources (``Organization``, ``Practitioner``);
    the empty value is itself bound, so a ciphertext for "no patient" cannot be
    presented for a patient. ``purpose`` is optional.

    Use ``"*"`` as ``field_path`` for a whole-resource ciphertext.
    """

    tenant: str
    patient: str
    resource_type: str
    field_path: str
    purpose: str = ""

    def __post_init__(self) -> None:
        for name in _FIELDS:
            value = getattr(self, name)
            if not isinstance(value, str):
                raise ContextError(f"{name} must be a str")
            normalised = unicodedata.normalize("NFC", value)
            if normalised != value:
                object.__setattr__(self, name, normalised)
            try:
                raw = normalised.encode("utf-8")
            except UnicodeEncodeError as exc:  # lone surrogates
                raise ContextError(f"{name} is not valid Unicode text") from exc
            if len(raw) > MAX_FIELD_BYTES:
                raise ContextError(f"{name} exceeds {MAX_FIELD_BYTES} bytes")
            if any(unicodedata.category(ch) in ("Cc", "Cs") for ch in normalised):
                raise ContextError(f"{name} contains a control character")
        for name in _REQUIRED:
            if getattr(self, name) == "":
                raise ContextError(f"{name} is required")

    def canonical(self) -> bytes:
        """Length-prefixed, fixed-order encoding. Injective over valid contexts."""
        out = bytearray([ENCODING_VERSION])
        for name in _FIELDS:
            raw = getattr(self, name).encode("utf-8")
            out += len(raw).to_bytes(2, "big")
            out += raw
        return bytes(out)
