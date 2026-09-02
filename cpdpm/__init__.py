"""cpdpm: context-bound authenticated encryption for clinical records.

Protocol version 2 replaces the shipped v1 (see ``legacy/``). Specification in
``docs/design-v2.md``; threat model in ``docs/threat-model.md``.

Minimal use::

    from cpdpm import Context, Keyring, encrypt, decrypt

    keyring = Keyring.generate()
    ctx = Context(tenant="org:st-marys", patient="Patient/8f3a",
                  resource_type="Condition", field_path="code.text")
    blob = encrypt(keyring, ctx, b"Type 2 diabetes mellitus")
    assert decrypt(keyring, ctx, blob) == b"Type 2 diabetes mellitus"
"""

from cpdpm.context import Context
from cpdpm.core import decrypt, decrypt_from_str, encrypt, encrypt_to_str, is_cpdpm2
from cpdpm.errors import (
    ContextError,
    CPDPMError,
    DecryptionError,
    KeyringError,
    SuiteUnavailableError,
)
from cpdpm.header import PROTOCOL_VERSION, Suite
from cpdpm.keys import Keyring, KeyWrapper, LocalKeyWrapper

__version__ = "0.1.0a0"

__all__ = [
    "PROTOCOL_VERSION",
    "CPDPMError",
    "Context",
    "ContextError",
    "DecryptionError",
    "KeyWrapper",
    "Keyring",
    "KeyringError",
    "LocalKeyWrapper",
    "Suite",
    "SuiteUnavailableError",
    "__version__",
    "decrypt",
    "decrypt_from_str",
    "encrypt",
    "encrypt_to_str",
    "is_cpdpm2",
]
