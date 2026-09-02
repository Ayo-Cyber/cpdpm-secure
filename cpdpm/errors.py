"""Exception types.

The decrypt path raises exactly one type, :class:`DecryptionError`, with a fixed
message. Which check failed (malformed header, unknown key version, AEAD tag,
commitment) is never disclosed, so the library cannot be used as an oracle.
"""

from __future__ import annotations


class CPDPMError(Exception):
    """Base class for all cpdpm errors."""


class DecryptionError(CPDPMError):
    """Raised for any failure on the decrypt path. Carries no detail by design."""

    def __init__(self) -> None:
        super().__init__("decryption failed")


class ContextError(CPDPMError, ValueError):
    """An invalid :class:`~cpdpm.context.Context` was constructed."""


class KeyringError(CPDPMError):
    """Key material is missing, retired, or malformed."""


class SuiteUnavailableError(CPDPMError):
    """The requested cipher suite needs an optional dependency that is not installed."""
