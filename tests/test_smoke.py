"""Week-0 smoke test: the package imports and the build is wired up.

Real tests arrive with the construction in week 3 (round-trip, tamper,
wrong-context, rotation, property-based).
"""

import cpdpm


def test_package_imports() -> None:
    assert cpdpm.PROTOCOL_VERSION == 2
    assert cpdpm.__version__.startswith("0.1.0")
