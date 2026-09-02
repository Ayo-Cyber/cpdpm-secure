"""cpdpm: context-bound authenticated encryption for clinical records.

Protocol version 2 replaces the shipped v1 (see ``legacy/``). The construction
is specified in ``docs/design-v2.md`` and its threat model in
``docs/threat-model.md``. Implementation begins in week 3 of ``docs/ROADMAP.md``.
"""

__version__ = "0.1.0a0"
PROTOCOL_VERSION = 2

__all__ = ["PROTOCOL_VERSION", "__version__"]
