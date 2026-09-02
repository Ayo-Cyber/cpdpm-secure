"""Field-level encryption of FHIR JSON resources. See ``docs/design-v2.md`` §8.

A policy is a list of paths such as ``"code.text"`` or ``"note[*].text"``. Each
matched value is JSON-serialised, encrypted under a context whose
``field_path`` is the canonical path (array indices collapsed to ``[*]``), and
replaced in place by a ``cpdpm2:`` string. The encrypted paths are recorded in
``meta.tag`` under the system ``urn:cpdpm:encrypted-paths``.

Context discipline (threat model §6.2): at **encrypt** time the patient may be
derived from the resource for convenience. At **decrypt** time the caller must
supply ``patient`` from an authenticated source, never from the stored document.
"""

from __future__ import annotations

import copy
import json
import re
from collections.abc import Iterator
from typing import Any

from cpdpm.context import Context
from cpdpm.core import TEXT_PREFIX, decrypt_from_str, encrypt_to_str
from cpdpm.errors import DecryptionError
from cpdpm.header import Suite
from cpdpm.keys import Keyring

TAG_SYSTEM = "urn:cpdpm:encrypted-paths"
WHOLE = "*"

_SEGMENT = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)(\[\*\])?$")


def _parse(path: str) -> list[tuple[str, bool]]:
    segments = []
    for part in path.split("."):
        m = _SEGMENT.match(part)
        if not m:
            raise ValueError(f"bad path segment {part!r} in {path!r}")
        segments.append((m.group(1), m.group(2) is not None))
    return segments


def _walk(node: Any, segments: list[tuple[str, bool]]) -> Iterator[tuple[Any, str]]:
    """Yield (container, key) pairs for every leaf the path selects."""
    if not isinstance(node, dict):
        return
    name, is_array = segments[0]
    if name not in node:
        return
    rest = segments[1:]
    if is_array:
        items = node[name]
        if not isinstance(items, list):
            return
        for i, item in enumerate(items):
            if rest:
                yield from _walk(item, rest)
            else:
                yield items, i  # type: ignore[misc]
    elif rest:
        yield from _walk(node[name], rest)
    else:
        yield node, name


def derive_patient(resource: dict[str, Any]) -> str:
    """Convenience for encrypt time only. Returns "" for tenant-level resources."""
    if resource.get("resourceType") == "Patient" and "id" in resource:
        return f"Patient/{resource['id']}"
    for key in ("subject", "patient"):
        ref = resource.get(key)
        if isinstance(ref, dict) and isinstance(ref.get("reference"), str):
            return str(ref["reference"])
    return ""


def _recorded_paths(resource: dict[str, Any]) -> list[str]:
    tags = resource.get("meta", {}).get("tag", [])
    return [t["code"] for t in tags if isinstance(t, dict) and t.get("system") == TAG_SYSTEM]


def encrypt_resource(
    keyring: Keyring,
    tenant: str,
    resource: dict[str, Any],
    paths: list[str],
    *,
    patient: str | None = None,
    purpose: str = "",
    suite: Suite = Suite.AES_256_GCM,
) -> dict[str, Any]:
    """Return a copy of ``resource`` with the selected paths encrypted."""
    if "resourceType" not in resource:
        raise ValueError("resource has no resourceType")
    out = copy.deepcopy(resource)
    rtype = str(out["resourceType"])
    pat = derive_patient(resource) if patient is None else patient
    done: list[str] = []
    for path in paths:
        segments = _parse(path)
        ctx = Context(tenant, pat, rtype, path, purpose)
        hit = False
        for container, key in _walk(out, segments):
            value = container[key]
            if isinstance(value, str) and value.startswith(TEXT_PREFIX):
                raise ValueError(f"{path} is already encrypted")
            payload = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
            container[key] = encrypt_to_str(keyring, ctx, payload, suite=suite)
            hit = True
        if hit:
            done.append(path)
    meta = out.setdefault("meta", {})
    tags = [t for t in meta.get("tag", []) if t.get("system") != TAG_SYSTEM]
    tags.extend({"system": TAG_SYSTEM, "code": p} for p in done)
    meta["tag"] = tags
    return out


def decrypt_resource(
    keyring: Keyring,
    tenant: str,
    resource: dict[str, Any],
    *,
    patient: str,
    purpose: str = "",
) -> dict[str, Any]:
    """Return a copy of ``resource`` with every recorded path decrypted.

    ``patient`` is required and must come from the authenticated row or request,
    not from the document. Any failure raises :class:`DecryptionError`.
    """
    try:
        out = copy.deepcopy(resource)
        rtype = str(out["resourceType"])
        for path in _recorded_paths(out):
            ctx = Context(tenant, patient, rtype, path, purpose)
            for container, key in _walk(out, _parse(path)):
                value = container[key]
                if not (isinstance(value, str) and value.startswith(TEXT_PREFIX)):
                    raise ValueError("recorded path is not encrypted")
                container[key] = json.loads(decrypt_from_str(keyring, ctx, value))
        meta = out.get("meta", {})
        meta["tag"] = [t for t in meta.get("tag", []) if t.get("system") != TAG_SYSTEM]
        if not meta["tag"]:
            del meta["tag"]
        if not meta and "meta" in out:
            del out["meta"]
        return out
    except DecryptionError:
        raise
    except Exception:
        raise DecryptionError() from None


def encrypt_resource_whole(
    keyring: Keyring,
    tenant: str,
    resource: dict[str, Any],
    *,
    patient: str | None = None,
    purpose: str = "",
    suite: Suite = Suite.AES_256_GCM,
) -> str:
    """Encrypt an entire resource as one opaque ``cpdpm2:`` string (field_path ``"*"``)."""
    rtype = str(resource["resourceType"])
    pat = derive_patient(resource) if patient is None else patient
    ctx = Context(tenant, pat, rtype, WHOLE, purpose)
    payload = json.dumps(resource, separators=(",", ":"), sort_keys=True).encode()
    return encrypt_to_str(keyring, ctx, payload, suite=suite)


def decrypt_resource_whole(
    keyring: Keyring,
    tenant: str,
    text: str,
    *,
    resource_type: str,
    patient: str,
    purpose: str = "",
) -> dict[str, Any]:
    ctx = Context(tenant, patient, resource_type, WHOLE, purpose)
    try:
        result: dict[str, Any] = json.loads(decrypt_from_str(keyring, ctx, text))
    except DecryptionError:
        raise
    except Exception:
        raise DecryptionError() from None
    return result
