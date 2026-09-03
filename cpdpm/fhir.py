"""Field-level encryption of FHIR JSON resources. See ``docs/design.md`` §8.

A policy is a list of paths such as ``"code.text"`` or ``"note[*].text"``. Each
matched value is JSON-serialised, encrypted under a context whose
``field_path`` is the canonical path (array indices collapsed to ``[*]``), and
replaced in place by a ``cpdpm1:`` string.

Structural integrity. Per-field AEAD binds each value to its path, but not the
*set* of values: an adversary could delete an encrypted note, or put back an
older ciphertext of the same field. So every encrypted resource also carries a
**manifest**: the ordered list of (path, SHA-256 of ciphertext) for every
encrypted value, itself encrypted under the context ``field_path="_manifest"``.
Decryption verifies the manifest before releasing any field. With
``bind_cleartext=True`` the manifest also carries a digest of the remaining
clear fields, making the whole resource tamper-evident while search fields stay
readable.

Context discipline (threat model §6.2): at **encrypt** time the patient may be
derived from the resource for convenience. At **decrypt** time the caller must
supply ``patient`` from an authenticated source, never from the stored document.

What the manifest does not cover: replacing the *entire* resource, manifest
included, with an older version of itself. That needs application-side
versioning and is listed as a limitation.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
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
MANIFEST_SYSTEM = "urn:cpdpm:manifest"
MANIFEST_PATH = "_manifest"
WHOLE = "*"
_PLACEHOLDER = "\x00cpdpm-encrypted"

_SEGMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\[\*\])?")


def _parse(path: str) -> list[tuple[str, bool]]:
    segments = []
    for part in path.split("."):
        m = _SEGMENT.fullmatch(part)
        if not m:
            raise ValueError(f"bad path segment {part!r} in {path!r}")
        name = part[:-3] if m.group(1) else part
        segments.append((name, m.group(1) is not None))
    return segments


def _walk(node: Any, segments: list[tuple[str, bool]]) -> Iterator[tuple[Any, str | int]]:
    """Yield (container, key) pairs for every leaf the path selects, in document order."""
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
                yield items, i
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


def _is_blob(value: Any) -> bool:
    return isinstance(value, str) and value.startswith(TEXT_PREFIX)


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _our_tags(resource: dict[str, Any]) -> list[dict[str, Any]]:
    tags = resource.get("meta", {}).get("tag", [])
    return [
        t for t in tags if isinstance(t, dict) and t.get("system") in (TAG_SYSTEM, MANIFEST_SYSTEM)
    ]


def _strip_our_tags(resource: dict[str, Any]) -> None:
    meta = resource.get("meta")
    if not isinstance(meta, dict):
        return
    tags = [t for t in meta.get("tag", []) if t not in _our_tags(resource)]
    if tags:
        meta["tag"] = tags
    else:
        meta.pop("tag", None)
    if not meta:
        resource.pop("meta", None)


def _clear_digest(encrypted: dict[str, Any], paths: list[str]) -> str:
    """Digest of the resource with encrypted values blanked and our tags removed."""
    shadow = copy.deepcopy(encrypted)
    for path in paths:
        for container, key in _walk(shadow, _parse(path)):
            if _is_blob(container[key]):
                container[key] = _PLACEHOLDER
    _strip_our_tags(shadow)
    return _digest(json.dumps(shadow, separators=(",", ":"), sort_keys=True))


def _entries(encrypted: dict[str, Any], paths: list[str]) -> list[list[str]]:
    out = []
    for path in paths:
        for container, key in _walk(encrypted, _parse(path)):
            value = container[key]
            if not _is_blob(value):
                raise ValueError("recorded path is not encrypted")
            out.append([path, _digest(value)])
    return out


def encrypt_resource(
    keyring: Keyring,
    tenant: str,
    resource: dict[str, Any],
    paths: list[str],
    *,
    patient: str | None = None,
    purpose: str = "",
    suite: Suite = Suite.AES_256_GCM,
    bind_cleartext: bool = False,
) -> dict[str, Any]:
    """Return a copy of ``resource`` with the selected paths encrypted and a manifest attached.

    ``bind_cleartext=True`` also binds every unencrypted field: any later change to the
    clear part of the resource makes decryption fail. Leave it off when the application
    legitimately edits clear fields without re-encrypting.
    """
    if "resourceType" not in resource:
        raise ValueError("resource has no resourceType")
    if _our_tags(resource):
        raise ValueError("resource already carries cpdpm tags")
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
            if _is_blob(value):
                raise ValueError(f"{path} is already encrypted")
            payload = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
            container[key] = encrypt_to_str(keyring, ctx, payload, suite=suite)
            hit = True
        if hit:
            done.append(path)

    manifest = {
        "v": 1,
        "paths": done,
        "entries": _entries(out, done),
        "clear": _clear_digest(out, done) if bind_cleartext else None,
    }
    manifest_ctx = Context(tenant, pat, rtype, MANIFEST_PATH, purpose)
    manifest_blob = encrypt_to_str(
        keyring,
        manifest_ctx,
        json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode(),
        suite=suite,
    )
    meta = out.setdefault("meta", {})
    tags = list(meta.get("tag", []))
    tags.extend({"system": TAG_SYSTEM, "code": p} for p in done)
    tags.append({"system": MANIFEST_SYSTEM, "code": manifest_blob})
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
    """Return a copy of ``resource`` with every encrypted field restored.

    Verifies the manifest first: the set, order and ciphertext digests of encrypted
    values must match what was written, and the clear digest too if it was bound.
    ``patient`` is required and must come from the authenticated row or request,
    not from the document. Any failure raises :class:`DecryptionError`.
    """
    try:
        out = copy.deepcopy(resource)
        rtype = str(out["resourceType"])
        manifests = [t for t in _our_tags(out) if t.get("system") == MANIFEST_SYSTEM]
        if len(manifests) != 1:
            raise ValueError("exactly one manifest required")
        manifest_ctx = Context(tenant, patient, rtype, MANIFEST_PATH, purpose)
        manifest = json.loads(decrypt_from_str(keyring, manifest_ctx, str(manifests[0]["code"])))
        if manifest.get("v") != 1:
            raise ValueError("manifest version")
        paths = [str(p) for p in manifest["paths"]]
        expected = json.dumps(manifest["entries"], separators=(",", ":"))
        actual = json.dumps(_entries(out, paths), separators=(",", ":"))
        if not hmac.compare_digest(expected.encode(), actual.encode()):
            raise ValueError("manifest mismatch")
        clear = manifest.get("clear")
        if clear is not None and not hmac.compare_digest(
            str(clear).encode(), _clear_digest(out, paths).encode()
        ):
            raise ValueError("cleartext mismatch")
        for path in paths:
            ctx = Context(tenant, patient, rtype, path, purpose)
            for container, key in _walk(out, _parse(path)):
                container[key] = json.loads(decrypt_from_str(keyring, ctx, container[key]))
        _strip_our_tags(out)
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
    """Encrypt an entire resource as one opaque ``cpdpm1:`` string (field_path ``"*"``)."""
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
