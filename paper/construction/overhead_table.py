"""Chapter 4, table 4-1: bytes added per ciphertext, measured not computed.

Run: python -m paper.construction.overhead_table
Writes paper/construction/results/overhead.json and paper/figures/table4-1_overhead.md.
"""

from __future__ import annotations

import io
import json
import os
from pathlib import Path

from cpdpm import Context, Keyring, Suite, encrypt, encrypt_to_str
from cpdpm.stream import encrypt_stream

ROOT = Path(__file__).resolve().parents[2]
RESULTS = Path(__file__).resolve().parent / "results"
FIGURES = ROOT / "paper" / "figures"

SIZES = [0, 64, 726, 6_761, 67_113, 669_830]  # 0, tiny, then the four evaluation payloads
CTX = Context("org:st-marys", "Patient/8f3a", "Observation", "note[*].text")


def main() -> None:
    kr = Keyring.generate()
    rows = []
    for n in SIZES:
        pt = os.urandom(n)
        row: dict[str, int | float] = {"plaintext_bytes": n}
        for suite in (Suite.AES_256_GCM, Suite.XCHACHA20_POLY1305):
            tag = "gcm" if suite is Suite.AES_256_GCM else "xchacha"
            blob = encrypt(kr, CTX, pt, suite=suite)
            text = encrypt_to_str(kr, CTX, pt, suite=suite)
            out = io.BytesIO()
            encrypt_stream(kr, CTX, io.BytesIO(pt), out, suite=suite, chunk_size=1 << 16)
            row[f"{tag}_blob_overhead"] = len(blob) - n
            row[f"{tag}_text_overhead"] = len(text) - n
            row[f"{tag}_stream_64k_overhead"] = len(out.getvalue()) - n
        rows.append(row)

    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "overhead.json").write_text(json.dumps(rows, indent=2) + "\n")

    lines = [
        "| Plaintext | GCM blob | GCM text | XChaCha blob | XChaCha text | GCM stream (64 KiB chunks) |",  # noqa: E501
        "|---:|---:|---:|---:|---:|---:|",
    ]
    for r in rows:
        lines.append(
            f"| {r['plaintext_bytes']:,} B | +{r['gcm_blob_overhead']} B | +{r['gcm_text_overhead']:,} B "  # noqa: E501
            f"| +{r['xchacha_blob_overhead']} B | +{r['xchacha_text_overhead']:,} B "
            f"| +{r['gcm_stream_64k_overhead']} B |"
        )
    lines.append("")
    lines.append(
        "Blob overhead is constant: 11-byte header + nonce (12 or 24) + 32-byte commitment + 16-byte tag. "  # noqa: E501
        "Text form adds the 7-byte `cpdpm2:` prefix and base64url expansion (one third of the blob). "  # noqa: E501
        "Stream overhead is 15 + prefix + 32 + 16 bytes per chunk."
    )
    FIGURES.mkdir(parents=True, exist_ok=True)
    (FIGURES / "table4-1_overhead.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
