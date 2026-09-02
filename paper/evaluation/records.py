"""Realistic record content for the evaluation, built from the stroke dataset.

Each CSV row becomes one FHIR-shaped Observation for a synthetic patient. The
dataset is public and has no direct identifiers; it supplies realistic field
shapes and sizes, nothing more.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
CSV = ROOT / "data" / "healthcare-dataset-stroke-data.csv"

# Fields the field-level benchmark and the attack demo encrypt.
POLICY = ["component[*].valueQuantity", "note[*].text", "effectiveDateTime"]


def load_rows(limit: int | None = None) -> list[dict[str, str]]:
    with CSV.open(newline="") as fh:
        rows = list(csv.DictReader(fh))
    return rows[:limit] if limit else rows


def observation(row: dict[str, str], tenant_hint: str = "org:st-marys") -> dict[str, Any]:
    pid = f"Patient/{row['id']}"

    def q(code: str, value: str, unit: str) -> dict[str, Any]:
        try:
            v: float | None = float(value)
        except ValueError:
            v = None
        return {
            "code": {"coding": [{"system": "http://loinc.org", "code": code}]},
            "valueQuantity": {"value": v, "unit": unit},
        }

    return {
        "resourceType": "Observation",
        "id": f"obs-{row['id']}",
        "status": "final",
        "subject": {"reference": pid},
        "performer": [{"reference": tenant_hint}],
        "effectiveDateTime": "2026-01-15T09:30:00Z",
        "component": [
            q("2339-0", row["avg_glucose_level"], "mg/dL"),
            q("39156-5", row["bmi"], "kg/m2"),
            q("30525-0", row["age"], "a"),
        ],
        "note": [
            {
                "text": (
                    f"{row['gender']}, {row['work_type']}, {row['Residence_type']}, "
                    f"smoking: {row['smoking_status']}, hypertension: {row['hypertension']}, "
                    f"heart disease: {row['heart_disease']}, stroke: {row['stroke']}"
                )
            }
        ],
    }


def bundle_bytes(n: int) -> bytes:
    """JSON of a FHIR Bundle holding ``n`` observations. Used as the byte payload."""
    rows = load_rows(n)
    bundle = {
        "resourceType": "Bundle",
        "type": "collection",
        "entry": [{"resource": observation(r)} for r in rows],
    }
    return json.dumps(bundle, separators=(",", ":")).encode()


if __name__ == "__main__":
    for n in (1, 10, 100, 1000):
        print(n, len(bundle_bytes(n)), "bytes")
