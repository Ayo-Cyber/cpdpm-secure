"""Chapter 3, finding 2: v1 "context-aware" keys are not derived from the context.

``CPDPMCore.generate_context_key`` hashes the context into a NumPy seed, but the
coefficients are drawn from ``secrets`` and ignore that seed. The same context
therefore yields a fresh key on every call, and the two v1 tests that assert
determinism fail. Decryption still works only because the key is shipped inside
the package (see affine_map.py).

Run: python -m paper.analysis.context_key
"""

from __future__ import annotations

import re
import subprocess
import sys

from paper.analysis._legacy import ROOT, add_legacy_paths, write_result

add_legacy_paths()

from cpdpm_core import CPDPMCore  # noqa: E402


def same_context_many_times(trials: int = 200) -> dict:
    core = CPDPMCore()
    keys = {
        tuple(core.generate_context_key("patient:001|vitals").coefficients) for _ in range(trials)
    }
    return {
        "context": "patient:001|vitals",
        "trials": trials,
        "distinct_keys": len(keys),
        "deterministic": len(keys) == 1,
    }


def legacy_suite() -> dict:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            str(ROOT / "legacy" / "tests" / "test_cpdpm_comprehensive.py"),
            "-p",
            "no:cacheprovider",
            "--no-header",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        cwd=ROOT,
        timeout=600,
    )
    out = proc.stdout
    failed = re.findall(r"^FAILED (\S+)", out, flags=re.M)
    n_failed = re.search(r"(\d+) failed", out)
    n_passed = re.search(r"(\d+) passed", out)
    return {
        "failed_tests": [f.split("::", 1)[1] for f in failed],
        "n_failed": int(n_failed.group(1)) if n_failed else len(failed),
        "n_passed": int(n_passed.group(1)) if n_passed else None,
        "exit_code": proc.returncode,
    }


def main() -> None:
    write_result(
        "context_key",
        {
            "same_context_many_times": same_context_many_times(),
            "legacy_test_suite": legacy_suite(),
            "source": "legacy/src/cpdpm_core.py: generate_context_key seeds np.random; "
            "generate_polynomial_key draws from secrets.randbelow",
        },
    )


if __name__ == "__main__":
    main()
