#!/usr/bin/env python3
"""Run the isolated v0.1 integration crate without joining the root workspace."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tests" / "integration" / "v0_1" / "Cargo.toml"


def run_step(label: str, command: list[str], suppress_stdout: bool = False) -> int:
    print(f"==> {label}", flush=True)
    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            check=False,
            stdout=subprocess.DEVNULL if suppress_stdout else None,
        )
    except FileNotFoundError as exc:
        print(f"ERROR: cannot run {command[0]!r}: {exc}", file=sys.stderr)
        return 1
    if result.returncode != 0:
        print(
            f"ERROR: {label} failed with exit code {result.returncode}",
            file=sys.stderr,
        )
    return result.returncode


def main() -> int:
    if not MANIFEST.is_file():
        print(f"ERROR: isolated integration manifest is missing: {MANIFEST}", file=sys.stderr)
        return 1

    manifest = str(MANIFEST)
    steps = [
        (
            "validate repository task contracts",
            [sys.executable, "-B", str(ROOT / "scripts" / "validate_tasks.py")],
            False,
        ),
        (
            "test the anti-shortcut quality gate",
            [
                sys.executable,
                "-B",
                "-m",
                "unittest",
                "discover",
                "-s",
                str(ROOT / "scripts" / "tests"),
                "-p",
                "test_quality_gate.py",
            ],
            False,
        ),
        (
            "run the repository anti-shortcut gate",
            [sys.executable, "-B", str(ROOT / "scripts" / "quality_gate.py")],
            False,
        ),
        (
            "verify the independent lock file",
            [
                "cargo",
                "metadata",
                "--manifest-path",
                manifest,
                "--locked",
                "--no-deps",
                "--format-version",
                "1",
            ],
            True,
        ),
        (
            "check isolated Rust formatting",
            ["cargo", "fmt", "--manifest-path", manifest, "--all", "--", "--check"],
            False,
        ),
        (
            "lint isolated integration targets",
            [
                "cargo",
                "clippy",
                "--manifest-path",
                manifest,
                "--locked",
                "--all-targets",
                "--",
                "-D",
                "warnings",
            ],
            False,
        ),
        (
            "run the deterministic architecture proof",
            [
                "cargo",
                "test",
                "--manifest-path",
                manifest,
                "--locked",
                "--test",
                "architecture_proof",
            ],
            False,
        ),
        (
            "run the generated-CA TLS interception proof",
            [
                "cargo",
                "test",
                "--manifest-path",
                manifest,
                "--locked",
                "--test",
                "tls_interception_proof",
            ],
            False,
        ),
        (
            "run the hermetic real-proof curl command tests",
            [
                "cargo",
                "test",
                "--manifest-path",
                manifest,
                "--locked",
                "--bin",
                "flowprobe-v0-1-real-singbox-proof",
            ],
            False,
        ),
        (
            "test isolated integration targets",
            [
                "cargo",
                "test",
                "--manifest-path",
                manifest,
                "--locked",
                "--all-targets",
            ],
            False,
        ),
    ]
    for label, command, suppress_stdout in steps:
        code = run_step(label, command, suppress_stdout)
        if code != 0:
            return code
    print("v0.1 isolated integration gate passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
