#!/usr/bin/env python3
"""Prove that an executable but byte-modified sing-box is rejected before use."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import prove_v0_1_local_network as proof

ROOT = Path(__file__).resolve().parents[1]
PROOF_SCRIPT = ROOT / "scripts" / "prove_v0_1_local_network.py"


def fail(message: str) -> int:
    print(f"ERROR: {message}", file=sys.stderr)
    return 1


def run(command: list[str], environment: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def main() -> int:
    target = proof.supported_target()
    if target is None:
        return fail("the SHA-negative proof requires a supported OS/architecture")
    try:
        source = proof.executable_from_env("FLOWPROBE_SING_BOX_BIN")
        proof.binary_evidence(source, target)
    except (OSError, proof.ProofFailure) as exc:
        return fail(f"source sing-box is not the pinned valid binary: {exc}")

    try:
        with tempfile.TemporaryDirectory(prefix="flowprobe-sha-negative-") as temporary:
            mutated = Path(temporary) / "sing-box-mutated"
            shutil.copy2(source, mutated)
            with mutated.open("ab") as stream:
                stream.write(b"\x00")

            version = run([str(mutated), "version"])
            version_lines = [line.strip() for line in version.stdout.splitlines() if line.strip()]
            if version.returncode != 0:
                return fail("the appended-byte binary no longer accepts the version command")
            if not version_lines or version_lines[0] != proof.EXPECTED_VERSION:
                return fail("the appended-byte binary changed its reported version")
            if [line for line in version_lines if line.startswith("Revision:")] != [
                proof.EXPECTED_REVISION
            ]:
                return fail("the appended-byte binary changed its reported revision")
            print("mutated-version-exit=0")

            environment = os.environ.copy()
            environment["FLOWPROBE_SING_BOX_BIN"] = str(mutated)
            # The mismatch must be decided before resolving curl/OpenSSL or
            # spawning Cargo, so no PATH command is available to the child.
            environment["PATH"] = ""
            rejected = run(
                [sys.executable, str(PROOF_SCRIPT), "--require-supported"],
                environment,
            )
            combined = rejected.stdout + rejected.stderr
            print(rejected.stdout, end="")
            print(rejected.stderr, end="", file=sys.stderr)
            print(f"negative-proof-exit={rejected.returncode}")
            if rejected.returncode != 1:
                return fail(f"SHA-negative proof returned {rejected.returncode}, expected 1")
            required = [
                "sing-box-sha256-expected=",
                "sing-box-sha256-actual=",
                "ERROR: sing-box SHA-256 mismatch",
            ]
            if not all(marker in combined for marker in required):
                return fail("proof did not report complete SHA mismatch evidence")
            forbidden = [
                "sing-box-sha256-verified=true",
                "Compiling ",
                "Finished ",
                "Running `",
                "runtime-version=",
                "http-origin-observed",
                "https-connect-origin-observed",
                "local-network-proof=passed",
            ]
            if any(marker in combined for marker in forbidden):
                return fail("proof reached verified-binary, Cargo, runtime, or origin work")
    except (OSError, subprocess.TimeoutExpired) as exc:
        return fail(f"cannot complete SHA-negative proof: {exc}")

    print("sha-mismatch-before-cargo-or-origins=passed")
    print("temporary-mutated-binary-cleanup=passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
