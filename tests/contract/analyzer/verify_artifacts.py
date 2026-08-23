#!/usr/bin/env python3
"""Rebuild checked-in Analyzer components and require byte-for-byte equality."""

from __future__ import annotations

import hashlib
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = "wasm32-unknown-unknown"
DEMO_CORE = ROOT / "target" / TARGET / "release" / "flowprobe_demo_analyzer.wasm"
GUEST_MANIFEST = ROOT / "tests/contract/analyzer/guest/Cargo.toml"
GUEST_CORE = (
    ROOT
    / "tests/contract/analyzer/guest/target"
    / TARGET
    / "release/flowprobe_adversarial_analyzer_fixture.wasm"
)


def run(*args: str) -> None:
    subprocess.run(args, cwd=ROOT, check=True)


def componentize(core: Path, output: Path) -> None:
    run(
        "cargo",
        "run",
        "-p",
        "flowprobe-analyzer-runtime",
        "--example",
        "componentize",
        "--",
        str(core),
        str(output),
    )


def require_equal(generated: Path, checked_in: Path) -> None:
    generated_bytes = generated.read_bytes()
    checked_in_bytes = checked_in.read_bytes()
    generated_hash = hashlib.sha256(generated_bytes).hexdigest()
    checked_in_hash = hashlib.sha256(checked_in_bytes).hexdigest()
    if generated_bytes != checked_in_bytes:
        raise SystemExit(
            f"artifact drift for {checked_in.relative_to(ROOT)}: "
            f"generated sha256={generated_hash}, checked-in sha256={checked_in_hash}"
        )
    print(f"verified {checked_in.relative_to(ROOT)} sha256={checked_in_hash}")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="flowprobe-analyzer-artifacts-") as directory:
        temporary = Path(directory)

        run("cargo", "build", "-p", "flowprobe-demo-analyzer", "--target", TARGET, "--release")
        demo = temporary / "demo.wasm"
        componentize(DEMO_CORE, demo)
        require_equal(demo, ROOT / "plugins/demo/artifacts/flowprobe_demo_analyzer.wasm")

        run(
            "cargo",
            "build",
            "--manifest-path",
            str(GUEST_MANIFEST),
            "--target",
            TARGET,
            "--release",
        )
        adversarial = temporary / "adversarial.wasm"
        componentize(GUEST_CORE, adversarial)
        require_equal(
            adversarial,
            ROOT / "tests/contract/analyzer/artifacts/adversarial_analyzer.wasm",
        )

        run(
            "cargo",
            "build",
            "--manifest-path",
            str(GUEST_MANIFEST),
            "--target",
            TARGET,
            "--release",
            "--features",
            "invalid-info",
        )
        invalid_info = temporary / "invalid-info.wasm"
        componentize(GUEST_CORE, invalid_info)
        require_equal(
            invalid_info,
            ROOT / "tests/contract/analyzer/artifacts/invalid_info_analyzer.wasm",
        )

        run(
            "cargo",
            "build",
            "--manifest-path",
            str(GUEST_MANIFEST),
            "--target",
            TARGET,
            "--release",
            "--features",
            "hostile-info",
        )
        hostile_info = temporary / "hostile-info.wasm"
        componentize(GUEST_CORE, hostile_info)
        require_equal(
            hostile_info,
            ROOT / "tests/contract/analyzer/artifacts/hostile_info_analyzer.wasm",
        )


if __name__ == "__main__":
    main()
