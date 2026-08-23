#!/usr/bin/env python3
"""Explicitly provision and identify the pinned sing-box proof binary with mise."""
from __future__ import annotations

import argparse
import hashlib
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

TOOL = "github:sagernet/sing-box@1.13.19"
EXPECTED_VERSION = "sing-box version 1.13.19"
EXPECTED_REVISION = "Revision: b5ebaa1fc0f2b94256180b95468e73ef53caa27d"
UNSUPPORTED_EXIT = 77
EXPECTED_BINARY_SHA256 = {
    ("darwin", "arm64"): "5b75c1dec19488675f725adc7a6e3a7301a553117af835dc47669b1fa918976b",
    ("darwin", "x86_64"): "078164e43464f2282ae526151411320582c3e60a0294cec24a627edf205305a6",
    ("linux", "aarch64"): "0bd9f22cd677d7fe70324944b3dfaf967971607ac3f713d1b754248d8b0d702d",
    ("linux", "x86_64"): "7e9dcd7239c49478a576d79f272751e5ed1c2aba7cc08ab1b2bd69c00c904ba1",
}


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True, timeout=180)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fail(message: str) -> int:
    print(f"ERROR: {message}", file=sys.stderr)
    return 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require-supported",
        action="store_true",
        help="turn an unsupported OS/architecture into a failing exit instead of exit 77",
    )
    return parser.parse_args()


def supported_target() -> tuple[str, str] | None:
    if sys.platform == "darwin":
        system = "darwin"
    elif sys.platform.startswith("linux"):
        system = "linux"
    else:
        return None

    machine = platform.machine().lower()
    if machine in {"arm64", "aarch64"}:
        architecture = "arm64" if system == "darwin" else "aarch64"
    elif machine in {"x86_64", "amd64"}:
        architecture = "x86_64"
    else:
        return None
    target = (system, architecture)
    return target if target in EXPECTED_BINARY_SHA256 else None


def main() -> int:
    args = parse_args()
    target = supported_target()
    if target is None:
        message = (
            f"unsupported host {sys.platform!r}/{platform.machine()!r}: provisioning is pinned "
            "for darwin-arm64, darwin-x86_64, linux-aarch64, or linux-x86_64"
        )
        print(f"ERROR: {message}", file=sys.stderr)
        return 1 if args.require_supported else UNSUPPORTED_EXIT

    mise = shutil.which("mise")
    if mise is None:
        return fail("mise is required for explicit sing-box provisioning")

    try:
        installed = run([mise, "install", TOOL])
    except subprocess.TimeoutExpired:
        return fail("mise sing-box installation timed out")
    if installed.returncode != 0:
        return fail(
            "mise sing-box installation failed: "
            + (installed.stderr.strip() or installed.stdout.strip() or "no diagnostic")
        )

    try:
        located = run([mise, "which", "sing-box", "--tool", TOOL])
    except subprocess.TimeoutExpired:
        return fail("mise sing-box lookup timed out")
    if located.returncode != 0:
        return fail(
            "mise could not locate pinned sing-box: "
            + (located.stderr.strip() or located.stdout.strip() or "no diagnostic")
        )
    lines = [line.strip() for line in located.stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        return fail("mise returned an ambiguous sing-box path")
    binary = Path(lines[0])
    if not binary.is_absolute() or not binary.is_file() or not os.access(binary, os.X_OK):
        return fail(f"mise sing-box path is not an absolute executable file: {binary}")

    try:
        actual_checksum = sha256(binary)
    except OSError as exc:
        return fail(f"cannot hash pinned sing-box binary: {exc}")
    expected_checksum = EXPECTED_BINARY_SHA256[target]
    print(f"sing-box-binary={binary}")
    print(f"sing-box-platform={target[0]}-{target[1]}")
    print(f"sing-box-sha256-expected={expected_checksum}")
    print(f"sing-box-sha256-actual={actual_checksum}")
    if actual_checksum != expected_checksum:
        return fail(
            "sing-box SHA-256 mismatch for "
            f"{target[0]}-{target[1]}: expected {expected_checksum}, got {actual_checksum}"
        )
    print("sing-box-sha256-verified=true")

    # Execute the file only after its bytes match the official pinned release.
    try:
        version = run([str(binary), "version"])
    except subprocess.TimeoutExpired:
        return fail("pinned sing-box version command timed out")
    if version.returncode != 0:
        return fail("pinned sing-box version command failed")
    version_lines = [line.strip() for line in version.stdout.splitlines() if line.strip()]
    if not version_lines or version_lines[0] != EXPECTED_VERSION:
        return fail(f"unexpected sing-box version output: {version_lines[:1]!r}")
    if [line for line in version_lines if line.startswith("Revision:")] != [EXPECTED_REVISION]:
        return fail("sing-box revision does not match the INT-001 pin")

    print(f"sing-box-version={EXPECTED_VERSION.removeprefix('sing-box version ')}")
    print(f"sing-box-revision={EXPECTED_REVISION.removeprefix('Revision: ')}")
    print(f"FLOWPROBE_SING_BOX_BIN={binary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
