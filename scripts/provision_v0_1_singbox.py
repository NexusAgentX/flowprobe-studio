#!/usr/bin/env python3
"""Explicitly provision and identify the pinned sing-box proof binary with mise."""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

TOOL = "github:sagernet/sing-box@1.13.19"
EXPECTED_VERSION = "sing-box version 1.13.19"
EXPECTED_REVISION = "Revision: b5ebaa1fc0f2b94256180b95468e73ef53caa27d"


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


def main() -> int:
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

    print(f"sing-box-binary={binary}")
    print(f"sing-box-version={EXPECTED_VERSION.removeprefix('sing-box version ')}")
    print(f"sing-box-revision={EXPECTED_REVISION.removeprefix('Revision: ')}")
    print(f"sing-box-sha256={sha256(binary)}")
    print(f"FLOWPROBE_SING_BOX_BIN={binary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
