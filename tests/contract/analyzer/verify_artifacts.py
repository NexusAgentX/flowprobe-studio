#!/usr/bin/env python3
"""Rebuild Analyzer components reproducibly and verify checked-in bytes."""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
TARGET = "wasm32-unknown-unknown"
GUEST_MANIFEST = ROOT / "tests/contract/analyzer/guest/Cargo.toml"


@dataclass(frozen=True)
class Artifact:
    name: str
    package: str | None
    manifest: Path
    features: tuple[str, ...]
    core_name: str
    checked_in: Path


ARTIFACTS = (
    Artifact(
        name="demo",
        package="flowprobe-demo-analyzer",
        manifest=ROOT / "Cargo.toml",
        features=(),
        core_name="flowprobe_demo_analyzer.wasm",
        checked_in=ROOT / "plugins/demo/artifacts/flowprobe_demo_analyzer.wasm",
    ),
    Artifact(
        name="adversarial",
        package=None,
        manifest=GUEST_MANIFEST,
        features=(),
        core_name="flowprobe_adversarial_analyzer_fixture.wasm",
        checked_in=ROOT
        / "tests/contract/analyzer/artifacts/adversarial_analyzer.wasm",
    ),
    Artifact(
        name="invalid-info",
        package=None,
        manifest=GUEST_MANIFEST,
        features=("invalid-info",),
        core_name="flowprobe_adversarial_analyzer_fixture.wasm",
        checked_in=ROOT
        / "tests/contract/analyzer/artifacts/invalid_info_analyzer.wasm",
    ),
    Artifact(
        name="hostile-info",
        package=None,
        manifest=GUEST_MANIFEST,
        features=("hostile-info",),
        core_name="flowprobe_adversarial_analyzer_fixture.wasm",
        checked_in=ROOT
        / "tests/contract/analyzer/artifacts/hostile_info_analyzer.wasm",
    ),
)


def run(*args: str, env: dict[str, str] | None = None) -> None:
    subprocess.run(args, cwd=ROOT, env=env, check=True)


def output(*args: str) -> str:
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def cargo_home() -> Path:
    configured = os.environ.get("CARGO_HOME")
    candidate = Path(configured).expanduser() if configured else Path.home() / ".cargo"
    return candidate.absolute()


def path_spellings(path: Path) -> tuple[Path, ...]:
    """Return lexical and filesystem-resolved spellings of an absolute path."""
    absolute = path.expanduser().absolute()
    return tuple(dict.fromkeys((absolute, absolute.resolve())))


def reproducible_environment(target_dir: Path) -> tuple[dict[str, str], tuple[Path, ...]]:
    home = Path.home().absolute()
    cargo = cargo_home()
    registry_source = cargo / "registry/src"
    sysroot = Path(output("rustc", "--print", "sysroot")).absolute()

    conceptual_remaps = (
        (target_dir, "/flowprobe/target"),
        (ROOT, "/flowprobe/source"),
        (registry_source, "/flowprobe/cargo-registry-src"),
        (cargo, "/flowprobe/cargo-home"),
        (sysroot, "/flowprobe/rust-sysroot"),
    )
    # Cargo/rustc can retain either a configured lexical path (for example
    # `/tmp`) or its filesystem-resolved spelling (`/private/tmp`). Remap both
    # to the same virtual prefix so a symlink alias cannot evade reproducibility.
    remaps = tuple(
        (spelling, destination)
        for source, destination in conceptual_remaps
        for spelling in path_spellings(source)
    )
    flags = tuple(f"--remap-path-prefix={source}={destination}" for source, destination in remaps)

    environment = os.environ.copy()
    environment.pop("RUSTFLAGS", None)
    environment.update(
        {
            "CARGO_ENCODED_RUSTFLAGS": "\x1f".join(flags),
            "CARGO_INCREMENTAL": "0",
            "CARGO_TARGET_DIR": str(target_dir),
            "CARGO_TERM_COLOR": "never",
            "SOURCE_DATE_EPOCH": "0",
        }
    )
    local_paths = tuple(
        spelling
        for source in (ROOT, home, cargo, registry_source, sysroot)
        for spelling in path_spellings(source)
    )
    return environment, local_paths


def build_componentizer(temporary: Path) -> tuple[Path, tuple[Path, ...]]:
    target_dir = temporary / "componentizer-target"
    environment, forbidden_paths = reproducible_environment(target_dir)
    run(
        "cargo",
        "build",
        "--manifest-path",
        str(ROOT / "Cargo.toml"),
        "--locked",
        "--offline",
        "-p",
        "flowprobe-analyzer-runtime",
        "--example",
        "componentize",
        env=environment,
    )
    executable = target_dir / "debug/examples/componentize"
    if os.name == "nt":
        executable = executable.with_suffix(".exe")
    return executable, forbidden_paths


def build_artifact(
    artifact: Artifact,
    temporary: Path,
    componentizer: Path,
    forbidden_paths: tuple[Path, ...],
) -> Path:
    # A distinct target tree per artifact/feature prevents feature-unification
    # or stale incremental output from affecting the bytes under verification.
    target_dir = temporary / f"{artifact.name}-target"
    environment, observed_paths = reproducible_environment(target_dir)
    if observed_paths != forbidden_paths:
        raise SystemExit("build path discovery changed during artifact generation")

    command = [
        "cargo",
        "build",
        "--manifest-path",
        str(artifact.manifest),
        "--locked",
        "--offline",
        "--target",
        TARGET,
        "--release",
    ]
    if artifact.package is not None:
        command.extend(("-p", artifact.package))
    if artifact.features:
        command.extend(("--features", ",".join(artifact.features)))
    run(*command, env=environment)

    core = target_dir / TARGET / "release" / artifact.core_name
    generated = temporary / f"{artifact.name}.wasm"
    run(str(componentizer), str(core), str(generated), env=environment)
    reject_local_paths(
        generated,
        forbidden_paths
        + path_spellings(temporary)
        + path_spellings(target_dir),
    )
    return generated


def reject_local_paths(artifact: Path, paths: tuple[Path, ...]) -> None:
    artifact_bytes = artifact.read_bytes()
    for path in dict.fromkeys(paths):
        encoded = os.fsencode(path)
        if encoded and encoded in artifact_bytes:
            raise SystemExit(f"local absolute path leaked into {artifact}: {path}")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def install_or_verify(
    generated: Path,
    checked_in: Path,
    forbidden_paths: tuple[Path, ...],
    write: bool,
) -> None:
    if write:
        checked_in.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(generated, checked_in)
    reject_local_paths(checked_in, forbidden_paths)

    generated_bytes = generated.read_bytes()
    checked_in_bytes = checked_in.read_bytes()
    generated_hash = sha256(generated)
    checked_in_hash = sha256(checked_in)
    if generated_bytes != checked_in_bytes:
        raise SystemExit(
            f"artifact drift for {checked_in.relative_to(ROOT)}: "
            f"generated sha256={generated_hash}, checked-in sha256={checked_in_hash}"
        )
    action = "regenerated" if write else "verified"
    print(f"{action} {checked_in.relative_to(ROOT)} sha256={checked_in_hash}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write",
        action="store_true",
        help="replace checked-in artifacts with the reproducible build output",
    )
    return parser.parse_args()


def main() -> None:
    arguments = parse_args()
    with tempfile.TemporaryDirectory(prefix="flowprobe-analyzer-artifacts-") as directory:
        temporary = Path(directory)
        componentizer, forbidden_paths = build_componentizer(temporary)
        for artifact in ARTIFACTS:
            generated = build_artifact(
                artifact, temporary, componentizer, forbidden_paths
            )
            install_or_verify(
                generated,
                artifact.checked_in,
                forbidden_paths,
                arguments.write,
            )


if __name__ == "__main__":
    main()
