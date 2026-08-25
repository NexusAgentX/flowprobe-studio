#!/usr/bin/env python3
"""Run the fail-closed v0.1 clean-checkout release gate."""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
import tomllib
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
SYSTEM_GIT = Path("/usr/bin/git")
MANIFEST = ROOT / "tests" / "integration" / "v0_1" / "Cargo.toml"
LEDGER = ROOT / "specs" / "nonconformance" / "v0.1" / "task-scope.toml"
MILESTONE_PATH = "docs/milestones/v0.1.md"
HISTORY_ANCHOR = "8e1461305206d93fdd068711310f8ba38cd8b158"
REQUIRED_TASK_SCOPE_TESTS = 43
EXPECTED_LEDGER_COUNTS = (8, 15, 4)
ORIGINAL_TASK_PATHS = (
    "specs/tasks/v0.1/CAP-001.toml",
    "specs/tasks/v0.1/CFG-001.toml",
    "specs/tasks/v0.1/FLOW-001.toml",
    "specs/tasks/v0.1/FOUND-001.toml",
    "specs/tasks/v0.1/GATE-001.toml",
    "specs/tasks/v0.1/INT-001.toml",
    "specs/tasks/v0.1/INT-002.toml",
    "specs/tasks/v0.1/NET-001.toml",
    "specs/tasks/v0.1/PLAN-001.toml",
    "specs/tasks/v0.1/STORE-001.toml",
    "specs/tasks/v0.1/TLS-001.toml",
    "specs/tasks/v0.1/UI-001.toml",
    "specs/tasks/v0.1/WASM-001.toml",
)
OID_RE = re.compile(r"[0-9a-f]{40}")
ATX_HEADING_RE = re.compile(rb"^( {0,3})(#{1,6})(?:[ \t]+(.*)|[ \t]*)$")


class GateError(RuntimeError):
    """A fail-closed release-gate error."""


class StepError(GateError):
    """A release-gate subprocess failure."""

    def __init__(self, code: int) -> None:
        super().__init__(f"release-gate step failed with exit code {code}")
        self.code = code


def controlled_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for name in tuple(environment):
        if name.startswith("GIT_"):
            environment.pop(name, None)
    inherited_path = environment.get("PATH", "")
    trusted_prefix = os.pathsep.join((str(SYSTEM_GIT.parent), "/bin"))
    environment["PATH"] = (
        f"{trusted_prefix}{os.pathsep}{inherited_path}"
        if inherited_path
        else trusted_prefix
    )
    environment.update(
        {
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
        }
    )
    return environment


def run_step(
    label: str,
    command: list[str],
    suppress_stdout: bool = False,
    environment_overrides: dict[str, str] | None = None,
) -> None:
    print(f"==> {label}", flush=True)
    environment = controlled_environment()
    if environment_overrides:
        environment.update(environment_overrides)
    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            check=False,
            env=environment,
            stdout=subprocess.DEVNULL if suppress_stdout else None,
        )
    except FileNotFoundError as exc:
        raise GateError(f"cannot run {command[0]!r}: executable is missing") from exc
    if result.returncode != 0:
        print(
            f"ERROR: {label} failed with exit code {result.returncode}",
            file=sys.stderr,
        )
        raise StepError(result.returncode)


def git(command: list[str], label: str) -> bytes:
    if not SYSTEM_GIT.is_file() or not os.access(SYSTEM_GIT, os.X_OK):
        raise GateError(f"trusted Git executable is missing: {SYSTEM_GIT}")
    environment = controlled_environment()
    environment.update(
        {
            "LANG": "C",
            "LC_ALL": "C",
        }
    )
    try:
        result = subprocess.run(
            [
                str(SYSTEM_GIT),
                "--no-replace-objects",
                "--no-pager",
                "-c",
                "core.fsmonitor=false",
                "-c",
                f"core.hooksPath={os.devnull}",
                *command,
            ],
            cwd=ROOT,
            check=False,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise GateError("git executable is missing") from exc
    if result.returncode != 0 or result.stderr:
        raise GateError(
            f"{label}: controlled Git command failed closed with exit code "
            f"{result.returncode}"
        )
    return result.stdout


def decode_ascii(value: bytes, label: str) -> str:
    try:
        return value.decode("ascii")
    except UnicodeDecodeError as exc:
        raise GateError(f"{label}: Git output is not ASCII") from exc


def check_clean_checkout(label: str) -> None:
    index_entries = git(
        ["ls-files", "-v", "-z", "--cached", "--"],
        f"{label} checkout index flags",
    )
    if index_entries and not index_entries.endswith(b"\0"):
        raise GateError(f"{label} checkout index listing is malformed")
    hidden_entries: list[str] = []
    for entry in index_entries[:-1].split(b"\0") if index_entries else ():
        if len(entry) < 3 or entry[1:2] != b" ":
            raise GateError(f"{label} checkout index listing is malformed")
        tag = entry[0:1]
        if tag == b"S" or tag.islower():
            hidden_entries.append(entry[2:].decode("utf-8", errors="backslashreplace"))
    if hidden_entries:
        raise GateError(
            f"{label} checkout has assume-unchanged or skip-worktree entries: "
            f"{hidden_entries[:20]!r}"
        )
    status = git(
        [
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignored=no",
            "--ignore-submodules=none",
        ],
        f"{label} checkout status",
    )
    if status:
        entries = [
            item.decode("utf-8", errors="backslashreplace")
            for item in status.rstrip(b"\0").split(b"\0")[:20]
        ]
        raise GateError(f"{label} checkout is not clean: {entries!r}")
    print(f"{label} checkout tracked/untracked state: clean")


def verify_task_scope_test_inventory() -> None:
    suite = unittest.defaultTestLoader.discover(
        str(ROOT / "scripts" / "tests"), pattern="test_task_scope.py"
    )
    discovered = suite.countTestCases()
    if discovered < REQUIRED_TASK_SCOPE_TESTS:
        raise GateError(
            "task-scope self-test inventory shrank: "
            f"expected at least {REQUIRED_TASK_SCOPE_TESTS}, found {discovered}"
        )
    print(
        "task-scope self-test inventory: "
        f"{discovered} discovered ({REQUIRED_TASK_SCOPE_TESTS} required)"
    )


def verify_ledger_counts() -> None:
    try:
        with LEDGER.open("rb") as handle:
            ledger = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise GateError("canonical task-scope ledger is unreadable") from exc

    declared = (
        ledger.get("pull_request_count"),
        ledger.get("instance_count"),
        ledger.get("adoption_count"),
    )
    actual = (
        len(ledger.get("pull_requests", [])),
        len(ledger.get("instances", [])),
        len(ledger.get("adoptions", [])),
    )
    if declared != EXPECTED_LEDGER_COUNTS or actual != EXPECTED_LEDGER_COUNTS:
        raise GateError(
            "canonical ledger counts changed: "
            f"expected {EXPECTED_LEDGER_COUNTS}, declared {declared}, actual {actual}"
        )
    numbers = tuple(entry.get("number") for entry in ledger.get("pull_requests", []))
    if numbers != tuple(range(11, 19)):
        raise GateError("canonical ledger pull-request identities are not 11 through 18")
    print("canonical ledger cardinality: 8 pull requests, 15 instances, 4 adoptions")


def parse_tree(output: bytes, label: str) -> dict[str, tuple[str, str]]:
    entries: dict[str, tuple[str, str]] = {}
    for record in output.rstrip(b"\0").split(b"\0") if output else ():
        try:
            metadata, encoded_path = record.split(b"\t", 1)
            mode, object_type, encoded_oid = metadata.split(b" ")
            path = encoded_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as exc:
            raise GateError(f"{label}: malformed ls-tree output") from exc
        mode_text = decode_ascii(mode, f"{label} mode")
        type_text = decode_ascii(object_type, f"{label} type")
        oid = decode_ascii(encoded_oid, f"{label} object id")
        if type_text != "blob" or OID_RE.fullmatch(oid) is None:
            raise GateError(f"{label}: expected an ordinary SHA-1 blob entry")
        if path in entries:
            raise GateError(f"{label}: duplicate tree path")
        entries[path] = (mode_text, oid)
    return entries


def tree_entries(commit: str, pathspec: str, label: str) -> dict[str, tuple[str, str]]:
    return parse_tree(
        git(
            ["ls-tree", "-rz", "--full-tree", commit, "--", pathspec],
            label,
        ),
        label,
    )


def read_blob(oid: str, label: str) -> bytes:
    return git(["cat-file", "blob", oid], label)


def extract_exit_criteria(document: bytes, label: str) -> bytes:
    if b"\0" in document:
        raise GateError(f"{label}: milestone contains a NUL byte")
    lines = document.splitlines(keepends=True)
    headings: list[tuple[int, int, bytes]] = []
    for index, line in enumerate(lines):
        body = line.rstrip(b"\r\n")
        match = ATX_HEADING_RE.fullmatch(body)
        if match is None:
            continue
        content = match.group(3) or b""
        content = re.sub(rb"[ \t]+#+[ \t]*$", b"", content).rstrip(b" \t")
        headings.append((index, len(match.group(2)), content))
    starts = [
        index
        for index, level, content in headings
        if level == 2 and content == b"Exit criteria"
    ]
    if len(starts) != 1:
        raise GateError(f"{label}: expected exactly one Exit criteria heading")
    start = starts[0]
    end = len(lines)
    for index, level, _content in headings:
        if index > start and level == 2:
            end = index
            break
    block = b"".join(lines[start:end])
    if not block.endswith(b"\n"):
        raise GateError(f"{label}: Exit criteria block is not newline-terminated")
    return block


def verify_historic_immutability() -> None:
    top_level = decode_ascii(
        git(["rev-parse", "--show-toplevel"], "repository root"),
        "repository root",
    ).strip()
    if Path(top_level).resolve() != ROOT:
        raise GateError("script root does not match the controlled Git worktree root")
    shallow = decode_ascii(
        git(["rev-parse", "--is-shallow-repository"], "shallow-repository check"),
        "shallow-repository check",
    ).strip()
    if shallow != "false":
        raise GateError("full Git history is required; shallow checkout detected")
    anchor_type = decode_ascii(
        git(["cat-file", "-t", HISTORY_ANCHOR], "history anchor object"),
        "history anchor object",
    ).strip()
    if anchor_type != "commit":
        raise GateError("history anchor is missing or is not a commit")
    resolved_anchor = decode_ascii(
        git(["rev-parse", "--verify", f"{HISTORY_ANCHOR}^{{commit}}"], "history anchor"),
        "history anchor",
    ).strip()
    if resolved_anchor != HISTORY_ANCHOR:
        raise GateError("history anchor did not resolve to its pinned identity")
    head = decode_ascii(
        git(["rev-parse", "--verify", "HEAD^{commit}"], "HEAD commit"),
        "HEAD commit",
    ).strip()
    first_parent_history = set(
        decode_ascii(
            git(["rev-list", "--first-parent", head], "first-parent history"),
            "first-parent history",
        ).splitlines()
    )
    if HISTORY_ANCHOR not in first_parent_history:
        raise GateError("history anchor is not present on HEAD's first-parent history")

    anchor_contracts = tree_entries(
        HISTORY_ANCHOR, "specs/tasks/v0.1", "anchor task-contract tree"
    )
    if tuple(sorted(anchor_contracts)) != ORIGINAL_TASK_PATHS:
        raise GateError("history anchor does not contain the fixed original 13-task path set")
    head_contracts = tree_entries(head, "specs/tasks/v0.1", "HEAD task-contract tree")
    for path in ORIGINAL_TASK_PATHS:
        anchor_entry = anchor_contracts[path]
        head_entry = head_contracts.get(path)
        if anchor_entry[0] != "100644" or head_entry is None or head_entry[0] != "100644":
            raise GateError(f"original task contract is not a mode-100644 blob: {path}")
        if head_entry[1] != anchor_entry[1]:
            raise GateError(f"original task contract was rewritten after the anchor: {path}")

    git(
        [
            "diff",
            "--quiet",
            "--no-ext-diff",
            "--no-textconv",
            HISTORY_ANCHOR,
            head,
            "--",
            *ORIGINAL_TASK_PATHS,
        ],
        "original task-contract diff",
    )

    anchor_milestone = tree_entries(
        HISTORY_ANCHOR, MILESTONE_PATH, "anchor milestone tree entry"
    )
    head_milestone = tree_entries(head, MILESTONE_PATH, "HEAD milestone tree entry")
    anchor_entry = anchor_milestone.get(MILESTONE_PATH)
    head_entry = head_milestone.get(MILESTONE_PATH)
    if (
        anchor_entry is None
        or head_entry is None
        or anchor_entry[0] != "100644"
        or head_entry[0] != "100644"
    ):
        raise GateError("v0.1 milestone must be a mode-100644 blob at anchor and HEAD")
    anchor_exit = extract_exit_criteria(
        read_blob(anchor_entry[1], "anchor milestone blob"), "anchor milestone"
    )
    head_exit = extract_exit_criteria(
        read_blob(head_entry[1], "HEAD milestone blob"), "HEAD milestone"
    )
    if head_exit != anchor_exit:
        raise GateError("the complete v0.1 Exit criteria block was rewritten after the anchor")
    exit_digest = hashlib.sha256(anchor_exit).hexdigest()
    print(
        "historic immutability: anchor on first-parent history; "
        f"13 contracts unchanged; Exit criteria sha256={exit_digest}"
    )
    print("controlled Git: replacements disabled; external diff/textconv disabled; locale=C")


def execute_gate() -> None:
    if not MANIFEST.is_file():
        raise GateError(f"isolated integration manifest is missing: {MANIFEST}")

    manifest = str(MANIFEST)
    run_step(
        "validate repository task contracts",
        [sys.executable, "-B", str(ROOT / "scripts" / "validate_tasks.py")],
    )
    verify_task_scope_test_inventory()
    run_step(
        "run at least 43 task-scope self-tests",
        [
            sys.executable,
            "-B",
            "-m",
            "unittest",
            "discover",
            "-s",
            str(ROOT / "scripts" / "tests"),
            "-p",
            "test_task_scope.py",
        ],
    )
    run_step(
        "audit the canonical task-scope ledger (8 PRs / 15 instances / 4 adoptions)",
        [
            sys.executable,
            "-B",
            str(ROOT / "scripts" / "check_task_scope.py"),
            "audit",
            "--ledger",
            str(LEDGER),
        ],
    )
    verify_ledger_counts()
    verify_historic_immutability()

    steps: list[tuple[str, list[str], bool, dict[str, str] | None]] = [
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
            None,
        ),
        (
            "run the repository anti-shortcut gate",
            [sys.executable, "-B", str(ROOT / "scripts" / "quality_gate.py")],
            False,
            None,
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
            None,
        ),
        (
            "check isolated Rust formatting",
            ["cargo", "fmt", "--manifest-path", manifest, "--all", "--", "--check"],
            False,
            None,
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
            None,
        ),
        (
            "document the isolated integration crate with warnings denied",
            [
                "cargo",
                "doc",
                "--manifest-path",
                manifest,
                "--locked",
                "--no-deps",
            ],
            False,
            {"RUSTDOCFLAGS": "-Dwarnings"},
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
            None,
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
            None,
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
            None,
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
            None,
        ),
    ]
    for label, command, suppress_stdout, environment in steps:
        run_step(label, command, suppress_stdout, environment)


def main() -> int:
    result = 0
    try:
        check_clean_checkout("starting")
        execute_gate()
    except StepError as exc:
        result = exc.code
    except GateError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        result = 1
    finally:
        try:
            check_clean_checkout("ending")
        except GateError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            if result == 0:
                result = 1
    if result == 0:
        print("v0.1 clean-checkout integration gate passed.")
    return result


if __name__ == "__main__":
    raise SystemExit(main())
