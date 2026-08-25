#!/usr/bin/env python3
"""Enforce task path contracts and audit the v0.1 scope ledger."""
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Sequence


SCRIPT_ROOT = Path(__file__).resolve().parents[1]
TASK_PREFIX = "specs/tasks/"
CANONICAL_LEDGER = "specs/nonconformance/v0.1/task-scope.toml"
LEDGER_KIND = "flowprobe-task-scope-nonconformance"
LEDGER_MILESTONE = "v0.1"
LEDGER_STATUS = "historic-nonconformance-corrected-and-closed"
LEDGER_CORRECTION_TASK = "SCOPE-001"
LEDGER_HISTORY_TIP = "8e1461305206d93fdd068711310f8ba38cd8b158"
LEDGER_CORRECTION_BASE = "f8fdf889aa51c35e1a081018e402008f53a72acf"
LEDGER_PR_COUNT = 8
LEDGER_INSTANCE_COUNT = 15
LEDGER_ADOPTION_COUNT = 4
LEDGER_ADOPTION_PATHS = ("Cargo.toml", "Cargo.lock", "pnpm-lock.yaml", "mise.toml")
ZERO_OID = "0" * 40
MAX_INPUT_BYTES = 4 * 1024 * 1024
DIFF_RENAME_LIMIT = 1000
PROTECTED_ARCHITECTURE_NAMESPACES = (
    "PRODUCT.md",
    "ARCHITECTURE.md",
    "docs/adr",
    "docs/contracts",
)
EXPECTED_CHECK_CONTRACTS = {
    "description": "Validate task contracts, task scope, and anti-shortcut policy",
    "run": [
        "python -B scripts/validate_tasks.py",
        "python -B -m unittest discover -s scripts/tests -p 'test_quality_gate.py'",
        "python -B -m unittest discover -s scripts/tests -p 'test_task_scope.py'",
        "python -B scripts/quality_gate.py",
        "python -B scripts/check_task_scope.py audit --ledger specs/nonconformance/v0.1/task-scope.toml",
    ],
}

TASK_ID_RE = re.compile(r"^[A-Z][A-Z0-9]+-[0-9]{3}$")
TASK_ID_LINE_RE = re.compile(r"^Task ID: ([A-Z][A-Z0-9]+-[0-9]{3})$")
OID_RE = re.compile(r"^[0-9a-f]{40}$")
MODE_RE = re.compile(r"^[0-7]{6}$")
STATUS_RE = re.compile(r"^(?:[AMDT]|[RC](?:0[0-9]{2}|100))$")
SAFE_EXACT_PATTERN_RE = re.compile(r"^[A-Za-z0-9._@+ -]+(?:/[A-Za-z0-9._@+ -]+)*$")

TASK_REQUIRED_FIELDS = {
    "id",
    "milestone",
    "title",
    "goal",
    "depends_on",
    "allowed_paths",
    "forbidden_paths",
    "acceptance",
    "definition_of_done",
}
LEDGER_TOP_FIELDS = {
    "schema_version",
    "kind",
    "milestone",
    "status",
    "correction_task",
    "history_tip",
    "correction_base",
    "first_base",
    "pull_request_count",
    "instance_count",
    "adoption_count",
    "canonical_path",
    "statement",
    "pull_requests",
    "disclosures",
    "instances",
    "adoptions",
}
PR_FIELDS = {
    "number",
    "task_id",
    "url",
    "base_commit",
    "head_commit",
    "merge_commit",
    "merge_kind",
    "contract_path",
    "contract_blob",
    "disclosure_id",
    "nonconformance_instance_count",
}
DISCLOSURE_FIELDS = {
    "id",
    "pr_number",
    "source_kind",
    "source_url",
    "retrieved_at",
    "source_utf8_bytes",
    "source_sha256",
    "excerpt",
    "interpretation",
}
INSTANCE_FIELDS = {
    "pr_number",
    "task_id",
    "change_status",
    "path_role",
    "path",
    "old_path",
    "new_path",
    "old_mode",
    "new_mode",
    "old_blob",
    "new_blob",
    "allowed_matches",
    "forbidden_matches",
    "literal_allowed",
    "literal_forbidden",
    "decision",
    "task_relevance",
    "disclosure_id",
}
ADOPTION_FIELDS = {
    "path",
    "baseline_commit",
    "baseline_blob",
    "adopted_blob",
    "supports_tasks",
    "necessity",
    "verification",
    "content_change",
}


class ScopeError(RuntimeError):
    """A fail-closed validation error with a secret-safe diagnostic."""


@dataclass(frozen=True)
class TaskContract:
    task_id: str
    milestone: str
    path: str
    blob: str
    depends_on: tuple[str, ...]
    allowed_paths: tuple[str, ...]
    forbidden_paths: tuple[str, ...]


@dataclass(frozen=True)
class NameChange:
    status: str
    old_path: str
    new_path: str

    def endpoints(self) -> tuple[tuple[str, str], ...]:
        if self.status[0] in {"R", "C"}:
            return (("old", self.old_path), ("new", self.new_path))
        path = self.new_path if self.status == "A" else self.old_path
        return (("path", path),)


@dataclass(frozen=True)
class RawChange:
    status: str
    old_path: str
    new_path: str
    old_mode: str
    new_mode: str
    old_blob: str
    new_blob: str


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _text(value: object, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise ScopeError(f"{label}: expected {'a string' if allow_empty else 'a non-empty string'}")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ScopeError(f"{label}: control characters are not allowed")
    return value


def _integer(value: object, label: str, *, minimum: int = 0) -> int:
    if not _is_int(value) or value < minimum:
        raise ScopeError(f"{label}: expected an integer >= {minimum}")
    return value


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise ScopeError(f"{label}: expected a boolean")
    return value


def _string_array(value: object, label: str, *, nonempty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ScopeError(f"{label}: expected an array of strings")
    result = tuple(_text(item, f"{label} item") for item in value)
    if nonempty and not result:
        raise ScopeError(f"{label}: expected at least one item")
    if len(result) != len(set(result)):
        raise ScopeError(f"{label}: duplicate items are not allowed")
    return result


def _require_fields(value: object, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ScopeError(f"{label}: expected a table")
    actual = set(value)
    if actual != expected:
        raise ScopeError(f"{label}: schema fields do not match")
    return value


def _oid(value: object, label: str, *, zero_allowed: bool = False) -> str:
    result = _text(value, label)
    if not OID_RE.fullmatch(result) or (not zero_allowed and result == ZERO_OID):
        raise ScopeError(f"{label}: invalid object identity")
    return result


def _mode(value: object, label: str, *, zero_allowed: bool = False) -> str:
    result = _text(value, label)
    if not MODE_RE.fullmatch(result) or (not zero_allowed and result == "000000"):
        raise ScopeError(f"{label}: invalid Git mode")
    return result


def validate_path(value: str, label: str, *, allow_empty: bool = False) -> str:
    if allow_empty and value == "":
        return value
    _text(value, label)
    if value.startswith("/") or "\\" in value or value.endswith("/") or "//" in value:
        raise ScopeError(f"{label}: invalid repository path")
    parsed = PurePosixPath(value)
    if not parsed.parts or any(part in {"", ".", ".."} for part in parsed.parts):
        raise ScopeError(f"{label}: invalid repository path")
    if parsed.as_posix() != value:
        raise ScopeError(f"{label}: non-canonical repository path")
    return value


def validate_pattern(value: str, label: str) -> str:
    _text(value, label)
    recursive = value.endswith("/**")
    exact = value[:-3] if recursive else value
    validate_path(exact, label)
    if any(character in exact for character in "*?[") or not SAFE_EXACT_PATTERN_RE.fullmatch(exact):
        raise ScopeError(f"{label}: unsupported path pattern")
    return value


def pattern_matches(pattern: str, path: str) -> bool:
    if pattern.endswith("/**"):
        prefix = pattern[:-3]
        return path.startswith(prefix + "/")
    return path == pattern


def matching_patterns(patterns: Sequence[str], path: str) -> tuple[str, ...]:
    return tuple(pattern for pattern in patterns if pattern_matches(pattern, path))


def pattern_intersects_protected_architecture(pattern: str) -> bool:
    if not pattern.endswith("/**"):
        return any(
            pattern == protected or pattern.startswith(protected + "/")
            for protected in PROTECTED_ARCHITECTURE_NAMESPACES
        )
    prefix = pattern[:-3]
    return any(
        prefix == protected
        or prefix.startswith(protected + "/")
        or protected.startswith(prefix + "/")
        for protected in PROTECTED_ARCHITECTURE_NAMESPACES
    )


def _git(
    root: Path,
    arguments: Sequence[str],
    *,
    input_bytes: bytes | None = None,
    label: str,
) -> bytes:
    environment = os.environ.copy()
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    environment["LC_ALL"] = "C"
    environment["LANG"] = "C"
    command = ["git", "--no-replace-objects", *arguments]
    try:
        result = subprocess.run(
            command,
            cwd=root,
            env=environment,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        raise ScopeError(f"Git {label} could not be executed") from exc
    if result.returncode != 0:
        raise ScopeError(f"Git {label} failed")
    if result.stderr:
        raise ScopeError(f"Git {label} emitted unexpected diagnostics")
    return result.stdout


def _decode(encoded: bytes, label: str) -> str:
    try:
        return encoded.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ScopeError(f"{label}: invalid UTF-8") from exc


def resolve_repo_root(candidate: Path) -> Path:
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise ScopeError("repository root is unreadable") from exc
    if not resolved.is_dir():
        raise ScopeError("repository root is not a directory")
    reported = _decode(
        _git(resolved, ["rev-parse", "--show-toplevel"], label="repository discovery"),
        "repository root",
    ).rstrip("\n")
    try:
        git_root = Path(reported).resolve(strict=True)
    except OSError as exc:
        raise ScopeError("Git reported an unreadable repository root") from exc
    if git_root != resolved:
        raise ScopeError("--repo-root must name the Git worktree root")
    return resolved


def resolve_commit(root: Path, revision: str, label: str) -> str:
    _text(revision, label)
    encoded = _git(
        root,
        ["rev-parse", "--verify", "--end-of-options", f"{revision}^{{commit}}"],
        label=f"{label} resolution",
    )
    result = _decode(encoded, label).strip()
    if not OID_RE.fullmatch(result):
        raise ScopeError(f"{label}: Git did not return one full commit identity")
    return result


def merge_base(root: Path, base: str, head: str) -> str:
    encoded = _git(root, ["merge-base", "--all", base, head], label="merge-base resolution")
    lines = _decode(encoded, "merge base").splitlines()
    if len(lines) != 1 or not OID_RE.fullmatch(lines[0]):
        raise ScopeError("merge-base resolution was ambiguous")
    return lines[0]


def _parse_ls_tree(encoded: bytes, label: str) -> list[tuple[str, str, str, str]]:
    result: list[tuple[str, str, str, str]] = []
    for entry in encoded.split(b"\0"):
        if not entry:
            continue
        try:
            header, raw_path = entry.split(b"\t", 1)
            raw_mode, raw_type, raw_oid = header.split(b" ")
        except ValueError as exc:
            raise ScopeError(f"{label}: malformed Git tree record") from exc
        mode = _decode(raw_mode, label)
        object_type = _decode(raw_type, label)
        oid = _decode(raw_oid, label)
        path = validate_path(_decode(raw_path, label), label)
        if not MODE_RE.fullmatch(mode) or not OID_RE.fullmatch(oid):
            raise ScopeError(f"{label}: malformed Git tree identity")
        result.append((mode, object_type, oid, path))
    return result


def tree_entry(root: Path, commit: str, path: str, *, required: bool = True) -> tuple[str, str] | None:
    validate_path(path, "tree path")
    entries = _parse_ls_tree(
        _git(root, ["ls-tree", "-z", commit, "--", path], label="tree lookup"),
        "tree lookup",
    )
    exact = [entry for entry in entries if entry[3] == path]
    if not exact:
        if required:
            raise ScopeError("required committed path is missing")
        return None
    if len(exact) != 1 or exact[0][1] != "blob":
        raise ScopeError("committed path does not identify one blob")
    return exact[0][0], exact[0][2]


def read_blob(root: Path, oid: str, label: str) -> bytes:
    _oid(oid, label)
    size_encoded = _git(root, ["cat-file", "-s", oid], label=f"{label} size")
    try:
        size = int(_decode(size_encoded, f"{label} size").strip())
    except ValueError as exc:
        raise ScopeError(f"{label}: invalid blob size") from exc
    if size < 0 or size > MAX_INPUT_BYTES:
        raise ScopeError(f"{label}: blob exceeds the input limit")
    encoded = _git(root, ["cat-file", "blob", oid], label=f"{label} read")
    if len(encoded) != size:
        raise ScopeError(f"{label}: blob size changed during read")
    return encoded


def read_commit_path(root: Path, commit: str, path: str, label: str) -> tuple[str, bytes]:
    entry = tree_entry(root, commit, path)
    assert entry is not None
    _mode_value, oid = entry
    return oid, read_blob(root, oid, label)


def read_task_contract_path(root: Path, commit: str, path: str, label: str) -> tuple[str, bytes]:
    entry = tree_entry(root, commit, path)
    assert entry is not None
    if entry[0] != "100644":
        raise ScopeError(f"{label}: task contract mode must be 100644")
    return entry[1], read_blob(root, entry[1], label)


def _load_toml(encoded: bytes, label: str) -> dict[str, Any]:
    try:
        text = encoded.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ScopeError(f"{label}: invalid UTF-8") from exc
    try:
        value = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError) as exc:
        raise ScopeError(f"{label}: invalid TOML") from exc
    if not isinstance(value, dict):
        raise ScopeError(f"{label}: expected a TOML table")
    return value


def _validate_task_data(data: dict[str, Any], *, path: str, blob: str) -> TaskContract:
    missing = TASK_REQUIRED_FIELDS - data.keys()
    if missing:
        raise ScopeError("task contract: required fields are missing")
    task_id = _text(data.get("id"), "task contract id")
    if not TASK_ID_RE.fullmatch(task_id):
        raise ScopeError("task contract: invalid task id")
    milestone = _text(data.get("milestone"), "task contract milestone")
    expected_parts = PurePosixPath(path).parts
    if len(expected_parts) != 4 or expected_parts[:2] != ("specs", "tasks"):
        raise ScopeError("task contract: invalid contract path")
    if expected_parts[2] != milestone or expected_parts[3] != f"{task_id}.toml":
        raise ScopeError("task contract: path does not match id and milestone")
    for field in ("title", "goal"):
        _text(data.get(field), f"task contract {field}")
    depends_on = _string_array(data.get("depends_on"), "task contract depends_on")
    for dependency in depends_on:
        if not TASK_ID_RE.fullmatch(dependency):
            raise ScopeError("task contract: invalid dependency id")
    for field in ("acceptance", "definition_of_done"):
        _string_array(data.get(field), f"task contract {field}")
    allowed = _string_array(data.get("allowed_paths"), "task contract allowed_paths")
    forbidden = _string_array(data.get("forbidden_paths"), "task contract forbidden_paths")
    for index, pattern in enumerate(allowed):
        validate_pattern(pattern, f"allowed_paths[{index}]")
    for index, pattern in enumerate(forbidden):
        validate_pattern(pattern, f"forbidden_paths[{index}]")
    if not task_id.startswith("ARCH-") and any(
        pattern_intersects_protected_architecture(pattern) for pattern in allowed
    ):
        raise ScopeError("ordinary task contract may not allow protected architecture paths")
    return TaskContract(task_id, milestone, path, blob, depends_on, allowed, forbidden)


def list_task_contract_paths(root: Path, commit: str) -> tuple[str, ...]:
    entries = _parse_ls_tree(
        _git(
            root,
            ["ls-tree", "-r", "-z", "--full-tree", commit, "--", "specs/tasks"],
            label="task contract discovery",
        ),
        "task contract discovery",
    )
    paths = tuple(
        path
        for _mode_value, object_type, _oid_value, path in entries
        if object_type == "blob" and path.startswith(TASK_PREFIX) and path.endswith(".toml")
    )
    if len(paths) != len(set(paths)):
        raise ScopeError("task contract discovery returned duplicate paths")
    return paths


def load_task_contract(root: Path, commit: str, task_id: str) -> TaskContract:
    if not TASK_ID_RE.fullmatch(task_id):
        raise ScopeError("invalid task identity")
    matches = [
        path
        for path in list_task_contract_paths(root, commit)
        if PurePosixPath(path).name == f"{task_id}.toml"
    ]
    if len(matches) != 1:
        raise ScopeError("task identity is unknown or ambiguous at the trusted base")
    oid, encoded = read_task_contract_path(root, commit, matches[0], "task contract")
    return _validate_task_data(_load_toml(encoded, "task contract"), path=matches[0], blob=oid)


def load_task_contracts(root: Path, commit: str) -> tuple[TaskContract, ...]:
    contracts: list[TaskContract] = []
    for path in list_task_contract_paths(root, commit):
        oid, encoded = read_task_contract_path(root, commit, path, "task contract")
        contracts.append(
            _validate_task_data(
                _load_toml(encoded, "task contract"),
                path=path,
                blob=oid,
            )
        )
    if len({contract.task_id for contract in contracts}) != len(contracts):
        raise ScopeError("trusted-base task ids must be unique")
    return tuple(contracts)


def validate_task_dag(contracts: Sequence[TaskContract]) -> None:
    by_id = {contract.task_id: contract for contract in contracts}
    if len(by_id) != len(contracts):
        raise ScopeError("merged task ids must be unique")
    for contract in contracts:
        for dependency in contract.depends_on:
            if dependency not in by_id:
                raise ScopeError("merged task DAG contains an unknown dependency")

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(task_id: str) -> None:
        if task_id in visited:
            return
        if task_id in visiting:
            raise ScopeError("merged task DAG contains a dependency cycle")
        visiting.add(task_id)
        for dependency in by_id[task_id].depends_on:
            visit(dependency)
        visiting.remove(task_id)
        visited.add(task_id)

    for task_id in by_id:
        visit(task_id)


def parse_name_changes(encoded: bytes) -> tuple[NameChange, ...]:
    fields = encoded.split(b"\0")
    if fields and fields[-1] == b"":
        fields.pop()
    result: list[NameChange] = []
    index = 0
    while index < len(fields):
        status = _decode(fields[index], "name-status record")
        index += 1
        if not STATUS_RE.fullmatch(status):
            raise ScopeError("name-status record: unsupported change status")
        if status[0] in {"R", "C"}:
            if index + 1 >= len(fields):
                raise ScopeError("name-status record: missing rename/copy endpoint")
            old_path = validate_path(_decode(fields[index], "old path"), "old path")
            new_path = validate_path(_decode(fields[index + 1], "new path"), "new path")
            index += 2
        else:
            if index >= len(fields):
                raise ScopeError("name-status record: missing path")
            path = validate_path(_decode(fields[index], "changed path"), "changed path")
            index += 1
            old_path = "" if status == "A" else path
            new_path = "" if status == "D" else path
        result.append(NameChange(status, old_path, new_path))
    if not result:
        raise ScopeError("pull request diff is empty")
    return tuple(result)


def changed_names(root: Path, base: str, head: str) -> tuple[NameChange, ...]:
    encoded = _git(
        root,
        [
            "diff",
            "--name-status",
            "-z",
            "--no-ext-diff",
            "--no-textconv",
            "--find-renames=50%",
            "--find-copies=50%",
            "--find-copies-harder",
            f"-l{DIFF_RENAME_LIMIT}",
            base,
            head,
            "--",
        ],
        label="pull request path diff",
    )
    return parse_name_changes(encoded)


def _contract_scope_decision(contract: TaskContract, path: str) -> tuple[bool, bool]:
    allowed = bool(matching_patterns(contract.allowed_paths, path))
    forbidden = bool(matching_patterns(contract.forbidden_paths, path))
    return allowed, forbidden


def _check_changes_against_contract(contract: TaskContract, changes: Sequence[NameChange]) -> None:
    errors: list[str] = []
    for change in changes:
        for role, path in change.endpoints():
            allowed, forbidden = _contract_scope_decision(contract, path)
            if forbidden:
                errors.append(f"{change.status} {role} {path}: path is forbidden")
            elif not allowed:
                errors.append(f"{change.status} {role} {path}: path is outside allowed_paths")
    if errors:
        raise ScopeError("task path scope rejected:\n" + "\n".join(sorted(errors)))


def _is_new_task_toml(path: str) -> bool:
    parts = PurePosixPath(path).parts
    return (
        len(parts) == 4
        and parts[:2] == ("specs", "tasks")
        and parts[2].startswith("v")
        and parts[3].endswith(".toml")
        and TASK_ID_RE.fullmatch(parts[3][:-5]) is not None
    )


def _check_plan_bootstrap(
    root: Path,
    trusted_base: str,
    head: str,
    task_id: str,
    changes: Sequence[NameChange],
) -> None:
    if not task_id.startswith("PLAN-"):
        raise ScopeError("unknown task is not an eligible planning bootstrap")
    for change in changes:
        if change.status != "A" or change.old_path or not _is_new_task_toml(change.new_path):
            raise ScopeError("planning bootstrap may only add new task TOML files")
        if tree_entry(root, trusted_base, change.new_path, required=False) is not None:
            raise ScopeError("planning bootstrap may not replace a trusted-base task contract")
    head_contracts: list[TaskContract] = []
    for change in changes:
        oid, encoded = read_task_contract_path(root, head, change.new_path, "planning contract")
        head_contracts.append(
            _validate_task_data(
                _load_toml(encoded, "planning contract"),
                path=change.new_path,
                blob=oid,
            )
        )
    if len({contract.task_id for contract in head_contracts}) != len(head_contracts):
        raise ScopeError("planning bootstrap task ids must be unique")
    trusted_contracts = load_task_contracts(root, trusted_base)
    trusted_ids = {contract.task_id for contract in trusted_contracts}
    if any(contract.task_id in trusted_ids for contract in head_contracts):
        raise ScopeError("planning bootstrap may not duplicate a trusted-base task id")
    matching = [contract for contract in head_contracts if contract.task_id == task_id]
    if len(matching) != 1:
        raise ScopeError("planning bootstrap task identity is missing or ambiguous")
    added_paths = {change.new_path for change in changes}
    if set(matching[0].allowed_paths) != added_paths:
        raise ScopeError("planning bootstrap allowed_paths must exactly name every added task contract")
    if any("/**" in pattern for pattern in matching[0].allowed_paths):
        raise ScopeError("planning bootstrap may not use recursive allowed_paths")
    for path in added_paths:
        if matching_patterns(matching[0].forbidden_paths, path):
            raise ScopeError("planning bootstrap task path is forbidden by the PLAN contract")
    validate_task_dag((*trusted_contracts, *head_contracts))


def check_scope(root: Path, task_id: str, base_revision: str, head_revision: str) -> None:
    base_commit = resolve_commit(root, base_revision, "base revision")
    head_commit = resolve_commit(root, head_revision, "head revision")
    diff_base = merge_base(root, base_commit, head_commit)
    changes = changed_names(root, diff_base, head_commit)
    try:
        contract = load_task_contract(root, base_commit, task_id)
    except ScopeError as exc:
        if "unknown or ambiguous" not in str(exc):
            raise
        _check_plan_bootstrap(root, base_commit, head_commit, task_id, changes)
        return
    if any(
        endpoint_path == contract.path
        for change in changes
        for _role, endpoint_path in change.endpoints()
    ):
        raise ScopeError("an ordinary task may not modify its trusted-base contract")
    _check_changes_against_contract(contract, changes)


def read_event_file(path: Path) -> tuple[str, str, str]:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_INPUT_BYTES:
            raise ScopeError("event file is not a bounded regular file")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            encoded = os.read(descriptor, MAX_INPUT_BYTES + 1)
            if os.fstat(descriptor).st_size != metadata.st_size:
                raise ScopeError("event file changed during read")
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise ScopeError("event file is unreadable") from exc
    if len(encoded) > MAX_INPUT_BYTES:
        raise ScopeError("event file exceeds the input limit")
    try:
        event = json.loads(encoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ScopeError("event file is not valid UTF-8 JSON") from exc
    if not isinstance(event, dict) or "pull_request" not in event:
        raise ScopeError("event file has an unsupported schema")
    pull_request = event["pull_request"]
    if not isinstance(pull_request, dict):
        raise ScopeError("event file pull_request is not an object")
    body = pull_request.get("body")
    if not isinstance(body, str):
        raise ScopeError("pull request body must be a string")
    task_lines = [match.group(1) for line in body.splitlines() if (match := TASK_ID_LINE_RE.fullmatch(line))]
    if len(task_lines) != 1:
        raise ScopeError("pull request body must contain exactly one 'Task ID: <ID>' line")
    base = pull_request.get("base")
    head = pull_request.get("head")
    if not isinstance(base, dict) or "sha" not in base:
        raise ScopeError("event file base schema is invalid")
    if not isinstance(head, dict) or "sha" not in head:
        raise ScopeError("event file head schema is invalid")
    base_sha = _oid(base.get("sha"), "event base sha")
    head_sha = _oid(head.get("sha"), "event head sha")
    return task_lines[0], base_sha, head_sha


def parse_raw_changes(encoded: bytes) -> tuple[RawChange, ...]:
    fields = encoded.split(b"\0")
    if fields and fields[-1] == b"":
        fields.pop()
    result: list[RawChange] = []
    index = 0
    while index < len(fields):
        header = _decode(fields[index], "raw diff record")
        index += 1
        if not header.startswith(":"):
            raise ScopeError("raw diff record: malformed header")
        parts = header[1:].split(" ")
        if len(parts) != 5:
            raise ScopeError("raw diff record: malformed identity fields")
        old_mode, new_mode, old_blob, new_blob, status = parts
        _mode(old_mode, "raw old mode", zero_allowed=True)
        _mode(new_mode, "raw new mode", zero_allowed=True)
        _oid(old_blob, "raw old blob", zero_allowed=True)
        _oid(new_blob, "raw new blob", zero_allowed=True)
        if not STATUS_RE.fullmatch(status):
            raise ScopeError("raw diff record: unsupported status")
        if status[0] in {"R", "C"}:
            if index + 1 >= len(fields):
                raise ScopeError("raw diff record: missing rename/copy endpoint")
            old_path = validate_path(_decode(fields[index], "raw old path"), "raw old path")
            new_path = validate_path(_decode(fields[index + 1], "raw new path"), "raw new path")
            index += 2
        else:
            if index >= len(fields):
                raise ScopeError("raw diff record: missing path")
            path = validate_path(_decode(fields[index], "raw path"), "raw path")
            index += 1
            old_path = "" if status == "A" else path
            new_path = "" if status == "D" else path
        result.append(RawChange(status, old_path, new_path, old_mode, new_mode, old_blob, new_blob))
    return tuple(result)


def raw_changes(root: Path, base: str, merge: str) -> tuple[RawChange, ...]:
    return parse_raw_changes(
        _git(
            root,
            [
                "diff",
                "--raw",
                "-z",
                "--abbrev=40",
                "--no-ext-diff",
                "--no-textconv",
                "--find-renames=50%",
                "--find-copies=50%",
                "--find-copies-harder",
                f"-l{DIFF_RENAME_LIMIT}",
                base,
                merge,
                "--",
            ],
            label="historic raw diff",
        )
    )


def commit_parents(root: Path, commit: str) -> tuple[str, ...]:
    line = _decode(
        _git(root, ["rev-list", "--parents", "-n", "1", commit], label="commit parent lookup"),
        "commit parent lookup",
    ).strip()
    fields = line.split()
    if not fields or fields[0] != commit or any(not OID_RE.fullmatch(value) for value in fields):
        raise ScopeError("commit parent lookup returned malformed data")
    return tuple(fields[1:])


def commit_tree(root: Path, commit: str) -> str:
    encoded = _git(root, ["show", "-s", "--format=%T", commit], label="commit tree lookup")
    tree = _decode(encoded, "commit tree").strip()
    return _oid(tree, "commit tree")


def is_ancestor(root: Path, ancestor: str, descendant: str, label: str) -> None:
    environment = os.environ.copy()
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    environment["LC_ALL"] = "C"
    environment["LANG"] = "C"
    try:
        result = subprocess.run(
            ["git", "--no-replace-objects", "merge-base", "--is-ancestor", ancestor, descendant],
            cwd=root,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        raise ScopeError(f"Git {label} could not be executed") from exc
    if result.returncode != 0:
        raise ScopeError(f"{label}: required ancestry is absent")
    if result.stderr:
        raise ScopeError(f"Git {label} emitted unexpected diagnostics")


def _read_worktree_file(path: Path, expected_size_limit: int, label: str) -> bytes:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > expected_size_limit:
            raise ScopeError(f"{label}: expected a bounded regular file")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            encoded = os.read(descriptor, expected_size_limit + 1)
            opened = os.fstat(descriptor)
            if opened.st_size != metadata.st_size or opened.st_ino != metadata.st_ino:
                raise ScopeError(f"{label}: file changed during read")
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise ScopeError(f"{label}: file is unreadable") from exc
    if len(encoded) > expected_size_limit:
        raise ScopeError(f"{label}: file exceeds the input limit")
    return encoded


def _validate_url(value: object, label: str, suffix: str | None = None) -> str:
    result = _text(value, label)
    if not result.startswith("https://") or suffix is not None and not result.endswith(suffix):
        raise ScopeError(f"{label}: invalid HTTPS evidence URL")
    return result


def _find_first_ledger_commit(root: Path, head: str) -> str:
    encoded = _git(
        root,
        ["rev-list", "--first-parent", "--reverse", head, "--", CANONICAL_LEDGER],
        label="ledger first-parent history",
    )
    lines = _decode(encoded, "ledger first-parent history").splitlines()
    if len(lines) != 1 or not OID_RE.fullmatch(lines[0]):
        raise ScopeError("ledger must have exactly one first-parent introduction change")
    return lines[0]


def _validate_ledger_header(data: dict[str, Any]) -> tuple[str, str, str]:
    _require_fields(data, LEDGER_TOP_FIELDS, "ledger")
    if _integer(data["schema_version"], "schema_version") != 1:
        raise ScopeError("ledger schema_version is unsupported")
    exact_values = {
        "kind": LEDGER_KIND,
        "milestone": LEDGER_MILESTONE,
        "status": LEDGER_STATUS,
        "correction_task": LEDGER_CORRECTION_TASK,
        "history_tip": LEDGER_HISTORY_TIP,
        "correction_base": LEDGER_CORRECTION_BASE,
        "canonical_path": CANONICAL_LEDGER,
    }
    for field, expected in exact_values.items():
        if _text(data[field], field) != expected:
            raise ScopeError(f"ledger {field} does not match the v0.1 policy anchor")
    first_base = _oid(data["first_base"], "first_base")
    for field, expected in (
        ("pull_request_count", LEDGER_PR_COUNT),
        ("instance_count", LEDGER_INSTANCE_COUNT),
        ("adoption_count", LEDGER_ADOPTION_COUNT),
    ):
        if _integer(data[field], field) != expected:
            raise ScopeError(f"ledger {field} does not match the v0.1 policy count")
    statement = _text(data["statement"], "statement").lower()
    if "nonconform" not in statement or "does not" not in statement or "compliance" not in statement:
        raise ScopeError("ledger statement must preserve nonconformance without retroactive compliance")
    return first_base, LEDGER_HISTORY_TIP, LEDGER_CORRECTION_BASE


def validate_mise_adoption(root: Path, baseline_blob: str, adopted_blob: str) -> None:
    baseline = _load_toml(read_blob(root, baseline_blob, "baseline mise"), "baseline mise")
    adopted = _load_toml(read_blob(root, adopted_blob, "adopted mise"), "adopted mise")
    if set(baseline) != {"tools", "tasks"} or set(adopted) != {"tools", "tasks"}:
        raise ScopeError("mise adoption must contain only tools and tasks tables")
    baseline_tools = baseline.get("tools")
    adopted_tools = adopted.get("tools")
    if not isinstance(baseline_tools, dict) or adopted_tools != baseline_tools:
        raise ScopeError("mise adoption may not change pinned tools")
    baseline_tasks = baseline.get("tasks")
    adopted_tasks = adopted.get("tasks")
    if not isinstance(baseline_tasks, dict) or not isinstance(adopted_tasks, dict):
        raise ScopeError("mise adoption tasks schema is invalid")
    baseline_other = {
        key: value for key, value in baseline_tasks.items() if key != "check:contracts"
    }
    adopted_other = {
        key: value for key, value in adopted_tasks.items() if key != "check:contracts"
    }
    if adopted_other != baseline_other:
        raise ScopeError("mise adoption may only change check:contracts")
    if adopted_tasks.get("check:contracts") != EXPECTED_CHECK_CONTRACTS:
        raise ScopeError("mise check:contracts does not match the scope gate policy")


def audit_ledger(root: Path, ledger_argument: Path) -> None:
    expected_path = root / CANONICAL_LEDGER
    if not ledger_argument.is_absolute() or ledger_argument != expected_path:
        raise ScopeError("--ledger must name the canonical repository ledger")
    cursor = root
    try:
        for index, part in enumerate(PurePosixPath(CANONICAL_LEDGER).parts):
            cursor /= part
            metadata = cursor.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise ScopeError("canonical ledger path may not contain symbolic links")
            final = index == len(PurePosixPath(CANONICAL_LEDGER).parts) - 1
            if final and not stat.S_ISREG(metadata.st_mode):
                raise ScopeError("canonical ledger must be a regular file")
            if not final and not stat.S_ISDIR(metadata.st_mode):
                raise ScopeError("canonical ledger parent must be a directory")
    except OSError as exc:
        raise ScopeError("ledger path is unreadable") from exc
    encoded = _read_worktree_file(expected_path, MAX_INPUT_BYTES, "ledger")
    data = _load_toml(encoded, "ledger")
    first_base, history_tip, correction_base = _validate_ledger_header(data)

    head = resolve_commit(root, "HEAD", "HEAD")
    current_entry = tree_entry(root, head, CANONICAL_LEDGER)
    assert current_entry is not None
    current_mode, current_blob = current_entry
    worktree_blob = _decode(
        _git(root, ["hash-object", "--stdin"], input_bytes=encoded, label="ledger blob hash"),
        "ledger blob hash",
    ).strip()
    if current_mode != "100644" or worktree_blob != current_blob:
        raise ScopeError("ledger worktree bytes do not match the committed canonical blob")
    introduction = _find_first_ledger_commit(root, head)
    parents = commit_parents(root, introduction)
    if not parents or parents[0] != correction_base:
        raise ScopeError("ledger introduction first parent must be correction_base")
    introduced_entry = tree_entry(root, introduction, CANONICAL_LEDGER)
    assert introduced_entry is not None
    if introduced_entry != ("100644", current_blob):
        raise ScopeError("ledger committed blob is not immutable from its introduction")

    resolve_commit(root, first_base, "first_base")
    resolve_commit(root, history_tip, "history_tip")
    resolve_commit(root, correction_base, "correction_base")
    is_ancestor(root, first_base, history_tip, "historic range")
    is_ancestor(root, history_tip, correction_base, "correction base range")
    is_ancestor(root, correction_base, introduction, "ledger introduction range")

    pull_request_values = data["pull_requests"]
    disclosure_values = data["disclosures"]
    instance_values = data["instances"]
    adoption_values = data["adoptions"]
    for label, value, expected_count in (
        ("pull_requests", pull_request_values, LEDGER_PR_COUNT),
        ("disclosures", disclosure_values, LEDGER_PR_COUNT),
        ("instances", instance_values, LEDGER_INSTANCE_COUNT),
        ("adoptions", adoption_values, LEDGER_ADOPTION_COUNT),
    ):
        if not isinstance(value, list) or len(value) != expected_count:
            raise ScopeError(f"ledger {label} count is invalid")

    disclosures: dict[str, dict[str, Any]] = {}
    disclosure_prs: set[int] = set()
    disclosure_order: list[int] = []
    for index, raw in enumerate(disclosure_values):
        value = _require_fields(raw, DISCLOSURE_FIELDS, f"disclosures[{index}]")
        disclosure_id = _text(value["id"], "disclosure id")
        if disclosure_id in disclosures:
            raise ScopeError("ledger disclosure ids must be unique")
        pr_number = _integer(value["pr_number"], "disclosure pr_number", minimum=1)
        if pr_number in disclosure_prs:
            raise ScopeError("ledger must contain one disclosure per pull request")
        disclosure_prs.add(pr_number)
        disclosure_order.append(pr_number)
        _text(value["source_kind"], "disclosure source_kind")
        _validate_url(value["source_url"], "disclosure source_url")
        _text(value["retrieved_at"], "disclosure retrieved_at")
        _integer(value["source_utf8_bytes"], "disclosure source_utf8_bytes", minimum=1)
        source_sha = _text(value["source_sha256"], "disclosure source_sha256")
        if re.fullmatch(r"[0-9a-f]{64}", source_sha) is None:
            raise ScopeError("disclosure source_sha256 is invalid")
        _text(value["excerpt"], "disclosure excerpt")
        if value["interpretation"] != "disclosed-but-did-not-authorize-outside-allowed-paths":
            raise ScopeError("disclosure interpretation is invalid")
        disclosures[disclosure_id] = value
    if disclosure_order != sorted(disclosure_order):
        raise ScopeError("disclosures must be ordered by pull request number")

    pull_requests: dict[int, dict[str, Any]] = {}
    contracts: dict[int, TaskContract] = {}
    historic_changes: dict[int, tuple[RawChange, ...]] = {}
    ordered_numbers: list[int] = []
    ordered_merges: list[str] = []
    for index, raw in enumerate(pull_request_values):
        value = _require_fields(raw, PR_FIELDS, f"pull_requests[{index}]")
        number = _integer(value["number"], "pull request number", minimum=1)
        if number in pull_requests:
            raise ScopeError("ledger pull request numbers must be unique")
        task_id = _text(value["task_id"], "pull request task_id")
        if not TASK_ID_RE.fullmatch(task_id):
            raise ScopeError("pull request task_id is invalid")
        _validate_url(value["url"], "pull request url", f"/pull/{number}")
        base = _oid(value["base_commit"], "pull request base_commit")
        head_commit = _oid(value["head_commit"], "pull request head_commit")
        merge_commit = _oid(value["merge_commit"], "pull request merge_commit")
        for label, commit in (("base", base), ("head", head_commit), ("merge", merge_commit)):
            resolved = resolve_commit(root, commit, f"pull request {label}")
            if resolved != commit:
                raise ScopeError("pull request commit identity is not exact")
        merge_kind = _text(value["merge_kind"], "pull request merge_kind")
        if merge_kind not in {"squash", "merge"}:
            raise ScopeError("pull request merge_kind is invalid")
        parents = commit_parents(root, merge_commit)
        if not parents or parents[0] != base:
            raise ScopeError("pull request merge first parent does not match base_commit")
        if merge_kind == "squash":
            if len(parents) != 1 or commit_tree(root, merge_commit) != commit_tree(root, head_commit):
                raise ScopeError("squash merge identity or tree is invalid")
        elif parents != (base, head_commit):
            raise ScopeError("merge pull request parents do not match base/head identities")
        contract_path = validate_path(_text(value["contract_path"], "contract_path"), "contract_path")
        contract_blob = _oid(value["contract_blob"], "contract_blob")
        actual_contract_blob, contract_bytes = read_task_contract_path(
            root, base, contract_path, "historic task contract"
        )
        if actual_contract_blob != contract_blob:
            raise ScopeError("historic task contract blob does not match the ledger")
        contract = _validate_task_data(
            _load_toml(contract_bytes, "historic task contract"),
            path=contract_path,
            blob=contract_blob,
        )
        if contract.task_id != task_id:
            raise ScopeError("historic contract task id does not match pull request")
        disclosure_id = _text(value["disclosure_id"], "pull request disclosure_id")
        if disclosure_id not in disclosures or disclosures[disclosure_id]["pr_number"] != number:
            raise ScopeError("pull request disclosure reference is invalid")
        _integer(value["nonconformance_instance_count"], "nonconformance_instance_count", minimum=1)
        pull_requests[number] = value
        contracts[number] = contract
        historic_changes[number] = raw_changes(root, base, merge_commit)
        ordered_numbers.append(number)
        ordered_merges.append(merge_commit)
    if ordered_numbers != sorted(ordered_numbers):
        raise ScopeError("pull_requests must be ordered by number")
    if set(disclosure_prs) != set(pull_requests):
        raise ScopeError("disclosure pull request coverage is incomplete")
    if first_base != pull_requests[ordered_numbers[0]]["base_commit"]:
        raise ScopeError("first_base does not match the first affected pull request")
    previous = first_base
    for number, merge_commit in zip(ordered_numbers, ordered_merges, strict=True):
        base = pull_requests[number]["base_commit"]
        if previous != base:
            raise ScopeError("affected pull requests are not a contiguous first-parent sequence")
        previous = merge_commit
    is_ancestor(root, previous, history_tip, "affected merge history tip")

    counted_by_pr = {number: 0 for number in pull_requests}
    seen_instances: set[tuple[object, ...]] = set()
    previous_instance_pr = 0
    for index, raw in enumerate(instance_values):
        value = _require_fields(raw, INSTANCE_FIELDS, f"instances[{index}]")
        number = _integer(value["pr_number"], "instance pr_number", minimum=1)
        if number not in pull_requests:
            raise ScopeError("instance references an unknown pull request")
        task_id = _text(value["task_id"], "instance task_id")
        if task_id != pull_requests[number]["task_id"]:
            raise ScopeError("instance task_id does not match pull request")
        status = _text(value["change_status"], "instance change_status")
        if not STATUS_RE.fullmatch(status):
            raise ScopeError("instance change_status is invalid")
        role = _text(value["path_role"], "instance path_role")
        if role not in {"old", "new", "both"}:
            raise ScopeError("instance path_role is invalid")
        path = validate_path(_text(value["path"], "instance path"), "instance path")
        old_path = validate_path(_text(value["old_path"], "instance old_path", allow_empty=True), "instance old_path", allow_empty=True)
        new_path = validate_path(_text(value["new_path"], "instance new_path", allow_empty=True), "instance new_path", allow_empty=True)
        old_mode = _mode(value["old_mode"], "instance old_mode", zero_allowed=True)
        new_mode = _mode(value["new_mode"], "instance new_mode", zero_allowed=True)
        old_blob = _oid(value["old_blob"], "instance old_blob", zero_allowed=True)
        new_blob = _oid(value["new_blob"], "instance new_blob", zero_allowed=True)
        identity = (number, status, old_path, new_path, old_mode, new_mode, old_blob, new_blob, role, path)
        if identity in seen_instances:
            raise ScopeError("ledger instances must be unique")
        seen_instances.add(identity)
        raw_identity = (status, old_path, new_path, old_mode, new_mode, old_blob, new_blob)
        if raw_identity not in {
            (
                change.status,
                change.old_path,
                change.new_path,
                change.old_mode,
                change.new_mode,
                change.old_blob,
                change.new_blob,
            )
            for change in historic_changes[number]
        }:
            raise ScopeError("instance raw mode/blob identity is absent from the historic merge tree diff")
        if role == "old" and path != old_path or role == "new" and path != new_path:
            raise ScopeError("instance path does not match its endpoint role")
        if role == "both" and (path != old_path or path != new_path):
            raise ScopeError("instance both role requires identical old and new paths")
        contract = contracts[number]
        expected_allowed = matching_patterns(contract.allowed_paths, path)
        expected_forbidden = matching_patterns(contract.forbidden_paths, path)
        actual_allowed = _string_array(value["allowed_matches"], "instance allowed_matches")
        actual_forbidden = _string_array(value["forbidden_matches"], "instance forbidden_matches")
        if actual_allowed != expected_allowed or actual_forbidden != expected_forbidden:
            raise ScopeError("instance literal pattern matches do not match the historic contract")
        literal_allowed = _boolean(value["literal_allowed"], "instance literal_allowed")
        literal_forbidden = _boolean(value["literal_forbidden"], "instance literal_forbidden")
        if literal_allowed != bool(expected_allowed) or literal_forbidden != bool(expected_forbidden):
            raise ScopeError("instance literal scope booleans are invalid")
        decision = _text(value["decision"], "instance decision")
        expected_decision = "inside_forbidden_paths" if expected_forbidden else "outside_allowed_paths" if not expected_allowed else "allowed"
        if decision != expected_decision or decision == "allowed":
            raise ScopeError("instance is not an exact historic nonconformance")
        _text(value["task_relevance"], "instance task_relevance")
        disclosure_id = _text(value["disclosure_id"], "instance disclosure_id")
        if disclosure_id != pull_requests[number]["disclosure_id"]:
            raise ScopeError("instance disclosure reference is invalid")
        if number < previous_instance_pr:
            raise ScopeError("instances must be ordered by pull request")
        previous_instance_pr = number
        counted_by_pr[number] += 1
    for number, count in counted_by_pr.items():
        if count != pull_requests[number]["nonconformance_instance_count"]:
            raise ScopeError("pull request nonconformance instance count is invalid")
    expected_instances: set[tuple[object, ...]] = set()
    for number, changes in historic_changes.items():
        contract = contracts[number]
        for change in changes:
            if change.status[0] in {"R", "C"}:
                endpoints = (
                    (("old", change.old_path), ("new", change.new_path))
                    if change.status[0] == "R"
                    else (("new", change.new_path),)
                )
            elif change.status == "A":
                endpoints = (("new", change.new_path),)
            elif change.status == "D":
                endpoints = (("old", change.old_path),)
            else:
                endpoints = (("both", change.old_path),)
            for role, path in endpoints:
                allowed, forbidden = _contract_scope_decision(contract, path)
                if forbidden or not allowed:
                    expected_instances.add(
                        (
                            number,
                            change.status,
                            change.old_path,
                            change.new_path,
                            change.old_mode,
                            change.new_mode,
                            change.old_blob,
                            change.new_blob,
                            role,
                            path,
                        )
                    )
    if seen_instances != expected_instances:
        raise ScopeError("ledger instances do not exactly cover every historic scope violation")

    adoption_paths: list[str] = []
    for index, raw in enumerate(adoption_values):
        value = _require_fields(raw, ADOPTION_FIELDS, f"adoptions[{index}]")
        path = validate_path(_text(value["path"], "adoption path"), "adoption path")
        adoption_paths.append(path)
        baseline_commit = _oid(value["baseline_commit"], "adoption baseline_commit")
        baseline_blob = _oid(value["baseline_blob"], "adoption baseline_blob")
        adopted_blob = _oid(value["adopted_blob"], "adoption adopted_blob")
        if baseline_commit != history_tip:
            raise ScopeError("adoption baseline_commit must equal history_tip")
        if resolve_commit(root, baseline_commit, "adoption baseline") != baseline_commit:
            raise ScopeError("adoption baseline commit is not exact")
        baseline_entry = tree_entry(root, baseline_commit, path, required=False)
        if baseline_entry != ("100644", baseline_blob):
            raise ScopeError("adoption baseline blob does not match history")
        introduced_root_entry = tree_entry(root, introduction, path)
        assert introduced_root_entry is not None
        if introduced_root_entry != ("100644", adopted_blob):
            raise ScopeError("adoption blob does not match the ledger introduction tree")
        supports = _string_array(value["supports_tasks"], "adoption supports_tasks", nonempty=True)
        if any(not TASK_ID_RE.fullmatch(task_id) for task_id in supports):
            raise ScopeError("adoption supports_tasks contains an invalid task id")
        _text(value["necessity"], "adoption necessity")
        _string_array(value["verification"], "adoption verification", nonempty=True)
        content_change = _text(value["content_change"], "adoption content_change")
        if content_change not in {"none", "scope-gate-integration"}:
            raise ScopeError("adoption content_change is invalid")
        if content_change == "none" and baseline_blob != adopted_blob:
            raise ScopeError("unchanged adoption must preserve the baseline blob")
        if content_change == "scope-gate-integration" and baseline_blob == adopted_blob:
            raise ScopeError("scope-gate integration adoption must identify a changed blob")
        if path in {"Cargo.toml", "Cargo.lock", "pnpm-lock.yaml"}:
            if content_change != "none" or adopted_blob != baseline_blob:
                raise ScopeError("root build adoption must preserve the history_tip blob")
        elif path == "mise.toml":
            if content_change != "scope-gate-integration":
                raise ScopeError("mise adoption must be the scope-gate integration change")
            validate_mise_adoption(root, baseline_blob, adopted_blob)
    if tuple(adoption_paths) != LEDGER_ADOPTION_PATHS:
        raise ScopeError("adoptions must exactly cover the four canonical root paths in order")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=SCRIPT_ROOT)
    subparsers = parser.add_subparsers(dest="command", required=True)

    check_parser = subparsers.add_parser("check", help="check one pull request task scope")
    identity = check_parser.add_mutually_exclusive_group(required=True)
    identity.add_argument("--task", action="append")
    identity.add_argument("--event-file", type=Path)
    check_parser.add_argument("--base-ref")
    check_parser.add_argument("--head-ref")

    audit_parser = subparsers.add_parser("audit", help="audit the immutable v0.1 ledger")
    audit_parser.add_argument("--ledger", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        root = resolve_repo_root(arguments.repo_root)
        if arguments.command == "check":
            if arguments.event_file is not None:
                task_id, event_base, event_head = read_event_file(arguments.event_file)
                if (arguments.base_ref is None) != (arguments.head_ref is None):
                    raise ScopeError("--event-file requires both ref assertions or neither")
                if arguments.base_ref is not None:
                    asserted_base = resolve_commit(root, arguments.base_ref, "asserted base revision")
                    asserted_head = resolve_commit(root, arguments.head_ref, "asserted head revision")
                    if asserted_base != event_base or asserted_head != event_head:
                        raise ScopeError("event commit identity does not match the asserted refs")
                base_ref = event_base
                head_ref = event_head
            else:
                if arguments.base_ref is None or arguments.head_ref is None:
                    raise ScopeError("--task requires both --base-ref and --head-ref")
                if arguments.task is None or len(arguments.task) != 1:
                    raise ScopeError("check requires exactly one --task value")
                task_id = _text(arguments.task[0], "task identity")
                if not TASK_ID_RE.fullmatch(task_id):
                    raise ScopeError("invalid task identity")
                base_ref = arguments.base_ref
                head_ref = arguments.head_ref
            check_scope(root, task_id, base_ref, head_ref)
            print(f"Task scope passed for {task_id}.")
        else:
            ledger = arguments.ledger
            if not ledger.is_absolute():
                ledger = root / ledger
            audit_ledger(root, ledger)
            print(
                f"Task scope ledger passed: {LEDGER_PR_COUNT} pull requests, "
                f"{LEDGER_INSTANCE_COUNT} instances, {LEDGER_ADOPTION_COUNT} adoptions."
            )
    except ScopeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
