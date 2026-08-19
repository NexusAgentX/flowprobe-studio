#!/usr/bin/env python3
"""Validate FlowProbe TOML task contracts using only Python stdlib."""
from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TASK_ROOT = ROOT / "specs" / "tasks"
REQUIRED = {
    "id", "milestone", "title", "goal", "depends_on", "allowed_paths",
    "forbidden_paths", "acceptance", "definition_of_done",
}
ID_RE = re.compile(r"^[A-Z][A-Z0-9]+-[0-9]{3}$")


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)


def main() -> int:
    files = sorted(TASK_ROOT.glob("v*/*.toml"))
    if not files:
        fail("no task contracts found")
        return 1

    tasks: dict[str, tuple[Path, dict]] = {}
    errors = 0
    for path in files:
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            fail(f"{path.relative_to(ROOT)}: invalid TOML: {exc}")
            errors += 1
            continue
        missing = REQUIRED - data.keys()
        if missing:
            fail(f"{path.relative_to(ROOT)}: missing fields {sorted(missing)}")
            errors += 1
            continue
        task_id = data["id"]
        if not isinstance(task_id, str) or not ID_RE.match(task_id):
            fail(f"{path.relative_to(ROOT)}: invalid id {task_id!r}")
            errors += 1
            continue
        if task_id in tasks:
            fail(f"duplicate task id {task_id}: {path} and {tasks[task_id][0]}")
            errors += 1
        tasks[task_id] = (path, data)
        expected_milestone = path.parent.name
        if data["milestone"] != expected_milestone:
            fail(f"{task_id}: milestone {data['milestone']!r} != directory {expected_milestone!r}")
            errors += 1
        for field in ("depends_on", "allowed_paths", "forbidden_paths", "acceptance", "definition_of_done"):
            value = data[field]
            if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
                fail(f"{task_id}: {field} must be an array of strings")
                errors += 1
        protected = {"PRODUCT.md", "ARCHITECTURE.md", "docs/adr/**", "docs/contracts/**"}
        if not task_id.startswith("ARCH-") and protected.intersection(data["allowed_paths"]):
            fail(f"{task_id}: ordinary task may not allow protected architecture paths")
            errors += 1

    for task_id, (_path, data) in tasks.items():
        for dep in data["depends_on"]:
            if dep not in tasks:
                fail(f"{task_id}: unknown dependency {dep}")
                errors += 1
            elif dep == task_id:
                fail(f"{task_id}: self dependency")
                errors += 1

    # Cycle detection.
    visiting: set[str] = set()
    visited: set[str] = set()
    def visit(task_id: str) -> None:
        nonlocal errors
        if task_id in visited:
            return
        if task_id in visiting:
            fail(f"dependency cycle detected at {task_id}")
            errors += 1
            return
        visiting.add(task_id)
        for dep in tasks[task_id][1]["depends_on"]:
            if dep in tasks:
                visit(dep)
        visiting.remove(task_id)
        visited.add(task_id)

    for task_id in tasks:
        visit(task_id)

    if errors:
        print(f"Task contract validation failed with {errors} error(s).", file=sys.stderr)
        return 1
    print(f"Validated {len(tasks)} task contract(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
