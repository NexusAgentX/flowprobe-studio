# Task Contracts

Tasks are TOML and form a dependency DAG. `scripts/validate_tasks.py` checks identifiers, required fields, path restrictions and dependency references.

Start with `v0.1/FOUND-001.toml`. Once it merges, independent tasks whose dependencies are satisfied may run in separate worktrees.

Do not mark a task complete because an agent says it is done; use its acceptance commands and verifier evidence.
