from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


sys.dont_write_bytecode = True
SCRIPTS = Path(__file__).resolve().parents[1]
REPOSITORY = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))

import check_task_scope as scope  # noqa: E402


def tearDownModule() -> None:
    cache = Path(__file__).parent / "__pycache__"
    if cache.exists():
        shutil.rmtree(cache)


def run_git(root: Path, *arguments: str, input_bytes: bytes | None = None) -> bytes:
    return subprocess.run(
        ["git", "--no-replace-objects", *arguments],
        cwd=root,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout


def task_contract(
    task_id: str = "TEST-001",
    *,
    milestone: str = "v0.1",
    allowed: tuple[str, ...] = ("allowed/**",),
    forbidden: tuple[str, ...] = ("forbidden/**",),
    depends_on: tuple[str, ...] = (),
) -> str:
    def array(values: tuple[str, ...]) -> str:
        return "[" + ", ".join(json.dumps(value) for value in values) + "]"

    return (
        f'id = "{task_id}"\n'
        f'milestone = "{milestone}"\n'
        'title = "Test contract"\n'
        'goal = "Exercise literal path scope"\n'
        f"depends_on = {array(depends_on)}\n"
        f"allowed_paths = {array(allowed)}\n"
        f"forbidden_paths = {array(forbidden)}\n"
        'acceptance = ["python -B check.py"]\n'
        'definition_of_done = ["Every path decision is deterministic"]\n'
    )


class Repository:
    def __init__(self, case: unittest.TestCase) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="flowprobe-scope-test-")
        case.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        run_git(self.root.parent, "init", "--quiet", "--initial-branch=main", str(self.root))
        run_git(self.root, "config", "user.name", "FlowProbe Tests")
        run_git(self.root, "config", "user.email", "flowprobe-tests@example.invalid")

    def write(self, relative: str, content: str) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def commit(self, message: str) -> str:
        run_git(self.root, "add", "-A")
        run_git(self.root, "commit", "--quiet", "-m", message)
        return run_git(self.root, "rev-parse", "HEAD").decode("ascii").strip()

    def base(
        self,
        *,
        task_id: str = "TEST-001",
        allowed: tuple[str, ...] = ("allowed/**",),
        forbidden: tuple[str, ...] = ("forbidden/**",),
    ) -> str:
        self.write(
            f"specs/tasks/v0.1/{task_id}.toml",
            task_contract(task_id, allowed=allowed, forbidden=forbidden),
        )
        self.write("allowed/existing.txt", "before\n")
        self.write("forbidden/existing.txt", "before\n")
        return self.commit("base")


class PathPatternTests(unittest.TestCase):
    def test_exact_and_recursive_patterns_are_literal(self) -> None:
        self.assertTrue(scope.pattern_matches("Cargo.toml", "Cargo.toml"))
        self.assertFalse(scope.pattern_matches("Cargo.toml", "nested/Cargo.toml"))
        self.assertTrue(scope.pattern_matches("apps/**", "apps/desktop/main.ts"))
        self.assertFalse(scope.pattern_matches("apps/**", "apps2/main.ts"))

    def test_invalid_paths_and_patterns_fail_closed(self) -> None:
        for value in ("/absolute", "../escape", "a//b", "a\\b", "a/"):
            with self.subTest(value=value), self.assertRaises(scope.ScopeError):
                scope.validate_path(value, "test path")
        for value in ("apps/*", "apps/?", "apps/[a]", "../**"):
            with self.subTest(value=value), self.assertRaises(scope.ScopeError):
                scope.validate_pattern(value, "test pattern")


class NameStatusTests(unittest.TestCase):
    def test_parses_every_supported_status_and_both_endpoints(self) -> None:
        encoded = (
            b"A\0added\0M\0modified\0D\0deleted\0T\0typed\0"
            b"R100\0old-name\0new-name\0C075\0copy-from\0copy-to\0"
        )
        changes = scope.parse_name_changes(encoded)
        self.assertEqual([change.status for change in changes], ["A", "M", "D", "T", "R100", "C075"])
        self.assertEqual(changes[4].endpoints(), (("old", "old-name"), ("new", "new-name")))
        self.assertEqual(changes[5].endpoints(), (("old", "copy-from"), ("new", "copy-to")))

    def test_rejects_unsupported_status_truncation_and_invalid_utf8(self) -> None:
        for encoded in (
            b"U\0path\0",
            b"R100\0old\0",
            b"A\0\xff\0",
            b"R999\0old\0new\0",
            b"C1\0old\0new\0",
        ):
            with self.subTest(encoded=encoded), self.assertRaises(scope.ScopeError):
                scope.parse_name_changes(encoded)

    def test_raw_parser_requires_full_object_identities(self) -> None:
        full = b"1" * 40
        valid = b":100644 100644 " + full + b" " + b"2" * 40 + b" M\0path\0"
        self.assertEqual(scope.parse_raw_changes(valid)[0].status, "M")
        abbreviated = b":100644 100644 1111111 2222222 M\0path\0"
        with self.assertRaises(scope.ScopeError):
            scope.parse_raw_changes(abbreviated)
        for status in (b"R999", b"C1"):
            invalid = b":100644 100644 " + full + b" " + b"2" * 40 + b" " + status + b"\0old\0new\0"
            with self.subTest(status=status), self.assertRaises(scope.ScopeError):
                scope.parse_raw_changes(invalid)


class ScopeCheckTests(unittest.TestCase):
    def test_valid_task_allows_explicit_root_files(self) -> None:
        repository = Repository(self)
        base = repository.base(allowed=("Cargo.toml", "Cargo.lock", "mise.toml", "pnpm-lock.yaml"))
        for path in ("Cargo.toml", "Cargo.lock", "mise.toml", "pnpm-lock.yaml"):
            repository.write(path, f"{path}\n")
        head = repository.commit("allowed root files")
        scope.check_scope(repository.root, "TEST-001", base, head)

    def test_added_modified_and_deleted_paths_are_checked(self) -> None:
        repository = Repository(self)
        base = repository.base()
        repository.write("allowed/existing.txt", "after\n")
        repository.write("allowed/added.txt", "added\n")
        (repository.root / "forbidden/existing.txt").unlink()
        head = repository.commit("mixed paths")
        with self.assertRaisesRegex(scope.ScopeError, "path is forbidden"):
            scope.check_scope(repository.root, "TEST-001", base, head)

    def test_forbidden_takes_precedence_over_allowed(self) -> None:
        repository = Repository(self)
        base = repository.base(allowed=("shared/**",), forbidden=("shared/secret.txt",))
        repository.write("shared/secret.txt", "sensitive\n")
        head = repository.commit("overlap")
        with self.assertRaisesRegex(scope.ScopeError, "path is forbidden"):
            scope.check_scope(repository.root, "TEST-001", base, head)

    def test_copy_detection_ignores_low_repo_limit_and_checks_forbidden_source(self) -> None:
        repository = Repository(self)
        repository.base(allowed=("allowed/**",), forbidden=("forbidden/**",))
        sources = {
            "forbidden/alpha.txt": "".join(
                f"alpha stable source line {index:03d}\n" for index in range(200)
            ),
            "forbidden/beta.txt": "".join(
                f"beta distinct source line {index:03d}\n" for index in range(200)
            ),
        }
        for path, source in sources.items():
            repository.write(path, source)
        base = repository.commit("copy sources")
        run_git(repository.root, "config", "diff.renameLimit", "1")
        target_by_source = {
            "forbidden/alpha.txt": "allowed/alpha-copy.txt",
            "forbidden/beta.txt": "allowed/beta-copy.txt",
        }
        for source_path, target_path in target_by_source.items():
            copied_lines = sources[source_path].splitlines(keepends=True)
            copied_lines[20:30] = [
                f"changed {Path(source_path).stem} line {index:03d}\n"
                for index in range(10)
            ]
            repository.write(target_path, "".join(copied_lines))
        head = repository.commit("similar copies")
        degraded_environment = os.environ.copy()
        degraded_environment["LC_ALL"] = "C"
        degraded_environment["LANG"] = "C"
        degraded = subprocess.run(
            [
                "git",
                "--no-replace-objects",
                "diff",
                "--name-status",
                "-z",
                "--no-ext-diff",
                "--no-textconv",
                "--find-renames=50%",
                "--find-copies=50%",
                "--find-copies-harder",
                base,
                head,
                "--",
            ],
            cwd=repository.root,
            env=degraded_environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(degraded.returncode, 0)
        self.assertTrue(degraded.stderr)
        self.assertFalse(
            any(
                change.status.startswith("C")
                for change in scope.parse_name_changes(degraded.stdout)
            )
        )
        changes = scope.changed_names(repository.root, base, head)
        copies = [change for change in changes if change.status.startswith("C")]
        self.assertEqual(len(copies), 2)
        self.assertEqual(
            {change.old_path for change in copies},
            set(target_by_source),
        )
        with self.assertRaises(scope.ScopeError) as captured:
            scope.check_scope(repository.root, "TEST-001", base, head)
        diagnostic = str(captured.exception)
        for source_path in target_by_source:
            self.assertIn(f"old {source_path}", diagnostic)

    def test_supporting_manifest_has_no_implicit_exception(self) -> None:
        repository = Repository(self)
        base = repository.base()
        repository.write("Cargo.toml", "[workspace]\n")
        head = repository.commit("root manifest")
        with self.assertRaisesRegex(scope.ScopeError, "outside allowed_paths"):
            scope.check_scope(repository.root, "TEST-001", base, head)

    def test_rename_checks_old_and_new_paths(self) -> None:
        repository = Repository(self)
        base = repository.base(allowed=("allowed/new.txt",))
        source = repository.write("outside/old.txt", "enough text to detect an exact rename\n")
        base = repository.commit("rename source")
        destination = repository.root / "allowed/new.txt"
        destination.parent.mkdir(parents=True, exist_ok=True)
        source.rename(destination)
        head = repository.commit("rename")
        changes = scope.changed_names(repository.root, base, head)
        self.assertEqual(changes[0].status, "R100")
        with self.assertRaisesRegex(scope.ScopeError, "old outside/old.txt"):
            scope.check_scope(repository.root, "TEST-001", base, head)

    def test_rename_passes_when_both_endpoints_are_allowed(self) -> None:
        repository = Repository(self)
        repository.base(allowed=("allowed/**",))
        source = repository.write("allowed/old.txt", "enough text to detect an exact rename\n")
        base = repository.commit("rename source")
        source.rename(repository.root / "allowed/new.txt")
        head = repository.commit("rename")
        scope.check_scope(repository.root, "TEST-001", base, head)

    def test_type_change_is_checked(self) -> None:
        repository = Repository(self)
        repository.base(allowed=("allowed/**",))
        target = repository.root / "allowed/type"
        target.write_text("regular\n", encoding="utf-8")
        base = repository.commit("regular file")
        target.unlink()
        target.symlink_to("existing.txt")
        head = repository.commit("symbolic link")
        changes = scope.changed_names(repository.root, base, head)
        self.assertEqual(changes[0].status, "T")
        scope.check_scope(repository.root, "TEST-001", base, head)

    def test_same_pull_request_cannot_widen_its_contract(self) -> None:
        repository = Repository(self)
        base = repository.base(allowed=("allowed/**", "specs/tasks/v0.1/TEST-001.toml"))
        repository.write(
            "specs/tasks/v0.1/TEST-001.toml",
            task_contract(allowed=("allowed/**", "Cargo.toml", "specs/tasks/v0.1/TEST-001.toml")),
        )
        repository.write("Cargo.toml", "[workspace]\n")
        head = repository.commit("contract widening")
        with self.assertRaisesRegex(scope.ScopeError, "trusted-base contract"):
            scope.check_scope(repository.root, "TEST-001", base, head)

    def test_latest_base_contract_rejects_scope_allowed_at_fork_point(self) -> None:
        repository = Repository(self)
        fork_point = repository.base(allowed=("legacy/**",))
        run_git(repository.root, "branch", "feature", fork_point)
        repository.write(
            "specs/tasks/v0.1/TEST-001.toml",
            task_contract(allowed=("current/**",)),
        )
        latest_base = repository.commit("tighten task contract")
        run_git(repository.root, "checkout", "--quiet", "feature")
        repository.write("legacy/change.txt", "accepted only by the old contract\n")
        head = repository.commit("stale feature change")
        with self.assertRaisesRegex(scope.ScopeError, "outside allowed_paths"):
            scope.check_scope(repository.root, "TEST-001", latest_base, head)

    def test_task_added_on_latest_base_is_not_treated_as_plan_bootstrap(self) -> None:
        repository = Repository(self)
        repository.write("README.md", "base\n")
        fork_point = repository.commit("fork point")
        run_git(repository.root, "branch", "feature", fork_point)
        repository.write(
            "specs/tasks/v0.1/LATE-001.toml",
            task_contract("LATE-001", allowed=("allowed/**",)),
        )
        latest_base = repository.commit("add ordinary task contract")
        run_git(repository.root, "checkout", "--quiet", "feature")
        repository.write("allowed/change.txt", "ordinary task change\n")
        head = repository.commit("implement ordinary task")
        scope.check_scope(repository.root, "LATE-001", latest_base, head)

    def test_gate_modification_is_an_ordinary_path_decision(self) -> None:
        repository = Repository(self)
        base = repository.base(allowed=("Cargo.toml",))
        repository.write("scripts/check_task_scope.py", "print('changed')\n")
        head = repository.commit("gate change")
        with self.assertRaisesRegex(scope.ScopeError, "outside allowed_paths"):
            scope.check_scope(repository.root, "TEST-001", base, head)

    def test_unknown_task_and_missing_history_fail_closed(self) -> None:
        repository = Repository(self)
        base = repository.base()
        repository.write("allowed/change.txt", "change\n")
        head = repository.commit("change")
        with self.assertRaises(scope.ScopeError):
            scope.check_scope(repository.root, "UNKNOWN-999", base, head)
        with self.assertRaises(scope.ScopeError):
            scope.check_scope(repository.root, "TEST-001", "f" * 40, head)

    def test_malformed_trusted_contract_and_pattern_fail_closed(self) -> None:
        repository = Repository(self)
        repository.write(
            "specs/tasks/v0.1/TEST-001.toml",
            task_contract(allowed=("allowed/*",)),
        )
        base = repository.commit("invalid contract")
        repository.write("allowed/change.txt", "change\n")
        head = repository.commit("change")
        with self.assertRaisesRegex(scope.ScopeError, "unsupported path pattern"):
            scope.check_scope(repository.root, "TEST-001", base, head)

    def test_invalid_utf8_git_path_fails_closed(self) -> None:
        repository = Repository(self)
        base = repository.base(allowed=("allowed/**",))
        blob = run_git(repository.root, "hash-object", "-w", "--stdin", input_bytes=b"data\n").strip()
        run_git(
            repository.root,
            "update-index",
            "--add",
            "-z",
            "--index-info",
            input_bytes=b"100644 " + blob + b"\tallowed/\xff\0",
        )
        run_git(repository.root, "commit", "--quiet", "-m", "invalid utf8 path")
        head = run_git(repository.root, "rev-parse", "HEAD").decode("ascii").strip()
        with self.assertRaisesRegex(scope.ScopeError, "invalid UTF-8"):
            scope.check_scope(repository.root, "TEST-001", base, head)

    def test_safe_plan_bootstrap_adds_only_exact_task_contracts(self) -> None:
        repository = Repository(self)
        repository.write("README.md", "base\n")
        base = repository.commit("base")
        plan_path = "specs/tasks/v0.2/PLAN-001.toml"
        task_path = "specs/tasks/v0.2/NEXT-001.toml"
        repository.write(
            plan_path,
            task_contract("PLAN-001", milestone="v0.2", allowed=(plan_path, task_path), forbidden=("apps/**",)),
        )
        repository.write(
            task_path,
            task_contract("NEXT-001", milestone="v0.2", allowed=("apps/**",), forbidden=("docs/contracts/**",)),
        )
        head = repository.commit("plan bootstrap")
        scope.check_scope(repository.root, "PLAN-001", base, head)

    def test_plan_bootstrap_rejects_non_contract_or_recursive_scope(self) -> None:
        repository = Repository(self)
        repository.write("README.md", "base\n")
        base = repository.commit("base")
        plan_path = "specs/tasks/v0.2/PLAN-001.toml"
        repository.write(
            plan_path,
            task_contract("PLAN-001", milestone="v0.2", allowed=(plan_path, "specs/tasks/v0.2/**")),
        )
        repository.write("apps/change.ts", "export const value = 1;\n")
        head = repository.commit("unsafe plan")
        with self.assertRaisesRegex(scope.ScopeError, "only add new task TOML"):
            scope.check_scope(repository.root, "PLAN-001", base, head)

    def test_plan_bootstrap_rejects_unknown_dependency(self) -> None:
        repository = Repository(self)
        repository.write("README.md", "base\n")
        base = repository.commit("base")
        plan_path = "specs/tasks/v0.2/PLAN-001.toml"
        repository.write(
            plan_path,
            task_contract(
                "PLAN-001",
                milestone="v0.2",
                allowed=(plan_path,),
                depends_on=("MISSING-001",),
            ),
        )
        head = repository.commit("unknown dependency")
        with self.assertRaisesRegex(scope.ScopeError, "unknown dependency"):
            scope.check_scope(repository.root, "PLAN-001", base, head)

    def test_plan_bootstrap_rejects_dependency_cycle(self) -> None:
        repository = Repository(self)
        repository.write("README.md", "base\n")
        base = repository.commit("base")
        plan_path = "specs/tasks/v0.2/PLAN-001.toml"
        task_path = "specs/tasks/v0.2/NEXT-001.toml"
        repository.write(
            plan_path,
            task_contract(
                "PLAN-001",
                milestone="v0.2",
                allowed=(plan_path, task_path),
                depends_on=("NEXT-001",),
            ),
        )
        repository.write(
            task_path,
            task_contract(
                "NEXT-001",
                milestone="v0.2",
                depends_on=("PLAN-001",),
            ),
        )
        head = repository.commit("dependency cycle")
        with self.assertRaisesRegex(scope.ScopeError, "dependency cycle"):
            scope.check_scope(repository.root, "PLAN-001", base, head)

    def test_plan_bootstrap_forbidden_paths_override_allowed_paths(self) -> None:
        repository = Repository(self)
        repository.write("README.md", "base\n")
        base = repository.commit("base")
        plan_path = "specs/tasks/v0.2/PLAN-001.toml"
        task_path = "specs/tasks/v0.2/NEXT-001.toml"
        repository.write(
            plan_path,
            task_contract(
                "PLAN-001",
                milestone="v0.2",
                allowed=(plan_path, task_path),
                forbidden=("specs/tasks/v0.2/**",),
            ),
        )
        repository.write(
            task_path,
            task_contract("NEXT-001", milestone="v0.2"),
        )
        head = repository.commit("forbidden task contracts")
        with self.assertRaisesRegex(scope.ScopeError, "forbidden by the PLAN contract"):
            scope.check_scope(repository.root, "PLAN-001", base, head)

    def test_plan_bootstrap_rejects_executable_and_symbolic_link_contracts(self) -> None:
        for mode in ("executable", "symlink"):
            with self.subTest(mode=mode):
                repository = Repository(self)
                repository.write("README.md", "base\n")
                base = repository.commit("base")
                plan_path = "specs/tasks/v0.2/PLAN-001.toml"
                task_path = "specs/tasks/v0.2/NEXT-001.toml"
                repository.write(
                    plan_path,
                    task_contract(
                        "PLAN-001",
                        milestone="v0.2",
                        allowed=(plan_path,) if mode == "executable" else (plan_path, task_path),
                    ),
                )
                if mode == "executable":
                    (repository.root / plan_path).chmod(0o755)
                else:
                    target = repository.root / task_path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.symlink_to("PLAN-001.toml")
                head = repository.commit(f"{mode} contract")
                with self.assertRaisesRegex(scope.ScopeError, "mode must be 100644"):
                    scope.check_scope(repository.root, "PLAN-001", base, head)

    def test_plan_bootstrap_rejects_ordinary_protected_architecture_scope(self) -> None:
        repository = Repository(self)
        repository.write("README.md", "base\n")
        base = repository.commit("base")
        plan_path = "specs/tasks/v0.2/PLAN-001.toml"
        task_path = "specs/tasks/v0.2/NEXT-001.toml"
        repository.write(
            plan_path,
            task_contract("PLAN-001", milestone="v0.2", allowed=(plan_path, task_path)),
        )
        repository.write(
            task_path,
            task_contract(
                "NEXT-001",
                milestone="v0.2",
                allowed=("docs/contracts/new.md",),
            ),
        )
        head = repository.commit("unsafe architecture scope")
        with self.assertRaisesRegex(scope.ScopeError, "protected architecture"):
            scope.check_scope(repository.root, "PLAN-001", base, head)

    def test_trusted_ordinary_contract_cannot_bypass_architecture_boundary(self) -> None:
        repository = Repository(self)
        base = repository.base(allowed=("docs/contracts/new.md",))
        repository.write("docs/contracts/new.md", "contract change\n")
        head = repository.commit("protected change")
        with self.assertRaisesRegex(scope.ScopeError, "protected architecture"):
            scope.check_scope(repository.root, "TEST-001", base, head)

    def test_product_namespace_recursive_pattern_is_protected(self) -> None:
        repository = Repository(self)
        base = repository.base(allowed=("PRODUCT.md/**",))
        repository.write("PRODUCT.md/child", "protected descendant\n")
        head = repository.commit("product namespace descendant")
        with self.assertRaisesRegex(scope.ScopeError, "protected architecture"):
            scope.check_scope(repository.root, "TEST-001", base, head)

    def test_architecture_task_may_explicitly_allow_protected_path(self) -> None:
        repository = Repository(self)
        base = repository.base(task_id="ARCH-001", allowed=("docs/contracts/new.md",))
        repository.write("docs/contracts/new.md", "contract change\n")
        head = repository.commit("architecture change")
        scope.check_scope(repository.root, "ARCH-001", base, head)


class EventTests(unittest.TestCase):
    def event_file(self, body: object, base: str = "1" * 40, head: str = "2" * 40) -> Path:
        temporary = tempfile.NamedTemporaryFile(prefix="flowprobe-event-", suffix=".json", delete=False)
        temporary.close()
        path = Path(temporary.name)
        self.addCleanup(path.unlink, missing_ok=True)
        path.write_text(
            json.dumps(
                {
                    "action": "opened",
                    "pull_request": {
                        "body": body,
                        "base": {"sha": base, "ref": "main"},
                        "head": {"sha": head, "ref": "branch"},
                    },
                }
            ),
            encoding="utf-8",
        )
        return path

    def test_event_extracts_one_exact_task_line(self) -> None:
        self.assertEqual(
            scope.read_event_file(self.event_file("Summary\n\nTask ID: TEST-001\n")),
            ("TEST-001", "1" * 40, "2" * 40),
        )

    def test_event_rejects_missing_multiple_and_repeated_identity(self) -> None:
        bodies = (
            "Summary only",
            "Task-ID: TEST-001",
            "Task ID: TEST-001\nTask ID: OTHER-002",
            "Task ID: TEST-001\nTask ID: TEST-001",
        )
        for body in bodies:
            with self.subTest(body=body), self.assertRaises(scope.ScopeError):
                scope.read_event_file(self.event_file(body))

    def test_event_rejects_invalid_utf8_and_schema(self) -> None:
        path = self.event_file("Task ID: TEST-001")
        path.write_bytes(b"\xff")
        with self.assertRaises(scope.ScopeError):
            scope.read_event_file(path)
        path.write_text(json.dumps({"pull_request": {"body": 1}}), encoding="utf-8")
        with self.assertRaises(scope.ScopeError):
            scope.read_event_file(path)


class CommandTests(unittest.TestCase):
    def test_repo_root_and_cli_check(self) -> None:
        repository = Repository(self)
        base = repository.base()
        repository.write("allowed/change.txt", "change\n")
        head = repository.commit("change")
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            result = scope.main(
                [
                    "--repo-root",
                    str(repository.root),
                    "check",
                    "--task",
                    "TEST-001",
                    "--base-ref",
                    base,
                    "--head-ref",
                    head,
                ]
            )
        self.assertEqual(result, 0)
        self.assertIn("Task scope passed", stdout.getvalue())

    def test_diagnostic_does_not_print_changed_file_contents(self) -> None:
        repository = Repository(self)
        base = repository.base()
        canary = "AUTHORIZATION_SYNTHETIC_CANARY_6e2a"
        repository.write("outside.txt", canary + "\n")
        head = repository.commit("outside")
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = scope.main(
                [
                    "--repo-root",
                    str(repository.root),
                    "check",
                    "--task",
                    "TEST-001",
                    "--base-ref",
                    base,
                    "--head-ref",
                    head,
                ]
            )
        self.assertEqual(result, 1)
        self.assertNotIn(canary, stderr.getvalue())
        self.assertIn("outside.txt", stderr.getvalue())

    def test_event_ref_assertions_match_or_fail_individually(self) -> None:
        repository = Repository(self)
        base = repository.base()
        repository.write("allowed/change.txt", "change\n")
        head = repository.commit("change")
        event = repository.root / "event.json"
        event.write_text(
            json.dumps(
                {
                    "pull_request": {
                        "body": "Task ID: TEST-001",
                        "base": {"sha": base},
                        "head": {"sha": head},
                    }
                }
            ),
            encoding="utf-8",
        )
        matching = [
            "--repo-root",
            str(repository.root),
            "check",
            "--event-file",
            str(event),
            "--base-ref",
            base,
            "--head-ref",
            head,
        ]
        self.assertEqual(scope.main(matching), 0)
        for option, wrong in (("--base-ref", head), ("--head-ref", base)):
            mismatched = list(matching)
            mismatched[mismatched.index(option) + 1] = wrong
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(scope.main(mismatched), 1)
            self.assertIn("does not match", stderr.getvalue())
        incomplete = matching[:-2]
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(scope.main(incomplete), 1)

    def test_successful_git_command_with_stderr_fails_closed(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["git"],
            returncode=0,
            stdout=b"safe\n",
            stderr=b"warning: rename detection degraded\n",
        )
        with mock.patch.object(scope.subprocess, "run", return_value=completed) as run:
            with self.assertRaisesRegex(scope.ScopeError, "unexpected diagnostics"):
                scope._git(REPOSITORY, ["status"], label="warning regression")
        self.assertEqual(run.call_args.kwargs["env"]["LC_ALL"], "C")
        self.assertEqual(run.call_args.kwargs["env"]["LANG"], "C")


class LedgerAuditTests(unittest.TestCase):
    def reconstructed_introduction(
        self,
        *,
        adoption_baseline: str | None = None,
        drift_mise_tool: bool = False,
    ) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory(prefix="flowprobe-ledger-test-")
        root = Path(temporary.name)
        run_git(
            root.parent,
            "clone",
            "--quiet",
            "--shared",
            str(REPOSITORY),
            str(root),
        )
        run_git(root, "config", "user.name", "FlowProbe Tests")
        run_git(root, "config", "user.email", "flowprobe-tests@example.invalid")
        run_git(root, "checkout", "--quiet", "--detach", scope.LEDGER_CORRECTION_BASE)
        ledger = root / scope.CANONICAL_LEDGER
        ledger.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPOSITORY / scope.CANONICAL_LEDGER, ledger)
        shutil.copyfile(REPOSITORY / "mise.toml", root / "mise.toml")
        if adoption_baseline is not None:
            ledger.write_bytes(
                ledger.read_bytes().replace(
                    f'baseline_commit = "{scope.LEDGER_HISTORY_TIP}"'.encode("ascii"),
                    f'baseline_commit = "{adoption_baseline}"'.encode("ascii"),
                )
            )
        if drift_mise_tool:
            mise = root / "mise.toml"
            old_blob = run_git(root, "hash-object", "mise.toml").decode("ascii").strip()
            mise.write_text(
                mise.read_text(encoding="utf-8").replace(
                    'node = "24.19.0"',
                    'node = "24.19.1"',
                ),
                encoding="utf-8",
            )
            new_blob = run_git(root, "hash-object", "-w", "mise.toml").decode("ascii").strip()
            ledger.write_bytes(
                ledger.read_bytes().replace(
                    f'adopted_blob = "{old_blob}"'.encode("ascii"),
                    f'adopted_blob = "{new_blob}"'.encode("ascii"),
                )
            )
        run_git(root, "add", scope.CANONICAL_LEDGER, "mise.toml")
        run_git(root, "commit", "--quiet", "-m", "scope ledger introduction")
        return temporary, ledger

    def test_actual_ledger_replays_history_and_detects_worktree_mutation(self) -> None:
        temporary, ledger = self.reconstructed_introduction()
        self.addCleanup(temporary.cleanup)
        scope.audit_ledger(ledger.parents[3], ledger)
        ledger.write_bytes(ledger.read_bytes() + b"\n")
        with self.assertRaisesRegex(scope.ScopeError, "committed canonical blob"):
            scope.audit_ledger(ledger.parents[3], ledger)

    def test_actual_ledger_detects_deletion_and_committed_rewrite(self) -> None:
        temporary, ledger = self.reconstructed_introduction()
        self.addCleanup(temporary.cleanup)
        root = ledger.parents[3]
        ledger.write_bytes(ledger.read_bytes().replace(b"instance_count = 15", b"instance_count = 14"))
        run_git(root, "add", scope.CANONICAL_LEDGER)
        run_git(root, "commit", "--quiet", "-m", "rewrite ledger")
        with self.assertRaises(scope.ScopeError):
            scope.audit_ledger(root, ledger)
        ledger.unlink()
        with self.assertRaises(scope.ScopeError):
            scope.audit_ledger(root, ledger)

    def test_canonical_ledger_rejects_same_byte_shadow_symlink(self) -> None:
        temporary, ledger = self.reconstructed_introduction()
        self.addCleanup(temporary.cleanup)
        root = ledger.parents[3]
        shadow = ledger.with_name("shadow.toml")
        ledger.rename(shadow)
        ledger.symlink_to(shadow.name)
        with self.assertRaisesRegex(scope.ScopeError, "symbolic links"):
            scope.audit_ledger(root, ledger)

    def test_adoption_baseline_must_be_history_tip(self) -> None:
        temporary, ledger = self.reconstructed_introduction(
            adoption_baseline=scope.LEDGER_CORRECTION_BASE
        )
        self.addCleanup(temporary.cleanup)
        with self.assertRaisesRegex(scope.ScopeError, "must equal history_tip"):
            scope.audit_ledger(ledger.parents[3], ledger)

    def test_mise_adoption_rejects_tool_version_drift_at_introduction(self) -> None:
        temporary, ledger = self.reconstructed_introduction(drift_mise_tool=True)
        self.addCleanup(temporary.cleanup)
        with self.assertRaisesRegex(scope.ScopeError, "may not change pinned tools"):
            scope.audit_ledger(ledger.parents[3], ledger)

    def test_header_mutation_matrix_fails_closed(self) -> None:
        data = scope._load_toml(
            (REPOSITORY / scope.CANONICAL_LEDGER).read_bytes(),
            "ledger",
        )
        scope._validate_ledger_header(data)
        mutations = (
            ("schema_version", 2),
            ("kind", "different-kind"),
            ("status", "open"),
            ("history_tip", "1" * 40),
            ("correction_base", "2" * 40),
            ("pull_request_count", 7),
            ("instance_count", 14),
            ("adoption_count", 3),
            ("canonical_path", "other.toml"),
        )
        for field, value in mutations:
            altered = copy.deepcopy(data)
            altered[field] = value
            with self.subTest(field=field), self.assertRaises(scope.ScopeError):
                scope._validate_ledger_header(altered)


if __name__ == "__main__":
    unittest.main()
