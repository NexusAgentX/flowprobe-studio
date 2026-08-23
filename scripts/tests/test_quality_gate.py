from __future__ import annotations

import contextlib
import io
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path, PurePosixPath
from unittest import mock

sys.dont_write_bytecode = True
SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import prove_v0_1_local_network as proof  # noqa: E402
import quality_gate  # noqa: E402


def tearDownModule() -> None:
    cache = Path(__file__).parent / "__pycache__"
    if cache.exists():
        shutil.rmtree(cache)


def joined(*parts: str) -> str:
    return "".join(parts)


def rules(path: str, source: str) -> set[str]:
    return {
        finding.rule
        for finding in quality_gate.scan_source(PurePosixPath(path), source)
    }


class SourceRuleTests(unittest.TestCase):
    def test_rejects_all_text_markers(self) -> None:
        marker_words = [
            joined("TO", "DO"),
            joined("FIX", "ME"),
            joined("place", "holder"),
            joined("st", "ub"),
        ]
        for marker_word in marker_words:
            with self.subTest(marker_word=marker_word):
                self.assertIn(
                    "shortcut-marker",
                    rules("scripts/sample.py", f"# {marker_word}\n"),
                )

    def test_uppercase_marker_in_source_is_rejected(self) -> None:
        source = 'const status = "' + joined("PLACE", "HOLDER") + '";\n'
        self.assertIn("shortcut-marker", rules("apps/sample.ts", source))

    def test_marker_near_matches_are_allowed(self) -> None:
        source = """
const todoCount = 1;
const placeholderText = "filter";
const stubbornRuntime = true;
const input = <input placeholder={placeholderText} />;
"""
        self.assertEqual(rules("apps/sample.tsx", source), set())

    def test_lowercase_go_and_shell_comment_markers_are_rejected(self) -> None:
        go_source = "package sample\n// " + joined("place", "holder") + "\n"
        shell_source = "#!/bin/sh\n# " + joined("st", "ub") + "\n"
        self.assertIn("shortcut-marker", rules("crates/sample.go", go_source))
        self.assertIn("shortcut-marker", rules("runtime/sample.sh", shell_source))

    def test_go_and_shell_marker_words_inside_strings_are_allowed(self) -> None:
        go_source = 'package sample\nvar value = "// placeholder"\n'
        shell_source = "#!/bin/sh\nvalue='# stub'\nprintf '%s\\n' \"$value\"\n"
        self.assertEqual(rules("crates/sample.go", go_source), set())
        self.assertEqual(rules("runtime/sample.sh", shell_source), set())

    def test_shell_command_substitution_comments_and_heredoc_data(self) -> None:
        command_substitution = (
            'value="$(\n # ' + joined("place", "holder") + '\n echo x\n)"\n'
        )
        heredocs = [
            "cat <<'EOF'\n# " + joined("place", "holder") + " shown as data\nEOF\n",
            'value="$(cat <<EOF\n# '
            + joined("place", "holder")
            + ' shown as data\nEOF\n)"\n',
            'cat <<E"OF"\n# '
            + joined("place", "holder")
            + " shown as data\nEOF\n",
            "cat <<EOF>/dev/null\n# "
            + joined("place", "holder")
            + " shown as data\nEOF\n",
        ]
        self.assertIn(
            "shortcut-marker", rules("runtime/command.sh", command_substitution)
        )
        for heredoc in heredocs:
            with self.subTest(heredoc=heredoc):
                self.assertEqual(rules("runtime/heredoc.sh", heredoc), set())
        self.assertEqual(rules("runtime/arithmetic.sh", "value=$((1 << 2))\n"), set())
        self.assertEqual(
            rules("runtime/quoted.sh", "value='trailing\\'\n# safe comment\n"),
            set(),
        )

    def test_css_and_html_comments_are_scanned_without_attribute_false_positives(self) -> None:
        css = "/* " + joined("place", "holder") + " */\n.root { color: red; }\n"
        html = "<!-- " + joined("st", "ub") + ' -->\n<input placeholder="filter">\n'
        self.assertIn("shortcut-marker", rules("apps/styles.css", css))
        self.assertIn("shortcut-marker", rules("apps/index.html", html))
        self.assertEqual(
            rules("apps/index.html", '<input placeholder="filter">\n'), set()
        )

    def test_rejects_rust_unimplemented_forms(self) -> None:
        sources = [
            "fn value() { todo!() }",
            "fn value() { todo! {} }",
            "fn value() { unimplemented ! (\"reason\") }",
            "fn value() { unimplemented ! [\"reason\"] }",
            'fn value() { panic!("not implemented") }',
            'fn value() { panic! { "not implemented" } }',
            'fn value() { panic!(r#"not-implemented yet"#) }',
            'fn value() { panic!("{}", "not implemented") }',
        ]
        for source in sources:
            with self.subTest(source=source):
                self.assertIn("rust-unimplemented", rules("crates/sample.rs", source))

    def test_rejects_rust_ignored_test_forms(self) -> None:
        sources = [
            "#[ignore]\n#[test]\nfn hidden() {}",
            '#[ignore = "reason"]\n#[test]\nfn hidden() {}',
            '#[cfg_attr(target_os = "linux", ignore)]\n#[test]\nfn hidden() {}',
            '#[cfg_attr(feature = "ci", cfg_attr(unix, ignore))]\n#[test]\nfn hidden() {}',
        ]
        for source in sources:
            with self.subTest(source=source):
                self.assertIn("rust-ignored-test", rules("crates/sample.rs", source))

    def test_rust_comments_strings_typed_errors_and_iterator_skip_are_allowed(self) -> None:
        source = r'''
// unimplemented!()
fn value<'a>(items: &'a [u8]) -> Result<usize, Error> {
    let text = "todo!()";
    let byte = b'_';
    let character = '_';
    let _remaining = items.iter().skip(1);
    if text.is_empty() { return Err(Error::Unsupported); }
    Ok(byte as usize + character as usize)
}
#[serde(ignore)]
struct Wire;
#[cfg_attr(feature = "wire", serde(ignore))]
struct ConditionalWire;
'''
        self.assertEqual(rules("crates/sample.rs", source), set())

    def test_rejects_javascript_disabled_test_forms(self) -> None:
        sources = [
            'test.skip("case", () => {});',
            'it.todo("case");',
            'describe.only("group", () => {});',
            'test.concurrent.only("case", () => {});',
            'test.each([1]).skip("case", () => {});',
            'test["skip"]("case", () => {});',
            'test.skipIf(condition)("case", () => {});',
            'test?.skip("case", () => {});',
            'test?.["skip"]("case", () => {});',
            '(test).skip("case", () => {});',
            '(describe).only("group", () => {});',
            '(xit)("case", () => {});',
            'test!.skip("case", () => {});',
            'test.each`value\n${1}`.skip("case", () => {});',
            'xit("case", () => {});',
            'fdescribe("group", () => {});',
        ]
        for source in sources:
            with self.subTest(source=source):
                self.assertIn(
                    "javascript-disabled-test",
                    rules("apps/example.test.ts", source),
                )

    def test_javascript_test_syntax_in_template_expression_is_checked(self) -> None:
        source = 'const rendered = `prefix ${test.skip("case", () => {})}`;'
        self.assertIn(
            "javascript-disabled-test", rules("apps/example.test.ts", source)
        )

    def test_javascript_strings_regex_templates_and_object_skip_are_allowed(self) -> None:
        source = r'''
const stringValue = "test.skip(\"case\")";
const matcher = /test\.skip\(/;
const template = `test.skip("case")`;
items.skip(1);
testHelpers.skip();
runner.test.skip(1);
promise.catch(() => {});
class PromiseLike { catch() {} }
class ConsecutiveMethods { then() {} catch() {} }
const jsx = <p>don't fail</p>;
try { run(); } catch (error) { report(error); }
'''
        self.assertEqual(rules("apps/example.test.ts", source), set())

    def test_jsx_text_does_not_hide_a_later_disabled_test(self) -> None:
        sources = [
            "const value = <p>students' work https://example.com</p>; "
            'test.skip("case", () => {});\n',
            "const value = `${<p>students' work https://example.com</p>}`; "
            'test.skip("case", () => {});\n',
            "const value = <Panel child={<p>students' work</p>} />; "
            'test.skip("case", () => {});\n',
            r'const value = <div>{/\}/.test(text) ? test.skip("case", fn) : null}</div>;',
            r'const value = <div>{/[}]/.test(text) ? test.skip("case", fn) : null}</div>;',
        ]
        for source in sources:
            with self.subTest(source=source):
                self.assertEqual(
                    rules("apps/example.test.tsx", source),
                    {"javascript-disabled-test"},
                )

    def test_javascript_hashbang_is_allowed(self) -> None:
        source = "#!/usr/bin/env node\nexport const value = 1;\n"
        self.assertEqual(rules("apps/tool.mjs", source), set())

    def test_rejects_empty_javascript_handlers(self) -> None:
        sources = [
            "try { run(); } catch {}",
            "try { run(); } catch (error) {}",
            "try { run(); } catch ({ message }) { /* ignored intentionally */ ; }",
            'try { run(); } catch (error) { "reason"; 0; }',
            "try { run(); } catch (error) { null; false; }",
            'try { run(); } catch (error) { ("reason"); (null); {} }',
        ]
        for source in sources:
            with self.subTest(source=source):
                self.assertIn(
                    "javascript-empty-handler", rules("apps/sample.ts", source)
                )

    def test_rejects_empty_python_handlers(self) -> None:
        sources = [
            "try:\n    run()\nexcept OSError:\n    pass\n",
            "try:\n    run()\nexcept OSError:\n    ...\n",
            "try:\n    run()\nexcept OSError:\n    None\n",
            'try:\n    run()\nexcept OSError:\n    "ignored intentionally"\n',
            'try:\n    run()\nexcept OSError:\n    pass\n    "reason"\n',
        ]
        for source in sources:
            with self.subTest(source=source):
                self.assertIn(
                    "python-empty-handler", rules("scripts/sample.py", source)
                )

    def test_rejects_python_disabled_test_forms(self) -> None:
        sources = [
            'import unittest\n@unittest.skip("reason")\ndef test_case(): ...\n',
            'import unittest as unit\n@unit.skipIf(True, "reason")\ndef test_case(): ...\n',
            'from unittest import skipUnless as disabled\n@disabled(False, "reason")\ndef test_case(): ...\n',
            'import pytest\n@pytest.mark.skip(reason="reason")\ndef test_case(): ...\n',
            'import pytest as pt\n@pt.mark.skipif(True, reason="reason")\ndef test_case(): ...\n',
            'import pytest\ndef test_case(): pytest.skip("reason")\n',
            'def test_case():\n    import pytest as pt\n    pt.skip("reason")\n',
            'import pytest\nmodule = pytest.importorskip("optional")\n',
            'class TestCase:\n    def test_case(self): self.skipTest("reason")\n',
            'import unittest\nraise unittest.SkipTest("reason")\n',
            'import pytest\npytestmark = pytest.mark.skip\n',
        ]
        for source in sources:
            with self.subTest(source=source):
                self.assertIn(
                    "python-disabled-test", rules("scripts/tests/test_sample.py", source)
                )

    def test_python_iterator_parametrization_and_explicit_handler_are_allowed(self) -> None:
        source = """
import pytest

@pytest.mark.parametrize("value", [1])
def test_case(value):
    try:
        return iterator.skip(value)
    except LookupError as error:
        raise RuntimeError("lookup failed") from error
"""
        self.assertEqual(rules("scripts/tests/test_sample.py", source), set())

    def test_scanner_scans_its_own_source(self) -> None:
        source = "# " + joined("TO", "DO") + "\ntry:\n    run()\nexcept OSError:\n    pass\n"
        self.assertEqual(
            rules("scripts/quality_gate.py", source),
            {"python-empty-handler", "shortcut-marker"},
        )


class RepositoryScanTests(unittest.TestCase):
    def make_repository(self) -> Path:
        temporary = tempfile.TemporaryDirectory(prefix="flowprobe-gate-test-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        subprocess.run(
            ["git", "init", "--quiet", str(root)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return root

    def write(self, root: Path, relative: str, content: str) -> Path:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def test_discovers_tracked_and_unignored_but_not_ignored_or_generated(self) -> None:
        root = self.make_repository()
        marker = "# " + joined("TO", "DO") + "\n"
        self.write(
            root,
            ".gitignore",
            "crates/*.py\nruntime/ignored.py\napps/node_modules/\n",
        )
        self.write(root, "crates/tracked.py", marker)
        self.write(root, "scripts/untracked.py", marker)
        self.write(root, "runtime/ignored.py", marker)
        self.write(root, "apps/node_modules/generated.ts", "// " + marker)
        self.write(root, "scripts/.venv/lib/generated.py", marker)
        self.write(root, "apps/build/generated.ts", "// " + marker)
        subprocess.run(
            ["git", "add", "--force", "crates/tracked.py"],
            cwd=root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        paths = {finding.path for finding in quality_gate.scan_repository(root)}
        self.assertEqual(paths, {"crates/tracked.py", "scripts/untracked.py"})

    def test_forbidden_language_forms_cross_the_full_repository_pipeline(self) -> None:
        root = self.make_repository()
        marker_lines = "\n".join(
            "# " + joined(*parts)
            for parts in [("TO", "DO"), ("FIX", "ME"), ("place", "holder"), ("st", "ub")]
        )
        self.write(
            root,
            "crates/bad.rs",
            "fn a(){todo!{}}\nfn b(){unimplemented!()}\n"
            '#[ignore]\n#[test]\nfn hidden(){}\nfn c(){panic!("not implemented")}\n',
        )
        self.write(
            root,
            "apps/bad.test.ts",
            'test.skip("a",()=>{}); it.todo("b"); describe.only("c",()=>{});\n'
            'try { run(); } catch (error) { "reason"; }\n',
        )
        self.write(
            root,
            "scripts/tests/test_bad.py",
            marker_lines
            + '\nimport unittest\n@unittest.skip("reason")\ndef test_case(): ...\n'
            + "try:\n    run()\nexcept OSError:\n    pass\n",
        )
        self.write(root, "runtime/bad.sh", "# " + joined("st", "ub") + "\n")

        found_rules = {finding.rule for finding in quality_gate.scan_repository(root)}
        self.assertEqual(
            found_rules,
            {
                "javascript-disabled-test",
                "javascript-empty-handler",
                "python-disabled-test",
                "python-empty-handler",
                "rust-ignored-test",
                "rust-unimplemented",
                "shortcut-marker",
            },
        )

    def test_invalid_utf8_and_symlink_fail_closed(self) -> None:
        root = self.make_repository()
        invalid = root / "apps" / "invalid.py"
        invalid.parent.mkdir(parents=True)
        invalid.write_bytes(b"\xff\xfe")
        target = self.write(root, "outside.txt", "safe\n")
        link = root / "scripts" / "linked.py"
        link.parent.mkdir(parents=True)
        try:
            link.symlink_to(target)
        except OSError:
            link = None

        findings = quality_gate.scan_repository(root)
        by_path = {finding.path: finding.rule for finding in findings}
        self.assertEqual(by_path["apps/invalid.py"], "source-read-failure")
        if link is not None:
            self.assertEqual(by_path["scripts/linked.py"], "source-read-failure")

    def test_discovery_and_language_scanner_failures_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="flowprobe-gate-nongit-") as temporary:
            self.assertEqual(
                quality_gate.scan_repository(Path(temporary))[0].rule,
                "source-discovery-failure",
            )

        root = self.make_repository()
        self.write(root, "apps/broken.ts", 'const value = "unterminated;\n')
        self.assertEqual(
            quality_gate.scan_repository(root)[0].rule, "source-scan-failure"
        )

    def test_unexpected_scanner_failure_is_reported(self) -> None:
        root = self.make_repository()
        self.write(root, "scripts/source.py", "value = 1\n")
        with mock.patch.object(quality_gate, "scan_source", side_effect=RuntimeError):
            self.assertEqual(
                quality_gate.scan_repository(root)[0].rule, "source-scan-failure"
            )

    def test_diagnostics_are_ordered_and_do_not_print_source(self) -> None:
        root = self.make_repository()
        marker = joined("TO", "DO")
        canary = "AUTHORIZATION_SYNTHETIC_CANARY_9d8f"
        self.write(root, "scripts/z.py", f"# {marker} {canary}\n")
        self.write(root, "scripts/a.py", f"# {marker}\n")
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = quality_gate.main(root)

        diagnostic = stderr.getvalue()
        self.assertEqual(result, 1)
        self.assertNotIn(canary, diagnostic)
        self.assertLess(diagnostic.index("scripts/a.py"), diagnostic.index("scripts/z.py"))
        self.assertIn("shortcut-marker", diagnostic)


class CleanupRegressionTests(unittest.TestCase):
    def test_sigkill_process_group_already_gone_is_explicit_success(self) -> None:
        with tempfile.TemporaryDirectory(prefix="flowprobe-cleanup-test-") as temporary:
            pid_file = Path(temporary) / "runtime.pid"
            process_group = 987654
            pid_file.write_text(str(process_group), encoding="ascii")
            with (
                mock.patch.object(proof.os, "getpgrp", return_value=1),
                mock.patch.object(
                    proof.os,
                    "killpg",
                    side_effect=[None, ProcessLookupError()],
                ) as killpg,
                mock.patch.object(proof.time, "monotonic", side_effect=[0.0, 6.0]),
                mock.patch.object(proof, "process_group_is_alive", return_value=True),
            ):
                proof.force_runtime_cleanup(pid_file)

            self.assertFalse(pid_file.exists())
            self.assertEqual(
                killpg.call_args_list,
                [
                    mock.call(process_group, signal.SIGTERM),
                    mock.call(process_group, signal.SIGKILL),
                ],
            )


if __name__ == "__main__":
    unittest.main()
