#!/usr/bin/env python3
"""Fail-closed repository checks for shortcuts forbidden by AGENTS.md."""
from __future__ import annotations

import ast
import bisect
import io
import json
import os
import re
import stat
import subprocess
import sys
import tokenize
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
SCAN_ROOTS = ("apps", "crates", "runtime", "plugins", "scripts", "tests")
SOURCE_SUFFIXES = {
    ".cjs",
    ".css",
    ".cts",
    ".go",
    ".htm",
    ".html",
    ".js",
    ".jsx",
    ".mjs",
    ".mts",
    ".py",
    ".rs",
    ".sh",
    ".ts",
    ".tsx",
}
JAVASCRIPT_SUFFIXES = {".cjs", ".cts", ".js", ".jsx", ".mjs", ".mts", ".ts", ".tsx"}
GENERATED_DIRECTORIES = {
    ".cache",
    ".mypy_cache",
    ".next",
    ".nox",
    ".pnpm-store",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".vite",
    ".venv",
    "__pypackages__",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "out",
    "target",
    "vendor",
    "venv",
}
GENERATED_PREFIXES = {("apps", "desktop", "src-tauri", "gen")}
MAX_SOURCE_BYTES = 4 * 1024 * 1024

MARKER_WORDS = ("TO" + "DO", "FIX" + "ME", "PLACE" + "HOLDER", "ST" + "UB")
MARKER_ALTERNATION = "|".join(MARKER_WORDS)
RAW_MARKER_PATTERN = re.compile(
    rf"(?<![A-Za-z0-9_])(?:{MARKER_ALTERNATION})(?![A-Za-z0-9_])"
)
COMMENT_MARKER_PATTERN = re.compile(
    rf"(?<![A-Za-z0-9_])(?:{MARKER_ALTERNATION})(?![A-Za-z0-9_])",
    re.IGNORECASE,
)
NOT_IMPLEMENTED_PATTERN = re.compile(r"\bnot(?:[\s_-]+)implemented\b", re.IGNORECASE)


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    line: int
    column: int
    rule: str


@dataclass(frozen=True)
class Token:
    kind: str
    value: str
    offset: int
    line: int
    column: int


class ScanFailure(RuntimeError):
    def __init__(self, offset: int = 0) -> None:
        super().__init__()
        self.offset = offset


class SourceReadFailure(RuntimeError):
    pass


class PositionIndex:
    def __init__(self, text: str) -> None:
        self._starts = [0]
        self._starts.extend(index + 1 for index, char in enumerate(text) if char == "\n")

    def position(self, offset: int) -> tuple[int, int]:
        line_index = bisect.bisect_right(self._starts, offset) - 1
        return line_index + 1, offset - self._starts[line_index] + 1

    def offset(self, line: int, zero_based_column: int) -> int:
        return self._starts[line - 1] + zero_based_column


def _token(kind: str, value: str, offset: int, positions: PositionIndex) -> Token:
    line, column = positions.position(offset)
    return Token(kind, value, offset, line, column)


def _finding(path: PurePosixPath, token: Token, rule: str) -> Finding:
    return Finding(path.as_posix(), token.line, token.column, rule)


def _finding_at(path: PurePosixPath, positions: PositionIndex, offset: int, rule: str) -> Finding:
    line, column = positions.position(offset)
    return Finding(path.as_posix(), line, column, rule)


def is_relevant_source(path: PurePosixPath) -> bool:
    if not path.parts or path.parts[0] not in SCAN_ROOTS:
        return False
    if any(part in GENERATED_DIRECTORIES for part in path.parts[1:-1]):
        return False
    if any(path.parts[: len(prefix)] == prefix for prefix in GENERATED_PREFIXES):
        return False
    return path.suffix.lower() in SOURCE_SUFFIXES


def discover_sources(root: Path) -> list[PurePosixPath]:
    command = [
        "git",
        "ls-files",
        "-z",
        "--cached",
        "--others",
        "--exclude-standard",
        "--deduplicate",
        "--",
        *SCAN_ROOTS,
    ]
    try:
        result = subprocess.run(
            command,
            cwd=root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        raise ScanFailure() from exc
    if result.returncode != 0:
        raise ScanFailure()

    sources: set[PurePosixPath] = set()
    for encoded in result.stdout.split(b"\0"):
        if not encoded:
            continue
        path = PurePosixPath(os.fsdecode(encoded))
        if path.is_absolute() or ".." in path.parts or not path.parts:
            raise ScanFailure()
        if is_relevant_source(path):
            sources.add(path)
    return sorted(sources, key=lambda item: item.as_posix())


def read_source(root: Path, relative: PurePosixPath) -> str:
    candidate = root.joinpath(*relative.parts)
    try:
        metadata = candidate.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise SourceReadFailure()
        resolved_root = root.resolve(strict=True)
        resolved_candidate = candidate.resolve(strict=True)
        if not resolved_candidate.is_relative_to(resolved_root):
            raise SourceReadFailure()

        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(candidate, flags)
        try:
            opened_metadata = os.fstat(descriptor)
            if not stat.S_ISREG(opened_metadata.st_mode):
                raise SourceReadFailure()
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                encoded = stream.read(MAX_SOURCE_BYTES + 1)
        finally:
            os.close(descriptor)
    except (OSError, RuntimeError) as exc:
        if isinstance(exc, SourceReadFailure):
            raise
        raise SourceReadFailure() from exc
    if len(encoded) > MAX_SOURCE_BYTES:
        raise SourceReadFailure()
    try:
        return encoded.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SourceReadFailure() from exc


def _scan_marker_text(
    path: PurePosixPath,
    positions: PositionIndex,
    text: str,
    base_offset: int,
    pattern: re.Pattern[str],
) -> list[Finding]:
    return [
        _finding_at(path, positions, base_offset + match.start(), "shortcut-marker")
        for match in pattern.finditer(text)
    ]


def _scan_python(path: PurePosixPath, text: str, positions: PositionIndex) -> list[Finding]:
    findings: list[Finding] = []
    try:
        python_tokens = tokenize.generate_tokens(io.StringIO(text).readline)
        for item in python_tokens:
            if item.type != tokenize.COMMENT:
                continue
            offset = positions.offset(item.start[0], item.start[1])
            findings.extend(
                _scan_marker_text(path, positions, item.string, offset, COMMENT_MARKER_PATTERN)
            )
    except (IndentationError, tokenize.TokenError) as exc:
        line = getattr(exc, "lineno", None)
        if line is None and isinstance(exc, tokenize.TokenError) and len(exc.args) > 1:
            location = exc.args[1]
            if isinstance(location, tuple) and location and isinstance(location[0], int):
                line = location[0]
        return [Finding(path.as_posix(), max(line or 1, 1), 1, "python-scan-failure")]

    try:
        tree = ast.parse(text, filename=path.as_posix())
    except (SyntaxError, ValueError) as exc:
        line = max(getattr(exc, "lineno", 1) or 1, 1)
        column = max(getattr(exc, "offset", 1) or 1, 1)
        findings.append(Finding(path.as_posix(), line, column, "python-parse-failure"))
        return findings

    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in {"pytest", "unittest"}:
                    aliases[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module in {"pytest", "unittest"}:
            for alias in node.names:
                if alias.name != "*":
                    aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"

    def dotted_name(node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            parent = dotted_name(node.value)
            return f"{parent}.{node.attr}" if parent is not None else None
        return None

    disabled_calls = {
        "pytest.importorskip",
        "pytest.skip",
        "unittest.skip",
        "unittest.skipIf",
        "unittest.skipUnless",
    }
    disabled_attributes = {"pytest.mark.skip", "pytest.mark.skipif"}
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            empty = all(
                isinstance(statement, ast.Pass)
                or (
                    isinstance(statement, ast.Expr)
                    and isinstance(statement.value, ast.Constant)
                )
                for statement in node.body
            )
            if empty:
                findings.append(
                    Finding(path.as_posix(), node.lineno, node.col_offset + 1, "python-empty-handler")
                )
        elif isinstance(node, ast.Call):
            name = dotted_name(node.func)
            if name in disabled_calls or (name is not None and name.endswith(".skipTest")):
                findings.append(
                    Finding(path.as_posix(), node.lineno, node.col_offset + 1, "python-disabled-test")
                )
        elif isinstance(node, ast.Attribute):
            if dotted_name(node) in disabled_attributes:
                findings.append(
                    Finding(path.as_posix(), node.lineno, node.col_offset + 1, "python-disabled-test")
                )
        elif isinstance(node, ast.Raise) and node.exc is not None:
            raised = node.exc.func if isinstance(node.exc, ast.Call) else node.exc
            if dotted_name(raised) == "unittest.SkipTest":
                findings.append(
                    Finding(path.as_posix(), node.lineno, node.col_offset + 1, "python-disabled-test")
                )
    return findings


def _scan_quoted(
    text: str, start: int, quote: str, *, allow_newlines: bool = False
) -> tuple[int, str]:
    index = start + 1
    content_start = index
    while index < len(text):
        if text[index] == "\\":
            index += 2
        elif text[index] == quote:
            return index + 1, text[content_start:index]
        elif text[index] in "\r\n" and not allow_newlines:
            raise ScanFailure(start)
        else:
            index += 1
    raise ScanFailure(start)


def _rust_raw_string(text: str, start: int) -> tuple[int, str] | None:
    index = start
    if text.startswith("br", index):
        index += 2
    elif text.startswith("r", index):
        index += 1
    else:
        return None
    hashes = 0
    while index < len(text) and text[index] == "#":
        hashes += 1
        index += 1
    if index >= len(text) or text[index] != '"':
        return None
    content_start = index + 1
    terminator = '"' + "#" * hashes
    end = text.find(terminator, content_start)
    if end < 0:
        raise ScanFailure(start)
    return end + len(terminator), text[content_start:end]


def _lex_rust(text: str, positions: PositionIndex) -> tuple[list[Token], list[Token]]:
    tokens: list[Token] = []
    comments: list[Token] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char.isspace():
            index += 1
        elif text.startswith("//", index):
            end = text.find("\n", index + 2)
            end = len(text) if end < 0 else end
            comments.append(_token("comment", text[index:end], index, positions))
            index = end
        elif text.startswith("/*", index):
            depth = 1
            end = index + 2
            while end < len(text) and depth:
                if text.startswith("/*", end):
                    depth += 1
                    end += 2
                elif text.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            if depth:
                raise ScanFailure(index)
            comments.append(_token("comment", text[index:end], index, positions))
            index = end
        else:
            raw = _rust_raw_string(text, index)
            if raw is not None:
                end, content = raw
                tokens.append(_token("string", content, index, positions))
                index = end
                continue
            if char == '"' or (char == "b" and index + 1 < len(text) and text[index + 1] == '"'):
                quote_start = index if char == '"' else index + 1
                end, content = _scan_quoted(text, quote_start, '"', allow_newlines=True)
                tokens.append(_token("string", content, index, positions))
                index = end
            elif char == "b" and index + 1 < len(text) and text[index + 1] == "'":
                end, _content = _scan_quoted(
                    text, index + 1, "'", allow_newlines=False
                )
                index = end
            elif char == "'" and index + 1 < len(text):
                if text[index + 1] == "\\" or (
                    index + 2 < len(text) and text[index + 2] == "'"
                ):
                    end, _content = _scan_quoted(
                        text, index, "'", allow_newlines=False
                    )
                    index = end
                else:
                    tokens.append(_token("punct", "'", index, positions))
                    index += 1
            elif char.isalpha() or char == "_":
                end = index + 1
                while end < len(text) and (text[end].isalnum() or text[end] == "_"):
                    end += 1
                tokens.append(_token("identifier", text[index:end], index, positions))
                index = end
            else:
                tokens.append(_token("punct", char, index, positions))
                index += 1
    return tokens, comments


def _matching_token(tokens: list[Token], start: int, opening: str, closing: str) -> int | None:
    depth = 0
    for index in range(start, len(tokens)):
        if tokens[index].value == opening:
            depth += 1
        elif tokens[index].value == closing:
            depth -= 1
            if depth == 0:
                return index
    return None


def _opening_token(tokens: list[Token], end: int, opening: str, closing: str) -> int | None:
    depth = 0
    for index in range(end, -1, -1):
        if tokens[index].value == closing:
            depth += 1
        elif tokens[index].value == opening:
            depth -= 1
            if depth == 0:
                return index
    return None


def _rust_meta_has_ignore(tokens: list[Token]) -> bool:
    identifiers = [token for token in tokens if token.kind == "identifier"]
    if not identifiers:
        return False
    first = identifiers[0]
    if first.value == "ignore":
        return True
    if first.value != "cfg_attr":
        return False
    try:
        opening = tokens.index(first) + 1
    except ValueError:
        return False
    if opening >= len(tokens) or tokens[opening].value != "(":
        return False
    closing = _matching_token(tokens, opening, "(", ")")
    if closing is None:
        raise ScanFailure(first.offset)

    arguments: list[list[Token]] = [[]]
    depth = 0
    for token in tokens[opening + 1 : closing]:
        if token.value in {"(", "[", "{"}:
            depth += 1
        elif token.value in {")", "]", "}"}:
            depth -= 1
        if token.value == "," and depth == 0:
            arguments.append([])
        else:
            arguments[-1].append(token)
    return any(_rust_meta_has_ignore(argument) for argument in arguments[1:])


def _scan_rust(path: PurePosixPath, text: str, positions: PositionIndex) -> list[Finding]:
    tokens, comments = _lex_rust(text, positions)
    findings: list[Finding] = []
    for comment in comments:
        findings.extend(
            _scan_marker_text(
                path, positions, comment.value, comment.offset, COMMENT_MARKER_PATTERN
            )
        )
    for index, item in enumerate(tokens):
        if (
            item.kind == "identifier"
            and item.value in {"todo", "unimplemented"}
            and index + 2 < len(tokens)
            and tokens[index + 1].value == "!"
            and tokens[index + 2].value in {"(", "[", "{"}
        ):
            findings.append(_finding(path, item, "rust-unimplemented"))
        if (
            item.kind == "identifier"
            and item.value == "panic"
            and index + 2 < len(tokens)
            and tokens[index + 1].value == "!"
            and tokens[index + 2].value in {"(", "[", "{"}
        ):
            closing = {"(": ")", "[": "]", "{": "}"}[tokens[index + 2].value]
            macro_end = _matching_token(tokens, index + 2, tokens[index + 2].value, closing)
            if macro_end is None:
                raise ScanFailure(item.offset)
            if any(
                token.kind == "string" and NOT_IMPLEMENTED_PATTERN.search(token.value)
                for token in tokens[index + 3 : macro_end]
            ):
                findings.append(_finding(path, item, "rust-unimplemented"))
        if item.value != "#":
            continue
        cursor = index + 1
        if cursor < len(tokens) and tokens[cursor].value == "!":
            cursor += 1
        if cursor >= len(tokens) or tokens[cursor].value != "[":
            continue
        end = _matching_token(tokens, cursor, "[", "]")
        if end is None:
            raise ScanFailure(item.offset)
        inner = tokens[cursor + 1 : end]
        if _rust_meta_has_ignore(inner):
            findings.append(_finding(path, item, "rust-ignored-test"))
    return findings


def _js_regex_can_start(tokens: list[Token]) -> bool:
    if not tokens:
        return True
    previous = tokens[-1]
    if previous.kind == "identifier":
        return previous.value in {
            "await",
            "case",
            "delete",
            "do",
            "else",
            "in",
            "instanceof",
            "of",
            "return",
            "throw",
            "typeof",
            "void",
            "yield",
        }
    if previous.kind in {"number", "string"}:
        return False
    return previous.value not in {")", "]", "}"}


def _lex_go_comments(text: str, positions: PositionIndex) -> list[Token]:
    comments: list[Token] = []
    index = 0
    while index < len(text):
        if text.startswith("//", index):
            end = text.find("\n", index + 2)
            end = len(text) if end < 0 else end
            comments.append(_token("comment", text[index:end], index, positions))
            index = end
        elif text.startswith("/*", index):
            end = text.find("*/", index + 2)
            if end < 0:
                raise ScanFailure(index)
            end += 2
            comments.append(_token("comment", text[index:end], index, positions))
            index = end
        elif text[index] in {'"', "'"}:
            index, _content = _scan_quoted(text, index, text[index])
        elif text[index] == "`":
            end = text.find("`", index + 1)
            if end < 0:
                raise ScanFailure(index)
            index = end + 1
        else:
            index += 1
    return comments


def _lex_css_comments(text: str, positions: PositionIndex) -> list[Token]:
    comments: list[Token] = []
    index = 0
    while index < len(text):
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            if end < 0:
                raise ScanFailure(index)
            end += 2
            comments.append(_token("comment", text[index:end], index, positions))
            index = end
        elif text[index] in {'"', "'"}:
            index, _content = _scan_quoted(
                text, index, text[index], allow_newlines=True
            )
        else:
            index += 1
    return comments


def _lex_html_comments(text: str, positions: PositionIndex) -> list[Token]:
    comments: list[Token] = []
    index = 0
    while index < len(text):
        start = text.find("<!--", index)
        if start < 0:
            break
        end = text.find("-->", start + 4)
        if end < 0:
            raise ScanFailure(start)
        end += 3
        comments.append(_token("comment", text[start:end], start, positions))
        index = end
    return comments


def _shell_comment_starts(text: str, index: int) -> bool:
    return index == 0 or text[index - 1].isspace() or text[index - 1] in ";|&()"


def _scan_shell_single_quoted(text: str, start: int) -> tuple[int, str]:
    end = text.find("'", start + 1)
    if end < 0:
        raise ScanFailure(start)
    return end + 1, text[start + 1 : end]


def _shell_heredoc_word(text: str, start: int) -> tuple[int, str]:
    delimiter: list[str] = []
    index = start
    while (
        index < len(text)
        and not text[index].isspace()
        and text[index] not in ";|&()<>"
    ):
        if text[index] == "\\":
            if index + 1 >= len(text):
                raise ScanFailure(index)
            delimiter.append(text[index + 1])
            index += 2
        elif text[index] == "'":
            end, content = _scan_shell_single_quoted(text, index)
            delimiter.append(content)
            index = end
        elif text[index] == '"':
            end, content = _scan_quoted(text, index, '"', allow_newlines=False)
            delimiter.append(content)
            index = end
        else:
            delimiter.append(text[index])
            index += 1
    if not delimiter:
        raise ScanFailure(start)
    return index, "".join(delimiter)


def _shell_heredoc_mask(text: str) -> list[bool]:
    masked = [False] * len(text)
    pending: list[tuple[str, bool]] = []

    def consume_bodies(index: int) -> int:
        declarations = list(pending)
        pending.clear()
        for delimiter, strip_tabs in declarations:
            while index < len(text):
                line_end = text.find("\n", index)
                next_line = len(text) if line_end < 0 else line_end + 1
                content_end = line_end if line_end >= 0 else len(text)
                if content_end > index and text[content_end - 1] == "\r":
                    content_end -= 1
                content = text[index:content_end]
                comparison = content.lstrip("\t") if strip_tabs else content
                if comparison == delimiter:
                    index = next_line
                    break
                for offset in range(index, next_line):
                    masked[offset] = True
                index = next_line
            else:
                raise ScanFailure(max(index - 1, 0))
        return index

    def skip_arithmetic(index: int, depth: int = 2) -> int:
        start = index - depth
        while index < len(text):
            if text[index] == "\\":
                index += 2
            elif text[index] == "'":
                index, _content = _scan_shell_single_quoted(text, index)
            elif text[index] == '"':
                index, _content = _scan_quoted(
                    text, index, '"', allow_newlines=True
                )
            elif text[index] == "(":
                depth += 1
                index += 1
            elif text[index] == ")":
                depth -= 1
                index += 1
                if depth == 0:
                    return index
            else:
                index += 1
        raise ScanFailure(max(start, 0))

    def scan_double_quoted(index: int) -> int:
        start = index
        index += 1
        while index < len(text):
            if text[index] == "\\":
                index += 2
            elif text.startswith("$((", index):
                index = skip_arithmetic(index + 3)
            elif text.startswith("$(", index):
                index = scan_code(index + 2, stop_at_paren=True)
            elif text[index] == "`":
                index = scan_code(index + 1, stop_at_backtick=True)
            elif text[index] == '"':
                return index + 1
            else:
                index += 1
        raise ScanFailure(start)

    def scan_code(
        index: int, *, stop_at_paren: bool = False, stop_at_backtick: bool = False
    ) -> int:
        while index < len(text):
            if text[index] == "\n" and pending:
                index = consume_bodies(index + 1)
            elif text[index] == "\\":
                index += 2
            elif text[index] == "'":
                index, _content = _scan_shell_single_quoted(text, index)
            elif text[index] == '"':
                index = scan_double_quoted(index)
            elif text.startswith("$((", index):
                index = skip_arithmetic(index + 3)
            elif text.startswith("$(", index):
                index = scan_code(index + 2, stop_at_paren=True)
            elif text.startswith("((", index):
                index = skip_arithmetic(index + 2)
            elif text[index] == "`":
                if stop_at_backtick:
                    return index + 1
                index = scan_code(index + 1, stop_at_backtick=True)
            elif stop_at_paren and text[index] == ")":
                return index + 1
            elif stop_at_paren and text[index] == "(":
                index = scan_code(index + 1, stop_at_paren=True)
            elif text[index] == "#" and _shell_comment_starts(text, index):
                end = text.find("\n", index + 1)
                index = len(text) if end < 0 else end
            elif text.startswith("<<", index) and not text.startswith("<<<", index):
                cursor = index + 2
                strip_tabs = cursor < len(text) and text[cursor] == "-"
                if strip_tabs:
                    cursor += 1
                while cursor < len(text) and text[cursor] in " \t":
                    cursor += 1
                end, delimiter = _shell_heredoc_word(text, cursor)
                pending.append((delimiter, strip_tabs))
                index = end
            else:
                index += 1
        if stop_at_paren or stop_at_backtick or pending:
            raise ScanFailure(max(index - 1, 0))
        return index

    scan_code(0)
    return masked


def _lex_shell_comments(text: str, positions: PositionIndex) -> list[Token]:
    comments: list[Token] = []
    heredoc_mask = _shell_heredoc_mask(text)

    def scan_double_quoted(index: int) -> int:
        start = index
        index += 1
        while index < len(text):
            if heredoc_mask[index]:
                index += 1
            elif text[index] == "\\":
                index += 2
            elif text.startswith("$(", index):
                index = scan_code(index + 2, stop_at_paren=True)
            elif text[index] == '"':
                return index + 1
            else:
                index += 1
        raise ScanFailure(start)

    def scan_backtick(index: int) -> int:
        start = index
        index += 1
        while index < len(text):
            if heredoc_mask[index]:
                index += 1
            elif text[index] == "\\":
                index += 2
            elif text[index] == "`":
                return index + 1
            elif text[index] == '"':
                index = scan_double_quoted(index)
            elif text[index] == "'":
                index, _content = _scan_shell_single_quoted(text, index)
            elif text[index] == "#" and _shell_comment_starts(text, index):
                end = text.find("\n", index + 1)
                end = len(text) if end < 0 else end
                comments.append(_token("comment", text[index:end], index, positions))
                index = end
            else:
                index += 1
        raise ScanFailure(start)

    def scan_code(index: int, *, stop_at_paren: bool = False) -> int:
        while index < len(text):
            if heredoc_mask[index]:
                index += 1
            elif text[index] == "\\":
                index += 2
            elif text[index] == "'":
                index, _content = _scan_shell_single_quoted(text, index)
            elif text[index] == '"':
                index = scan_double_quoted(index)
            elif text[index] == "`":
                index = scan_backtick(index)
            elif text.startswith("$(", index):
                index = scan_code(index + 2, stop_at_paren=True)
            elif stop_at_paren and text[index] == ")":
                return index + 1
            elif stop_at_paren and text[index] == "(":
                index = scan_code(index + 1, stop_at_paren=True)
            elif text[index] == "#" and _shell_comment_starts(text, index):
                end = text.find("\n", index + 1)
                end = len(text) if end < 0 else end
                comments.append(_token("comment", text[index:end], index, positions))
                index = end
            else:
                index += 1
        if stop_at_paren:
            raise ScanFailure(max(index - 1, 0))
        return index

    scan_code(0)
    return comments


def _skip_js_regex(text: str, start: int) -> int:
    index = start + 1
    in_character_class = False
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 2
        elif char in "\r\n":
            raise ScanFailure(start)
        elif char == "[":
            in_character_class = True
            index += 1
        elif char == "]" and in_character_class:
            in_character_class = False
            index += 1
        elif char == "/" and not in_character_class:
            index += 1
            while index < len(text) and (text[index].isalnum() or text[index] in "$_"):
                index += 1
            return index
        else:
            index += 1
    raise ScanFailure(start)


def _skip_javascript_template(text: str, start: int) -> int:
    index = start + 1
    while index < len(text):
        if text[index] == "\\":
            index += 2
        elif text.startswith("${", index):
            index = _skip_javascript_braced(text, index + 1)
        elif text[index] == "`":
            return index + 1
        else:
            index += 1
    raise ScanFailure(start)


def _skip_javascript_braced(text: str, start: int) -> int:
    depth = 1
    index = start + 1
    tokens: list[Token] = []
    while index < len(text):
        if text.startswith("//", index):
            end = text.find("\n", index + 2)
            index = len(text) if end < 0 else end
        elif text.startswith("/*", index):
            end = text.find("*/", index + 2)
            if end < 0:
                raise ScanFailure(index)
            index = end + 2
        elif text[index] == "<" and _looks_like_jsx_root(text, index):
            element_end = _skip_jsx_element(text, index)
            if element_end is None:
                raise ScanFailure(index)
            tokens.append(Token("identifier", "jsx", index, 0, 0))
            index = element_end
        elif text[index] in {'"', "'"}:
            token_offset = index
            index, _content = _scan_quoted(text, index, text[index])
            tokens.append(Token("string", "", token_offset, 0, 0))
        elif text[index] == "`":
            token_offset = index
            index = _skip_javascript_template(text, index)
            tokens.append(Token("string", "", token_offset, 0, 0))
        elif text[index] == "/" and _js_regex_can_start(tokens):
            token_offset = index
            index = _skip_js_regex(text, index)
            tokens.append(Token("regex", "", token_offset, 0, 0))
        elif text[index].isalpha() or text[index] in "_$":
            end = index + 1
            while end < len(text) and (text[end].isalnum() or text[end] in "_$"):
                end += 1
            tokens.append(Token("identifier", text[index:end], index, 0, 0))
            index = end
        elif text[index].isdigit():
            end = index + 1
            while end < len(text) and (text[end].isalnum() or text[end] in "._"):
                end += 1
            tokens.append(Token("number", text[index:end], index, 0, 0))
            index = end
        elif text[index] == "{":
            depth += 1
            tokens.append(Token("punct", "{", index, 0, 0))
            index += 1
        elif text[index] == "}":
            depth -= 1
            tokens.append(Token("punct", "}", index, 0, 0))
            index += 1
            if depth == 0:
                return index
        else:
            if not text[index].isspace():
                tokens.append(Token("punct", text[index], index, 0, 0))
            index += 1
    raise ScanFailure(start)


def _jsx_tag_end(text: str, start: int) -> int | None:
    index = start + 1
    while index < len(text):
        if text[index] in {'"', "'"}:
            try:
                index, _content = _scan_quoted(
                    text, index, text[index], allow_newlines=True
                )
            except ScanFailure:
                return None
        elif text[index] == "{":
            try:
                index = _skip_javascript_braced(text, index)
            except ScanFailure:
                return None
        elif text[index] == ">":
            return index
        else:
            index += 1
    return None


def _jsx_tag_name(text: str, start: int) -> str | None:
    index = start + 1
    if index < len(text) and text[index] == "/":
        index += 1
    while index < len(text) and text[index].isspace():
        index += 1
    if index < len(text) and text[index] == ">":
        return ""
    match = re.match(r"[A-Za-z_$][A-Za-z0-9_$.:\-]*", text[index:])
    return match.group(0) if match is not None else None


def _looks_like_jsx_root(text: str, start: int) -> bool:
    if start + 1 >= len(text) or text[start + 1] == "/":
        return False
    end = _jsx_tag_end(text, start)
    name = _jsx_tag_name(text, start)
    if end is None or name is None:
        return False
    if text[start + 1 : end].rstrip().endswith("/"):
        return True
    if name == "":
        return "</>" in text[end + 1 :]
    return re.search(rf"</\s*{re.escape(name)}(?:\s|>)", text[end + 1 :]) is not None


def _mask_jsx_element(
    text: str,
    masked: list[str],
    start: int,
    expression_ranges: list[tuple[int, int]],
) -> int | None:
    opening_end = _jsx_tag_end(text, start)
    name = _jsx_tag_name(text, start)
    if opening_end is None or name is None:
        return None
    attribute_cursor = start + 1
    while attribute_cursor < opening_end:
        if text[attribute_cursor] in {'"', "'"}:
            attribute_cursor, _content = _scan_quoted(
                text,
                attribute_cursor,
                text[attribute_cursor],
                allow_newlines=True,
            )
        elif text[attribute_cursor] == "{":
            expression_end = _skip_javascript_braced(text, attribute_cursor)
            expression_ranges.append(
                (attribute_cursor + 1, expression_end - 1)
            )
            attribute_cursor = expression_end
        else:
            attribute_cursor += 1
    if text[start + 1 : opening_end].rstrip().endswith("/"):
        return opening_end + 1

    changed: list[tuple[int, str]] = []
    cursor = opening_end + 1
    while cursor < len(text):
        if text.startswith("</", cursor):
            closing_name = _jsx_tag_name(text, cursor)
            if closing_name == name:
                closing_end = _jsx_tag_end(text, cursor)
                if closing_end is not None:
                    return closing_end + 1
        if text[cursor] == "<":
            nested_end = _mask_jsx_element(
                text, masked, cursor, expression_ranges
            )
            if nested_end is not None:
                cursor = nested_end
                continue
        elif text[cursor] == "{":
            try:
                expression_end = _skip_javascript_braced(text, cursor)
                expression_ranges.append((cursor + 1, expression_end - 1))
                cursor = expression_end
                continue
            except ScanFailure:
                break
        if text[cursor] not in "\r\n":
            changed.append((cursor, masked[cursor]))
            masked[cursor] = " "
        cursor += 1

    for index, original in changed:
        masked[index] = original
    return None


def _skip_jsx_element(text: str, start: int) -> int | None:
    return _mask_jsx_element(text, list(text), start, [])


def _mask_jsx_text(text: str) -> str:
    masked = list(text)
    ranges = [(0, len(text))]
    while ranges:
        index, limit = ranges.pop()
        while index < limit:
            if text.startswith("//", index):
                end = text.find("\n", index + 2)
                index = limit if end < 0 else min(end, limit)
            elif text.startswith("/*", index):
                end = text.find("*/", index + 2)
                if end < 0 or end + 2 > limit:
                    raise ScanFailure(index)
                index = end + 2
            elif text[index] in {'"', "'"}:
                index, _content = _scan_quoted(text, index, text[index])
                if index > limit:
                    raise ScanFailure(index)
            elif text[index] == "`":
                template_end = _skip_javascript_template(text, index)
                cursor = index + 1
                while cursor < template_end - 1:
                    if text[cursor] == "\\":
                        cursor += 2
                    elif text.startswith("${", cursor):
                        expression_end = _skip_javascript_braced(text, cursor + 1)
                        ranges.append((cursor + 2, expression_end - 1))
                        cursor = expression_end
                    else:
                        cursor += 1
                index = template_end
            elif text[index] == "<" and _looks_like_jsx_root(text, index):
                expressions: list[tuple[int, int]] = []
                end = _mask_jsx_element(text, masked, index, expressions)
                if end is None:
                    raise ScanFailure(index)
                ranges.extend(expressions)
                index = end
            else:
                index += 1
    return "".join(masked)


def _lex_javascript(
    text: str, positions: PositionIndex, *, jsx: bool = False
) -> tuple[list[Token], list[Token]]:
    if jsx:
        text = _mask_jsx_text(text)
    tokens: list[Token] = []
    comments: list[Token] = []

    def code(index: int, stop_at_template_end: bool = False) -> int:
        template_brace_depth = 0
        while index < len(text):
            char = text[index]
            if stop_at_template_end and char == "}" and template_brace_depth == 0:
                tokens.append(_token("punct", "}", index, positions))
                return index + 1
            if index == 0 and text.startswith("#!", index):
                end = text.find("\n", index + 2)
                end = len(text) if end < 0 else end
                comments.append(_token("comment", text[index:end], index, positions))
                index = end
            elif char.isspace():
                index += 1
            elif text.startswith("//", index):
                end = text.find("\n", index + 2)
                end = len(text) if end < 0 else end
                comments.append(_token("comment", text[index:end], index, positions))
                index = end
            elif text.startswith("/*", index):
                end = text.find("*/", index + 2)
                if end < 0:
                    raise ScanFailure(index)
                end += 2
                comments.append(_token("comment", text[index:end], index, positions))
                index = end
            elif (
                char == "'"
                and index > 0
                and index + 1 < len(text)
                and text[index - 1].isalnum()
                and text[index + 1].isalnum()
            ):
                tokens.append(_token("punct", char, index, positions))
                index += 1
            elif char in {'"', "'"}:
                end, content = _scan_quoted(text, index, char)
                tokens.append(_token("string", content, index, positions))
                index = end
            elif char == "`":
                template_start = index
                index += 1
                while index < len(text):
                    if text[index] == "\\":
                        index += 2
                    elif text[index] == "`":
                        tokens.append(_token("string", "", template_start, positions))
                        index += 1
                        break
                    elif text.startswith("${", index):
                        tokens.append(_token("punct", "{", index + 1, positions))
                        index = code(index + 2, stop_at_template_end=True)
                    else:
                        index += 1
                else:
                    raise ScanFailure(template_start)
            elif (
                char == "/"
                and not (index > 0 and text[index - 1] == "<")
                and _js_regex_can_start(tokens)
            ):
                index = _skip_js_regex(text, index)
            elif char.isalpha() or char in "_$":
                end = index + 1
                while end < len(text) and (text[end].isalnum() or text[end] in "_$"):
                    end += 1
                tokens.append(_token("identifier", text[index:end], index, positions))
                index = end
            elif char.isdigit():
                end = index + 1
                while end < len(text) and (text[end].isalnum() or text[end] in "._"):
                    end += 1
                tokens.append(_token("number", text[index:end], index, positions))
                index = end
            else:
                tokens.append(_token("punct", char, index, positions))
                if stop_at_template_end and char == "{":
                    template_brace_depth += 1
                elif stop_at_template_end and char == "}":
                    template_brace_depth -= 1
                index += 1
        if stop_at_template_end:
            raise ScanFailure(max(index - 1, 0))
        return index

    code(0)
    return tokens, comments


def _is_javascript_test(path: PurePosixPath) -> bool:
    lowered_parts = {part.lower() for part in path.parts[:-1]}
    name = path.name.lower()
    return (
        bool(lowered_parts & {"test", "tests", "__tests__"})
        or re.search(r"(?:^|[._-])(?:test|spec)\.", name) is not None
        or name.startswith(("test_", "spec_"))
    )


def _javascript_root_cursor(tokens: list[Token], index: int) -> int:
    opening = index - 1
    wrappers = 0
    while opening >= 0 and tokens[opening].value == "(":
        wrappers += 1
        opening -= 1
    if wrappers and opening >= 0:
        prefix = tokens[opening]
        grouping_keywords = {
            "await",
            "case",
            "if",
            "new",
            "return",
            "switch",
            "throw",
            "while",
            "with",
            "yield",
        }
        if (
            prefix.kind in {"number", "string"}
            or prefix.value in {")", "]", "}"}
            or (prefix.kind == "identifier" and prefix.value not in grouping_keywords)
        ):
            wrappers = 0

    cursor = index + 1
    while cursor < len(tokens):
        if tokens[cursor].value == "!" and (
            cursor + 1 >= len(tokens) or tokens[cursor + 1].value != "="
        ):
            cursor += 1
        elif wrappers and tokens[cursor].value == ")":
            wrappers -= 1
            cursor += 1
        else:
            break
    return cursor


def _javascript_handler_is_empty(tokens: list[Token]) -> bool:
    return all(
        token.value in {"(", ")", ",", ";", "false", "null", "true", "{", "}"}
        or token.kind in {"number", "string"}
        for token in tokens
    )


def _scan_javascript(path: PurePosixPath, text: str, positions: PositionIndex) -> list[Finding]:
    tokens, comments = _lex_javascript(
        text, positions, jsx=path.suffix.lower() in {".jsx", ".tsx"}
    )
    findings: list[Finding] = []
    for comment in comments:
        findings.extend(
            _scan_marker_text(
                path, positions, comment.value, comment.offset, COMMENT_MARKER_PATTERN
            )
        )

    for index, item in enumerate(tokens):
        if item.kind != "identifier" or item.value != "catch":
            continue
        if index == 0 or tokens[index - 1].value != "}":
            continue
        try_block_start = _opening_token(tokens, index - 1, "{", "}")
        if (
            try_block_start is None
            or try_block_start == 0
            or tokens[try_block_start - 1].value != "try"
        ):
            continue
        cursor = index + 1
        if cursor < len(tokens) and tokens[cursor].value == "(":
            parameter_end = _matching_token(tokens, cursor, "(", ")")
            if parameter_end is None:
                raise ScanFailure(item.offset)
            cursor = parameter_end + 1
        if cursor >= len(tokens) or tokens[cursor].value != "{":
            continue
        body_end = _matching_token(tokens, cursor, "{", "}")
        if body_end is None:
            raise ScanFailure(item.offset)
        if _javascript_handler_is_empty(tokens[cursor + 1 : body_end]):
            findings.append(_finding(path, item, "javascript-empty-handler"))

    if not _is_javascript_test(path):
        return findings
    test_roots = {"context", "describe", "it", "specify", "suite", "test"}
    aliases = {
        "fcontext",
        "fdescribe",
        "fit",
        "fspecify",
        "fsuite",
        "ftest",
        "xcontext",
        "xdescribe",
        "xit",
        "xspecify",
        "xsuite",
        "xtest",
    }
    modifiers = {"only", "skip", "skipIf", "todo"}
    for index, item in enumerate(tokens):
        if item.kind != "identifier":
            continue
        if index > 0 and tokens[index - 1].value == ".":
            continue
        cursor = _javascript_root_cursor(tokens, index)
        if item.value in aliases and cursor < len(tokens) and tokens[cursor].value == "(":
            findings.append(_finding(path, item, "javascript-disabled-test"))
            continue
        if item.value not in test_roots:
            continue
        while cursor < len(tokens):
            if (
                (
                    tokens[cursor].value == "."
                    and cursor + 1 < len(tokens)
                    and tokens[cursor + 1].kind == "identifier"
                )
                or (
                    tokens[cursor].value == "?"
                    and cursor + 2 < len(tokens)
                    and tokens[cursor + 1].value == "."
                    and tokens[cursor + 2].kind == "identifier"
                )
            ):
                property_token = tokens[
                    cursor + 1 if tokens[cursor].value == "." else cursor + 2
                ]
                if property_token.value in modifiers:
                    findings.append(
                        _finding(path, property_token, "javascript-disabled-test")
                    )
                    break
                cursor += 2 if tokens[cursor].value == "." else 3
            elif (
                (
                    tokens[cursor].value == "["
                    and cursor + 2 < len(tokens)
                    and tokens[cursor + 1].kind == "string"
                    and tokens[cursor + 2].value == "]"
                )
                or (
                    tokens[cursor].value == "?"
                    and cursor + 4 < len(tokens)
                    and tokens[cursor + 1].value == "."
                    and tokens[cursor + 2].value == "["
                    and tokens[cursor + 3].kind == "string"
                    and tokens[cursor + 4].value == "]"
                )
            ):
                optional = tokens[cursor].value == "?"
                property_token = tokens[cursor + 3 if optional else cursor + 1]
                if property_token.value in modifiers:
                    findings.append(
                        _finding(path, property_token, "javascript-disabled-test")
                    )
                    break
                cursor += 5 if optional else 3
            elif tokens[cursor].value == "(":
                call_end = _matching_token(tokens, cursor, "(", ")")
                if call_end is None:
                    raise ScanFailure(item.offset)
                cursor = call_end + 1
            elif tokens[cursor].value == "{":
                expression_end = _matching_token(tokens, cursor, "{", "}")
                if expression_end is None:
                    raise ScanFailure(item.offset)
                cursor = expression_end + 1
            elif tokens[cursor].kind == "string":
                cursor += 1
            else:
                break
    return findings


def scan_source(path: PurePosixPath, text: str) -> list[Finding]:
    positions = PositionIndex(text)
    findings = _scan_marker_text(path, positions, text, 0, RAW_MARKER_PATTERN)

    suffix = path.suffix.lower()
    if suffix == ".py":
        findings.extend(_scan_python(path, text, positions))
    elif suffix == ".rs":
        findings.extend(_scan_rust(path, text, positions))
    elif suffix in JAVASCRIPT_SUFFIXES:
        findings.extend(_scan_javascript(path, text, positions))
    elif suffix == ".go":
        for comment in _lex_go_comments(text, positions):
            findings.extend(
                _scan_marker_text(
                    path, positions, comment.value, comment.offset, COMMENT_MARKER_PATTERN
                )
            )
    elif suffix == ".sh":
        for comment in _lex_shell_comments(text, positions):
            findings.extend(
                _scan_marker_text(
                    path, positions, comment.value, comment.offset, COMMENT_MARKER_PATTERN
                )
            )
    elif suffix == ".css":
        for comment in _lex_css_comments(text, positions):
            findings.extend(
                _scan_marker_text(
                    path, positions, comment.value, comment.offset, COMMENT_MARKER_PATTERN
                )
            )
    elif suffix in {".htm", ".html"}:
        for comment in _lex_html_comments(text, positions):
            findings.extend(
                _scan_marker_text(
                    path, positions, comment.value, comment.offset, COMMENT_MARKER_PATTERN
                )
            )
    return sorted(set(findings))


def scan_repository(root: Path) -> list[Finding]:
    try:
        sources = discover_sources(root)
    except Exception:
        return [Finding("<repository>", 1, 1, "source-discovery-failure")]

    findings: list[Finding] = []
    for relative in sources:
        try:
            text = read_source(root, relative)
        except Exception:
            findings.append(Finding(relative.as_posix(), 1, 1, "source-read-failure"))
            continue
        try:
            findings.extend(scan_source(relative, text))
        except ScanFailure as exc:
            positions = PositionIndex(text)
            line, column = positions.position(min(max(exc.offset, 0), len(text)))
            findings.append(
                Finding(relative.as_posix(), line, column, "source-scan-failure")
            )
        except Exception:
            findings.append(Finding(relative.as_posix(), 1, 1, "source-scan-failure"))
    return sorted(set(findings))


def _display_path(path: str) -> str:
    return json.dumps(path, ensure_ascii=True)


def main(root: Path = ROOT) -> int:
    try:
        findings = scan_repository(root)
    except Exception:
        findings = [Finding("<repository>", 1, 1, "scanner-failure")]
    if findings:
        print("Forbidden repository shortcuts found:", file=sys.stderr)
        for item in findings:
            print(
                f"{_display_path(item.path)}:{item.line}:{item.column}: {item.rule}",
                file=sys.stderr,
            )
        return 1
    print("Quality gate passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
