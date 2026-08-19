#!/usr/bin/env python3
"""Cheap repository-wide anti-shortcut checks. Deep quality remains the job of tests/review."""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCAN_ROOTS = [ROOT / "apps", ROOT / "crates", ROOT / "runtime", ROOT / "plugins"]
EXTS = {".rs", ".ts", ".tsx", ".js", ".jsx", ".py", ".go"}
PATTERNS = [
    re.compile(r"\bTODO\b"),
    re.compile(r"\bFIXME\b"),
    re.compile(r"unimplemented!\s*\("),
    re.compile(r"panic!\s*\(\s*[\"']not implemented", re.I),
]


def main() -> int:
    failures: list[str] = []
    for base in SCAN_ROOTS:
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if not path.is_file() or path.suffix not in EXTS:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            for number, line in enumerate(text.splitlines(), 1):
                if any(pattern.search(line) for pattern in PATTERNS):
                    failures.append(f"{path.relative_to(ROOT)}:{number}: {line.strip()}")
    if failures:
        print("Forbidden shortcut markers found:", file=sys.stderr)
        print("\n".join(failures), file=sys.stderr)
        return 1
    print("Quality gate passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
