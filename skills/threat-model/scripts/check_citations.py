#!/usr/bin/env python3
"""Check every `path:line` and `path:start-end` citation in a Markdown file against the repository.

A citation is a backtick span containing a repository-relative path, a colon, and a line number
or range. Network addresses such as `127.0.0.1:8080`, `0.0.0.0:80`, `[::1]:443`, and `localhost:3000`
are not citations and are skipped. Each is checked to be relative, inside the repository, an existing regular file, and
within the file's line count. Only existence is checked; whether the lines support the claim
still needs a human or agent reading.

Prints one JSON object: checked, valid, invalid (list of {citation, problem}).
Exit codes: 0 all citations valid; 1 at least one invalid; 2 bad arguments.
Standard library only; Python 3.9+. Read-only.
"""

import argparse
import json
import re
import sys
from pathlib import Path

CITATION = re.compile(r"`([^`\s:]+(?:/[^`\s:]+)*):(\d+)(?:-(\d+))?`")
NETWORK_HOST = re.compile(r"(?:\d{1,3}(?:\.\d{1,3}){3}|localhost|\[[0-9A-Fa-f:.]*\])", re.IGNORECASE)


def line_count(path):
    with path.open("rb") as handle:
        data = handle.read()
    return data.count(b"\n") + (0 if data.endswith(b"\n") or not data else 1)


def problem_with(repo, raw_path, start, end):
    if raw_path.startswith(("/", "~")) or re.match(r"^[A-Za-z]:", raw_path):
        return "path must be relative to the repository root"
    if ".." in Path(raw_path).parts:
        return "path must not contain '..'"
    target = (repo / raw_path).resolve()
    if target != repo and repo not in target.parents:
        return "path resolves outside the repository"
    if target.parts[len(repo.parts):][:1] == (".defense-factory",):
        return "citation points at Defense Factory output, not source"
    if not target.is_file():
        return "file does not exist"
    if start < 1 or end < start:
        return "invalid line range"
    total = line_count(target)
    if end > total:
        return f"line {end} is beyond the end of the file ({total} lines)"
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", required=True, help="repository root")
    parser.add_argument("document", help="Markdown file to check")
    args = parser.parse_args()

    repo = Path(args.repo).expanduser().resolve()
    document = Path(args.document).expanduser()
    if not repo.is_dir() or not document.is_file():
        parser.exit(2, "error: --repo must be a directory and document must be a file\n")

    seen, invalid = set(), []
    for match in CITATION.finditer(document.read_text(encoding="utf-8", errors="replace")):
        raw_path, start = match.group(1), int(match.group(2))
        if NETWORK_HOST.fullmatch(raw_path):
            continue
        end = int(match.group(3) or start)
        citation = match.group(0).strip("`")
        if citation in seen:
            continue
        seen.add(citation)
        problem = problem_with(repo, raw_path, start, end)
        if problem:
            invalid.append({"citation": citation, "problem": problem})

    print(json.dumps({"checked": len(seen), "valid": len(seen) - len(invalid), "invalid": invalid}, indent=2))
    return 1 if invalid else 0


if __name__ == "__main__":
    sys.exit(main())
