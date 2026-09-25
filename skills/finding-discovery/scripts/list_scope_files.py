#!/usr/bin/env python3
"""List the in-scope files a finding-discovery run must review, and say what was left out and why.

Uses the same file set as target_identity.py (tracked files plus untracked files Git does not
ignore, or a folder walk outside Git, never .git or .defense-factory, never operating-system
metadata), then excludes, by recorded rule: symbolic links, binary files, vendored dependency
folders, minified or generated bundles, dependency lockfiles, and any --exclude pattern the user
gave. Coverage is measured against the remaining list.

Writes the list, one repository-relative path per line, to --out (normally
<stage folder>/scope-inventory.txt). Prints one JSON object: repository_root, scope,
inventory (the --out path), included (count), excluded (list of {rule, count, examples}).

Exit codes: 0 success; 2 bad arguments or unreadable root.
Standard library only; Python 3.9+. Reads the target; writes only --out.
"""

import argparse
import fnmatch
import json
import sys
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parent))
import target_identity  # noqa: E402  (shared helper in this skill's scripts folder)

VENDORED_DIRS = {"node_modules", "vendor", "third_party", "bower_components"}
GENERATED_SUFFIXES = (".min.js", ".min.css", ".map")
LOCKFILES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
             "Pipfile.lock", "Cargo.lock", "Gemfile.lock", "composer.lock", "go.sum", "packages.lock.json"}
SNIFF_BYTES = 8192


def exclusion_rule(root, relative, user_patterns):
    """The rule that excludes a file, or None when it stays in scope."""
    path = root / relative
    parts = PurePosixPath(relative).parts
    for pattern in user_patterns:
        if fnmatch.fnmatch(relative, pattern) or any(fnmatch.fnmatch(part, pattern) for part in parts):
            return f"user exclusion: {pattern}"
    if path.is_symlink():
        return "symbolic link"
    if not path.is_file():
        return "not a regular file"
    if any(part in VENDORED_DIRS for part in parts[:-1]):
        return "vendored dependency folder"
    if parts[-1] in LOCKFILES:
        return "dependency lockfile"
    if parts[-1].endswith(GENERATED_SUFFIXES):
        return "minified or generated bundle"
    with path.open("rb") as handle:
        if b"\0" in handle.read(SNIFF_BYTES):
            return "binary file"
    return None


def build(root, scope, in_git, user_patterns=()):
    """Return (included paths, {rule: excluded paths})."""
    included, excluded = [], {}
    for relative in target_identity.inventory(root, scope, in_git):
        rule = exclusion_rule(root, relative, user_patterns)
        if rule:
            excluded.setdefault(rule, []).append(relative)
        else:
            included.append(relative)
    return included, excluded


def write_inventory(out, included):
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(f"{relative}\n" for relative in included), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", default=".", help="target root (default: current directory)")
    parser.add_argument("--scope", action="append", default=[], help="in-scope path; repeatable")
    parser.add_argument("--exclude", action="append", default=[],
                        help="glob the user asked to exclude, matched against the path and each folder name; repeatable")
    parser.add_argument("--out", required=True, help="file to write the inventory to")
    args = parser.parse_args()

    try:
        root, in_git, scope = target_identity.resolve(args.root, args.scope)
    except ValueError as exc:
        parser.exit(2, f"error: {exc}\n")

    included, excluded = build(root, scope, in_git, args.exclude)
    out = Path(args.out).expanduser().resolve()
    write_inventory(out, included)
    print(json.dumps({
        "repository_root": str(root),
        "scope": scope,
        "inventory": str(out),
        "included": len(included),
        "excluded": [{"rule": rule, "count": len(paths), "examples": paths[:5]}
                     for rule, paths in sorted(excluded.items())],
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
