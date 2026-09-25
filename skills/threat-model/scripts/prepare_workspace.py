#!/usr/bin/env python3
"""Create the output folders for a Defense Factory run, protected from accidental commits.

Default: <git top level>/.defense-factory/, containing a .gitignore with "*" so Git ignores
the folder and everything in it, then runs/<run-id>/<stage>/ inside it.
With --out-dir: use that folder instead (the user's chosen location).

Prints one JSON object: base_dir, run_dir, stage_dir, reusable_model, run_id, timestamp (current
UTC time for the record header), skill_version (fingerprint of this skill's instructions, template,
and scripts; a stored model may be reused only when its skill_version matches), git_ignored.

Exit codes:
  0  ready to write
  2  needs a decision from the user (not a Git repository and no --out-dir given)
  3  unsafe to write (location not ignored by Git, files inside already tracked, or an
     existing .gitignore in .defense-factory that does not ignore everything)
Standard library only; Python 3.9+. Writes only inside the output folder.
"""

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

IGNORE_ALL = "# Created by the Defense Factory plugin. Ignore this folder entirely.\n*\n"
SKILL_DIR = Path(__file__).resolve().parents[1]
UNVERSIONED = {"evals", "__pycache__"}  # test cases and caches do not change the skill's behaviour


def skill_version():
    """Content fingerprint of the skill: changes whenever its instructions, template, or scripts change."""
    digest = hashlib.sha256()
    for path in sorted(SKILL_DIR.rglob("*")):
        relative = path.relative_to(SKILL_DIR)
        if (not path.is_file() or relative.parts[0] in UNVERSIONED or path.suffix == ".pyc"
                or path.name.startswith(".")):
            continue
        digest.update(f"{relative.as_posix()}\0".encode() + path.read_bytes() + b"\0")
    return f"{SKILL_DIR.name}/sha256:{digest.hexdigest()[:16]}"


def git(root, *args):
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True)
    return result


def is_ignored(root, path):
    probe = path / "probe.md"
    return git(root, "check-ignore", "-q", "--no-index", str(probe)).returncode == 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", default=".", help="target root (default: current directory)")
    parser.add_argument("--out-dir", help="user-chosen output folder instead of .defense-factory/")
    parser.add_argument("--run-id", help="run identifier (default: UTC timestamp)")
    parser.add_argument("--stage", default="1-threat-model", help="stage folder name; matches the record's stage field")
    parser.add_argument("--allow-unignored", action="store_true",
                        help="write to --out-dir even if Git would not ignore it (user accepted the risk)")
    args = parser.parse_args()

    now = datetime.now(timezone.utc)
    run_id = args.run_id or now.strftime("%Y%m%dT%H%M%SZ")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", run_id) or not re.fullmatch(r"[A-Za-z0-9._-]+", args.stage):
        parser.exit(2, "error: --run-id and --stage may contain only letters, digits, '.', '_' and '-'\n")

    root = Path(args.root).expanduser().resolve()
    top = git(root, "rev-parse", "--show-toplevel")
    git_root = Path(top.stdout.strip()).resolve() if top.returncode == 0 else None

    if args.out_dir:
        base = Path(args.out_dir).expanduser().resolve()
    elif git_root:
        base = git_root / ".defense-factory"
    else:
        parser.exit(2, "needs-location: target is not a Git repository; ask the user where to save output\n")

    inside_repo = git_root is not None and (base == git_root or git_root in base.parents)
    if inside_repo:
        if base == git_root:
            parser.exit(3, "unsafe: output folder cannot be the repository root\n")
        tracked = git(git_root, "ls-files", "--", str(base)).stdout.strip()
        if tracked:
            parser.exit(3, f"unsafe: files under {base} are already tracked by Git; ask the user how to proceed\n")

    base.mkdir(parents=True, exist_ok=True)
    if base.name == ".defense-factory" and inside_repo:
        marker = base / ".gitignore"
        if not marker.exists():
            marker.write_text(IGNORE_ALL)
        elif "*" not in [line.strip() for line in marker.read_text().splitlines()]:
            parser.exit(3, f"unsafe: {marker} exists but does not ignore everything; ask the user\n")

    ignored = is_ignored(git_root, base) if inside_repo else None
    if inside_repo and not ignored and not args.allow_unignored:
        parser.exit(3, f"unsafe: Git would not ignore {base}; ask the user for another location\n")

    stage_dir = base / "runs" / run_id / args.stage
    stage_dir.mkdir(parents=True, exist_ok=True)
    print(json.dumps({
        "base_dir": str(base),
        "run_dir": str(stage_dir.parent),
        "stage_dir": str(stage_dir),
        "reusable_model": str(base / "threat-model.md"),
        "run_id": run_id,
        "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "skill_version": skill_version(),
        "git_ignored": ignored,
    }, indent=2))


if __name__ == "__main__":
    sys.exit(main())
