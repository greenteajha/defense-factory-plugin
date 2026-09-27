#!/usr/bin/env python3
"""Write a build context holding the exact revision stages 1 and 2 reviewed, into the run folder.

The target's code is copied **into** the context, never mounted from the user's tree, so the
container cannot write back to the host. For a clean Git checkout the committed bytes are taken
from Git (git archive), which also avoids Windows line-ending drift. For a dirty worktree or a
non-Git target the reviewed files are copied as they were reviewed (the same in-scope file set
target_identity.py digests), and code_source records which was used.

No credentials, sockets, or host environment enter the context: only the in-scope files. Symlinks
that stay inside the target are recreated; a symlink pointing outside it is skipped and recorded.

Prints one JSON object: out_dir, code_source, revision, target_kind, files, symlinks_skipped,
run_label, build_label_args (pass these to build and run so clean-up can find the resources),
problems. Exit codes: 0 written; 1 could not export; 2 bad arguments.
Standard library only; Python 3.9+. Writes only inside --out.
"""

import argparse
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import engine as engine_mod  # noqa: E402  (this skill's scripts folder)
import target_identity  # noqa: E402  (shared helper)

RUN_ID = re.compile(r"^[A-Za-z0-9._-]+$")


def within(base, path):
    base, path = base.resolve(), path.resolve()
    return path == base or base in path.parents


def git_archive(root, revision, scope, out, problems):
    """Extract `git archive <revision>` of the scope into out. Returns files written, or None."""
    paths = [] if scope == ["."] else scope
    result = subprocess.run(["git", "-C", str(root), "archive", "--format=tar", revision, "--", *paths],
                            capture_output=True)
    if result.returncode != 0:
        problems.append(f"git archive failed: {result.stderr.decode('utf-8', 'replace').strip()}")
        return None
    count = 0
    with tarfile.open(fileobj=io.BytesIO(result.stdout)) as tar:
        for member in tar.getmembers():
            destination = (out / member.name)
            if not within(out, destination):
                problems.append(f"git archive member {member.name!r} escapes the context; skipped")
                continue
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
            elif member.issym() or member.islnk():
                link_target = out / member.name
                link_target.parent.mkdir(parents=True, exist_ok=True)
                if member.issym() and not within(out, (link_target.parent / member.linkname)):
                    problems.append(f"symlink {member.name!r} points outside the context; skipped")
                    continue
                if link_target.exists() or link_target.is_symlink():
                    link_target.unlink()
                os.symlink(member.linkname, link_target)
                count += 1
            elif member.isfile():
                destination.parent.mkdir(parents=True, exist_ok=True)
                with tar.extractfile(member) as source, destination.open("wb") as handle:
                    shutil.copyfileobj(source, handle)
                count += 1
    return count


def copy_files(root, scope, in_git, out, problems):
    """Copy the reviewed in-scope files into out. Returns (files, symlinks_skipped)."""
    files, skipped = 0, 0
    for relative in target_identity.inventory(root, scope, in_git):
        source = root / relative
        destination = out / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if source.is_symlink():
            if within(out, (destination.parent / os.readlink(source))):
                if destination.exists() or destination.is_symlink():
                    destination.unlink()
                os.symlink(os.readlink(source), destination)
                files += 1
            else:
                problems.append(f"symlink {relative!r} points outside the target; skipped")
                skipped += 1
            continue
        try:
            shutil.copyfile(source, destination)
            files += 1
        except OSError as exc:
            problems.append(f"could not copy {relative!r}: {exc}")
    return files, skipped


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", default=".", help="target root (default: current directory)")
    parser.add_argument("--scope", action="append", default=[], help="in-scope path; repeatable")
    parser.add_argument("--out", required=True, help="build-context folder to write (created if absent)")
    parser.add_argument("--run-id", required=True, help="run id; the label put on resources built from this context")
    args = parser.parse_args()
    if not RUN_ID.fullmatch(args.run_id):
        parser.exit(2, "error: --run-id may contain only letters, digits, '.', '_' and '-'\n")
    try:
        identity = target_identity.identify(args.root, args.scope)
        root, in_git, scope = target_identity.resolve(args.root, args.scope)
    except ValueError as exc:
        parser.exit(2, f"error: {exc}\n")

    out = Path(args.out).expanduser().resolve()
    if out.exists() and any(out.iterdir()):
        parser.exit(2, f"error: {out} already exists and is not empty; choose a fresh build-context folder\n")
    out.mkdir(parents=True, exist_ok=True)

    problems, symlinks_skipped = [], 0
    if identity["target_kind"] == "git_revision" and identity["revision"]:
        code_source = f"git-archive:{identity['revision']}"
        files = git_archive(root, identity["revision"], scope, out, problems)
        if files is None:
            print(json.dumps({"out_dir": str(out), "code_source": code_source, "problems": problems}, indent=2))
            return 1
    else:
        code_source = "copied-files"
        files, symlinks_skipped = copy_files(root, scope, in_git, out, problems)

    print(json.dumps({
        "out_dir": str(out),
        "code_source": code_source,
        "revision": identity["revision"],
        "target_kind": identity["target_kind"],
        "files": files,
        "symlinks_skipped": symlinks_skipped,
        "run_label": engine_mod.run_label(args.run_id),
        "build_label_args": engine_mod.label_args(args.run_id),
        "problems": problems,
    }, indent=2))
    return 1 if (files == 0 or problems and files is None) else 0


if __name__ == "__main__":
    sys.exit(main())
