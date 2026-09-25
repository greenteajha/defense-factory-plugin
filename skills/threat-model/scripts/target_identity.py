#!/usr/bin/env python3
"""Report the stable identity and version of a threat-model target.

Prints one JSON object:
  target_id        sha256 of the sanitized remote URL, or of the absolute root path
  identity_source  "remote" or "local-path"
  target_kind      git_revision (clean checkout), git_worktree (uncommitted changes),
                   or directory_snapshot (not a Git repository)
  repository_root  absolute path of the Git top level, or of --root
  revision         HEAD commit, or null
  dirty            whether in-scope files differ from HEAD
                   (operating-system metadata such as .DS_Store is ignored everywhere)
  snapshot_digest  digest of in-scope file contents when not a clean checkout, else null
  version          revision for git_revision, otherwise snapshot_digest
  scope            in-scope paths relative to repository_root, or ["."]

Exit codes: 0 success; 2 bad arguments or unreadable root.
Standard library only; Python 3.9+. Read-only: never modifies the target.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

SNAPSHOT_PREFIX = "defense-factory-snapshot/v1:sha256:"
SKIP_DIRS = {".git", ".defense-factory"}
# Files the operating system creates when a folder is browsed; they are never part of the target.
OS_METADATA_FILES = {".DS_Store", "Thumbs.db", "desktop.ini", "Icon\r"}
OS_METADATA_DIRS = {".Spotlight-V100", ".Trashes", ".fseventsd", ".TemporaryItems"}


def is_os_metadata(relative):
    parts = relative.split("/")
    name = parts[-1]
    return (name in OS_METADATA_FILES or name.startswith("._")
            or any(part in OS_METADATA_DIRS for part in parts))


def git(root, *args):
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else None


def sanitize_remote(url):
    """Canonical host/path form of a remote URL, without credentials, query, or fragment."""
    url = url.strip()
    scp = re.fullmatch(r"(?:[^@/]+@)?([^:/]+):(?!//)(.+)", url)
    if scp and "://" not in url:
        host, path = scp.group(1), scp.group(2)
    else:
        parts = urlsplit(url)
        if not parts.hostname:
            return None
        host = parts.hostname + (f":{parts.port}" if parts.port else "")
        path = parts.path
    path = re.sub(r"\.git/?$", "", path.strip("/"))
    return f"{host.lower()}/{path}" if path else None


def file_digest(path):
    if path.is_symlink():
        return "symlink:" + hashlib.sha256(os.readlink(path).encode()).hexdigest()
    if not path.exists():
        return "deleted"
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inventory(root, scope, in_git):
    """Sorted repository-relative paths of the reviewed content."""
    if in_git:
        listed = git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", *scope)
        paths = {p for p in (listed or "").split("\0") if p}
        return sorted(p for p in paths if p.split("/", 1)[0] not in SKIP_DIRS and not is_os_metadata(p))
    found = []
    for item in scope:
        base = root / item
        if base.is_file() or base.is_symlink():
            found.append(Path(item).as_posix())
            continue
        for current, dirs, files in os.walk(base):
            dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
            for name in files:
                found.append((Path(current) / name).relative_to(root).as_posix())
    return sorted(p for p in set(found) if not is_os_metadata(p))


def changed_paths(root, scope):
    """Paths Git reports as changed or untracked in scope, ignoring operating-system metadata."""
    result = subprocess.run(["git", "-C", str(root), "status", "--porcelain", "-z", "--untracked-files=all",
                             "--", *scope], capture_output=True, text=True)
    entries, changed = result.stdout.split("\0"), []
    index = 0
    while index < len(entries):
        entry = entries[index]
        index += 1
        if len(entry) < 4:
            continue
        if entry[0] in "RC":  # renames and copies are followed by their original path
            index += 1
        if not is_os_metadata(entry[3:]):
            changed.append(entry[3:])
    return changed


def snapshot_digest(root, paths):
    digest = hashlib.sha256()
    for relative in paths:
        digest.update(f"{relative}\0{file_digest(root / relative)}\n".encode())
    return SNAPSHOT_PREFIX + digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", default=".", help="target root (default: current directory)")
    parser.add_argument("--scope", action="append", default=[], help="in-scope path; repeatable")
    args = parser.parse_args()

    start = Path(args.root).expanduser().resolve()
    if not start.is_dir():
        parser.exit(2, f"error: {start} is not a readable directory\n")

    top = git(start, "rev-parse", "--show-toplevel")
    in_git = top is not None
    root = Path(top).resolve() if in_git else start

    scope = []
    for item in args.scope or [str(start)]:
        candidate = (start / item).resolve() if not Path(item).is_absolute() else Path(item).resolve()
        if candidate != root and root not in candidate.parents:
            parser.exit(2, f"error: scope {item} is outside {root}\n")
        if not candidate.exists():
            parser.exit(2, f"error: scope {item} does not exist\n")
        scope.append(candidate.relative_to(root).as_posix() or ".")

    remote = None
    if in_git:
        remotes = (git(root, "remote") or "").split()
        name = "origin" if "origin" in remotes else (remotes[0] if remotes else None)
        if name:
            remote = sanitize_remote(git(root, "remote", "get-url", name) or "")
    identity = remote or str(root)
    target_id = "sha256:" + hashlib.sha256(identity.encode()).hexdigest()

    revision = git(root, "rev-parse", "--verify", "-q", "HEAD") if in_git else None
    dirty = bool(changed_paths(root, scope)) if in_git else None
    clean_revision = in_git and revision and not dirty
    digest = None if clean_revision else snapshot_digest(root, inventory(root, scope, in_git))

    print(json.dumps({
        "target_id": target_id,
        "identity_source": "remote" if remote else "local-path",
        "target_kind": "git_revision" if clean_revision else ("git_worktree" if in_git else "directory_snapshot"),
        "repository_root": str(root),
        "revision": revision,
        "dirty": dirty,
        "snapshot_digest": digest,
        "version": revision if clean_revision else digest,
        "scope": scope,
    }, indent=2))


if __name__ == "__main__":
    sys.exit(main())
