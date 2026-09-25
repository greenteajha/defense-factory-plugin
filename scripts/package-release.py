#!/usr/bin/env python3
"""Build the release packages for every install route from one commit of this repository.

The repository is the single source. Git-based routes (Claude Code and Codex marketplaces,
ChatGPT "Add a marketplace") read it directly and need nothing from this script. Routes that
take a file get a package built here:

  <plugin>-chatgpt-v<version>.zip  ChatGPT desktop / Codex "Upload plugin archive": plugin files
                                   only. Never contains .agents/: the uploader rejects an archive
                                   that includes .agents/plugins/marketplace.json.
  <plugin>-claude-v<version>.zip   Claude Code offline install: plugin files plus .claude-plugin/.
  <plugin>-cursor-v<version>.zip   Cursor local install (~/.cursor/plugins/local/): plugin files,
                                   plus .cursor-plugin/ if it exists.
  <skill>-v<version>.zip           One per skill, for single-skill uploads; the zip contains the
                                   skill folder itself (<skill>/SKILL.md).
  SHA256SUMS                       Checksums of the files above.

Packages come from the committed tree at --ref (default HEAD), never from uncommitted files. The
tree must pass scripts/check-package.py first. Every top-level entry must be a known plugin,
adapter, or repository path, so a new plugin folder cannot be left out silently. Each package is
reopened and compared byte for byte with the tree before the build counts as successful. Zips are
reproducible: fixed timestamps and sorted entries give identical bytes for identical input.

Prints one JSON summary. Exit codes: 0 success; 1 a check or verification failed; 2 bad arguments.
Standard library only; Python 3.9+.
"""

import argparse
import hashlib
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

# Top-level layout, following the plugin guideline's "plugin folders versus repository folders".
PLUGIN_PATHS = ("plugin.json", "skills", "assets", "mcp.json", "hooks", "README.md", "LICENSE")
ADAPTER_PATHS = (".claude-plugin", ".agents", ".cursor-plugin")
REPOSITORY_PATHS = (".github", "scripts", "tests", "docs", "examples", "CHANGELOG.md", "RELEASING.md",
                    "SECURITY.md", ".gitignore", ".gitattributes")
TARGETS = {
    "chatgpt": PLUGIN_PATHS,
    "claude": PLUGIN_PATHS + (".claude-plugin",),
    "cursor": PLUGIN_PATHS + (".cursor-plugin",),
}
FORBIDDEN = {"chatgpt": (".agents/",)}
JUNK_NAMES = {".DS_Store", "Thumbs.db", ".gitkeep"}
MAX_ARCHIVE_BYTES = 50 * 1024 * 1024  # Codex's upload limit; the ChatGPT dialog allows 100 MB
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


class BuildError(Exception):
    pass


def git(repo, *args, binary=False):
    result = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=not binary)
    if result.returncode != 0:
        detail = result.stderr if not binary else result.stderr.decode(errors="replace")
        raise BuildError(f"git {' '.join(args)} failed: {detail.strip()}")
    return result.stdout


def extract_tree(repo, commit, destination):
    """Unpack the committed tree; refuse links, which no install route accepts."""
    data = git(repo, "archive", "--format=tar", commit, binary=True)
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        for member in archive.getmembers():
            if member.issym() or member.islnk():
                raise BuildError(f"{member.name}: links are not allowed in the plugin")
        if hasattr(tarfile, "data_filter"):  # safe extraction where Python supports it
            archive.extractall(destination, filter="data")
        else:
            archive.extractall(destination)


def classify(tree):
    known = set(PLUGIN_PATHS + ADAPTER_PATHS + REPOSITORY_PATHS)
    unknown = sorted(entry.name for entry in tree.iterdir() if entry.name not in known)
    if unknown:
        raise BuildError(f"unclassified top-level entries {unknown}: add each to PLUGIN_PATHS, "
                         "ADAPTER_PATHS, or REPOSITORY_PATHS in scripts/package-release.py")


def is_junk(relative):
    parts = relative.split("/")
    return parts[-1] in JUNK_NAMES or "__pycache__" in parts or relative.endswith(".pyc")


def files_under(tree, top_level):
    """Repository-relative POSIX paths of the files under the given top-level entries."""
    found = []
    for name in top_level:
        base = tree / name
        if base.is_file():
            found.append(name)
        elif base.is_dir():
            found.extend(path.relative_to(tree).as_posix() for path in base.rglob("*") if path.is_file())
    return sorted(path for path in found if not is_junk(path))


def write_zip(destination, tree, paths, strip=""):
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        for relative in paths:
            source = tree / relative
            info = zipfile.ZipInfo(relative[len(strip):], date_time=ZIP_TIMESTAMP)
            mode = 0o755 if source.stat().st_mode & 0o111 else 0o644
            info.external_attr = (0o100000 | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, source.read_bytes())


def verify_zip(archive_path, tree, expected, strip="", forbidden=(), need=()):
    """Reopen the package and prove it holds exactly the expected, unmodified files."""
    with zipfile.ZipFile(archive_path) as archive:
        names = sorted(archive.namelist())
        wanted = sorted(path[len(strip):] for path in expected)
        if names != wanted:
            missing, extra = sorted(set(wanted) - set(names)), sorted(set(names) - set(wanted))
            raise BuildError(f"{archive_path.name}: contents differ (missing {missing}, extra {extra})")
        for name in names:
            if archive.read(name) != (tree / (strip + name)).read_bytes():
                raise BuildError(f"{archive_path.name}: {name} differs from the source tree")
        for prefix in forbidden:
            if any(name.startswith(prefix) for name in names):
                raise BuildError(f"{archive_path.name}: must not contain {prefix}")
        for name in need:
            if name not in names:
                raise BuildError(f"{archive_path.name}: missing required {name}")
    if archive_path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise BuildError(f"{archive_path.name}: exceeds {MAX_ARCHIVE_BYTES} bytes")


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(repo, ref, out_dir, expect_version):
    commit = git(repo, "rev-parse", "--verify", f"{ref}^{{commit}}").strip()
    if git(repo, "status", "--porcelain", "--untracked-files=no").strip():
        print(f"warning: uncommitted changes are not packaged; building {commit[:12]}", file=sys.stderr)

    with tempfile.TemporaryDirectory() as temporary:
        tree = Path(temporary) / "tree"
        tree.mkdir()
        extract_tree(repo, commit, tree)
        classify(tree)
        check = subprocess.run([sys.executable, str(tree / "scripts" / "check-package.py"), str(tree)],
                               capture_output=True, text=True)
        if check.returncode != 0:
            raise BuildError("package check failed on the committed tree:\n" + check.stderr.strip())

        manifest = json.loads((tree / "plugin.json").read_text(encoding="utf-8"))
        name, version = manifest["name"], manifest["version"]
        if expect_version and expect_version != version:
            raise BuildError(f"plugin.json version {version} does not match expected {expect_version}")

        out_dir.mkdir(parents=True, exist_ok=True)
        packages = []
        for target, top_level in TARGETS.items():
            paths = files_under(tree, top_level)
            archive_path = out_dir / f"{name}-{target}-v{version}.zip"
            write_zip(archive_path, tree, paths)
            verify_zip(archive_path, tree, paths, forbidden=FORBIDDEN.get(target, ()),
                       need=("plugin.json",))
            packages.append((target, archive_path, len(paths)))

        for skill in sorted(path.parent.name for path in (tree / "skills").glob("*/SKILL.md")):
            paths = files_under(tree, (f"skills/{skill}",))
            archive_path = out_dir / f"{skill}-v{version}.zip"
            write_zip(archive_path, tree, paths, strip="skills/")
            verify_zip(archive_path, tree, paths, strip="skills/", need=(f"{skill}/SKILL.md",))
            packages.append((f"skill:{skill}", archive_path, len(paths)))

    sums = "".join(f"{sha256(path)}  {path.name}\n" for _, path, _ in packages)
    (out_dir / "SHA256SUMS").write_text(sums, encoding="utf-8")
    return {
        "plugin": name,
        "version": version,
        "commit": commit,
        "out_dir": str(out_dir),
        "packages": [{"target": target, "file": path.name, "entries": entries,
                      "bytes": path.stat().st_size, "sha256": sha256(path)}
                     for target, path, entries in packages],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    default_repo = Path(__file__).resolve().parents[1]
    parser.add_argument("--repo", default=str(default_repo), help="repository to package (default: this one)")
    parser.add_argument("--ref", default="HEAD", help="commit, branch, or tag to package (default: HEAD)")
    parser.add_argument("--out-dir", help="output folder (default: <repo>/build/packages, ignored by Git)")
    parser.add_argument("--expect-version", help="fail unless plugin.json has this version (e.g. from a tag)")
    args = parser.parse_args()

    repo = Path(args.repo).expanduser().resolve()
    out_dir = Path(args.out_dir).expanduser().resolve() if args.out_dir else repo / "build" / "packages"
    try:
        summary = build(repo, args.ref, out_dir, args.expect_version)
    except BuildError as error:
        print(f"Packaging failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
