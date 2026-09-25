#!/usr/bin/env python3
"""Copy shared master files into every skill that uses them, or check that the copies match.

Masters live in shared/<folder>/<file> and are copied to skills/<skill>/<folder>/<file>, where
<folder> is references, assets, or scripts. shared/manifest.json maps each master to the skills
that receive it:

  {"files": {"references/record-and-status.md": ["threat-model", "finding-discovery"]}}

Default: report manifest problems, or else write every missing or differing copy.
--check: write nothing; report manifest problems and every missing or differing copy.

Exit codes: 0 in sync (or synced); 1 problems found; 2 bad arguments.
Standard library only; Python 3.9+. Maintainer tooling: the agent never runs this.
"""

import argparse
import json
import sys
from pathlib import Path, PurePosixPath

FOLDERS = ("references", "assets", "scripts")
UNMANAGED = {"manifest.json", "README.md"}  # describe the shared folder itself; never copied
IGNORED_NAMES = {".DS_Store", "Thumbs.db"}


def load_manifest(root):
    """Return ({master path: [skill names]}, problems)."""
    path = root / "shared" / "manifest.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}, ["shared/manifest.json is missing"]
    except (ValueError, UnicodeDecodeError) as exc:
        return {}, [f"shared/manifest.json is not valid JSON: {exc}"]
    files = data.get("files") if isinstance(data, dict) else None
    if not isinstance(files, dict) or set(data) != {"files"}:
        return {}, ['shared/manifest.json must be {"files": {"<folder>/<file>": ["<skill>", ...]}}']

    mapping, problems = {}, []
    for relative, skills in sorted(files.items()):
        parts = PurePosixPath(relative).parts
        if (len(parts) < 2 or parts[0] not in FOLDERS or ".." in parts or relative.startswith("/")
                or "\\" in relative):
            problems.append(f"shared/manifest.json: {relative!r} must be <folder>/<file> with folder "
                            f"one of {', '.join(FOLDERS)}")
            continue
        if (not isinstance(skills, list) or not skills or len(set(skills)) != len(skills)
                or not all(isinstance(name, str) and name for name in skills)):
            problems.append(f"shared/manifest.json: {relative!r} needs a non-empty list of distinct skill names")
            continue
        master = root / "shared" / relative
        if master.is_symlink() or not master.is_file():
            problems.append(f"shared/{relative}: listed in the manifest but missing (or not a regular file)")
        for name in skills:
            if not (root / "skills" / name / "SKILL.md").is_file():
                problems.append(f"shared/manifest.json: {relative!r} names skill {name!r}, which does not exist")
        mapping[relative] = skills
    return mapping, problems


def unmapped_masters(root, mapping):
    shared = root / "shared"
    problems = []
    for path in sorted(shared.rglob("*")):
        relative = path.relative_to(shared).as_posix()
        if path.is_dir() or path.name in IGNORED_NAMES or relative in UNMANAGED:
            continue
        if relative not in mapping:
            problems.append(f"shared/{relative}: not listed in shared/manifest.json")
    return problems


def unmapped_copies(root, mapping):
    """A skill holding a file at a shared path without being listed for it would drift unchecked."""
    problems = []
    if not (root / "skills").is_dir():
        return problems
    for relative, skills in sorted(mapping.items()):
        for skill_dir in sorted((root / "skills").iterdir()):
            if skill_dir.is_dir() and skill_dir.name not in skills and (skill_dir / relative).exists():
                problems.append(f"skills/{skill_dir.name}/{relative}: copy of a shared file, but "
                                f"{skill_dir.name!r} is not listed for it in shared/manifest.json")
    return problems


def copy_problems(root, mapping):
    """Return [(master, copy, problem)] for every mapped copy that is missing or differs."""
    found = []
    for relative, skills in sorted(mapping.items()):
        master = root / "shared" / relative
        if not master.is_file():
            continue
        for name in skills:
            copy = root / "skills" / name / relative
            if copy.is_symlink() or not copy.is_file():
                found.append((master, copy, "missing (or not a regular file)"))
            elif copy.read_bytes() != master.read_bytes():
                found.append((master, copy, f"differs from shared/{relative}"))
    return found


def problems(root):
    """Every problem, as messages. Used by check-package.py; writes nothing."""
    root = Path(root)
    if not (root / "shared").is_dir():
        return []
    mapping, found = load_manifest(root)
    found += unmapped_masters(root, mapping) + unmapped_copies(root, mapping)
    found += [f"{copy.relative_to(root)}: {problem}; edit the master and run scripts/sync-shared.py"
              for _, copy, problem in copy_problems(root, mapping)]
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]),
                        help="plugin repository root (default: this repository)")
    parser.add_argument("--check", action="store_true", help="report drift without writing")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    if not (root / "shared").is_dir() or not (root / "skills").is_dir():
        parser.exit(2, f"error: {root} has no shared/ or skills/ folder\n")

    if args.check:
        found = problems(root)
    else:
        mapping, found = load_manifest(root)
        found += unmapped_masters(root, mapping) + unmapped_copies(root, mapping)
        if not found:
            for master, copy, _ in copy_problems(root, mapping):
                if copy.is_symlink():
                    copy.unlink()
                copy.parent.mkdir(parents=True, exist_ok=True)
                copy.write_bytes(master.read_bytes())
                print(f"updated {copy.relative_to(root)}")
    for message in found:
        print(f"  - {message}", file=sys.stderr)
    if found:
        print("Shared resources are out of sync.", file=sys.stderr)
        return 1
    print("Shared resources in sync.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
