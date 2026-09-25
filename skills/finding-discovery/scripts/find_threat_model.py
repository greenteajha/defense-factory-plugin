#!/usr/bin/env python3
"""Find the stage 1 threat model that stage 2 should start from, without asking the user.

Looks at every run copy <base>/runs/<run_id>/1-threat-model/threat-model.md, where <base> is the
default .defense-factory folder (at the Git top level, or at --root for a target that is not a
Git repository) or --out-dir when the user chose another location for stage 1. A model is usable
when it passes check_model.py, its status is complete or inconclusive, and its version still
matches the code exactly (recomputed for the model's own scope). A model made at another path (a
moved or copied folder with no Git remote) is usable when its version matches; this is reported in
notes. The newest usable model, by
timestamp and then run ID, is selected.

Prints one JSON object: threat_model (path or null), run_id, scope, status, timestamp, notes,
and models (every run copy found, newest first, with usable, problems, and notes).

Exit codes: 0 a usable model was found; 1 none is usable (none exists, or all are stale or
invalid: offer to run the threat-model skill); 2 bad arguments.
Standard library only; Python 3.9+. Read-only.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_findings  # noqa: E402  (this skill's scripts folder, including shared helpers)
import check_model  # noqa: E402
import normalize_findings  # noqa: E402
import target_identity  # noqa: E402


def assess(path, repo_root):
    """Return (header, problems, notes) for one stage 1 run copy."""
    try:
        text = path.read_text(encoding="utf-8")
        header, _ = normalize_findings.split_model(text)
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        return {}, [f"cannot read: {exc}"], []
    problems = [f"fails check_model.py: {problem}" for problem in check_model.check(text)]
    if header.get("status") not in ("complete", "inconclusive"):
        problems.append(f"status {header.get('status')!r} cannot start stage 2")
    notes = []
    if not problems:
        identity_problems, notes = check_findings.model_identity(repo_root, header)
        problems += identity_problems
    return header, problems, notes


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", default=".", help="target root (default: current directory)")
    parser.add_argument("--out-dir", help="the output folder the user chose for stage 1, if not the default")
    args = parser.parse_args()
    try:
        repo_root = target_identity.resolve(args.root, [])[0]
    except ValueError as exc:
        parser.exit(2, f"error: {exc}\n")
    base = Path(args.out_dir).expanduser().resolve() if args.out_dir else repo_root / ".defense-factory"

    models = []
    for path in sorted((base / "runs").glob("*/1-threat-model/threat-model.md")):
        header, problems, notes = assess(path, repo_root)
        models.append({"path": str(path), "run_id": path.parent.parent.name, "timestamp": str(header.get("timestamp", "")),
                       "status": header.get("status"), "scope": header.get("scope"),
                       "usable": not problems, "problems": problems, "notes": notes})
    models.sort(key=lambda model: (model["timestamp"], model["run_id"]), reverse=True)
    chosen = next((model for model in models if model["usable"]), None)
    print(json.dumps({
        "threat_model": chosen["path"] if chosen else None,
        "run_id": chosen["run_id"] if chosen else None,
        "scope": chosen["scope"] if chosen else None,
        "status": chosen["status"] if chosen else None,
        "timestamp": chosen["timestamp"] if chosen else None,
        "notes": chosen["notes"] if chosen else [],
        "models": models,
    }, indent=2))
    return 0 if chosen else 1


if __name__ == "__main__":
    sys.exit(main())
