#!/usr/bin/env python3
"""Find the stage 2 findings.json that stage 3 should validate, without asking the user.

Looks at every run copy <base>/runs/<run_id>/2-finding-discovery/findings.json, where <base> is
the default .defense-factory folder (at the Git top level, or at --root for a target that is not a
Git repository) or --out-dir when the user chose another location. A record is usable when it
passes check_findings.py (which also confirms its version still matches the code) and its status
is complete or inconclusive. The newest usable record, by timestamp and then run ID, is selected.

Prints one JSON object: findings (path or null), run_id, scope, status, timestamp, finding_count,
and records (every run copy found, newest first, with usable and problems).

Exit codes: 0 a usable record was found; 1 none is usable (none exists, or all are stale or
invalid: offer to rerun finding-discovery); 2 bad arguments.
Standard library only; Python 3.9+. Read-only.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_findings  # noqa: E402  (shared helper, with its own shared imports)
import target_identity  # noqa: E402  (shared helper)


def assess(path, repo_root):
    """Return (record dict, problems) for one stage 2 run copy."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        return {}, [f"cannot read: {exc}"]
    try:
        problems = check_findings.check(data, path.parent, repo_root)
    except Exception as exc:  # a malformed record should not crash the search
        return data.get("record", {}), [f"could not check: {exc}"]
    record = data.get("record", {})
    if record.get("status") not in ("complete", "inconclusive"):
        problems = problems + [f"status {record.get('status')!r} cannot start stage 3"]
    return record, problems


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", default=".", help="target root (default: current directory)")
    parser.add_argument("--out-dir", help="the output folder the user chose, if not the default")
    args = parser.parse_args()
    try:
        repo_root = target_identity.resolve(args.root, [])[0]
    except ValueError as exc:
        parser.exit(2, f"error: {exc}\n")
    base = Path(args.out_dir).expanduser().resolve() if args.out_dir else repo_root / ".defense-factory"

    records = []
    for path in sorted((base / "runs").glob("*/2-finding-discovery/findings.json")):
        record, problems = assess(path, repo_root)
        records.append({"path": str(path), "run_id": path.parent.parent.name,
                        "timestamp": str(record.get("timestamp", "")), "status": record.get("status"),
                        "scope": record.get("scope"), "usable": not problems, "problems": problems})
    records.sort(key=lambda record: (record["timestamp"], record["run_id"]), reverse=True)
    chosen = next((record for record in records if record["usable"]), None)
    finding_count = None
    if chosen:
        try:
            finding_count = len(json.loads(Path(chosen["path"]).read_text(encoding="utf-8")).get("findings", []))
        except (OSError, UnicodeDecodeError, ValueError):
            finding_count = None
    print(json.dumps({
        "findings": chosen["path"] if chosen else None,
        "run_id": chosen["run_id"] if chosen else None,
        "scope": chosen["scope"] if chosen else None,
        "status": chosen["status"] if chosen else None,
        "timestamp": chosen["timestamp"] if chosen else None,
        "finding_count": finding_count,
        "records": records,
    }, indent=2))
    return 0 if chosen else 1


if __name__ == "__main__":
    sys.exit(main())
