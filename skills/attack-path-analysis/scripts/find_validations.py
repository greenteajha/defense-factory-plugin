#!/usr/bin/env python3
"""Find the stage 3 validations.json that stage 3b should analyse, without asking the user.

Looks at every run copy <base>/runs/<run_id>/3-finding-validation/validations.json, where <base>
is the default .defense-factory folder (at the Git top level, or at --root for a target that is
not a Git repository) or --out-dir when the user chose another location. A record is usable when
it passes check_validations.py (which also re-checks the stage 2 record and confirms the code is
unchanged) and its status is complete or inconclusive. The newest usable record, by timestamp and
then run ID, is selected.

Prints one JSON object: validations (path or null), run_id, status, timestamp, eligible (count of
confirmed or inconclusive verdicts), rejected (count), and records (every run copy found, newest
first, with usable and problems).

Exit codes: 0 a usable record was found; 1 none is usable (offer to run stage 3); 2 bad arguments.
Standard library only; Python 3.9+. Read-only.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_validations  # noqa: E402  (shared helper)
import target_identity  # noqa: E402  (shared helper)


def assess(path, repo_root):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        return {}, [f"cannot read: {exc}"]
    try:
        problems = check_validations.check(data, path.parent, repo_root)
    except Exception as exc:  # a malformed record should not stop the search
        return data, [f"could not check: {exc}"]
    status = data.get("record", {}).get("status")
    if status not in ("complete", "inconclusive"):
        problems = problems + [f"status {status!r} cannot start stage 3b"]
    return data, problems


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
    for path in sorted((base / "runs").glob("*/3-finding-validation/validations.json")):
        data, problems = assess(path, repo_root)
        record = data.get("record", {})
        verdicts = [v.get("verdict") for v in data.get("validations", [])]
        records.append({"path": str(path), "run_id": path.parent.parent.name,
                        "timestamp": str(record.get("timestamp", "")), "status": record.get("status"),
                        "eligible": sum(v in ("confirmed", "inconclusive") for v in verdicts),
                        "rejected": sum(v == "rejected" for v in verdicts),
                        "usable": not problems, "problems": problems})
    records.sort(key=lambda r: (r["timestamp"], r["run_id"]), reverse=True)
    chosen = next((r for r in records if r["usable"]), None)
    print(json.dumps({
        "validations": chosen["path"] if chosen else None,
        "run_id": chosen["run_id"] if chosen else None,
        "status": chosen["status"] if chosen else None,
        "timestamp": chosen["timestamp"] if chosen else None,
        "eligible": chosen["eligible"] if chosen else 0,
        "rejected": chosen["rejected"] if chosen else 0,
        "records": records,
    }, indent=2))
    return 0 if chosen else 1


if __name__ == "__main__":
    sys.exit(main())
