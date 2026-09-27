#!/usr/bin/env python3
"""Validate and normalize a validations.json file, then number its entries.

Steps, in order:
  1. Validate the file against assets/validations.schema.json (using the same schema validator as
     the finding-discovery normalizer, so an unknown keyword is an error rather than ignored).
  2. Order the validation entries by finding (FD-1, FD-2, ... then any supplied key), and within a
     finding by finding_key, and number them VD-1, VD-2, ....
Running it again on its own output changes nothing.

Writes the result over the input file (or to --out). Prints one JSON object: valid, validations
(count), problems. Nothing is written when there are problems.

Exit codes: 0 normalized; 1 problems found; 2 bad arguments.
Standard library only; Python 3.9+. Writes only the validations file.
"""

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import normalize_findings  # noqa: E402  (shared helper: its schema validator is reused here)

SCHEMA_FILE = Path(__file__).resolve().parents[1] / "assets" / "validations.schema.json"
VALIDATION_FIELDS = (
    "id", "finding_id", "finding_key", "finding_fingerprint", "title", "verdict", "method",
    "reproduced", "rubric", "control", "reachability", "repeat_confirmed", "evidence",
    "counterevidence_or_proof_gap", "setup_notes", "remaining_uncertainty", "confidence",
    "next_step", "affected_version", "artifacts",
)


def load_schema():
    return json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))


def validate(data):
    schema = load_schema()
    return normalize_findings.unsupported_keywords(schema) or normalize_findings.schema_errors(
        data, schema, schema, "validations.json")


def finding_order(finding_id):
    """FD ids sort by number and before any supplied key; keys sort after, alphabetically."""
    match = re.fullmatch(r"FD-(\d+)", finding_id)
    return (0, int(match.group(1)), "") if match else (1, 0, finding_id)


def ordered(entry):
    return {field: entry[field] for field in VALIDATION_FIELDS if field in entry}


def normalize(data):
    """Return (normalized data, problems). The input is not modified."""
    problems = validate(data)
    if problems:
        return data, problems
    data = json.loads(json.dumps(data))

    keys, finding_ids = set(), set()
    for entry in data["validations"]:
        if entry["finding_key"] in keys:
            problems.append(f"validations: finding_key {entry['finding_key']!r} is used by more than one entry")
        keys.add(entry["finding_key"])
        if entry["finding_id"] in finding_ids:
            problems.append(f"validations: finding_id {entry['finding_id']!r} is validated by more than one entry")
        finding_ids.add(entry["finding_id"])
    if problems:
        return data, problems

    entries = sorted(data["validations"], key=lambda entry: (finding_order(entry["finding_id"]), entry["finding_key"]))
    for number, entry in enumerate(entries, 1):
        entry["id"] = f"VD-{number}"
    data["validations"] = [ordered(entry) for entry in entries]
    return data, problems


def dump(data):
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", help="repository root (accepted for symmetry with the other checks; unused)")
    parser.add_argument("--out", help="write here instead of over the input file")
    parser.add_argument("validations", help="validations.json to normalize")
    args = parser.parse_args()

    source = Path(args.validations).expanduser().resolve()
    if not source.is_file():
        parser.exit(2, "error: validations must be a file\n")
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        print(json.dumps({"valid": False, "validations": 0, "problems": [f"not valid JSON: {exc}"]}, indent=2))
        return 1

    normalized, problems = normalize(data)
    if not problems:
        target = Path(args.out).expanduser().resolve() if args.out else source
        target.write_text(dump(normalized), encoding="utf-8")
    print(json.dumps({"valid": not problems,
                      "validations": len(normalized.get("validations", [])) if not problems else 0,
                      "problems": problems}, indent=2))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
