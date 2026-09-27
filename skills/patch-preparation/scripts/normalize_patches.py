#!/usr/bin/env python3
"""Validate and normalize a patches.json file, then number and order its patches.

Steps, in order:
  1. Validate the file against assets/patches.schema.json (with the same schema validator as the
     finding-discovery normalizer, so an unknown keyword is an error rather than ignored).
  2. Order the patches by priority (P0, P1, P2, P3, carried from stage 3b), then by finding
     number, then by analysis id, and number them PP-1, PP-2, ...; order not_eligible by
     analysis number.
Running it again on its own output changes nothing. It does not judge whether an outcome follows
the gate rules; check_patches.py recomputes that.

Writes the result over the input file (or to --out). Prints one JSON object: valid, patches,
problems. Nothing is written when there are problems.

Exit codes: 0 normalized; 1 problems found; 2 bad arguments.
Standard library only; Python 3.9+. Writes only the patches file.
"""

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import normalize_findings  # noqa: E402  (shared helper: its schema validator is reused here)

SCHEMA_FILE = Path(__file__).resolve().parents[1] / "assets" / "patches.schema.json"
PATCH_FIELDS = (
    "id", "analysis_id", "finding_id", "finding_key", "finding_fingerprint", "title", "severity",
    "priority", "outcome", "locations", "vulnerable_path", "security_invariant", "patch_strategy",
    "patch_ref", "files_changed", "tests_added", "gates", "reproduction_before", "reproduction_after",
    "legitimate_behavior", "candidate_review", "remaining_risk", "proof_gap", "confidence", "artifacts",
)
PRIORITY_ORDER = ("P0", "P1", "P2", "P3")


def number(ref):
    match = re.search(r"(\d+)$", ref)
    return int(match.group(1)) if match else 0


def load_schema():
    return json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))


def validate(data):
    schema = load_schema()
    return normalize_findings.unsupported_keywords(schema) or normalize_findings.schema_errors(
        data, schema, schema, "patches.json")


def ordered(patch):
    return {field: patch[field] for field in PATCH_FIELDS if field in patch}


def normalize(data):
    """Return (normalized data, problems). The input is not modified."""
    problems = validate(data)
    if problems:
        return data, problems
    data = json.loads(json.dumps(data))

    seen = set()
    for patch in data["patches"]:
        if patch["analysis_id"] in seen:
            problems.append(f"patches: {patch['analysis_id']} is patched more than once")
        seen.add(patch["analysis_id"])
    if problems:
        return data, problems

    patches = sorted(data["patches"], key=lambda p: (
        PRIORITY_ORDER.index(p["priority"]) if p["priority"] in PRIORITY_ORDER else len(PRIORITY_ORDER),
        number(p["finding_id"]), number(p["analysis_id"])))
    for index, patch in enumerate(patches, 1):
        patch["id"] = f"PP-{index}"
    data["patches"] = [ordered(p) for p in patches]
    data["not_eligible"] = sorted(data["not_eligible"], key=lambda item: number(item["analysis_id"]))
    return data, problems


def dump(data):
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", help="write here instead of over the input file")
    parser.add_argument("patches", help="patches.json to normalize")
    args = parser.parse_args()
    source = Path(args.patches).expanduser().resolve()
    if not source.is_file():
        parser.exit(2, "error: patches must be a file\n")
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        print(json.dumps({"valid": False, "patches": 0, "problems": [f"not valid JSON: {exc}"]}, indent=2))
        return 1
    normalized, problems = normalize(data)
    if not problems:
        target = Path(args.out).expanduser().resolve() if args.out else source
        target.write_text(dump(normalized), encoding="utf-8")
    print(json.dumps({"valid": not problems, "patches": len(normalized.get("patches", [])) if not problems else 0,
                      "problems": problems}, indent=2))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
