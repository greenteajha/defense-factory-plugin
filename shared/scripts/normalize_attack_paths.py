#!/usr/bin/env python3
"""Validate and normalize an attack-paths.json file, then number and prioritise its analyses.

Steps, in order:
  1. Validate the file against assets/attack-paths.schema.json (with the same schema validator as
     the finding-discovery normalizer, so an unknown keyword is an error rather than ignored).
  2. Derive each analysis's priority from its recorded severity (critical P0, high P1, medium P2,
     low P3; none for ignore or unknown, and none when the decision is ignore).
  3. Order the analyses by priority, then decision (reportable, deferred, ignore), then finding
     number, and number them AP-1, AP-2, ...; order not_eligible by validation number.
Running it again on its own output changes nothing. It does not judge whether a severity follows
the policy; check_attack_paths.py recomputes that with expected_severity() below.

Writes the result over the input file (or to --out). Prints one JSON object: valid, analyses,
problems. Nothing is written when there are problems.

Exit codes: 0 normalized; 1 problems found; 2 bad arguments.
Standard library only; Python 3.9+. Writes only the attack-paths file.
"""

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import normalize_findings  # noqa: E402  (shared helper: its schema validator is reused here)

SCHEMA_FILE = Path(__file__).resolve().parents[1] / "assets" / "attack-paths.schema.json"
ANALYSIS_FIELDS = (
    "id", "validation_id", "finding_id", "finding_key", "finding_fingerprint", "title", "verdict",
    "locations", "facts", "attacker_steps", "dataflow", "reachability", "counterevidence", "impact",
    "likelihood", "critical_criteria_met", "suppression", "calibration_override", "severity", "severity_rationale",
    "change_conditions", "proof_gap", "decision", "priority", "confidence",
)

# Severity policy -------------------------------------------------------------------------------
# Impact x likelihood, applied after hard suppression and the reportability gate (both recorded as
# a suppression reason). "critical" is only reached when the critical criteria are met; otherwise
# the top cell is "high". A finding that is not ignored never falls below "low".
MATRIX = {
    "high":    {"high": "critical", "medium": "medium", "low": "low", "unknown": "medium", "ignore": "ignore"},
    "medium":  {"high": "medium", "medium": "low", "low": "low", "unknown": "low", "ignore": "ignore"},
    "low":     {"high": "low", "medium": "low", "low": "low", "unknown": "low", "ignore": "ignore"},
    "unknown": {"high": "medium", "medium": "low", "low": "low", "unknown": "low", "ignore": "ignore"},
    "ignore":  {"high": "ignore", "medium": "ignore", "low": "ignore", "unknown": "ignore", "ignore": "ignore"},
}
PRIORITY = {"critical": "P0", "high": "P1", "medium": "P2", "low": "P3"}
PRIORITY_ORDER = ("P0", "P1", "P2", "P3")
DECISION_ORDER = ("reportable", "deferred", "ignore")


def matrix_severity(analysis):
    """The impact x likelihood result, with critical only when the critical criteria are met."""
    severity = MATRIX[analysis["impact"]][analysis["likelihood"]]
    if severity == "critical" and analysis.get("critical_criteria_met") is not True:
        return "high"
    return severity


def expected_severity(analysis):
    """The severity the policy gives: ignore when suppressed; otherwise a cited stage 1 calibration
    override when one is recorded; otherwise the matrix result."""
    if analysis.get("suppression"):
        return "ignore"
    override = analysis.get("calibration_override")
    if override:
        return override["severity"]
    severity = MATRIX[analysis["impact"]][analysis["likelihood"]]
    if severity == "critical" and analysis.get("critical_criteria_met") is not True:
        return "high"
    return severity


def priority_for(analysis):
    if analysis["decision"] == "ignore":
        return None
    return PRIORITY.get(analysis["severity"])


def number(ref):
    match = re.search(r"(\d+)$", ref)
    return int(match.group(1)) if match else 0


def load_schema():
    return json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))


def validate(data):
    schema = load_schema()
    return normalize_findings.unsupported_keywords(schema) or normalize_findings.schema_errors(
        data, schema, schema, "attack-paths.json")


def ordered(analysis):
    return {field: analysis[field] for field in ANALYSIS_FIELDS if field in analysis}


def normalize(data):
    """Return (normalized data, problems). The input is not modified."""
    problems = validate(data)
    if problems:
        return data, problems
    data = json.loads(json.dumps(data))

    seen = set()
    for analysis in data["analyses"]:
        if analysis["validation_id"] in seen:
            problems.append(f"analyses: {analysis['validation_id']} is analysed more than once")
        seen.add(analysis["validation_id"])
    if problems:
        return data, problems

    for analysis in data["analyses"]:
        analysis["priority"] = priority_for(analysis)
    analyses = sorted(data["analyses"], key=lambda a: (
        PRIORITY_ORDER.index(a["priority"]) if a["priority"] else len(PRIORITY_ORDER),
        DECISION_ORDER.index(a["decision"]), number(a["finding_id"]), a["validation_id"]))
    for index, analysis in enumerate(analyses, 1):
        analysis["id"] = f"AP-{index}"
    data["analyses"] = [ordered(a) for a in analyses]
    data["not_eligible"] = sorted(data["not_eligible"], key=lambda item: number(item["validation_id"]))
    return data, problems


def dump(data):
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", help="write here instead of over the input file")
    parser.add_argument("attack_paths", help="attack-paths.json to normalize")
    args = parser.parse_args()
    source = Path(args.attack_paths).expanduser().resolve()
    if not source.is_file():
        parser.exit(2, "error: attack_paths must be a file\n")
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        print(json.dumps({"valid": False, "analyses": 0, "problems": [f"not valid JSON: {exc}"]}, indent=2))
        return 1
    normalized, problems = normalize(data)
    if not problems:
        target = Path(args.out).expanduser().resolve() if args.out else source
        target.write_text(dump(normalized), encoding="utf-8")
    print(json.dumps({"valid": not problems, "analyses": len(normalized.get("analyses", [])) if not problems else 0,
                      "problems": problems}, indent=2))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
