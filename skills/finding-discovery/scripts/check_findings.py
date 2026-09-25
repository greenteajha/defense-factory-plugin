#!/usr/bin/env python3
"""Check a findings.json file before it is saved and rendered. Read-only.

Checks, in order:
  - it passes normalize_findings.py and is already in normalized form;
  - no "<fill: ...>" placeholder from start_findings.py remains anywhere, the record has no
    template placeholders, and it names an exact model;
  - the record's target_id, target_kind, and version match the target now (target_identity.py),
    and security-guidance.md exists in the stage folder;
  - with source stage-1-record: the stage 1 model exists, its sha256 matches, it passes
    check_model.py, its status is complete or inconclusive, its run_id matches, its timestamp is
    not later than this record's, its version still matches the code (recomputed for its own
    scope), its target_id matches or differs only because the folder moved (local-path identity
    with an identical version), and this run's scope lies within its scope; with source narrow-scan: named paths, no model, and a coverage
    gap that says so;
  - authorization quotes the user's request; an inherited authorization names the stage 1 run,
    shares its run_id, and repeats the stage 1 record's authorization value exactly;
  - every TM-H hypothesis in the stage 1 table and every seed has exactly one reconciliation row,
    and no row names anything else; a findings row lists findings whose origin includes it, and
    every finding origin is listed in its row; no-finding rows cite evidence; not-investigated
    rows are named in the record's coverage gaps; open-ended stands alone in an origin;
  - merged keys appear once across all findings;
  - each stage 1 open question (1..n) is carried forward exactly once;
  - coverage: reviewed files and remaining paths come from the scope inventory; complete means
    every inventory file was reviewed; partial means every unreviewed file is under a remaining path;
  - status complete is not claimed while a Critical or High hypothesis is not-investigated;
    a blocked record has no findings.

Prints one JSON object: valid, problems (list of strings).
Exit codes: 0 valid; 1 problems found; 2 bad arguments.
Standard library only; Python 3.9+. Read-only.
"""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_model  # noqa: E402  (shared helpers in this skill's scripts folder)
import normalize_findings  # noqa: E402
import target_identity  # noqa: E402

INHERITED = "inherited from stage 1 run "
GENERIC_MODELS = {"claude", "gpt", "unknown model"}
FILL = "<fill:"


def unfilled(value, where=""):
    """Locations of every string that still contains a start_findings.py placeholder."""
    if isinstance(value, str):
        return [where] if FILL in value else []
    if isinstance(value, list):
        return [found for index, item in enumerate(value) for found in unfilled(item, f"{where}[{index}]")]
    if isinstance(value, dict):
        return [found for key, item in value.items() for found in unfilled(item, f"{where}.{key}" if where else key)]
    return []


OPENING, CLOSING = '"\u201c', '"\u201d'
QUOTED = re.compile(f"[{OPENING}]" + f"([^{OPENING}{CLOSING}]+)" + f"[{CLOSING}]")


def quoted(text):
    """Quoted statements in a field, ignoring YAML escaping."""
    return [match.strip() for match in QUOTED.findall(text.replace('\\"', '"')) if match.strip()]


def inherited_text(run_id, stage1_authorization):
    """The authorization value stage 2 records when it carries the stage 1 request forward."""
    return f"{INHERITED}{run_id}: {str(stage1_authorization).replace(chr(92) + chr(34), chr(34))}"


def scope_items(scope):
    return [] if scope == "whole-repository" else list(scope)


def within(inner, outer):
    if outer == "whole-repository":
        return True
    if inner == "whole-repository":
        return False
    return all(normalize_findings.in_scope(normalize_findings.clean_path(item), outer) for item in inner)


def identity_problems(repo, scope, record, label):
    try:
        current = target_identity.identify(repo, scope_items(scope))
    except ValueError as exc:
        return [f"{label}: cannot identify the target ({exc})"]
    return [f"{label}: {field} {record.get(field)!r} does not match the target now ({current[field]!r}); "
            "the code changed or the value was not taken from target_identity.py"
            for field in ("target_id", "target_kind", "version") if record.get(field) != current[field]]


LOCATION_NOTE = ("same code, different location: the stage 1 model was made at another path (a moved or copied "
                 "folder) and its version matches the code exactly")


def model_identity(repo, header):
    """Compare a stage 1 model with the target now. Return (problems, notes).

    The version (commit, or content digest for the model's own scope) must match exactly. A
    different target_id is accepted when the target is identified by its local path, because
    moving or copying a folder changes that path but not the code; it is reported as a note.
    A different target_id for a target identified by its remote URL is a different repository.
    """
    try:
        current = target_identity.identify(repo, scope_items(header.get("scope")))
    except ValueError as exc:
        return [f"cannot identify the target ({exc})"], []
    if header.get("version") != current["version"]:
        return [f"the code changed since the model was built (version {header.get('version')!r}, "
                f"now {current['version']!r})"], []
    if header.get("target_id") == current["target_id"]:
        return [], []
    if current["identity_source"] == "local-path":
        return [], [LOCATION_NOTE]
    return [f"the model is for a different repository (target_id {header.get('target_id')!r}, "
            f"now {current['target_id']!r})"], []


def check_threat_model(data, findings_dir, repo, problems):
    """Return (stage 1 header, {TM-H: priority}); both empty when there is no usable model."""
    record, ref = data["record"], data["threat_model"]
    if record["source"] == "narrow-scan":
        if record["scope"] == "whole-repository":
            problems.append("a narrow scan names paths; for a whole repository, start from a stage 1 threat model")
        if ref is not None:
            problems.append("threat_model must be null when source is narrow-scan")
        if not any("threat model" in gap.lower() for gap in record["coverage_gaps"]):
            problems.append("record.coverage_gaps must say that no threat model was used")
        return {}, {}
    if ref is None:
        problems.append("threat_model is required when source is stage-1-record")
        return {}, {}
    path = normalize_findings.threat_model_path(data, findings_dir)
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8")
        header, _ = normalize_findings.split_model(text)
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        problems.append(f"threat_model.path: cannot read the stage 1 model ({exc})")
        return {}, {}
    if hashlib.sha256(raw).hexdigest() != ref["sha256"]:
        problems.append("threat_model.sha256 does not match the stage 1 model: it changed after it was read")
    problems += [f"stage 1 model fails check_model.py: {problem}" for problem in check_model.check(text)]
    if header.get("status") not in ("complete", "inconclusive"):
        problems.append(f"stage 1 model status {header.get('status')!r} cannot start stage 2")
    if header.get("run_id") != ref["run_id"]:
        problems.append("threat_model.run_id does not match the stage 1 model's run_id")
    problems += [f"stage 1 model: {problem}" for problem in model_identity(repo, header)[0]]
    if not within(record["scope"], header.get("scope")):
        problems.append("record.scope is wider than the stage 1 model's scope")
    return header, normalize_findings.stage1_hypotheses(text)


def check_authorization(data, header, problems):
    record, ref = data["record"], data["threat_model"]
    authorization = record["authorization"]
    if not authorization.startswith(INHERITED):
        if not quoted(authorization):
            problems.append("record.authorization must quote the user's request")
        return
    if ref is None or not header:
        problems.append("inherited authorization needs a usable stage 1 model")
        return
    if not authorization.startswith(f"{INHERITED}{ref['run_id']}:"):
        problems.append(f"inherited authorization must start with '{INHERITED}{ref['run_id']}:'")
    if record["run_id"] != ref["run_id"]:
        problems.append("inherited authorization is only valid in the stage 1 model's own run (same run_id)")
    if authorization != inherited_text(ref["run_id"], header.get("authorization", "")):
        problems.append("inherited authorization must repeat the stage 1 record's authorization value exactly")


def check_reconciliation(data, hypotheses, problems):
    findings = {finding["id"]: finding for finding in data["findings"]}
    seeds = [seed["id"] for seed in data["seeds"]]
    if len(seeds) != len(set(seeds)):
        problems.append("seed IDs must be unique")
    expected = set(hypotheses) | set(seeds)
    rows = {}
    for row in data["reconciliation"]:
        if row["ref"] in rows:
            problems.append(f"{row['ref']}: more than one reconciliation row")
        rows[row["ref"]] = row
        if row["ref"] not in expected:
            problems.append(f"{row['ref']}: reconciliation row for an unknown hypothesis or seed")
    for ref in sorted(expected - set(rows)):
        problems.append(f"{ref}: no reconciliation row; every hypothesis and seed needs one")

    gaps = " ".join(data["record"]["coverage_gaps"])
    for ref, row in rows.items():
        listed = row.get("findings", [])
        if row["disposition"] == "findings":
            if not listed:
                problems.append(f"{ref}: disposition findings needs at least one finding")
            for finding_id in listed:
                if finding_id in findings and ref not in findings[finding_id]["origin"]:
                    problems.append(f"{ref}: lists {finding_id}, whose origin does not include {ref}")
        elif listed:
            problems.append(f"{ref}: only a findings row may list findings")
        if row["disposition"] == "no-finding" and not row.get("evidence"):
            problems.append(f"{ref}: no-finding needs evidence citing the control that holds")
        if row["disposition"] == "not-investigated" and not re.search(rf"\b{re.escape(ref)}\b", gaps):
            problems.append(f"{ref}: not-investigated must also be named in record.coverage_gaps")

    for finding_id, finding in findings.items():
        origin = finding["origin"]
        if "open-ended" in origin and len(origin) > 1:
            problems.append(f"{finding_id}: open-ended cannot be combined with other origins")
        for ref in origin:
            if ref == "open-ended":
                continue
            if ref not in expected:
                problems.append(f"{finding_id}: origin {ref} is not a stage 1 hypothesis or seed")
            elif ref in rows and finding_id not in rows[ref].get("findings", []):
                problems.append(f"{finding_id}: origin {ref}, but the {ref} row does not list it")
    return rows


def check_merges(data, problems):
    seen = {}
    for finding in data["findings"]:
        for key in finding.get("merged_from", []):
            if key in seen:
                problems.append(f"merged key {key!r} appears in both {seen[key]} and {finding['id']}")
            seen[key] = finding["id"]


def check_open_questions(data, header, problems):
    numbers = [question["number"] for question in data["stage1_open_questions"]]
    if not header:
        if numbers:
            problems.append("stage1_open_questions must be empty without a stage 1 model")
        return
    try:
        count = int(header.get("open_questions", 0))
    except ValueError:
        return  # reported by check_model.py
    if sorted(numbers) != list(range(1, count + 1)):
        problems.append(f"stage1_open_questions must carry forward questions 1 to {count} exactly once")


def check_coverage(data, findings_dir, problems):
    coverage = data["coverage"]
    try:
        inventory = {line.strip() for line in (findings_dir / coverage["inventory"]).read_text(encoding="utf-8").splitlines()
                     if line.strip()}
    except (OSError, UnicodeDecodeError) as exc:
        problems.append(f"coverage.inventory: cannot read the scope inventory ({exc})")
        return
    reviewed = set(coverage["reviewed_files"])
    extra = sorted(reviewed - inventory)
    if extra:
        problems.append(f"coverage.reviewed_files are not in the scope inventory: {', '.join(extra[:5])}")
    remaining = set()
    for entry in coverage["remaining"]:
        for raw in entry["paths"]:
            path = normalize_findings.clean_path(raw).rstrip("/")
            matched = {item for item in inventory
                       if item == path or PurePosixPath(path) in PurePosixPath(item).parents}
            if not matched:
                problems.append(f"coverage.remaining path {raw!r} matches nothing in the scope inventory")
            remaining |= matched
    unaccounted = sorted(inventory - reviewed - remaining)
    if coverage["completeness"] == "complete":
        if coverage["remaining"]:
            problems.append("coverage.completeness is complete but coverage.remaining is not empty")
        if unaccounted:
            problems.append(f"coverage is complete but {len(unaccounted)} inventory file(s) were not reviewed, "
                            f"for example {', '.join(unaccounted[:5])}")
    else:
        if not coverage["remaining"]:
            problems.append("coverage.completeness is partial, so coverage.remaining must list what was not reviewed")
        if unaccounted:
            problems.append(f"{len(unaccounted)} inventory file(s) are neither reviewed nor listed in coverage.remaining, "
                            f"for example {', '.join(unaccounted[:5])}")


def check(data, findings_dir, repo):
    normalized, _, problems = normalize_findings.normalize(data, findings_dir, repo)
    if problems:
        return problems
    if normalized != data:
        return ["findings.json is not in normalized form; run normalize_findings.py first"]
    record = data["record"]
    problems += [f"{where} still holds a '{FILL}' placeholder from start_findings.py" for where in unfilled(data)]
    for field, value in record.items():
        if isinstance(value, str) and value.startswith("<") and FILL not in value:
            problems.append(f"record.{field} still holds a template placeholder")
    if record["model"].strip().lower() in GENERIC_MODELS:
        problems.append("record.model must name the exact model and version reported by the client, or 'unknown'")
    if record["status"] == "blocked":
        if data["findings"]:
            problems.append("a blocked record has no findings")
        return problems

    problems += identity_problems(repo, record["scope"], record, "record")
    if not (findings_dir / "security-guidance.md").is_file():
        problems.append("security-guidance.md is missing from the stage folder; save the resolve_security_md.py output there")
    header, hypotheses = check_threat_model(data, findings_dir, repo, problems)
    if header and str(header.get("timestamp", "")) > record["timestamp"]:
        problems.append("record.timestamp is earlier than the stage 1 model's timestamp")
    check_authorization(data, header, problems)
    rows = check_reconciliation(data, hypotheses, problems)
    check_merges(data, problems)
    check_open_questions(data, header, problems)
    check_coverage(data, findings_dir, problems)
    if record["status"] == "complete":
        for ref, row in sorted(rows.items()):
            if row["disposition"] == "not-investigated" and hypotheses.get(ref) in ("critical", "high"):
                problems.append(f"status cannot be complete: {ref} ({hypotheses[ref].capitalize()}) was not investigated")
    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", required=True, help="repository root")
    parser.add_argument("findings", help="findings.json to check")
    args = parser.parse_args()
    repo = Path(args.repo).expanduser().resolve()
    source = Path(args.findings).expanduser().resolve()
    if not repo.is_dir() or not source.is_file():
        parser.exit(2, "error: --repo must be a directory and findings must be a file\n")
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
        problems = check(data, source.parent, repo)
    except (ValueError, UnicodeDecodeError) as exc:
        problems = [f"not valid JSON: {exc}"]
    print(json.dumps({"valid": not problems, "problems": problems}, indent=2))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
