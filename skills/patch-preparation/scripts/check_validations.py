#!/usr/bin/env python3
"""Check a validations.json file before it is saved and rendered. Read-only.

Checks, in order:
  - it passes normalize_validations.py and is already in normalized form;
  - no "<fill: ...>" placeholder remains anywhere, the record has no template placeholders, and
    model names an exact model;
  - the record's target_id, target_kind, and version match the target now (target_identity.py);
  - with source validated-record: the stage 2 findings.json exists, its sha256 matches, it passes
    check_findings.py, its status is complete or inconclusive, its run_id matches, and this run's
    scope lies within its scope; every validated finding_id exists in it and its finding_key (and
    fingerprint when given) match; with source supplied-finding: validated_record is null;
  - authorization quotes the user's request, or an inherited authorization names the stage 2 run,
    shares its run_id, and repeats the stage 2 record's authorization value exactly;
  - each verdict has the evidence it needs: method and reproduced agree (static-assessment is
    never reproduced; any other method is); a static assessment is never High confidence; a
    confirmed verdict has repeat_confirmed true, a rubric criterion that passed, and real
    reachability evidence; a rejected verdict has a rubric criterion that failed;
  - a non-blocked record has an environment; a blocked record has none and no validations;
  - status complete needs every stage 2 finding either validated or named in coverage_gaps, an
    environment whose clean-up left nothing behind, and no inconclusive verdict.

Prints one JSON object: valid, problems (list of strings).
Exit codes: 0 valid; 1 problems found; 2 bad arguments.
Standard library only; Python 3.9+. Read-only.
"""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_findings  # noqa: E402  (shared helper)
import normalize_findings  # noqa: E402  (shared helper)
import normalize_validations  # noqa: E402  (this skill's scripts folder)
import target_identity  # noqa: E402  (shared helper)

INHERITED = "inherited from stage 2 run "
GENERIC_MODELS = {"claude", "gpt", "unknown model"}
FILL = "<fill:"
NULLISH = {"", "none", "n/a", "na", "none found", "not applicable", "unknown"}


def unfilled(value, where=""):
    if isinstance(value, str):
        return [where] if FILL in value else []
    if isinstance(value, list):
        return [found for index, item in enumerate(value) for found in unfilled(item, f"{where}[{index}]")]
    if isinstance(value, dict):
        return [found for key, item in value.items() for found in unfilled(item, f"{where}.{key}" if where else key)]
    return []


OPENING, CLOSING = '"“', '"”'
QUOTED = re.compile(f"[{OPENING}]" + f"([^{OPENING}{CLOSING}]+)" + f"[{CLOSING}]")


def quoted(text):
    return [match.strip() for match in QUOTED.findall(text.replace('\\"', '"')) if match.strip()]


def inherited_text(run_id, stage2_authorization):
    return f"{INHERITED}{run_id}: {str(stage2_authorization).replace(chr(92) + chr(34), chr(34))}"


def meaningful(text):
    return str(text).strip().lower() not in NULLISH


def load_stage2(data, stage_dir, repo, problems):
    """Return {FD id: finding} for a usable stage 2 record, or {} (recording every problem)."""
    ref = data["validated_record"]
    if data["record"]["source"] == "supplied-finding":
        if ref is not None:
            problems.append("validated_record must be null when source is supplied-finding")
        return {}
    if ref is None:
        problems.append("validated_record is required when source is validated-record")
        return {}
    path = (stage_dir / ref["path"]).resolve()
    try:
        raw = path.read_bytes()
        findings = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        problems.append(f"validated_record.path: cannot read the stage 2 findings.json ({exc})")
        return {}
    if hashlib.sha256(raw).hexdigest() != ref["sha256"]:
        problems.append("validated_record.sha256 does not match the stage 2 findings.json: it changed after it was read")
    if findings.get("record", {}).get("run_id") != ref["run_id"]:
        problems.append("validated_record.run_id does not match the stage 2 record's run_id")
    stage2_problems = check_findings.check(findings, path.parent, repo)
    problems += [f"stage 2 findings.json: {problem}" for problem in stage2_problems]
    if findings.get("record", {}).get("status") not in ("complete", "inconclusive"):
        problems.append(f"stage 2 status {findings.get('record', {}).get('status')!r} cannot start stage 3")
    if not check_findings.within(data["record"]["scope"], findings.get("record", {}).get("scope")):
        problems.append("record.scope is wider than the stage 2 record's scope")
    return {finding["id"]: finding for finding in findings.get("findings", [])}


def check_authorization(data, stage2_findings, problems):
    ref = data["validated_record"]
    authorization = data["record"]["authorization"]
    if not authorization.startswith(INHERITED):
        if not quoted(authorization):
            problems.append("record.authorization must quote the user's request")
        return
    if ref is None:
        problems.append("inherited authorization needs a stage 2 record")
        return
    if not authorization.startswith(f"{INHERITED}{ref['run_id']}:"):
        problems.append(f"inherited authorization must start with '{INHERITED}{ref['run_id']}:'")
    if data["record"]["run_id"] != ref["run_id"]:
        problems.append("inherited authorization is only valid in the stage 2 record's own run (same run_id)")


def check_verdict(entry, problems):
    where = f"validations[{entry.get('id', entry['finding_key'])}]"
    method, reproduced, verdict = entry["method"], entry["reproduced"], entry["verdict"]
    if method == "static-assessment":
        if reproduced is not False:
            problems.append(f"{where}: a static-assessment is never reproduced (set reproduced false)")
        if entry["confidence"]["level"] == "High":
            problems.append(f"{where}: a static-assessment cannot be High confidence")
    elif reproduced is not True:
        problems.append(f"{where}: method {method} ran in the container, so reproduced must be true")
    results = [item["result"] for item in entry["rubric"]]
    if verdict == "confirmed":
        if entry["repeat_confirmed"] is not True:
            problems.append(f"{where}: a confirmed verdict must be reproduced once (repeat_confirmed true)")
        if "pass" not in results:
            problems.append(f"{where}: a confirmed verdict needs at least one rubric criterion that passed")
        if not meaningful(entry["reachability"]):
            problems.append(f"{where}: a confirmed verdict needs evidence the suspect code was reached")
    if verdict == "rejected" and "fail" not in results:
        problems.append(f"{where}: a rejected verdict needs at least one rubric criterion that failed")


def check(data, stage_dir, repo):
    normalized, problems = normalize_validations.normalize(data)
    if problems:
        return problems
    if normalized != data:
        return ["validations.json is not in normalized form; run normalize_validations.py first"]
    record = data["record"]
    problems += [f"{where} still holds a '{FILL}' placeholder" for where in unfilled(data)]
    for field, value in record.items():
        if isinstance(value, str) and value.startswith("<") and FILL not in value:
            problems.append(f"record.{field} still holds a template placeholder")
    if record["model"].strip().lower() in GENERIC_MODELS:
        problems.append("record.model must name the exact model and version reported by the client, or 'unknown'")

    if record["status"] == "blocked":
        if data["validations"]:
            problems.append("a blocked record has no validations")
        if data["environment"] is not None:
            problems.append("a blocked record built no container, so environment must be null")
        return problems

    problems += check_findings.identity_problems(repo, record["scope"], record, "record")
    if data["environment"] is None:
        problems.append("environment is required once a container has been built (null only for a blocked run)")
    stage2_findings = load_stage2(data, stage_dir, repo, problems)
    check_authorization(data, stage2_findings, problems)

    for entry in data["validations"]:
        where = f"validations[{entry['id']}]"
        check_verdict(entry, problems)
        if record["source"] == "validated-record" and entry["finding_id"] not in stage2_findings:
            problems.append(f"{where}: finding_id {entry['finding_id']} is not in the stage 2 findings.json")
        elif record["source"] == "validated-record":
            finding = stage2_findings[entry["finding_id"]]
            if entry["finding_key"] != finding["key"]:
                problems.append(f"{where}: finding_key {entry['finding_key']!r} does not match {entry['finding_id']} "
                                f"(expected {finding['key']!r})")
            if entry.get("finding_fingerprint") not in (None, finding.get("fingerprint")):
                problems.append(f"{where}: finding_fingerprint does not match {entry['finding_id']}")

    if record["status"] == "complete":
        validated = {entry["finding_id"] for entry in data["validations"]}
        gaps = " ".join(record["coverage_gaps"])
        for finding_id in sorted(stage2_findings):
            if finding_id not in validated and not re.search(rf"\b{re.escape(finding_id)}\b", gaps):
                problems.append(f"status cannot be complete: {finding_id} was neither validated nor named in "
                                "record.coverage_gaps")
        if any(entry["verdict"] == "inconclusive" for entry in data["validations"]):
            problems.append("status cannot be complete while a validation is inconclusive")
        if data["environment"] and data["environment"]["cleanup"]["remaining"] != 0:
            problems.append("status cannot be complete while labelled resources remain after clean-up")
    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", required=True, help="repository root")
    parser.add_argument("validations", help="validations.json to check")
    args = parser.parse_args()
    repo = Path(args.repo).expanduser().resolve()
    source = Path(args.validations).expanduser().resolve()
    if not repo.is_dir() or not source.is_file():
        parser.exit(2, "error: --repo must be a directory and validations must be a file\n")
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
        problems = check(data, source.parent, repo)
    except (ValueError, UnicodeDecodeError) as exc:
        problems = [f"not valid JSON: {exc}"]
    print(json.dumps({"valid": not problems, "problems": problems}, indent=2))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
