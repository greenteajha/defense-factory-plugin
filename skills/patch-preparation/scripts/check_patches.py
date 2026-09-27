#!/usr/bin/env python3
"""Check a patches.json file before it is saved and rendered. Read-only.

Checks, in order:
  - it passes normalize_patches.py and is already in normalized form;
  - no "<fill: ...>" placeholder remains, the record has no template placeholders, and model names
    an exact model;
  - the record's target_id, target_kind, and version match the target now;
  - the stage 3b attack-paths.json exists, its sha256 matches, it passes check_attack_paths.py
    (which re-checks the stage 1-3 records and recomputes the severity policy), its status is
    complete or inconclusive, its run_id matches, and this run's scope lies within its scope; the
    threat model and security guidance, when referenced, still match their sha256;
  - authorization quotes the user's request, or repeats the stage 3b record's value exactly as
    "inherited from stage 3b run <run_id>: ..." within the same run;
  - a non-blocked record has an environment; a blocked record has none and no patches;
  - coverage: every patch names a reportable stage 3b analysis, with the same finding id, key,
    fingerprint, title, severity, and priority, and the stage 2/3b locations unchanged; no
    deferred or ignore analysis is patched; not_eligible lists exactly the deferred and ignore
    analyses;
  - the outcome rules, recomputed: fixed needs a written patch, files changed, a test added, every
    gate passed, and evidence the issue no longer reproduces; no_change writes no patch and changes
    no file; blocked and inconclusive need the exact proof_gap and write no verified fix, and an
    inconclusive outcome is never High confidence;
  - status complete needs every reportable analysis patched or named in coverage_gaps, an
    environment whose clean-up left nothing behind, and no blocked or inconclusive outcome.

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
import check_attack_paths  # noqa: E402  (shared helper)
import check_findings  # noqa: E402  (shared helper)
import check_validations  # noqa: E402  (shared helper: unfilled, quoted, meaningful)
import normalize_patches as npp  # noqa: E402  (this skill's scripts folder)

INHERITED = "inherited from stage 3b run "
GENERIC_MODELS = {"claude", "gpt", "unknown model"}
FILL = "<fill:"
PATCHABLE = "reportable"


def inherited_text(run_id, stage3b_authorization):
    return f"{INHERITED}{run_id}: {str(stage3b_authorization).replace(chr(92) + chr(34), chr(34))}"


def read_ref(ref, stage_dir, label, problems):
    path = (stage_dir / ref["path"]).resolve()
    try:
        raw = path.read_bytes()
    except OSError as exc:
        problems.append(f"{label}.path: cannot read {ref['path']} ({exc})")
        return path, None
    if hashlib.sha256(raw).hexdigest() != ref["sha256"]:
        problems.append(f"{label}.sha256 does not match {ref['path']}: it changed after it was read")
    return path, raw


def load_stage3b(data, stage_dir, repo, problems):
    """Return (stage 3b record data, {AP id: analysis})."""
    ref = data["validated_record"]
    path, raw = read_ref(ref, stage_dir, "validated_record", problems)
    if raw is None:
        return {}, {}
    try:
        stage3b = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        problems.append(f"validated_record: not valid JSON ({exc})")
        return {}, {}
    problems += [f"stage 3b attack-paths.json: {p}" for p in check_attack_paths.check(stage3b, path.parent, repo)]
    record = stage3b.get("record", {})
    if record.get("status") not in ("complete", "inconclusive"):
        problems.append(f"stage 3b status {record.get('status')!r} cannot start stage 4")
    if ref.get("run_id") != record.get("run_id"):
        problems.append("validated_record.run_id does not match the stage 3b record's run_id")
    if not check_findings.within(data["record"]["scope"], record.get("scope")):
        problems.append("record.scope is wider than the stage 3b record's scope")
    analyses = {a["id"]: a for a in stage3b.get("analyses", []) if "id" in a}
    return stage3b, analyses


def check_outcome(p, problems):
    where = f"patches[{p.get('id', p['analysis_id'])}]"
    outcome = p["outcome"]
    results = [g["result"] for g in p["gates"]]
    if outcome == "fixed":
        if not p["patch_ref"]:
            problems.append(f"{where}: a fixed outcome needs a written patch (patch_ref)")
        if not p["files_changed"]:
            problems.append(f"{where}: a fixed outcome must change at least one file")
        if not p["tests_added"]:
            problems.append(f"{where}: a fixed outcome needs a focused test (code inspection is not enough)")
        if not p["gates"] or any(r != "pass" for r in results):
            problems.append(f"{where}: a fixed outcome needs every verification gate to pass")
        if not check_validations.meaningful(p["reproduction_after"]):
            problems.append(f"{where}: a fixed outcome needs evidence the issue no longer reproduces (reproduction_after)")
        if not check_validations.meaningful(p["reproduction_before"]):
            problems.append(f"{where}: a fixed outcome needs the before-state reproduction (reproduction_before)")
    elif outcome == "no_change":
        if p["patch_ref"] is not None:
            problems.append(f"{where}: a no_change outcome writes no patch (patch_ref must be null)")
        if p["files_changed"]:
            problems.append(f"{where}: a no_change outcome changes no file")
        if not check_validations.meaningful(p["patch_strategy"]):
            problems.append(f"{where}: a no_change outcome must explain why the current code is already safe")
    elif outcome in ("blocked", "inconclusive"):
        if not p.get("proof_gap") or not check_validations.meaningful(p["proof_gap"]):
            problems.append(f"{where}: a {outcome} outcome needs the exact proof_gap")
        if any(r == "pass" for r in results) and outcome == "blocked":
            # a blocked outcome means no safe fix was produced; passing every gate would be "fixed"
            if p["gates"] and all(r == "pass" for r in results) and p["patch_ref"]:
                problems.append(f"{where}: every gate passed with a written patch; that is a fixed outcome, not blocked")
        if outcome == "inconclusive" and p["confidence"]["level"] == "High":
            problems.append(f"{where}: an inconclusive outcome cannot have High confidence")


def check(data, stage_dir, repo):
    normalized, problems = npp.normalize(data)
    if problems:
        return problems
    if normalized != data:
        return ["patches.json is not in normalized form; run normalize_patches.py first"]
    record = data["record"]
    problems += [f"{where} still holds a '{FILL}' placeholder" for where in check_validations.unfilled(data)]
    for field, value in record.items():
        if isinstance(value, str) and value.startswith("<") and FILL not in value:
            problems.append(f"record.{field} still holds a template placeholder")
    if record["model"].strip().lower() in GENERIC_MODELS:
        problems.append("record.model must name the exact model and version reported by the client, or 'unknown'")

    if record["status"] == "blocked":
        if data["patches"]:
            problems.append("a blocked record has no patches")
        if data["environment"] is not None:
            problems.append("a blocked record built no container, so environment must be null")
        return problems

    problems += check_findings.identity_problems(repo, record["scope"], record, "record")
    if data["environment"] is None:
        problems.append("environment is required once a container has been built (null only for a blocked run)")
    stage3b, analyses = load_stage3b(data, stage_dir, repo, problems)
    for label in ("threat_model", "security_guidance"):
        if data[label] is not None:
            read_ref(data[label], stage_dir, label, problems)

    authorization = record["authorization"]
    if authorization.startswith(INHERITED):
        run3b = data["validated_record"].get("run_id")
        if record["run_id"] != run3b:
            problems.append("inherited authorization is only valid in the stage 3b record's own run (same run_id)")
        elif stage3b and authorization != inherited_text(run3b, stage3b.get("record", {}).get("authorization", "")):
            problems.append("inherited authorization must repeat the stage 3b record's authorization value exactly")
    elif not check_validations.quoted(authorization):
        problems.append("record.authorization must quote the user's request")

    reportable = {ap: a for ap, a in analyses.items() if a["decision"] == PATCHABLE}
    other = {ap: a for ap, a in analyses.items() if a["decision"] != PATCHABLE}
    for p in data["patches"]:
        where = f"patches[{p['id']}]"
        a = analyses.get(p["analysis_id"])
        if a is None:
            problems.append(f"{where}: {p['analysis_id']} is not in the stage 3b record")
        elif a["decision"] != PATCHABLE:
            problems.append(f"{where}: {p['analysis_id']} was {a['decision']} in stage 3b, not reportable, so it is not patched")
        else:
            for field, theirs in (("finding_id", a["finding_id"]), ("finding_key", a["finding_key"]),
                                  ("finding_fingerprint", a.get("finding_fingerprint")), ("title", a["title"]),
                                  ("severity", a["severity"]), ("priority", a["priority"])):
                if p.get(field) != theirs:
                    problems.append(f"{where}: {field} {p.get(field)!r} does not match the stage 3b analysis ({theirs!r})")
            if p["locations"] != a["locations"]:
                problems.append(f"{where}: locations must be the stage 3b analysis's locations, unchanged")
        check_outcome(p, problems)

    listed = {(n["analysis_id"], n["finding_id"]) for n in data["not_eligible"]}
    wanted = {(ap, a["finding_id"]) for ap, a in other.items()}
    if analyses and listed != wanted:
        problems.append(f"not_eligible must list exactly the deferred and ignore analyses {sorted(w[1] for w in wanted)}, "
                        f"not {sorted(item[1] for item in listed)}")

    if record["status"] == "complete":
        patched = {p["analysis_id"] for p in data["patches"]}
        gaps = " ".join(record["coverage_gaps"])
        for ap, a in sorted(reportable.items()):
            if ap not in patched and not re.search(rf"\b{re.escape(a['finding_id'])}\b", gaps):
                problems.append(f"status cannot be complete: {a['finding_id']} ({ap}) was neither patched nor named "
                                "in record.coverage_gaps")
        if any(p["outcome"] in ("blocked", "inconclusive") for p in data["patches"]):
            problems.append("status cannot be complete while a patch outcome is blocked or inconclusive")
        if data["environment"] and data["environment"]["cleanup"]["remaining"] != 0:
            problems.append("status cannot be complete while labelled resources remain after clean-up")
    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", required=True, help="repository root")
    parser.add_argument("patches", help="patches.json to check")
    args = parser.parse_args()
    repo = Path(args.repo).expanduser().resolve()
    source = Path(args.patches).expanduser().resolve()
    if not repo.is_dir() or not source.is_file():
        parser.exit(2, "error: --repo must be a directory and patches must be a file\n")
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
        problems = check(data, source.parent, repo)
    except (ValueError, UnicodeDecodeError) as exc:
        problems = [f"not valid JSON: {exc}"]
    print(json.dumps({"valid": not problems, "problems": problems}, indent=2))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
