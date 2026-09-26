#!/usr/bin/env python3
"""Check an attack-paths.json file before it is saved and rendered. Read-only.

Checks, in order:
  - it passes normalize_attack_paths.py and is already in normalized form;
  - no "<fill: ...>" placeholder remains, the record has no template placeholders, and model names
    an exact model;
  - the record's target_id, target_kind, and version match the target now;
  - the stage 3 validations.json exists, its sha256 matches, it passes check_validations.py (which
    re-checks the stage 2 record and that the code is unchanged), its status is complete or
    inconclusive, its run_id matches, and this run's scope lies within its scope; the threat model
    and security guidance, when referenced, still match their sha256;
  - authorization quotes the user's request, or repeats the stage 3 record's value exactly as
    "inherited from stage 3 run <run_id>: ..." within the same run;
  - coverage: every analysis names a confirmed or inconclusive stage 3 validation, with the same
    finding id, key, fingerprint, title, and verdict, and the stage 2 locations unchanged; no
    rejected finding is analysed; not_eligible lists exactly the rejected findings;
  - the severity policy, recomputed: a scope-gate fact of "no" (or unachievable preconditions)
    needs a suppression reason; severity must equal the policy result (suppression; then a cited
    stage 1 calibration_override, which may not be combined with a suppression, an ignore
    decision, or the matrix's own result; then the impact x likelihood matrix, with critical only
    when the critical criteria are met);
    reportable needs a confirmed verdict and a real severity; ignore needs severity ignore and a
    reason (suppression, an ignore rating, or dispositive counterevidence); deferred needs a
    proof gap and a provisional severity (the policy result, or unknown); an inconclusive verdict
    is always deferred and never High confidence;
  - status complete needs every eligible finding analysed or named in coverage_gaps; a blocked
    record has no analyses.

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
import check_validations  # noqa: E402  (shared helper)
import normalize_attack_paths as nap  # noqa: E402  (this skill's scripts folder)

INHERITED = "inherited from stage 3 run "
GENERIC_MODELS = {"claude", "gpt", "unknown model"}
FILL = "<fill:"
ELIGIBLE = ("confirmed", "inconclusive")


def inherited_text(run_id, stage3_authorization):
    return f"{INHERITED}{run_id}: {str(stage3_authorization).replace(chr(92) + chr(34), chr(34))}"


def read_ref(ref, stage_dir, label, problems):
    """Read a referenced file and confirm its digest. Returns (path, bytes) or (path, None)."""
    path = (stage_dir / ref["path"]).resolve()
    try:
        raw = path.read_bytes()
    except OSError as exc:
        problems.append(f"{label}.path: cannot read {ref['path']} ({exc})")
        return path, None
    if hashlib.sha256(raw).hexdigest() != ref["sha256"]:
        problems.append(f"{label}.sha256 does not match {ref['path']}: it changed after it was read")
    return path, raw


def load_stage3(data, stage_dir, repo, problems):
    """Return (stage 3 data, {VD id: validation}, {FD id: stage 2 finding})."""
    ref = data["validated_record"]
    path, raw = read_ref(ref, stage_dir, "validated_record", problems)
    if raw is None:
        return {}, {}, {}
    try:
        stage3 = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        problems.append(f"validated_record: not valid JSON ({exc})")
        return {}, {}, {}
    problems += [f"stage 3 validations.json: {p}" for p in check_validations.check(stage3, path.parent, repo)]
    record3 = stage3.get("record", {})
    if record3.get("status") not in ("complete", "inconclusive"):
        problems.append(f"stage 3 status {record3.get('status')!r} cannot start stage 3b")
    if ref.get("run_id") != record3.get("run_id"):
        problems.append("validated_record.run_id does not match the stage 3 record's run_id")
    if not check_findings.within(data["record"]["scope"], record3.get("scope")):
        problems.append("record.scope is wider than the stage 3 record's scope")
    findings = {}
    ref2 = stage3.get("validated_record")
    if isinstance(ref2, dict):
        try:
            stage2 = json.loads((path.parent / ref2["path"]).resolve().read_text(encoding="utf-8"))
            findings = {f["id"]: f for f in stage2.get("findings", [])}
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            problems.append(f"cannot read the stage 2 findings.json behind the stage 3 record ({exc})")
    validations = {v["id"]: v for v in stage3.get("validations", []) if "id" in v}
    return stage3, validations, findings


def check_policy(a, problems):
    where = f"analyses[{a.get('id', a['validation_id'])}]"
    facts, decision, severity = a["facts"], a["decision"], a["severity"]
    expected = nap.expected_severity(a)
    gate_fails = (facts["security_vulnerability"] == "no" or facts["in_scope"] == "no"
                  or facts["product_surface"] == "no" or facts["preconditions"] == "unachievable")
    if gate_fails and not a["suppression"]:
        problems.append(f"{where}: the facts fail the scope gate (not a vulnerability, out of scope, not a product "
                        "surface, or unachievable preconditions), so a suppression reason is required")
    override = a.get("calibration_override")
    if override:
        if a["suppression"]:
            problems.append(f"{where}: a calibration_override cannot be combined with a suppression")
        if decision == "ignore":
            problems.append(f"{where}: a calibration_override sets a severity, so the decision cannot be ignore")
        if override["severity"] == nap.matrix_severity(a):
            problems.append(f"{where}: the calibration_override gives the same severity as the matrix; remove it")
    if a["verdict"] == "inconclusive":
        if decision != "deferred":
            problems.append(f"{where}: an inconclusive stage 3 verdict is always deferred, never {decision}")
        if a["confidence"]["level"] == "High":
            problems.append(f"{where}: an inconclusive finding cannot have High confidence")
    if decision == "reportable":
        if a["verdict"] != "confirmed":
            problems.append(f"{where}: only a confirmed finding can be reportable")
        if a["suppression"]:
            problems.append(f"{where}: a suppressed finding cannot be reportable")
        if severity != expected or severity in ("ignore", "unknown"):
            problems.append(f"{where}: reportable severity must be the policy result {expected!r} "
                            f"(impact {a['impact']}, likelihood {a['likelihood']}), not {severity!r}")
    elif decision == "ignore":
        if severity != "ignore":
            problems.append(f"{where}: an ignore decision needs severity 'ignore', not {severity!r}")
        dispositive = any(c["dispositive"] for c in a["counterevidence"])
        if not (a["suppression"] or expected == "ignore" or dispositive):
            problems.append(f"{where}: an ignore decision needs a suppression reason, an 'ignore' rating, or "
                            "dispositive counterevidence")
    elif decision == "deferred":
        if not a.get("proof_gap"):
            problems.append(f"{where}: a deferred decision needs the exact proof_gap")
        allowed = {"unknown"} | ({expected} if expected != "ignore" else set())
        if severity not in allowed:
            problems.append(f"{where}: a deferred severity must be the provisional policy result or 'unknown' "
                            f"(allowed: {sorted(allowed)}), not {severity!r}")


def check(data, stage_dir, repo):
    normalized, problems = nap.normalize(data)
    if problems:
        return problems
    if normalized != data:
        return ["attack-paths.json is not in normalized form; run normalize_attack_paths.py first"]
    record = data["record"]
    problems += [f"{where} still holds a '{FILL}' placeholder" for where in check_validations.unfilled(data)]
    for field, value in record.items():
        if isinstance(value, str) and value.startswith("<") and FILL not in value:
            problems.append(f"record.{field} still holds a template placeholder")
    if record["model"].strip().lower() in GENERIC_MODELS:
        problems.append("record.model must name the exact model and version reported by the client, or 'unknown'")
    if record["status"] == "blocked":
        if data["analyses"]:
            problems.append("a blocked record has no analyses")
        return problems

    problems += check_findings.identity_problems(repo, record["scope"], record, "record")
    stage3, validations, findings = load_stage3(data, stage_dir, repo, problems)
    for label in ("threat_model", "security_guidance"):
        if data[label] is not None:
            read_ref(data[label], stage_dir, label, problems)

    authorization = record["authorization"]
    if authorization.startswith(INHERITED):
        run3 = data["validated_record"].get("run_id")
        if record["run_id"] != run3:
            problems.append("inherited authorization is only valid in the stage 3 record's own run (same run_id)")
        elif stage3 and authorization != inherited_text(run3, stage3.get("record", {}).get("authorization", "")):
            problems.append("inherited authorization must repeat the stage 3 record's authorization value exactly")
    elif not check_validations.quoted(authorization):
        problems.append("record.authorization must quote the user's request")

    rejected = {vd: v for vd, v in validations.items() if v["verdict"] == "rejected"}
    eligible = {vd: v for vd, v in validations.items() if v["verdict"] in ELIGIBLE}
    for a in data["analyses"]:
        where = f"analyses[{a['id']}]"
        v = validations.get(a["validation_id"])
        if v is None:
            problems.append(f"{where}: {a['validation_id']} is not in the stage 3 record")
        elif a["validation_id"] in rejected:
            problems.append(f"{where}: {a['validation_id']} was rejected in stage 3 and must be listed as not eligible")
        else:
            for field, theirs in (("finding_id", v["finding_id"]), ("finding_key", v["finding_key"]),
                                  ("finding_fingerprint", v.get("finding_fingerprint")), ("title", v["title"]),
                                  ("verdict", v["verdict"])):
                if a.get(field) != theirs:
                    problems.append(f"{where}: {field} {a.get(field)!r} does not match the stage 3 record ({theirs!r})")
            finding = findings.get(a["finding_id"])
            if finding is not None and a["locations"] != finding["locations"]:
                problems.append(f"{where}: locations must be the stage 2 finding's locations, unchanged")
        check_policy(a, problems)

    listed = {(n["validation_id"], n["finding_id"]) for n in data["not_eligible"]}
    wanted = {(vd, v["finding_id"]) for vd, v in rejected.items()}
    if validations and listed != wanted:
        problems.append(f"not_eligible must list exactly the rejected findings {sorted(w[1] for w in wanted)}, "
                        f"not {sorted(item[1] for item in listed)}")

    if record["status"] == "complete":
        analysed = {a["validation_id"] for a in data["analyses"]}
        gaps = " ".join(record["coverage_gaps"])
        for vd, v in sorted(eligible.items()):
            if vd not in analysed and not re.search(rf"\b{re.escape(v['finding_id'])}\b", gaps):
                problems.append(f"status cannot be complete: {v['finding_id']} ({vd}) was neither analysed nor named "
                                "in record.coverage_gaps")
    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", required=True, help="repository root")
    parser.add_argument("attack_paths", help="attack-paths.json to check")
    args = parser.parse_args()
    repo = Path(args.repo).expanduser().resolve()
    source = Path(args.attack_paths).expanduser().resolve()
    if not repo.is_dir() or not source.is_file():
        parser.exit(2, "error: --repo must be a directory and attack_paths must be a file\n")
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
        problems = check(data, source.parent, repo)
    except (ValueError, UnicodeDecodeError) as exc:
        problems = [f"not valid JSON: {exc}"]
    print(json.dumps({"valid": not problems, "problems": problems}, indent=2))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
