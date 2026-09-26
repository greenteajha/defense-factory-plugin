#!/usr/bin/env python3
"""Check the stage 3 validations.json, then start an attack-path record (stage 3b).

The stage 3 record must pass check_validations.py (which also re-checks the stage 2 record and
confirms the code is unchanged) and have status complete or inconclusive. If not, nothing is
written and the problems are reported, so the user can run stage 3 first.

Writes into --stage-dir (from prepare_workspace.py, normally .../runs/<run_id>/3b-attack-path-analysis):
  attack-paths.json  a skeleton: the record with target identity, run ID, timestamp, and
                     skill_version filled in; references (path and sha256) to the stage 3 record,
                     the stage 1 threat model, and the resolved security policy; one analysis per
                     eligible finding (stage 3 verdict confirmed or inconclusive) with its stage 2
                     locations copied, ratings set to unknown, and "<fill: ...>" markers; and every
                     rejected finding under not_eligible. Authorization is pre-filled as inherited
                     when the stage 3 record belongs to the same run.

Selection: without --finding, every eligible finding is included; with one or more --finding FD-n,
only those are, and the other eligible findings are named in coverage_gaps.

Prints one JSON object: created, analyses, not_eligible, not_selected, authorization_inherited,
problems. Exit codes: 0 created; 1 the stage 3 record cannot be used (nothing written); 2 bad
arguments; 3 attack-paths.json already exists (never overwritten).
Standard library only; Python 3.9+. Writes only inside --stage-dir.
"""

import argparse
import hashlib
import json
import os
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_attack_paths  # noqa: E402  (this skill's scripts folder)
import check_findings  # noqa: E402  (shared helper)
import check_validations  # noqa: E402  (shared helper)
import normalize_attack_paths as nap  # noqa: E402
import prepare_workspace  # noqa: E402  (shared helper)
import target_identity  # noqa: E402  (shared helper)

STAGE = "3b-attack-path-analysis"
HELPERS = "prepare_workspace.py, find_validations.py, start_attack_paths.py"
ELIGIBLE = ("confirmed", "inconclusive")


def fill(text):
    return f"<fill: {text}>"


def file_ref(path, stage_dir, run_id=None):
    raw = path.read_bytes()
    ref = {"path": Path(os.path.relpath(path, stage_dir)).as_posix(), "sha256": hashlib.sha256(raw).hexdigest()}
    if run_id:
        ref["run_id"] = run_id
    return ref


def skeleton(validation, finding):
    return {
        "validation_id": validation["id"],
        "finding_id": validation["finding_id"],
        "finding_key": validation["finding_key"],
        "finding_fingerprint": validation.get("finding_fingerprint"),
        "title": validation["title"],
        "verdict": validation["verdict"],
        "locations": finding["locations"],
        "facts": {
            "in_scope": "unknown", "security_vulnerability": "unknown", "product_surface": "unknown", "vector": "unknown",
            "auth_scope": "unknown", "cross_boundary": "unknown", "preconditions": "unknown",
            "attacker_input_control": "unknown",
            "exposure": fill("listeners, bind addresses, routing, or manifests that expose the entry point"),
            "identity": fill("who the attacker is and which identity or trust boundary they cross"),
            "impact_surface": fill("what is affected: data, runtime, identity, network, build, or other"),
            "target_reach": fill("one service, a shared component, a fleet, or unknown"),
            "controls": fill("existing controls and mitigations on this path"),
            "secrets": fill("secrets involved, by name and location only, or none"),
            "blind_spots": fill("what could not be seen from the repository"),
        },
        "attacker_steps": [fill("one attacker step per entry, in order")],
        "dataflow": fill("source -> transformations -> sink -> outcome"),
        "reachability": fill(f"attacker -> entry point -> preconditions -> outcome; cite stage 3 {validation['id']} and its artifacts rather than restating test inputs"),
        "counterevidence": [{"fact": fill("which fact this challenges"), "evidence": fill("what was checked and found"),
                             "dispositive": False}],
        "impact": "unknown",
        "likelihood": "unknown",
        "critical_criteria_met": False,
        "suppression": None,
        "severity": "unknown",
        "severity_rationale": fill("why this severity, citing stage 1's calibration table and the policy"),
        "change_conditions": fill("the concrete evidence that would raise or lower the severity"),
        "proof_gap": fill("for deferred: the exact missing proof; remove this field otherwise"),
        "decision": "deferred",
        "confidence": {"level": "Low", "reason": fill("confidence in these facts, kept separate from severity")},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", default=".", help="target root (default: current directory)")
    parser.add_argument("--stage-dir", required=True, help="stage folder printed by prepare_workspace.py")
    parser.add_argument("--validations", required=True, help="stage 3 validations.json (from find_validations.py)")
    parser.add_argument("--finding", action="append", default=[], help="FD id to analyse; repeatable (default: all eligible)")
    args = parser.parse_args()

    stage_dir = Path(args.stage_dir).expanduser().resolve()
    if not stage_dir.is_dir() or stage_dir.name != STAGE:
        parser.exit(2, f"error: --stage-dir must be an existing folder named {STAGE} (from prepare_workspace.py)\n")
    out_file = stage_dir / "attack-paths.json"
    if out_file.exists():
        parser.exit(3, f"error: {out_file} already exists; it is never overwritten\n")
    v_path = Path(args.validations).expanduser().resolve()
    if not v_path.is_file():
        parser.exit(2, f"error: {v_path} is not a file\n")
    try:
        repo_root = target_identity.resolve(args.root, [])[0]
    except ValueError as exc:
        parser.exit(2, f"error: {exc}\n")

    try:
        stage3 = json.loads(v_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        print(json.dumps({"created": None, "problems": [f"cannot read the stage 3 validations.json: {exc}"]}, indent=2))
        return 1
    problems = check_validations.check(stage3, v_path.parent, repo_root)
    record3 = stage3.get("record", {})
    if record3.get("status") not in ("complete", "inconclusive"):
        problems.append(f"stage 3 status {record3.get('status')!r} cannot start stage 3b")
    if problems:
        print(json.dumps({"created": None, "problems": problems}, indent=2))
        return 1

    stage2_path = (v_path.parent / stage3["validated_record"]["path"]).resolve()
    stage2 = json.loads(stage2_path.read_text(encoding="utf-8"))
    findings = {f["id"]: f for f in stage2.get("findings", [])}
    validations = [v for v in stage3["validations"]]
    eligible = [v for v in validations if v["verdict"] in ELIGIBLE]
    rejected = [v for v in validations if v["verdict"] == "rejected"]

    wanted = args.finding or [v["finding_id"] for v in eligible]
    by_finding = {v["finding_id"]: v for v in eligible}
    bad = [fid for fid in wanted if fid not in by_finding]
    if bad:
        print(json.dumps({"created": None, "problems": [f"not an eligible (confirmed or inconclusive) finding: {', '.join(bad)}"]}, indent=2))
        return 1
    selected = [by_finding[fid] for fid in wanted]
    not_selected = [v["finding_id"] for v in eligible if v["finding_id"] not in set(wanted)]

    threat_model = None
    tm = stage2.get("threat_model")
    if isinstance(tm, dict):
        tm_path = (stage2_path.parent / tm["path"]).resolve()
        if tm_path.is_file():
            threat_model = file_ref(tm_path, stage_dir, tm.get("run_id"))
    guidance_path = stage2_path.parent / "security-guidance.md"
    security_guidance = file_ref(guidance_path, stage_dir) if guidance_path.is_file() else None

    identity = target_identity.identify(repo_root, check_findings.scope_items(record3["scope"]))
    run_id = stage_dir.parent.name
    inherited = record3.get("run_id") == run_id
    authorization = (check_attack_paths.inherited_text(run_id, record3.get("authorization", ""))
                     if inherited else fill('requested by the user in session on <date>: "<their request, quoted>"'))
    output_location = ("default .defense-factory (Git-ignored)" if (repo_root / ".defense-factory") in stage_dir.parents
                       else fill("user-chosen: <path> (ignored or not ignored by Git)"))

    data = {
        "record": {
            "record_version": 1, "stage": STAGE, "status": "inconclusive", "run_id": run_id,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "actor": fill("agent and client; requesting user if known"),
            "model": fill("exact model and version the client reports, or unknown"),
            "skill_version": prepare_workspace.skill_version(),
            "target_id": identity["target_id"], "target_kind": identity["target_kind"],
            "version": identity["version"], "revision": identity["revision"], "scope": record3["scope"],
            "authorization": authorization, "output_location": output_location, "source": "validated-record",
            "inputs": [], "tools": f"Python {platform.python_version()}; {HELPERS}; " + fill("add every other helper you ran"),
            "evidence": "attack-paths.md; the stage 1-3 records referenced in attack-paths.json",
            "assumptions": [],
            "coverage_gaps": [f"{fid}: not selected for attack-path analysis in this run." for fid in not_selected],
            "next_action": fill("normally: stage 4 (patch preparation) for reportable findings in priority order, or human triage while stage 4 is unavailable"),
        },
        "validated_record": file_ref(v_path, stage_dir, record3.get("run_id")),
        "threat_model": threat_model,
        "security_guidance": security_guidance,
        "analyses": [skeleton(v, findings[v["finding_id"]]) for v in selected],
        "not_eligible": [{"validation_id": v["id"], "finding_id": v["finding_id"], "verdict": "rejected",
                          "reason": "rejected in stage 3: the control held, so there is no attack path to rate"} for v in rejected],
        "open_questions": [],
    }
    out_file.write_text(nap.dump(data), encoding="utf-8")
    print(json.dumps({"created": str(out_file), "analyses": [v["finding_id"] for v in selected],
                      "not_eligible": [v["finding_id"] for v in rejected], "not_selected": not_selected,
                      "authorization_inherited": inherited, "problems": []}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
