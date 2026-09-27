#!/usr/bin/env python3
"""Check the stage 3b attack-paths.json, then start a patch-preparation record (stage 4).

The stage 3b record must pass check_attack_paths.py (which also re-checks the stage 1-3 records and
confirms the code is unchanged) and have status complete or inconclusive. If not, nothing is
written and the problems are reported, so the user can run stage 3b first.

Writes into --stage-dir (from prepare_workspace.py, normally .../runs/<run_id>/4-patch-preparation):
  patches.json  a skeleton: the record with target identity, run ID, timestamp, and skill_version
                filled in; references (path and sha256) to the stage 3b record, the stage 1 threat
                model, and the resolved security policy; environment null (filled once the container
                is built); one patch per reportable analysis with its stage 3b locations, severity,
                and priority copied and "<fill: ...>" markers; and every deferred or ignore analysis
                under not_eligible. Authorization is pre-filled as inherited when the stage 3b
                record belongs to the same run.

Selection: without --finding, every reportable finding is included; with one or more --finding FD-n,
only those are, and the other reportable findings are named in coverage_gaps.

Prints one JSON object: created, patches, not_eligible, not_selected, authorization_inherited,
problems. Exit codes: 0 created; 1 the stage 3b record cannot be used (nothing written); 2 bad
arguments; 3 patches.json already exists (never overwritten).
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
import check_attack_paths  # noqa: E402  (shared helper)
import check_findings  # noqa: E402  (shared helper)
import check_patches  # noqa: E402  (this skill's scripts folder)
import normalize_patches as npp  # noqa: E402
import prepare_workspace  # noqa: E402  (shared helper)
import target_identity  # noqa: E402  (shared helper)

STAGE = "4-patch-preparation"
HELPERS = "prepare_workspace.py, check_environment.py, find_attack_paths.py, start_patches.py, export_target.py, run_container.py, cleanup_run.py"
PATCHABLE = "reportable"


def fill(text):
    return f"<fill: {text}>"


def file_ref(path, stage_dir, run_id=None):
    raw = path.read_bytes()
    ref = {"path": Path(os.path.relpath(path, stage_dir)).as_posix(), "sha256": hashlib.sha256(raw).hexdigest()}
    if run_id:
        ref["run_id"] = run_id
    return ref


def skeleton(analysis):
    return {
        "analysis_id": analysis["id"],
        "finding_id": analysis["finding_id"],
        "finding_key": analysis["finding_key"],
        "finding_fingerprint": analysis.get("finding_fingerprint"),
        "title": analysis["title"],
        "severity": analysis["severity"],
        "priority": analysis["priority"],
        "outcome": "inconclusive",
        "locations": analysis["locations"],
        "vulnerable_path": fill("the concrete source-to-sink path the fix must close"),
        "security_invariant": fill("the invariant the shared enforcement boundary must preserve"),
        "patch_strategy": fill("the minimal, repository-native fix at the shared boundary, and why"),
        "patch_ref": None,
        "files_changed": [],
        "tests_added": [],
        "gates": [],
        "reproduction_before": fill("cite stage 3's reproduction; do not restate its test inputs"),
        "reproduction_after": fill("what the same reproduction does against the patched code"),
        "legitimate_behavior": fill("the legitimate control that must still work, and its result"),
        "candidate_review": fill("the fresh read-only review of the patch: surviving routes or broken legitimate inputs"),
        "remaining_risk": fill("what the patch does not cover (siblings, other entry points)"),
        "proof_gap": fill("for blocked or inconclusive: the exact missing proof; remove this field for fixed or no_change"),
        "confidence": {"level": "Low", "reason": fill("confidence in this outcome, from the evidence actually obtained")},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", default=".", help="target root (default: current directory)")
    parser.add_argument("--stage-dir", required=True, help="stage folder printed by prepare_workspace.py")
    parser.add_argument("--attack-paths", required=True, help="stage 3b attack-paths.json (from find_attack_paths.py)")
    parser.add_argument("--finding", action="append", default=[], help="FD id to patch; repeatable (default: all reportable)")
    args = parser.parse_args()

    stage_dir = Path(args.stage_dir).expanduser().resolve()
    if not stage_dir.is_dir() or stage_dir.name != STAGE:
        parser.exit(2, f"error: --stage-dir must be an existing folder named {STAGE} (from prepare_workspace.py)\n")
    out_file = stage_dir / "patches.json"
    if out_file.exists():
        parser.exit(3, f"error: {out_file} already exists; it is never overwritten\n")
    ap_path = Path(args.attack_paths).expanduser().resolve()
    if not ap_path.is_file():
        parser.exit(2, f"error: {ap_path} is not a file\n")
    try:
        repo_root = target_identity.resolve(args.root, [])[0]
    except ValueError as exc:
        parser.exit(2, f"error: {exc}\n")

    try:
        stage3b = json.loads(ap_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        print(json.dumps({"created": None, "problems": [f"cannot read the stage 3b attack-paths.json: {exc}"]}, indent=2))
        return 1
    problems = check_attack_paths.check(stage3b, ap_path.parent, repo_root)
    record3b = stage3b.get("record", {})
    if record3b.get("status") not in ("complete", "inconclusive"):
        problems.append(f"stage 3b status {record3b.get('status')!r} cannot start stage 4")
    if problems:
        print(json.dumps({"created": None, "problems": problems}, indent=2))
        return 1

    analyses = stage3b["analyses"]
    reportable = [a for a in analyses if a["decision"] == PATCHABLE]
    other = [a for a in analyses if a["decision"] != PATCHABLE]

    wanted = args.finding or [a["finding_id"] for a in reportable]
    by_finding = {a["finding_id"]: a for a in reportable}
    bad = [fid for fid in wanted if fid not in by_finding]
    if bad:
        print(json.dumps({"created": None, "problems": [f"not a reportable finding in the stage 3b record: {', '.join(bad)}"]}, indent=2))
        return 1
    selected = [by_finding[fid] for fid in wanted]
    not_selected = [a["finding_id"] for a in reportable if a["finding_id"] not in set(wanted)]

    threat_model = None
    tm = stage3b.get("threat_model")
    if isinstance(tm, dict):
        tm_path = (ap_path.parent / tm["path"]).resolve()
        if tm_path.is_file():
            threat_model = file_ref(tm_path, stage_dir, tm.get("run_id"))
    security_guidance = None
    sg = stage3b.get("security_guidance")
    if isinstance(sg, dict):
        sg_path = (ap_path.parent / sg["path"]).resolve()
        if sg_path.is_file():
            security_guidance = file_ref(sg_path, stage_dir, sg.get("run_id"))

    identity = target_identity.identify(repo_root, check_findings.scope_items(record3b["scope"]))
    run_id = stage_dir.parent.name
    inherited = record3b.get("run_id") == run_id
    authorization = (check_patches.inherited_text(run_id, record3b.get("authorization", ""))
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
            "version": identity["version"], "revision": identity["revision"], "scope": record3b["scope"],
            "authorization": authorization, "output_location": output_location, "source": "analysed-record",
            "inputs": [], "tools": f"Python {platform.python_version()}; {HELPERS}; " + fill("add every other helper you ran"),
            "evidence": "patches.md; the diffs under patches/; the stage 1-3b records referenced in patches.json",
            "assumptions": [],
            "coverage_gaps": [f"{fid}: not selected for patch preparation in this run." for fid in not_selected],
            "next_action": fill("normally: stage 5 (human review of the prepared patches), P0 first"),
        },
        "validated_record": file_ref(ap_path, stage_dir, record3b.get("run_id")),
        "threat_model": threat_model,
        "security_guidance": security_guidance,
        "environment": None,
        "patches": [skeleton(a) for a in selected],
        "not_eligible": [{"analysis_id": a["id"], "finding_id": a["finding_id"], "decision": a["decision"],
                          "reason": f"{a['decision']} in stage 3b: not a reportable finding, so no fix is prepared"} for a in other],
        "open_questions": [],
    }
    out_file.write_text(npp.dump(data), encoding="utf-8")
    print(json.dumps({"created": str(out_file), "patches": [a["finding_id"] for a in selected],
                      "not_eligible": [a["finding_id"] for a in other], "not_selected": not_selected,
                      "authorization_inherited": inherited, "problems": []}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
