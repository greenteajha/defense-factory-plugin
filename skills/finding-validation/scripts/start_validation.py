#!/usr/bin/env python3
"""Check the stage 2 findings.json, then start a finding-validation record.

The stage 2 record must pass check_findings.py (which also confirms its version still matches the
code), have status complete or inconclusive, and still identify the same target. If any of this
fails, nothing is written and the problems are reported, so the user can choose to rerun stage 2.

Writes into --stage-dir (from prepare_workspace.py, normally .../runs/<run_id>/3-finding-validation):
  validations.json  a skeleton: the record with target identity, run ID, timestamp, and
                    skill_version filled in; the stage 2 reference and digest; environment null
                    (the agent fills it after building the container); one validation entry per
                    selected finding, with the verdict fields marked "<fill: ...>". Authorization
                    is pre-filled as inherited when the stage 2 record belongs to the same run.

Selection: without --finding, every stage 2 finding is included; with one or more --finding FD-n,
only those are, and the rest are recorded in coverage_gaps so the run can still complete.

Prints one JSON object: created, findings_selected, findings_deferred, authorization_inherited,
problems. Exit codes: 0 created; 1 the stage 2 record cannot be used (nothing written); 2 bad
arguments; 3 validations.json already exists (never overwritten).
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
import check_findings  # noqa: E402  (shared helper)
import check_validations  # noqa: E402  (this skill's scripts folder)
import normalize_validations  # noqa: E402
import prepare_workspace  # noqa: E402  (shared helper)
import target_identity  # noqa: E402  (shared helper)

STAGE = "3-finding-validation"
HELPERS = "prepare_workspace.py, start_validation.py, check_environment.py, export_target.py, cleanup_run.py"


def fill(text):
    return f"<fill: {text}>"


def entry_skeleton(finding, affected_version):
    return {
        "finding_id": finding["id"],
        "finding_key": finding["key"],
        "finding_fingerprint": finding.get("fingerprint"),
        "title": finding["title"],
        "verdict": "inconclusive",
        "method": "static-assessment",
        "reproduced": False,
        "rubric": [{"criterion": fill(f'from the investigation_question: "{finding.get("investigation_question", "")}"'
                                      " -- up to five pass/fail criteria decided before running"),
                    "result": "unknown"}],
        "control": fill("the harmless control you ran first and its result"),
        "reachability": fill("evidence the attacker-controlled input reached the suspected sink; required to confirm"),
        "repeat_confirmed": False,
        "evidence": fill("what you observed, with artifact paths; this grounds the verdict"),
        "counterevidence_or_proof_gap": fill("for rejected, the control that holds; for inconclusive, the exact missing proof"),
        "setup_notes": fill("what you installed; record any setup failure, which is never counterevidence"),
        "remaining_uncertainty": fill("what a stronger test would still add"),
        "confidence": {"level": "Low", "reason": fill("calibrated from the method and evidence, not the bug class")},
        "next_step": fill("the minimal next action if more proof is needed"),
        "affected_version": affected_version,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", default=".", help="target root (default: current directory)")
    parser.add_argument("--stage-dir", required=True, help="stage folder printed by prepare_workspace.py")
    parser.add_argument("--findings", required=True, help="stage 2 findings.json (from find_findings.py)")
    parser.add_argument("--finding", action="append", default=[], help="FD id to validate; repeatable (default: all)")
    args = parser.parse_args()

    stage_dir = Path(args.stage_dir).expanduser().resolve()
    if not stage_dir.is_dir() or stage_dir.name != STAGE:
        parser.exit(2, f"error: --stage-dir must be an existing folder named {STAGE} (from prepare_workspace.py)\n")
    out_file = stage_dir / "validations.json"
    if out_file.exists():
        parser.exit(3, f"error: {out_file} already exists; it is never overwritten\n")
    findings_path = Path(args.findings).expanduser().resolve()
    if not findings_path.is_file():
        parser.exit(2, f"error: {findings_path} is not a file\n")
    try:
        repo_root = target_identity.resolve(args.root, [])[0]
    except ValueError as exc:
        parser.exit(2, f"error: {exc}\n")

    try:
        raw = findings_path.read_bytes()
        stage2 = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        print(json.dumps({"created": None, "problems": [f"cannot read the stage 2 findings.json: {exc}"]}, indent=2))
        return 1
    problems = check_findings.check(stage2, findings_path.parent, repo_root)
    stage2_record = stage2.get("record", {})
    if stage2_record.get("status") not in ("complete", "inconclusive"):
        problems.append(f"stage 2 status {stage2_record.get('status')!r} cannot start stage 3")
    if problems:
        print(json.dumps({"created": None, "problems": problems}, indent=2))
        return 1

    scope = stage2_record["scope"]
    findings = {finding["id"]: finding for finding in stage2.get("findings", [])}
    selected_ids = args.finding or list(findings)
    unknown = [fid for fid in selected_ids if fid not in findings]
    if unknown:
        print(json.dumps({"created": None, "problems": [f"unknown finding id(s): {', '.join(unknown)}"]}, indent=2))
        return 1
    selected = [findings[fid] for fid in selected_ids]
    deferred = [fid for fid in findings if fid not in set(selected_ids)]

    identity = target_identity.identify(repo_root, check_findings.scope_items(scope))
    run_id = stage_dir.parent.name

    inherited = stage2_record.get("run_id") == run_id
    authorization = (check_validations.inherited_text(run_id, str(stage2_record.get("authorization", "")))
                     if inherited else fill('requested by the user in session on <date>: "<their request, quoted>"'))
    default_location = repo_root / ".defense-factory"
    output_location = ("default .defense-factory (Git-ignored)" if default_location in stage_dir.parents
                       else fill("user-chosen: <path> (ignored or not ignored by Git)"))
    coverage_gaps = [f"{fid}: not selected for validation in this run." for fid in deferred]

    data = {
        "record": {
            "record_version": 1,
            "stage": STAGE,
            "status": "inconclusive",
            "run_id": run_id,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "actor": fill("agent and client; requesting user if known"),
            "model": fill("exact model and version the client reports, or unknown"),
            "skill_version": prepare_workspace.skill_version(),
            "target_id": identity["target_id"],
            "target_kind": identity["target_kind"],
            "version": identity["version"],
            "revision": identity["revision"],
            "scope": scope,
            "authorization": authorization,
            "output_location": output_location,
            "source": "validated-record",
            "inputs": [],
            "tools": f"Python {platform.python_version()}; {HELPERS}; " + fill("add the engine and version, e.g. docker 29.6.2"),
            "evidence": "citations in validation.md; artifacts/ per finding; container-build/",
            "assumptions": [],
            "coverage_gaps": coverage_gaps,
            "next_action": fill("recommended next step, normally human triage of the confirmed findings"),
        },
        "validated_record": {
            "path": Path(os.path.relpath(findings_path, stage_dir)).as_posix(),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "run_id": stage2_record.get("run_id", ""),
        },
        "environment": None,
        "validations": [entry_skeleton(finding, identity["version"]) for finding in selected],
        "open_questions": [],
    }
    out_file.write_text(normalize_validations.dump(data), encoding="utf-8")
    print(json.dumps({
        "created": str(out_file),
        "findings_selected": [finding["id"] for finding in selected],
        "findings_deferred": deferred,
        "authorization_inherited": inherited,
        "problems": [],
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
