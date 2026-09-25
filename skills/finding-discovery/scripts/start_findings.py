#!/usr/bin/env python3
"""Check the stage 1 threat model, then start a finding-discovery record.

With --threat-model (the stage 1 run copy, normally <run>/1-threat-model/threat-model.md), the
model must pass check_model.py, have status complete or inconclusive, and still match the code:
its target_id and version are recomputed for its own scope. A requested --scope must lie inside
the model's scope; without --scope, the model's scope is used. If any of this fails, nothing is
written and the problems are reported, so the user can choose between rerunning stage 1 and a
narrow scan.

Without --threat-model (a narrow scan), --scope must name paths below the repository root; for a
whole repository, run the threat-model skill first.

Writes into --stage-dir (from prepare_workspace.py, normally .../runs/<run_id>/2-finding-discovery):
  scope-inventory.txt  the in-scope files (list_scope_files.py rules)
  findings.json        a skeleton: the record with target identity, run ID, timestamp, and
                       skill_version filled in; the threat-model reference and digest; one
                       reconciliation row per TM-H hypothesis; one entry per stage 1 open
                       question; coverage and exclusions. Every value the agent must supply is
                       marked "<fill: ...>"; check_findings.py fails while any remains.
Authorization is pre-filled as inherited when the model belongs to the same run; otherwise the
user's request is left to fill.

Prints one JSON object: created, inventory ({included, excluded}), hypotheses ([{id, priority}]),
stage1_open_questions, authorization_inherited, problems.

Exit codes: 0 created; 1 the threat model cannot be used (nothing written); 2 bad arguments;
3 findings.json already exists (never overwritten).
Standard library only; Python 3.9+. Writes only inside --stage-dir.
"""

import argparse
import hashlib
import json
import os
import platform
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_findings  # noqa: E402  (this skill's scripts folder, including shared helpers)
import check_model  # noqa: E402
import list_scope_files  # noqa: E402
import normalize_findings  # noqa: E402
import prepare_workspace  # noqa: E402
import target_identity  # noqa: E402

STAGE = "2-finding-discovery"
HELPERS = "prepare_workspace.py, start_findings.py (with list_scope_files.py)"


def by_number(hypotheses):
    return sorted(hypotheses.items(), key=lambda item: int(item[0][4:]))


def fill(text):
    return f"<fill: {text}>"


def open_question_texts(body):
    section = re.search(r"^## Open questions\s*$(.*?)(?=^## |\Z)", body, re.MULTILINE | re.DOTALL)
    return re.findall(r"^\d+\.\s+(.*)$", section.group(1), re.MULTILINE) if section else []


def read_model(path, repo_root, requested_scope, problems):
    """Return (header, body, raw bytes) of a usable model, recording every problem."""
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8")
        header, body = normalize_findings.split_model(text)
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        problems.append(f"cannot read the stage 1 model: {exc}")
        return None, None, None
    problems += [f"stage 1 model fails check_model.py: {problem}" for problem in check_model.check(text)]
    if header.get("stage") != "1-threat-model":
        problems.append("the file is not a stage 1 threat-model record")
    if header.get("status") not in ("complete", "inconclusive"):
        problems.append(f"stage 1 status {header.get('status')!r} cannot start stage 2")
    problems += check_findings.identity_problems(repo_root, header.get("scope"), header, "stage 1 model is stale")
    if requested_scope is not None and not check_findings.within(requested_scope, header.get("scope")):
        problems.append("the requested scope is wider than the stage 1 model's scope")
    return header, body, raw


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", default=".", help="target root (default: current directory)")
    parser.add_argument("--stage-dir", required=True, help="stage folder printed by prepare_workspace.py")
    parser.add_argument("--threat-model", help="stage 1 threat-model.md; omit for a narrow scan")
    parser.add_argument("--scope", action="append", default=[], help="in-scope path; repeatable")
    parser.add_argument("--exclude", action="append", default=[], help="glob the user asked to exclude; repeatable")
    args = parser.parse_args()

    stage_dir = Path(args.stage_dir).expanduser().resolve()
    if not stage_dir.is_dir() or stage_dir.name != STAGE:
        parser.exit(2, f"error: --stage-dir must be an existing folder named {STAGE} (from prepare_workspace.py)\n")
    findings_file = stage_dir / "findings.json"
    if findings_file.exists():
        parser.exit(3, f"error: {findings_file} already exists; it is never overwritten\n")
    try:
        repo_root, in_git, _ = target_identity.resolve(args.root, [])
        scope_paths = target_identity.resolve(args.root, args.scope)[2] if args.scope else None
    except ValueError as exc:
        parser.exit(2, f"error: {exc}\n")
    requested = None if scope_paths is None else ("whole-repository" if scope_paths == ["."] else scope_paths)
    run_id = stage_dir.parent.name

    problems, header, body, raw = [], None, None, None
    model = Path(args.threat_model).expanduser().resolve() if args.threat_model else None
    if model is not None:
        header, body, raw = read_model(model, repo_root, requested, problems)
        scope = requested if requested is not None else (header or {}).get("scope", "whole-repository")
    else:
        if requested in (None, "whole-repository"):
            parser.exit(2, "error: a narrow scan needs --scope paths below the repository root; for a whole "
                           "repository, run the threat-model skill first\n")
        scope = requested
    if problems:
        print(json.dumps({"created": None, "problems": problems}, indent=2))
        return 1

    identity = target_identity.identify(repo_root, check_findings.scope_items(scope))
    included, excluded = list_scope_files.build(repo_root, identity["scope"], in_git, args.exclude)
    list_scope_files.write_inventory(stage_dir / "scope-inventory.txt", included)

    inherited = False
    authorization = fill('requested by the user in session on <date>: "<their request, quoted>"')
    coverage_gaps = []
    if header:
        stage1_authorization = str(header.get("authorization", ""))
        if header.get("run_id") == run_id:
            authorization = check_findings.inherited_text(run_id, stage1_authorization)
            inherited = True
        stage1_gaps = header.get("coverage_gaps") or []
        coverage_gaps = [f"From stage 1: {gap}" for gap in (stage1_gaps if isinstance(stage1_gaps, list) else [stage1_gaps])]
    else:
        coverage_gaps = ["No threat model: narrow scan of the named paths, so there were no hypotheses to reconcile."]
    default_location = repo_root / ".defense-factory"
    output_location = ("default .defense-factory (Git-ignored)" if default_location in stage_dir.parents
                       else fill("user-chosen: <path> (ignored or not ignored by Git)"))

    hypotheses = normalize_findings.stage1_hypotheses(raw.decode("utf-8")) if raw else {}
    questions = open_question_texts(body) if body is not None else []
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
            "source": "stage-1-record" if header else "narrow-scan",
            "inputs": [],
            "independent_baseline": "not-performed: " + fill("reason; or replace the whole value with independent or not-independent"),
            "tools": f"Python {platform.python_version()}; {HELPERS}; " + fill("add every other helper you ran"),
            "evidence": "citations in findings.md; scope-inventory.txt; security-guidance.md",
            "assumptions": [],
            "coverage_gaps": coverage_gaps,
            "next_action": fill("recommended next step, normally stage 3 validation of the highest-priority findings"),
        },
        "threat_model": {
            "path": Path(os.path.relpath(model, stage_dir)).as_posix(),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "run_id": header.get("run_id", ""),
        } if header else None,
        "seeds": [],
        "findings": [],
        "reconciliation": [
            {"ref": ref, "disposition": "not-investigated",
             "note": fill(f"{priority.capitalize() if priority else 'unknown priority'} hypothesis: change the disposition "
                          "to findings, no-finding, or open-question, or give the reason it was not investigated")}
            for ref, priority in by_number(hypotheses)
        ],
        "stage1_open_questions": [
            {"number": number, "status": "open", "note": fill(f"{text} -- answered (with evidence) or still open")}
            for number, text in enumerate(questions, 1)
        ],
        "coverage": {
            "inventory": "scope-inventory.txt",
            "reviewed_files": [],
            "completeness": "partial",
            "remaining": [{"paths": ["."], "reason": fill("replace with the paths not fully reviewed and why, or empty "
                                                          "this list and set completeness to complete")}],
            "exclusions": [{"pattern": rule, "reason": f"{len(paths)} file(s) excluded by list_scope_files.py"}
                           for rule, paths in sorted(excluded.items())],
        },
        "open_questions": [],
    }
    findings_file.write_text(normalize_findings.dump(data), encoding="utf-8")
    print(json.dumps({
        "created": str(findings_file),
        "inventory": {"included": len(included), "excluded": {rule: len(paths) for rule, paths in sorted(excluded.items())}},
        "hypotheses": [{"id": ref, "priority": priority} for ref, priority in by_number(hypotheses)],
        "stage1_open_questions": len(questions),
        "authorization_inherited": inherited,
        "problems": [],
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
