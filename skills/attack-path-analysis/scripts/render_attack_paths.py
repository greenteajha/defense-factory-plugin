#!/usr/bin/env python3
"""Render attack-paths.json as attack-paths.md, the reviewer's view of stage 3b.

The Markdown starts with the stage record as a YAML header (the record fields plus a reference to
the stage 3 record and counts by severity and decision), then the priority order, one section per
analysis (affected lines by role, numbered attacker steps, facts, dataflow and reachability,
counterevidence, calibration, decision, change conditions), the findings that were not eligible,
and open questions. Affected lines are written as backtick `path:line` citations, so
check_citations.py can check them. attack-paths.md is never edited by hand: change
attack-paths.json and render again.

Run check_attack_paths.py first; this script only refuses input that fails the schema or has not
been normalized.

Writes <folder of attack-paths.json>/attack-paths.md (or --out). Prints one JSON object: written,
analyses. Exit codes: 0 written; 1 input invalid; 2 bad arguments.
Standard library only; Python 3.9+. Writes only the Markdown file.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import normalize_attack_paths as nap  # noqa: E402  (this skill's scripts folder)

RECORD_ORDER = (
    "record_version", "stage", "status", "run_id", "timestamp", "actor", "model", "skill_version",
    "target_id", "target_kind", "version", "revision", "scope", "authorization", "output_location",
    "source", "inputs", "tools", "evidence", "assumptions", "coverage_gaps",
)
SEVERITIES = ("critical", "high", "medium", "low", "ignore", "unknown")
FACT_LABELS = (
    ("security_vulnerability", "Security vulnerability"), ("in_scope", "In scope"), ("product_surface", "Product surface"),
    ("vector", "Vector"),
    ("auth_scope", "Auth scope"), ("cross_boundary", "Crosses a trust boundary"), ("preconditions", "Preconditions"),
    ("attacker_input_control", "Attacker controls the input"), ("exposure", "Exposure"), ("identity", "Identity"),
    ("impact_surface", "Impact surface"), ("target_reach", "Reach"), ("controls", "Controls"),
    ("secrets", "Secrets"), ("blind_spots", "Blind spots"),
)


def yaml_value(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    return json.dumps(value, ensure_ascii=False)


def yaml_field(name, value):
    if isinstance(value, list):
        return [f"{name}: []"] if not value else [f"{name}:"] + [f"  - {yaml_value(item)}" for item in value]
    if isinstance(value, dict):
        return [f"{name}: {{{', '.join(f'{k}: {yaml_value(v)}' for k, v in value.items())}}}"]
    return [f"{name}: {yaml_value(value)}"]


def cell(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def citation(location):
    lines = str(location["start_line"])
    if location["end_line"] != location["start_line"]:
        lines += f"-{location['end_line']}"
    return f"`{location['path']}:{lines}`"


def bullet(label, text):
    lines = str(text).splitlines() or [""]
    return [f"- **{label}:** {lines[0]}"] + [f"  {line}" if line else "" for line in lines[1:]]


def header(data):
    record, analyses = data["record"], data["analyses"]
    ref = data["validated_record"]
    lines = ["---"]
    for name in RECORD_ORDER:
        lines += yaml_field(name, record[name])
    lines += yaml_field("validated_record_ref", f"{ref['path']} sha256:{ref['sha256']}")
    lines += yaml_field("severities", {s: sum(a["severity"] == s for a in analyses) for s in SEVERITIES})
    lines += yaml_field("decisions", {d: sum(a["decision"] == d for a in analyses) for d in nap.DECISION_ORDER})
    lines += yaml_field("next_action", record["next_action"])
    return lines + ["---", ""]


def analysis_section(a):
    lines = [f"### {a['id']}: {a['title']}", "",
             f"- **Finding:** {a['finding_id']} (`{a['finding_key']}`), validated as {a['validation_id']}: **{a['verdict']}**",
             f"- **Severity:** {a['severity']}. **Priority:** {a['priority'] or 'none'}. **Decision:** {a['decision']}",
             f"- **Confidence:** {a['confidence']['level']}: {a['confidence']['reason']}", "",
             "**Affected lines:**"]
    lines += [f"- {loc['role']}: {citation(loc)}" for loc in a["locations"]]
    lines += ["", "**Attacker steps:**"] + [f"{i}. {step}" for i, step in enumerate(a["attacker_steps"], 1)]
    lines += ["", "**Facts:**"] + [f"- {label}: {a['facts'][key]}" for key, label in FACT_LABELS]
    lines += [""] + bullet("Dataflow", a["dataflow"]) + bullet("Reachability", a["reachability"])
    lines += ["", "**Counterevidence:**"]
    lines += [f"- {c['fact']}: {c['evidence']} ({'dispositive' if c['dispositive'] else 'not dispositive'})"
              for c in a["counterevidence"]]
    lines += ["", "**Calibration:**",
              f"- Impact {a['impact']}, likelihood {a['likelihood']}; critical criteria met: {'yes' if a['critical_criteria_met'] else 'no'}",
              f"- Suppression: {a['suppression'] or 'none'}"]
    if a.get("calibration_override"):
        o = a["calibration_override"]
        lines += [f"- Calibrated by stage 1's table to **{o['severity']}** (matrix: {nap.matrix_severity(a)}): {o['row']}",
                  f"  Reason: {o['reason']}"]
    lines += bullet("Severity rationale", a["severity_rationale"]) + bullet("Change conditions", a["change_conditions"])
    if a.get("proof_gap"):
        lines += bullet("Proof gap", a["proof_gap"])
    return lines + [""]


def render(data):
    analyses = data["analyses"]
    counts = {d: sum(a["decision"] == d for a in analyses) for d in nap.DECISION_ORDER}
    lines = header(data)
    lines += ["# Attack-path analysis", "",
              f"{len(analyses)} finding(s) analysed: " + ", ".join(f"{n} {d}" for d, n in counts.items()) + ".", "",
              "## Priority order", "",
              "| Analysis | Finding | Title | Severity | Priority | Decision |",
              "| --- | --- | --- | --- | --- | --- |"]
    lines += [f"| {a['id']} | {a['finding_id']} | {cell(a['title'])} | {a['severity']} | {a['priority'] or '-'} | {a['decision']} |"
              for a in analyses] or ["| - | - | No findings were analysed. | - | - | - |"]
    lines += ["", "## Analyses", ""]
    for a in analyses:
        lines += analysis_section(a)
    lines += ["## Not eligible", ""]
    lines += ([f"- {n['finding_id']} ({n['validation_id']}, {n['verdict']}): {n['reason']}" for n in data["not_eligible"]]
              or ["- None."])
    lines += ["", "## Open questions", ""]
    lines += [f"- {q}" for q in data["open_questions"]] or ["- None."]
    return "\n".join(lines).rstrip() + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", help="write here instead of attack-paths.md beside attack-paths.json")
    parser.add_argument("attack_paths", help="attack-paths.json to render")
    args = parser.parse_args()
    source = Path(args.attack_paths).expanduser().resolve()
    if not source.is_file():
        parser.exit(2, "error: attack_paths must be a file\n")
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        print(json.dumps({"written": None, "analyses": 0, "problems": [f"not valid JSON: {exc}"]}, indent=2))
        return 1
    normalized, problems = nap.normalize(data)
    if problems or normalized != data:
        print(json.dumps({"written": None, "analyses": 0,
                          "problems": problems or ["not in normalized form; run normalize_attack_paths.py first"]}, indent=2))
        return 1
    target = Path(args.out).expanduser().resolve() if args.out else source.parent / "attack-paths.md"
    target.write_text(render(data), encoding="utf-8")
    print(json.dumps({"written": str(target), "analyses": len(data["analyses"])}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
