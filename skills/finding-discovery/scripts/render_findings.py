#!/usr/bin/env python3
"""Render findings.json as findings.md, the reviewer's view of a finding-discovery run.

The Markdown starts with the stage record as a YAML header (the record fields plus
threat_model_ref and counts derived from the body), followed by a summary, the reconciliation of
every hypothesis and seed, one section per finding, threat-model feedback, carried-forward stage 1
open questions, coverage, coverage gaps, and open questions. Locations are written as backtick
`path:line` citations, so check_citations.py can check the output. findings.md is never edited
by hand: change findings.json and render again.

Run check_findings.py first; this script only refuses input that fails the schema or has not been
normalized.

Writes <folder of findings.json>/findings.md (or --out). Prints one JSON object: written, findings.
Exit codes: 0 written; 1 input invalid; 2 bad arguments.
Standard library only; Python 3.9+. Writes only the Markdown file.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import normalize_findings  # noqa: E402  (this skill's scripts folder)

RECORD_ORDER = (
    "record_version", "stage", "status", "run_id", "timestamp", "actor", "model", "skill_version",
    "target_id", "target_kind", "version", "revision", "scope", "authorization", "output_location",
    "source", "inputs", "independent_baseline", "tools", "evidence", "assumptions", "coverage_gaps",
)
CONFIDENCE = ("High", "Medium", "Low")
DISPOSITIONS = ("findings", "no-finding", "open-question", "not-investigated")


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
        if not value:
            return [f"{name}: []"]
        return [f"{name}:"] + [f"  - {yaml_value(item)}" for item in value]
    if isinstance(value, dict):
        return [f"{name}: {{{', '.join(f'{key}: {yaml_value(item)}' for key, item in value.items())}}}"]
    return [f"{name}: {yaml_value(value)}"]


def citation(location):
    lines = str(location["start_line"])
    if location["end_line"] != location["start_line"]:
        lines += f"-{location['end_line']}"
    return f"`{location['path']}:{lines}`"


def cell(text):
    return str(text).replace("|", "\\|").replace("\r", "").replace("\n", "<br>")


def bullet(label, text):
    lines = str(text).splitlines() or [""]
    return [f"- **{label}:** {lines[0]}"] + [f"  {line}" if line else "" for line in lines[1:]]


def bullet_list(label, items, empty="none"):
    if not items:
        return [f"- **{label}:** {empty}"]
    return [f"- **{label}:**"] + [f"  - {item}" for item in items]


def header(data):
    record, findings = data["record"], data["findings"]
    ref = data["threat_model"]
    lines = ["---"]
    for name in RECORD_ORDER:
        lines += yaml_field(name, record[name])
    lines += yaml_field("threat_model_ref", f"{ref['path']} sha256:{ref['sha256']}" if ref else "none")
    lines += yaml_field("findings", {level.lower(): sum(finding["confidence"]["level"] == level for finding in findings)
                                     for level in CONFIDENCE})
    lines += yaml_field("reconciliation", {name: sum(row["disposition"] == name for row in data["reconciliation"])
                                           for name in DISPOSITIONS})
    lines += yaml_field("coverage", data["coverage"]["completeness"])
    lines += yaml_field("next_action", record["next_action"])
    return lines + ["---", ""]


def finding_section(finding):
    title = f"### {finding['id']}: {finding['title']}"
    family = f"`{finding['family']}`" + (f" (instance `{finding['instance']}`)" if finding.get("instance") else "")
    lines = [title, "",
             f"- **Status:** unvalidated. **Confidence:** {finding['confidence']['level']}: {finding['confidence']['reason']}",
             f"- **Family:** {family}. **CWE:** {', '.join(finding['cwe_ids']) or 'unclassified'}",
             f"- **Origin:** {', '.join(finding['origin'])}. **Hypothesis priority:** {finding['hypothesis_priority'] or 'none'}",
             f"- **Fingerprint:** `{finding['fingerprint']}`. **Discovered by:** {', '.join(finding['discovered_by'])}"]
    lines += bullet_list("Locations", [f"{location['role']}: {citation(location)}" for location in finding["locations"]])
    for label, field in (("Attacker", "attacker"), ("Source", "source"), ("Control", "control"), ("Sink", "sink"),
                         ("Path", "path"), ("Impact", "impact")):
        lines += bullet(label, finding[field])
    lines += bullet_list("Exposure assumptions", finding["exposure_assumptions"])
    lines += bullet("Counterevidence", finding["counterevidence"])
    lines += bullet_list("Proof gaps", finding["proof_gaps"])
    lines += bullet("Investigation question", finding["investigation_question"])
    if finding.get("merged_from"):
        lines.append(f"- **Merged from:** {', '.join(finding['merged_from'])}")
    if finding.get("related"):
        lines.append(f"- **Related:** {', '.join(finding['related'])}")
    if finding.get("excerpt"):
        lines += ["- **Excerpt:**", "", "  ```text"] + [f"  {line}" for line in finding["excerpt"].splitlines()] + ["  ```"]
    return lines + [""]


def render(data):
    record, findings, coverage = data["record"], data["findings"], data["coverage"]
    lines = header(data)
    lines += [f"# Finding discovery: run {record['run_id']}", "",
              "> Every finding in this document is unvalidated: stage 3 decides whether it holds. Treat this file as sensitive.", ""]
    if record["status"] == "blocked":
        return "\n".join(lines + [f"Blocked. {record['next_action']}", ""])

    ref = data["threat_model"]
    counts = {level: sum(finding["confidence"]["level"] == level for finding in findings) for level in CONFIDENCE}
    lines += ["## Summary", "",
              f"- **Status:** {record['status']}",
              f"- **Threat model:** " + (f"`{ref['path']}` (run {ref['run_id']})" if ref else "none (narrow scan)"),
              f"- **Findings:** {len(findings)} (" + ", ".join(f"{level} {count}" for level, count in counts.items()) + ")",
              f"- **Coverage:** {coverage['completeness']}, {len(coverage['reviewed_files'])} file(s) fully reviewed",
              f"- **Independent baseline:** {record['independent_baseline']}", ""]

    lines += ["## Hypotheses and seeds", ""]
    if data["reconciliation"]:
        lines += ["| Ref | Disposition | Findings | Note | Evidence |", "| --- | --- | --- | --- | --- |"]
        for row in data["reconciliation"]:
            evidence = ", ".join(citation(location) for location in row.get("evidence", []))
            lines.append(f"| {row['ref']} | {row['disposition']} | {', '.join(row.get('findings', []))} | "
                         f"{cell(row['note'])} | {evidence} |")
    else:
        lines.append("No hypotheses or seeds to reconcile.")
    lines.append("")

    if data["seeds"]:
        lines += ["## Seeds", "", "| ID | Kind | Label | Summary | Locations |", "| --- | --- | --- | --- | --- |"]
        for seed in data["seeds"]:
            lines.append(f"| {seed['id']} | {seed['kind']} | {cell(seed['label'])} | {cell(seed['summary'])} | "
                         f"{', '.join(citation(location) for location in seed.get('locations', []))} |")
        lines.append("")

    lines += ["## Findings", ""]
    if findings:
        for finding in findings:
            lines += finding_section(finding)
    else:
        lines += ["No plausible findings in the reviewed scope. The reconciliation and coverage sections show what was checked.", ""]

    missed = [finding for finding in findings if finding["origin"] == ["open-ended"]]
    if ref and missed:
        lines += ["## Boundaries the threat model missed", "",
                  "These findings match no stage 1 hypothesis. Consider them when the threat model is next updated.", ""]
        lines += [f"- {finding['id']}: {finding['title']}" for finding in missed] + [""]

    if data["stage1_open_questions"]:
        lines += ["## Stage 1 open questions", ""]
        lines += [f"{question['number']}. **{question['status'].capitalize()}:** {cell(question['note'])}"
                  for question in data["stage1_open_questions"]] + [""]

    lines += ["## Coverage", "",
              f"- **Scope inventory:** `{coverage['inventory']}`",
              f"- **Completeness:** {coverage['completeness']}",
              f"- **Fully reviewed files:** {len(coverage['reviewed_files'])}"]
    lines += bullet_list("Not reviewed", [f"{', '.join(entry['paths'])}: {cell(entry['reason'])}"
                                          for entry in coverage["remaining"]])
    lines += bullet_list("Exclusions", [f"`{entry['pattern']}`: {cell(entry['reason'])}" for entry in coverage["exclusions"]])
    lines += ["", "## Coverage gaps", ""]
    lines += [f"- {cell(gap)}" for gap in record["coverage_gaps"]] or ["- None."]
    lines += ["", "## Open questions", ""]
    lines += [f"{number}. {cell(question)}" for number, question in enumerate(data["open_questions"], 1)] or ["None."]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", help="Markdown file to write (default: findings.md beside the input)")
    parser.add_argument("findings", help="normalized findings.json")
    args = parser.parse_args()
    source = Path(args.findings).expanduser().resolve()
    if not source.is_file():
        parser.exit(2, "error: findings must be a file\n")
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        print(json.dumps({"written": None, "problems": [f"not valid JSON: {exc}"]}, indent=2))
        return 1
    problems = normalize_findings.validate(data)
    if not problems and any("id" not in finding or "fingerprint" not in finding for finding in data["findings"]):
        problems = ["findings.json is not normalized; run normalize_findings.py and check_findings.py first"]
    if problems:
        print(json.dumps({"written": None, "problems": problems}, indent=2))
        return 1
    out = Path(args.out).expanduser().resolve() if args.out else source.parent / "findings.md"
    out.write_text(render(data), encoding="utf-8")
    print(json.dumps({"written": str(out), "findings": len(data["findings"])}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
