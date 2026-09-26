#!/usr/bin/env python3
"""Render validations.json as validation.md, the reviewer's view of a finding-validation run.

The Markdown starts with the stage record as a YAML header (the record fields plus a reference to
the stage 2 record and counts derived from the body), then a summary, one section per validated
finding with its rubric as a checklist and its evidence, the container environment, the clean-up
receipt, and open questions. validation.md is never edited by hand: change validations.json and
render again.

Run check_validations.py first; this script only refuses input that fails the schema or has not
been normalized.

Writes <folder of validations.json>/validation.md (or --out). Prints one JSON object: written,
validations. Exit codes: 0 written; 1 input invalid; 2 bad arguments.
Standard library only; Python 3.9+. Writes only the Markdown file.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import normalize_validations  # noqa: E402  (this skill's scripts folder)

RECORD_ORDER = (
    "record_version", "stage", "status", "run_id", "timestamp", "actor", "model", "skill_version",
    "target_id", "target_kind", "version", "revision", "scope", "authorization", "output_location",
    "source", "inputs", "tools", "evidence", "assumptions", "coverage_gaps",
)
VERDICTS = ("confirmed", "rejected", "inconclusive")
CHECK = {"pass": "x", "fail": " ", "unknown": "~"}


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


def bullet(label, text):
    lines = str(text).splitlines() or [""]
    return [f"- **{label}:** {lines[0]}"] + [f"  {line}" if line else "" for line in lines[1:]]


def header(data):
    record, validations = data["record"], data["validations"]
    ref, env = data["validated_record"], data["environment"]
    lines = ["---"]
    for name in RECORD_ORDER:
        lines += yaml_field(name, record[name])
    lines += yaml_field("validated_record_ref", f"{ref['path']} sha256:{ref['sha256']}" if ref else "none")
    lines += yaml_field("verdicts", {verdict: sum(entry["verdict"] == verdict for entry in validations)
                                     for verdict in VERDICTS})
    lines += yaml_field("engine", f"{env['engine']} on {env['host_arch']}" if env else "none")
    if env:
        cleanup = "clean" if env["cleanup"]["remaining"] == 0 else f"incomplete ({env['cleanup']['remaining']} left)"
    else:
        cleanup = "none"
    lines += yaml_field("cleanup", cleanup)
    lines += yaml_field("next_action", record["next_action"])
    return lines + ["---", ""]


def validation_section(entry):
    reproduced = "reproduced" if entry["reproduced"] else "not reproduced"
    if entry["method"] == "static-assessment":
        reproduced = "assessed statically, not reproduced"
    lines = [f"### {entry['id']}: {entry['title']}", "",
             f"- **Finding:** {entry['finding_id']} (`{entry['finding_key']}`)",
             f"- **Verdict:** {entry['verdict']}. **Method:** {entry['method']} ({reproduced}).",
             f"- **Confidence:** {entry['confidence']['level']}: {entry['confidence']['reason']}",
             f"- **Affected version:** {entry['affected_version']}", "",
             "**Rubric:**"]
    lines += [f"- [{CHECK[item['result']]}] {item['criterion']}" for item in entry["rubric"]]
    lines += [""]
    lines += bullet("Control", entry["control"])
    lines += bullet("Reachability", entry["reachability"])
    lines += [f"- **Repeated confirmation:** {'yes' if entry['repeat_confirmed'] else 'no'}"]
    lines += bullet("Evidence", entry["evidence"])
    lines += bullet("Counterevidence / proof gap", entry["counterevidence_or_proof_gap"])
    lines += bullet("Setup notes", entry["setup_notes"])
    lines += bullet("Remaining uncertainty", entry["remaining_uncertainty"])
    lines += bullet("Next step", entry["next_step"])
    if entry.get("artifacts"):
        lines += ["- **Artifacts:**"] + [f"  - `{path}`" for path in entry["artifacts"]]
    return lines + [""]


def environment_section(env):
    if env is None:
        return ["## Environment", "", "No container was built (blocked run).", ""]
    limits = env["limits"]
    lines = ["## Environment", "",
             f"- **Host:** {env['host_os']} / {env['host_arch']}",
             f"- **Engine:** {env['engine']} {env['engine_version']}",
             f"- **Base image:** {env['base_image']} (`{env['base_image_digest']}`)",
             f"- **Emulation:** {env['emulation']}",
             f"- **Code source:** {env['code_source']}",
             f"- **Limits:** memory {limits['memory']}, cpus {limits['cpus']}, pids {limits['pids']}, "
             f"timeout {limits['timeout_seconds']}s",
             f"- **Network:** setup {env['network_setup']}, testing {env['network_testing']}", "",
             "## Clean-up", "",
             f"- **Label:** `{env['cleanup']['label']}`",
             f"- **Removed:** " + ", ".join(f"{count} {kind}" for kind, count in env["cleanup"]["removed"].items()),
             f"- **Remaining:** {env['cleanup']['remaining']}", ""]
    return lines


def render(data):
    validations, env = data["validations"], data["environment"]
    lines = header(data)
    summary = {verdict: sum(entry["verdict"] == verdict for entry in validations) for verdict in VERDICTS}
    lines += ["# Validation report", "",
              f"{len(validations)} finding(s) validated: "
              + ", ".join(f"{count} {verdict}" for verdict, count in summary.items()) + ".", ""]
    lines += ["## Verdicts", ""]
    if validations:
        for entry in validations:
            lines += validation_section(entry)
    else:
        lines += ["No findings were validated in this run.", ""]
    lines += environment_section(env)
    lines += ["## Open questions", ""]
    lines += ([f"- {question}" for question in data["open_questions"]] if data["open_questions"] else ["- None."])
    return "\n".join(lines).rstrip() + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", help="write here instead of validation.md beside validations.json")
    parser.add_argument("validations", help="validations.json to render")
    args = parser.parse_args()
    source = Path(args.validations).expanduser().resolve()
    if not source.is_file():
        parser.exit(2, "error: validations must be a file\n")
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        print(json.dumps({"written": None, "validations": 0, "problems": [f"not valid JSON: {exc}"]}, indent=2))
        return 1
    normalized, problems = normalize_validations.normalize(data)
    if problems or normalized != data:
        print(json.dumps({"written": None, "validations": 0,
                          "problems": problems or ["not in normalized form; run normalize_validations.py first"]}, indent=2))
        return 1
    target = Path(args.out).expanduser().resolve() if args.out else source.parent / "validation.md"
    target.write_text(render(data), encoding="utf-8")
    print(json.dumps({"written": str(target), "validations": len(data["validations"])}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
