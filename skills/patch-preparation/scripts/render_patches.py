#!/usr/bin/env python3
"""Render patches.json as patches.md, the reviewer's view of stage 4.

The Markdown starts with the stage record as a YAML header (the record fields, a reference to the
stage 3b record, counts by outcome, the container environment, and the clean-up receipt), then the
priority order, one section per patch (affected lines by role, the vulnerable path and invariant,
the patch strategy and the diff's path, files changed and tests added, the verification gates, the
before/after reproduction, the patch-candidate review, remaining risk), the analyses that were not
eligible for a patch, and open questions. Affected lines are written as backtick `path:line`
citations. patches.md is never edited by hand: change patches.json and render again.

Run check_patches.py first; this script only refuses input that fails the schema or has not been
normalized.

Writes <folder of patches.json>/patches.md (or --out). Prints one JSON object: written, patches.
Exit codes: 0 written; 1 input invalid; 2 bad arguments.
Standard library only; Python 3.9+. Writes only the Markdown file.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import normalize_patches as npp  # noqa: E402  (this skill's scripts folder)

RECORD_ORDER = (
    "record_version", "stage", "status", "run_id", "timestamp", "actor", "model", "skill_version",
    "target_id", "target_kind", "version", "revision", "scope", "authorization", "output_location",
    "source", "inputs", "tools", "evidence", "assumptions", "coverage_gaps",
)
OUTCOMES = ("fixed", "no_change", "blocked", "inconclusive")


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
    record, patches = data["record"], data["patches"]
    ref = data["validated_record"]
    lines = ["---"]
    for name in RECORD_ORDER:
        lines += yaml_field(name, record[name])
    lines += yaml_field("validated_record_ref", f"{ref['path']} sha256:{ref['sha256']}")
    lines += yaml_field("outcomes", {o: sum(p["outcome"] == o for p in patches) for o in OUTCOMES})
    env = data["environment"]
    if env is not None:
        lines += yaml_field("engine", f"{env['engine']} on {env['host_arch']}")
        lines += yaml_field("cleanup", "clean" if env["cleanup"]["remaining"] == 0
                            else f"incomplete: {env['cleanup']['remaining']} labelled resource(s) remain")
    lines += yaml_field("next_action", record["next_action"])
    return lines + ["---", ""]


def gate_line(gate):
    return f"- {gate['result']}: {gate['gate']}"


def patch_section(p):
    lines = [f"### {p['id']}: {p['title']}", "",
             f"- **Finding:** {p['finding_id']} (`{p['finding_key']}`), from stage 3b {p['analysis_id']}",
             f"- **Severity:** {p['severity']}. **Priority:** {p['priority']}. **Outcome:** {p['outcome']}",
             f"- **Confidence:** {p['confidence']['level']}: {p['confidence']['reason']}", "",
             "**Affected lines:**"]
    lines += [f"- {loc['role']}: {citation(loc)}" for loc in p["locations"]]
    lines += [""] + bullet("Vulnerable path", p["vulnerable_path"]) + bullet("Security invariant", p["security_invariant"])
    lines += bullet("Patch strategy", p["patch_strategy"])
    lines += bullet("Patch diff", p["patch_ref"] if p["patch_ref"] else "none (no file was changed)")
    lines += ["", "**Files changed:**"] + ([f"- `{f}`" for f in p["files_changed"]] or ["- None."])
    lines += ["", "**Tests added:**"] + ([f"- {t}" for t in p["tests_added"]] or ["- None."])
    lines += ["", "**Verification gates:**"] + ([gate_line(g) for g in p["gates"]] or ["- None run."])
    lines += [""] + bullet("Reproduction before", p["reproduction_before"])
    lines += bullet("Reproduction after", p["reproduction_after"])
    lines += bullet("Legitimate behaviour", p["legitimate_behavior"])
    lines += bullet("Patch-candidate review", p["candidate_review"])
    lines += bullet("Remaining risk", p["remaining_risk"])
    if p.get("proof_gap"):
        lines += bullet("Proof gap", p["proof_gap"])
    return lines + [""]


def render(data):
    patches = data["patches"]
    counts = {o: sum(p["outcome"] == o for p in patches) for o in OUTCOMES}
    lines = header(data)
    lines += ["# Patch preparation", "",
              f"{len(patches)} patch(es) prepared: " + ", ".join(f"{n} {o}" for o, n in counts.items()) + ".", "",
              "Each patch is a diff prepared and tested in a disposable container; none is applied to the target.",
              "", "## Priority order", "",
              "| Patch | Finding | Title | Severity | Priority | Outcome |",
              "| --- | --- | --- | --- | --- | --- |"]
    lines += [f"| {p['id']} | {p['finding_id']} | {cell(p['title'])} | {p['severity']} | {p['priority']} | {p['outcome']} |"
              for p in patches] or ["| - | - | No patches were prepared. | - | - | - |"]
    lines += ["", "## Patches", ""]
    for p in patches:
        lines += patch_section(p)
    lines += ["## Not eligible for a patch", ""]
    lines += ([f"- {n['finding_id']} ({n['analysis_id']}, {n['decision']}): {n['reason']}" for n in data["not_eligible"]]
              or ["- None."])
    lines += ["", "## Open questions", ""]
    lines += [f"- {q}" for q in data["open_questions"]] or ["- None."]
    return "\n".join(lines).rstrip() + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", help="write here instead of patches.md beside patches.json")
    parser.add_argument("patches", help="patches.json to render")
    args = parser.parse_args()
    source = Path(args.patches).expanduser().resolve()
    if not source.is_file():
        parser.exit(2, "error: patches must be a file\n")
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        print(json.dumps({"written": None, "patches": 0, "problems": [f"not valid JSON: {exc}"]}, indent=2))
        return 1
    normalized, problems = npp.normalize(data)
    if problems or normalized != data:
        print(json.dumps({"written": None, "patches": 0,
                          "problems": problems or ["not in normalized form; run normalize_patches.py first"]}, indent=2))
        return 1
    target = Path(args.out).expanduser().resolve() if args.out else source.parent / "patches.md"
    target.write_text(render(data), encoding="utf-8")
    print(json.dumps({"written": str(target), "patches": len(data["patches"])}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
