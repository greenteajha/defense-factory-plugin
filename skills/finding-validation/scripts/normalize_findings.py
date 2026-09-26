#!/usr/bin/env python3
"""Validate and normalize a findings.json file, then number its findings.

Steps, in order:
  1. Validate the file against assets/findings.schema.json.
  2. Check every location (findings, seeds, reconciliation evidence): relative path inside the
     repository, an existing file, lines within the file. Strip "./", default end_line to
     start_line, drop repeated locations, and sort them by role (entrypoint, source, root_control,
     sink, concrete_implementation, evidence), then path and line.
  3. Require each finding to have at least one affected location (entrypoint, root_control, sink,
     or concrete_implementation) inside the record's scope; supporting source and evidence may
     lie outside it.
  4. Write CWE IDs as CWE-<n>, sorted and without repeats.
  5. Merge exact duplicates only: findings with the same family, instance, CWE IDs, and locations.
     The finding with the smallest key is kept; the others' keys go into its merged_from. Any
     further merging is the agent's decision (remediation subsumption), never this script's.
  6. Compute each fingerprint from the target ID, family, anchor file (the first root_control
     location, else the first sink, else the first location), and instance; no line numbers.
  7. Set hypothesis_priority to the highest stage 1 priority among the finding's TM-H origins.
  8. Number findings FD-1, FD-2, ... ordered by hypothesis priority, confidence, fingerprint, and
     key, and rewrite every reference (reconciliation rows, related) to the new IDs. References may
     use a finding's key, its previous FD ID, or a merged key.
Running it again on its own output changes nothing.

Writes the result over the input file (or to --out). Prints one JSON object: valid, findings,
merged (list of {kept, absorbed}), problems. Nothing is written when there are problems.

Exit codes: 0 normalized; 1 problems found; 2 bad arguments.
Standard library only; Python 3.9+. Reads the repository; writes only the findings file.
"""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_citations  # noqa: E402  (shared helpers in this skill's scripts folder)
import check_model  # noqa: E402

SCHEMA_FILE = Path(__file__).resolve().parents[1] / "assets" / "findings.schema.json"
ROLE_ORDER = ("entrypoint", "source", "root_control", "sink", "concrete_implementation", "evidence")
AFFECTED_ROLES = {"entrypoint", "root_control", "sink", "concrete_implementation"}
PRIORITIES = ("critical", "high", "medium", "low")
CONFIDENCE_ORDER = ("High", "Medium", "Low")
FINDING_FIELDS = (
    "id", "key", "fingerprint", "title", "family", "instance", "cwe_ids", "origin", "hypothesis_priority",
    "discovered_by", "locations", "attacker", "source", "control", "sink", "path", "impact",
    "exposure_assumptions", "counterevidence", "proof_gaps", "investigation_question", "confidence",
    "merged_from", "related", "excerpt", "status",
)
MERGED_TEXT = ("attacker", "source", "control", "sink", "path", "impact", "counterevidence",
               "investigation_question", "excerpt")
MERGED_LISTS = ("origin", "discovered_by", "exposure_assumptions", "proof_gaps", "related")
AUDITORS = ("baseline", "investigator", "parent")


# JSON Schema subset ---------------------------------------------------------------------------
# Only the keywords findings.schema.json uses. An unknown keyword is an error, so a schema edit can
# never silently weaken validation.

SUPPORTED_KEYWORDS = {
    "$schema", "$id", "$defs", "$ref", "title", "description", "type", "const", "enum", "pattern",
    "minLength", "minItems", "uniqueItems", "minimum", "properties", "required",
    "additionalProperties", "items", "anyOf",
}
TYPES = {"object": dict, "array": list, "string": str, "integer": int, "null": type(None)}


def unsupported_keywords(schema, where="schema"):
    found = []
    if isinstance(schema, dict):
        for key, value in schema.items():
            if key not in SUPPORTED_KEYWORDS:
                found.append(f"{where}: unsupported keyword {key!r}")
            if key in ("properties", "$defs"):
                for name, sub in value.items():
                    found += unsupported_keywords(sub, f"{where}.{key}.{name}")
            elif key in ("items", "additionalProperties"):
                found += unsupported_keywords(value, f"{where}.{key}")
            elif key == "anyOf":
                for index, sub in enumerate(value):
                    found += unsupported_keywords(sub, f"{where}.anyOf[{index}]")
    return found


def is_type(value, name):
    if name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    return isinstance(value, TYPES[name])


def schema_errors(value, schema, root, where):
    if "$ref" in schema:
        return schema_errors(value, root["$defs"][schema["$ref"].rsplit("/", 1)[-1]], root, where)
    if "anyOf" in schema:
        if all(schema_errors(value, sub, root, where) for sub in schema["anyOf"]):
            return [f"{where}: does not match any allowed form"]
        return []
    if "const" in schema and (value != schema["const"] or type(value) is not type(schema["const"])):
        return [f"{where}: must be {json.dumps(schema['const'])}"]
    if "enum" in schema and value not in schema["enum"]:
        return [f"{where}: must be one of {', '.join(map(str, schema['enum']))}"]
    if "type" in schema and not is_type(value, schema["type"]):
        return [f"{where}: must be of type {schema['type']}"]
    errors = []
    if isinstance(value, str):
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errors.append(f"{where}: {value!r} does not match {schema['pattern']}")
        if len(value) < schema.get("minLength", 0):
            errors.append(f"{where}: too short")
    if is_type(value, "integer") and value < schema.get("minimum", value):
        errors.append(f"{where}: must be at least {schema['minimum']}")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            errors.append(f"{where}: needs at least {schema['minItems']} item(s)")
        if schema.get("uniqueItems"):
            seen = [json.dumps(item, sort_keys=True) for item in value]
            if len(seen) != len(set(seen)):
                errors.append(f"{where}: items must be unique")
        if "items" in schema:
            for index, item in enumerate(value):
                errors += schema_errors(item, schema["items"], root, f"{where}[{index}]")
    if isinstance(value, dict):
        for name in schema.get("required", ()):
            if name not in value:
                errors.append(f"{where}: missing field {name!r}")
        properties = schema.get("properties", {})
        for name, item in value.items():
            if name in properties:
                errors += schema_errors(item, properties[name], root, f"{where}.{name}")
            elif schema.get("additionalProperties") is False:
                errors.append(f"{where}: unknown field {name!r}")
    return errors


def load_schema():
    return json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))


def validate(data):
    schema = load_schema()
    return unsupported_keywords(schema) or schema_errors(data, schema, schema, "findings.json")


# Stage 1 model ----------------------------------------------------------------------------------

def split_model(text):
    """Return (header dict, body) of a stage 1 model. Raises ValueError."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---" or "---" not in (line.strip() for line in lines[1:]):
        raise ValueError("missing record header between --- lines")
    end = next(i for i, line in enumerate(lines[1:], 1) if line.strip() == "---")
    return check_model.parse_header(lines[1:end]), "\n".join(lines[end + 1:])


def stage1_hypotheses(text):
    """{TM-H ID: lowercase priority} from the stage 1 hypotheses table."""
    _, body = split_model(text)
    columns, rows = check_model.table_rows(body)
    if columns is None or "priority" not in columns:
        return {}
    index = columns.index("priority")
    return {row[0]: check_model.first_word(row[index]) for row in rows
            if row and len(row) > index and re.fullmatch(r"TM-H\d+", row[0])}


def threat_model_path(data, findings_dir):
    ref = data.get("threat_model")
    return (findings_dir / ref["path"]).resolve() if isinstance(ref, dict) else None


# Normalization ------------------------------------------------------------------------------------

def clean_path(raw):
    path = raw.strip()
    while path.startswith("./"):
        path = path[2:]
    return path


def in_scope(path, scope):
    if scope == "whole-repository":
        return True
    target = PurePosixPath(path)
    for item in scope:
        base = PurePosixPath(clean_path(item).rstrip("/") or ".")
        if str(base) == "." or target == base or base in target.parents:
            return True
    return False


def normalize_locations(locations, repo, where, problems):
    result = {}
    for index, location in enumerate(locations):
        path = clean_path(location["path"])
        start = location["start_line"]
        end = location.get("end_line", start)
        problem = check_citations.problem_with(repo, path, start, end)
        if problem:
            problems.append(f"{where}[{index}] {path}:{start}-{end}: {problem}")
        item = {"path": path, "start_line": start, "end_line": end, "role": location["role"]}
        result[json.dumps(item, sort_keys=True)] = item
    return sorted(result.values(), key=lambda item: (ROLE_ORDER.index(item["role"]), item["path"],
                                                     item["start_line"], item["end_line"]))


def normalize_cwes(values):
    return [f"CWE-{number}" for number in sorted({int(re.search(r"\d+", value).group()) for value in values})]


def anchor(locations):
    for role in ("root_control", "sink"):
        for location in locations:
            if location["role"] == role:
                return location["path"]
    return locations[0]["path"]


def fingerprint(target_id, finding):
    material = "\n".join((target_id, finding["family"], anchor(finding["locations"]), finding.get("instance", "")))
    return "fp:" + hashlib.sha256(material.encode()).hexdigest()[:16]


def union(*lists):
    merged = []
    for values in lists:
        for value in values:
            if value not in merged:
                merged.append(value)
    return merged


def merge(group):
    """Merge exact duplicates into the finding with the smallest key."""
    group = sorted(group, key=lambda finding: finding["key"])
    kept = dict(group[0])
    for field in MERGED_TEXT:
        texts = union([finding[field] for finding in group if finding.get(field)])
        if texts:
            kept[field] = "\n\n".join(texts)
    for field in MERGED_LISTS:
        if any(field in finding for finding in group):
            kept[field] = union(*(finding.get(field, []) for finding in group))
    kept["confidence"] = min((finding["confidence"] for finding in group),
                             key=lambda confidence: CONFIDENCE_ORDER.index(confidence["level"]))
    absorbed = [finding["key"] for finding in group[1:]]
    kept["merged_from"] = union(kept.get("merged_from", []), absorbed,
                                *(finding.get("merged_from", []) for finding in group[1:]))
    return kept, absorbed


def ordered(finding):
    return {field: finding[field] for field in FINDING_FIELDS if field in finding}


def normalize(data, findings_dir, repo):
    """Return (normalized data, merges, problems). The input is not modified."""
    problems = validate(data)
    if problems:
        return data, [], problems
    data = json.loads(json.dumps(data))
    record, scope = data["record"], data["record"]["scope"]

    priorities = {}
    model = threat_model_path(data, findings_dir)
    if model is not None:
        try:
            priorities = stage1_hypotheses(model.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            problems.append(f"threat_model.path: cannot read the stage 1 model ({exc})")

    for seed in data["seeds"]:
        if "locations" in seed:
            seed["locations"] = normalize_locations(seed["locations"], repo, f"seeds[{seed['id']}].locations", problems)
    for row in data["reconciliation"]:
        if "evidence" in row:
            row["evidence"] = normalize_locations(row["evidence"], repo, f"reconciliation[{row['ref']}].evidence", problems)

    keys, previous_ids = {}, {}
    for finding in data["findings"]:
        where = f"findings[{finding['key']}]"
        if finding["key"] in keys:
            problems.append(f"{where}: key is used by more than one finding")
        keys[finding["key"]] = finding
        if "id" in finding:
            if finding["id"] in previous_ids:
                problems.append(f"{where}: id {finding['id']} is used by more than one finding")
            previous_ids[finding["id"]] = finding["key"]
        finding["locations"] = normalize_locations(finding["locations"], repo, f"{where}.locations", problems)
        if not any(location["role"] in AFFECTED_ROLES and in_scope(location["path"], scope)
                   for location in finding["locations"]):
            problems.append(f"{where}: needs an entrypoint, root_control, sink, or concrete_implementation "
                            "location inside the record's scope")
        finding["cwe_ids"] = normalize_cwes(finding["cwe_ids"])
        finding["discovered_by"] = sorted(finding["discovered_by"], key=AUDITORS.index)
    for finding in data["findings"]:
        for absorbed in finding.get("merged_from", []):
            if absorbed in keys:
                problems.append(f"findings[{finding['key']}]: merged_from lists {absorbed!r}, which is still a finding")
    if problems:
        return data, [], problems

    groups = {}
    for finding in data["findings"]:
        identity = json.dumps([finding["family"], finding.get("instance", ""), finding["cwe_ids"],
                               finding["locations"]], sort_keys=True)
        groups.setdefault(identity, []).append(finding)
    findings, merges, aliases = [], [], {}
    for group in groups.values():
        kept, absorbed = merge(group) if len(group) > 1 else (group[0], [])
        kept["discovered_by"] = sorted(kept["discovered_by"], key=AUDITORS.index)
        findings.append(kept)
        if absorbed:
            merges.append({"kept": kept["key"], "absorbed": absorbed})
        for finding in group:
            aliases[finding["key"]] = kept["key"]
            if "id" in finding:
                aliases[finding["id"]] = kept["key"]
        for key in kept.get("merged_from", []):
            aliases.setdefault(key, kept["key"])

    for finding in findings:
        finding["fingerprint"] = fingerprint(record["target_id"], finding)
        ranks = [PRIORITIES.index(priorities[origin]) for origin in finding["origin"]
                 if priorities.get(origin) in PRIORITIES]
        finding["hypothesis_priority"] = PRIORITIES[min(ranks)].capitalize() if ranks else None
        finding["status"] = "unvalidated"
    findings.sort(key=lambda finding: (
        PRIORITIES.index(finding["hypothesis_priority"].lower()) if finding["hypothesis_priority"] else len(PRIORITIES),
        CONFIDENCE_ORDER.index(finding["confidence"]["level"]), finding["fingerprint"], finding["key"]))
    new_ids = {}
    for number, finding in enumerate(findings, 1):
        finding["id"] = f"FD-{number}"
        new_ids[finding["key"]] = finding["id"]

    def resolve(reference, where):
        key = aliases.get(reference)
        if key is None:
            problems.append(f"{where}: {reference!r} is not a finding key, FD id, or merged key")
            return reference
        return new_ids[key]

    for finding in findings:
        if "related" in finding:
            related = union([resolve(ref, f"findings[{finding['key']}].related") for ref in finding["related"]])
            related = [ref for ref in related if ref != finding["id"]]
            if related:
                finding["related"] = related
            else:
                del finding["related"]
    for row in data["reconciliation"]:
        if "findings" in row:
            row["findings"] = sorted(union([resolve(ref, f"reconciliation[{row['ref']}].findings")
                                            for ref in row["findings"]]), key=fd_order)

    def ref_order(ref):
        kind, number = re.fullmatch(r"(TM-H|SEED-)(\d+)", ref).groups()
        return (kind != "TM-H", int(number))

    data["findings"] = [ordered(finding) for finding in findings]
    data["seeds"].sort(key=lambda seed: int(seed["id"].split("-")[1]))
    data["reconciliation"].sort(key=lambda row: ref_order(row["ref"]))
    data["stage1_open_questions"].sort(key=lambda question: question["number"])
    data["coverage"]["reviewed_files"] = sorted({clean_path(path) for path in data["coverage"]["reviewed_files"]})
    return data, merges, problems


def fd_order(ref):
    return (0, int(ref[3:]), ref) if re.fullmatch(r"FD-\d+", ref) else (1, 0, ref)


def dump(data):
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", required=True, help="repository root")
    parser.add_argument("--out", help="write here instead of over the input file")
    parser.add_argument("findings", help="findings.json to normalize")
    args = parser.parse_args()

    repo = Path(args.repo).expanduser().resolve()
    source = Path(args.findings).expanduser().resolve()
    if not repo.is_dir() or not source.is_file():
        parser.exit(2, "error: --repo must be a directory and findings must be a file\n")
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        print(json.dumps({"valid": False, "findings": 0, "merged": [], "problems": [f"not valid JSON: {exc}"]}, indent=2))
        return 1

    normalized, merges, problems = normalize(data, source.parent, repo)
    if not problems:
        target = Path(args.out).expanduser().resolve() if args.out else source
        target.write_text(dump(normalized), encoding="utf-8")
    print(json.dumps({"valid": not problems, "findings": len(normalized.get("findings", [])) if not problems else 0,
                      "merged": merges, "problems": problems}, indent=2))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
