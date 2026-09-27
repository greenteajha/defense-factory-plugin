#!/usr/bin/env python3
"""Check a threat-model document's record header against its body before it is saved.

Checks that the header has every required field (including the exact `model` and the
`skill_version`), that `status` and `source` use allowed values, that the `hypotheses` counts
match the priority column of the hypotheses table, that `open_questions` matches the numbered
list under "Open questions", that every hypothesis has a unique TM-H ID and a High, Medium, or
Low confidence, and that every required section is present. A `blocked` record needs only its
header. Citations are checked separately by check_citations.py.

Prints one JSON object: valid, problems (list of strings).
Exit codes: 0 valid; 1 problems found; 2 bad arguments.
Standard library only; Python 3.9+. Read-only.
"""

import argparse
import json
import re
import sys
from pathlib import Path

REQUIRED = (
    "record_version", "stage", "status", "run_id", "timestamp", "actor", "model", "skill_version",
    "target_id", "target_kind", "version", "scope", "authorization", "output_location", "source",
    "inputs", "independent_review", "tools", "evidence", "assumptions", "coverage_gaps",
    "open_questions", "hypotheses", "next_action",
)
MAY_BE_EMPTY = {"inputs", "assumptions", "coverage_gaps"}
STATUSES = {"complete", "inconclusive", "blocked"}
SOURCES = {"generated", "reused", "supplied", "supplied-revised", "repository-guidance"}
LEVELS = ("critical", "high", "medium", "low")
SECTIONS = (r"## 1\.", r"## 2\.", r"## 3\.", r"## 4\.", r"## Canonical summary", r"## Coverage gaps",
            r"## Open questions")


def parse_scalar(value):
    value = value.strip()
    if value[:1] in "\"'" and value[-1:] == value[:1]:
        return value[1:-1]
    value = re.sub(r"\s+#.*$", "", value)  # drop a trailing comment on an unquoted value
    if value == "[]":
        return []
    if value.startswith("[") and value.endswith("]"):
        return [part.strip().strip("\"'") for part in value[1:-1].split(",") if part.strip()]
    if value.startswith("{") and value.endswith("}"):
        pairs = (part.split(":", 1) for part in value[1:-1].split(",") if ":" in part)
        return {key.strip(): val.strip() for key, val in pairs}
    return value


def parse_header(lines):
    """Parse the simple YAML subset the template uses: scalars, flow lists and maps, block lists."""
    fields, key = {}, None
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.fullmatch(r"([a-z_]+):(?:\s+(.*))?", line)
        if match:
            key = match.group(1)
            if key in fields:
                raise ValueError(f"duplicate header field {key!r}")
            fields[key] = parse_scalar(match.group(2) or "") if match.group(2) else []
        elif line.lstrip().startswith("- ") and key is not None and isinstance(fields[key], list):
            fields[key].append(parse_scalar(line.lstrip()[2:]))
        else:
            raise ValueError(f"unreadable header line {line!r}")
    return fields


def table_rows(body):
    """Header cells and data rows of the hypotheses table (rows whose first cell is a TM-H ID)."""
    lines = body.splitlines()
    for index, line in enumerate(lines):
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if cells and cells[0] == "ID" and index + 1 < len(lines):
            rows = []
            for row in lines[index + 2:]:
                if not row.strip().startswith("|"):
                    break
                rows.append([cell.strip() for cell in row.strip().strip("|").split("|")])
            return [cell.lower() for cell in cells], rows
    return None, []


def first_word(cell):
    word = re.sub(r"[*_`]", "", cell).strip().split(" ", 1)[0].rstrip(".,:;").lower()
    return word


def check(text):
    problems = []
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---" or "---" not in (line.strip() for line in lines[1:]):
        return ["missing record header between --- lines"]
    end = next(i for i, line in enumerate(lines[1:], 1) if line.strip() == "---")
    try:
        header = parse_header(lines[1:end])
    except ValueError as exc:
        return [str(exc)]
    body = "\n".join(lines[end + 1:])

    for field in REQUIRED:
        value = header.get(field)
        if field not in header or (value in ("", []) and field not in MAY_BE_EMPTY):
            problems.append(f"header field {field!r} is missing or empty")
        elif isinstance(value, str) and value.startswith("<"):
            problems.append(f"header field {field!r} still holds a template placeholder")
    status, source = header.get("status"), header.get("source")
    if status not in STATUSES:
        problems.append(f"status {status!r} is not one of {sorted(STATUSES)}")
    if source not in SOURCES:
        problems.append(f"source {source!r} is not one of {sorted(SOURCES)}")
    if source == "reused" and not header.get("reused_from"):
        problems.append("source is reused but reused_from is missing")
    if str(header.get("model", "")).strip().lower() in {"claude", "gpt", "unknown model"}:
        problems.append("model must name the exact model and version reported by the client, or 'unknown'")
    if header.get("skill_version") and not str(header["skill_version"]).startswith("threat-model/sha256:"):
        problems.append("skill_version must be the value printed by prepare_workspace.py")
    if status == "blocked":
        return problems

    for pattern in SECTIONS:
        if not re.search(rf"^{pattern}", body, re.MULTILINE):
            problems.append(f"missing section starting {pattern.replace(chr(92), '')!r}")

    columns, rows = table_rows(body)
    if columns is None:
        problems.append("hypotheses table (header row starting '| ID |') not found")
        columns = []
    for name in ("priority", "confidence"):
        if columns and name not in columns:
            problems.append(f"hypotheses table has no {name.capitalize()} column")
    counts = {level: 0 for level in LEVELS}
    seen_ids = set()
    for row in rows:
        row_id = row[0] if row else ""
        if not re.fullmatch(r"TM-H\d+", row_id):
            problems.append(f"hypothesis row has an invalid ID {row_id!r}")
        elif row_id in seen_ids:
            problems.append(f"duplicate hypothesis ID {row_id}")
        seen_ids.add(row_id)
        if "priority" in columns and len(row) > columns.index("priority"):
            priority = first_word(row[columns.index("priority")])
            if priority in counts:
                counts[priority] += 1
            else:
                problems.append(f"{row_id}: priority {row[columns.index('priority')]!r} is not Critical, High, Medium, or Low")
        if "confidence" in columns and len(row) > columns.index("confidence"):
            if first_word(row[columns.index("confidence")]) not in ("high", "medium", "low"):
                problems.append(f"{row_id}: confidence must be High, Medium, or Low")

    declared = header.get("hypotheses")
    if isinstance(declared, dict):
        for level in LEVELS:
            try:
                stated = int(declared.get(level, "0"))
            except ValueError:
                problems.append(f"hypotheses.{level} is not a number")
                continue
            if stated != counts[level]:
                problems.append(f"header says {stated} {level} hypotheses but the table has {counts[level]}")
    else:
        problems.append("hypotheses must be a map such as {critical: 0, high: 1, medium: 2, low: 0}")

    questions = re.search(r"^## Open questions\s*$(.*?)(?=^## |\Z)", body, re.MULTILINE | re.DOTALL)
    listed = len(re.findall(r"^\d+\.\s", questions.group(1), re.MULTILINE)) if questions else 0
    try:
        if int(header.get("open_questions", "-1")) != listed:
            problems.append(f"header says {header.get('open_questions')} open questions but the list has {listed}")
    except ValueError:
        problems.append("open_questions is not a number")
    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("document", help="threat-model Markdown file to check")
    args = parser.parse_args()
    document = Path(args.document).expanduser()
    if not document.is_file():
        parser.exit(2, "error: document must be a file\n")
    problems = check(document.read_text(encoding="utf-8", errors="replace"))
    print(json.dumps({"valid": not problems, "problems": problems}, indent=2))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
