#!/usr/bin/env python3
"""Check the release package without third-party dependencies."""

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
manifest = json.loads((ROOT / "plugin.json").read_text())
claude = json.loads((ROOT / ".claude-plugin/plugin.json").read_text())
catalog = json.loads((ROOT / ".agents/plugins/marketplace.json").read_text())

assert manifest["$schema"] == "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"
assert re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?", manifest["name"])
assert "--" not in manifest["name"] and ".." not in manifest["name"]
assert re.fullmatch(r"\d+\.\d+\.\d+", manifest["version"])
assert manifest["name"] == claude["name"] == catalog["plugins"][0]["name"]
assert manifest["version"] == claude["version"]
assert manifest["license"] == "MIT" and (ROOT / "LICENSE").is_file()
assert catalog["plugins"][0]["source"]["path"] == "./"

skills = list((ROOT / "skills").glob("*/SKILL.md"))
assert skills, "At least one working skill is required"
for skill in skills:
    text = skill.read_text()
    assert text.startswith("---\n"), f"Missing frontmatter: {skill}"
    frontmatter = text.split("---\n", 2)[1]
    fields = dict(re.findall(r"^(name|description):\s*(.+)$", frontmatter, re.M))
    assert fields.get("name") == skill.parent.name, f"Skill name mismatch: {skill}"
    assert fields.get("description"), f"Missing description: {skill}"

print(f"Package checks passed: {manifest['name']} {manifest['version']} ({len(skills)} skill)")
