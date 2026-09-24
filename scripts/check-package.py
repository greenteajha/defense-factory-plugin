#!/usr/bin/env python3
"""Check the release package against the plugin layout rules, without third-party dependencies.

Reports every failure, then exits non-zero if any check failed.
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
errors = []


def check(condition, message):
    if not condition:
        errors.append(message)
    return condition


def load_json(relative):
    path = ROOT / relative
    if not check(path.is_file(), f"Missing {relative}"):
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        errors.append(f"Invalid JSON in {relative}: {exc}")
        return {}
    check(isinstance(data, dict), f"{relative} must contain a JSON object")
    return data if isinstance(data, dict) else {}


def single_plugin(catalog, relative):
    plugins = catalog.get("plugins")
    if check(isinstance(plugins, list) and len(plugins) == 1 and isinstance(plugins[0], dict),
             f"{relative} must list exactly one plugin entry"):
        return plugins[0]
    return {}


# Manifest and catalog identity -------------------------------------------------

KEBAB = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
RESERVED_CLAUDE_MARKETPLACES = {
    "claude-code-marketplace", "claude-code-plugins", "claude-plugins-official",
    "claude-plugins-community", "claude-community", "anthropic-marketplace",
    "anthropic-plugins", "agent-skills", "anthropic-agent-skills", "knowledge-work-plugins",
    "life-sciences", "claude-for-legal", "claude-for-financial-services",
    "financial-services-plugins", "first-party-plugins", "claude-tag-plugins", "healthcare",
    "npm", "pip", "uv", "cargo", "github", "gh",
}

manifest = load_json("plugin.json")
claude = load_json(".claude-plugin/plugin.json")
claude_catalog = load_json(".claude-plugin/marketplace.json")
codex_catalog = load_json(".agents/plugins/marketplace.json")

name = manifest.get("name", "")
version = manifest.get("version", "")

# Root manifest: Agent Plugins 1.0 identity; skills and MCP are discovered from the layout.
check(manifest.get("$schema") == "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
      "plugin.json: $schema must be the Agent Plugins 1.0 schema URL")
check(isinstance(name, str) and re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?", name)
      and "--" not in name and ".." not in name,
      f"plugin.json: invalid name {name!r}")
check(isinstance(version, str) and re.fullmatch(r"\d+\.\d+\.\d+", version),
      f"plugin.json: version {version!r} is not X.Y.Z")
for field in ("skills", "mcpServers"):
    check(field not in manifest,
          f"plugin.json: remove top-level {field!r}; portable packages discover it from the layout")
for field in ("description", "author", "repository", "license", "keywords"):
    check(manifest.get(field), f"plugin.json: missing baseline field {field!r}")
check(manifest.get("license") == "MIT" and (ROOT / "LICENSE").is_file(),
      "plugin.json: license must be MIT with a LICENSE file present")

# Claude adapter mirrors the root identity; the root manifest is the single version source.
for field in ("name", "version", "description", "author", "repository", "license", "keywords"):
    check(claude.get(field) == manifest.get(field),
          f".claude-plugin/plugin.json: {field!r} must match plugin.json")

marketplace_name = claude_catalog.get("name", "")
check(isinstance(marketplace_name, str) and KEBAB.fullmatch(marketplace_name)
      and marketplace_name.lower() not in RESERVED_CLAUDE_MARKETPLACES,
      f".claude-plugin/marketplace.json: invalid or reserved name {marketplace_name!r}")
check(isinstance(claude_catalog.get("owner"), dict) and claude_catalog["owner"].get("name"),
      ".claude-plugin/marketplace.json: owner.name is required")
entry = single_plugin(claude_catalog, ".claude-plugin/marketplace.json")
check(entry.get("name") == name, ".claude-plugin/marketplace.json: plugin name must match plugin.json")
check(entry.get("source") == "./", ".claude-plugin/marketplace.json: plugin source must be \"./\"")

# ChatGPT/Codex catalog: every entry needs policy and category.
entry = single_plugin(codex_catalog, ".agents/plugins/marketplace.json")
policy = entry.get("policy") if isinstance(entry.get("policy"), dict) else {}
check(entry.get("name") == name, ".agents/plugins/marketplace.json: plugin name must match plugin.json")
check(entry.get("source") == {"source": "local", "path": "./"},
      ".agents/plugins/marketplace.json: source must be local with path \"./\"")
check(policy.get("installation") in {"AVAILABLE", "INSTALLED_BY_DEFAULT", "NOT_AVAILABLE"},
      ".agents/plugins/marketplace.json: invalid policy.installation")
check(policy.get("authentication") in {"ON_INSTALL", "ON_USE"},
      ".agents/plugins/marketplace.json: invalid policy.authentication")
check(entry.get("category"), ".agents/plugins/marketplace.json: category is required")

# Layout rules: no fallback adapters, generated copies, or second version source.
for unwanted in (".codex-plugin", "dist", "VERSION"):
    check(not (ROOT / unwanted).exists(), f"Remove {unwanted}: not part of the package layout")
check(version and f"{version}" in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"),
      f"CHANGELOG.md does not mention version {version}")


# Skills ---------------------------------------------------------------------------

def parse_frontmatter(text):
    """Parse the top-level keys of simple YAML frontmatter, including block scalars and maps."""
    lines = text.split("\n")
    end = lines.index("---", 1)
    fields, key, style, block = {}, None, None, []

    def flush():
        if key is None:
            return
        if style in (">", "|"):
            joiner = " " if style == ">" else "\n"
            fields[key] = joiner.join(line.strip() for line in block).strip()
        elif block and all(re.match(r"\s+[^:\s][^:]*:\s", line + " ") for line in block):
            fields[key] = dict(line.strip().split(":", 1) for line in block)
        else:
            fields[key] = " ".join([fields[key]] + [line.strip() for line in block]).strip()

    for line in lines[1:end]:
        match = re.match(r"([A-Za-z0-9_-]+):(?:\s+(.*))?$", line)
        if match:
            flush()
            key, value = match.group(1), (match.group(2) or "").strip()
            if key in fields:
                raise ValueError(f"duplicate key {key!r}")
            style, block = (value[0], []) if value[:1] in (">", "|") else (None, [])
            if style is None:
                if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                    value = value[1:-1]
                fields[key] = value
        elif line.strip() and not line.lstrip().startswith("#"):
            if key is None or not line[:1].isspace():
                raise ValueError(f"unexpected line {line!r}")
            block.append(line)
    flush()
    return fields


def check_skill_name(skill_dir, value):
    check(isinstance(value, str) and 1 <= len(value) <= 64 and KEBAB.fullmatch(value),
          f"{skill_dir}: name must be 1-64 lowercase letters, digits and single hyphens")
    check(value == skill_dir.name, f"{skill_dir}: name {value!r} must match its folder")


LINK = re.compile(r"\]\(\s*<?([^)\s>]+)")
PARENT_PATH = re.compile(r"(?:\.\./)+[\w./-]*")


def check_self_contained(skill_dir):
    """A skill folder is the unit of portability: nothing inside may point outside it."""
    root = skill_dir.resolve()

    def inside(path):
        return path == root or root in path.parents

    for path in sorted(skill_dir.rglob("*")):
        relative = path.relative_to(ROOT)
        if path.is_symlink():
            check(inside(path.resolve()), f"{relative}: symlink points outside its skill folder")
            continue
        if not path.is_file() or not inside(path.resolve()):
            continue  # reached through an outside symlink, already reported
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        targets = {target.split("#", 1)[0]: False for target in PARENT_PATH.findall(text)}
        targets.update({target.split("#", 1)[0]: True for target in LINK.findall(text)})
        for target, is_link in sorted(targets.items()):
            if not target or re.match(r"[a-z][a-z0-9+.-]*:", target, re.I):
                continue
            resolved = (path.parent / target).resolve()
            if check(inside(resolved), f"{relative}: {target!r} points outside its skill folder") and is_link:
                check(resolved.exists(), f"{relative}: link target {target!r} does not exist")


skills_root = ROOT / "skills"
skills = []
if check(skills_root.is_dir(), "Missing skills directory"):
    for child in sorted(skills_root.iterdir()):
        if child.name == ".gitkeep":
            continue
        if not check(child.is_dir(), f"{child.relative_to(ROOT)}: only skill folders belong in skills/"):
            continue
        skill_file = child / "SKILL.md"
        if not check(skill_file.is_file(), f"{child.relative_to(ROOT)}: missing SKILL.md"):
            continue
        skills.append(child)
        text = skill_file.read_text(encoding="utf-8")
        if not check(text.startswith("---\n"), f"{skill_file.relative_to(ROOT)}: missing frontmatter"):
            continue
        try:
            fields = parse_frontmatter(text)
        except ValueError as exc:
            errors.append(f"{skill_file.relative_to(ROOT)}: unreadable frontmatter ({exc})")
            continue
        check_skill_name(child.relative_to(ROOT), fields.get("name"))
        description = fields.get("description")
        check(isinstance(description, str) and 1 <= len(description) <= 1024,
              f"{skill_file.relative_to(ROOT)}: description must be 1-1024 characters")
        if "compatibility" in fields:
            check(isinstance(fields["compatibility"], str) and 1 <= len(fields["compatibility"]) <= 500,
                  f"{skill_file.relative_to(ROOT)}: compatibility must be 1-500 characters")
        check_self_contained(child)

if errors:
    print("Package checks failed:", file=sys.stderr)
    for message in errors:
        print(f"  - {message}", file=sys.stderr)
    sys.exit(1)

print(f"Package checks passed: {name} {version} ({len(skills)} skill{'' if len(skills) == 1 else 's'})")
