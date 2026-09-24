#!/usr/bin/env python3
"""Check the release package against the plugin layout rules and each client's load rules.

Uses only the Python standard library and no network. Reports every failure, then exits
non-zero if any check failed. Pass a directory to check a package other than this repository.

Client rules are reproduced from primary sources, noted beside each section. They approximate
what each client accepts; they do not replace the live smoke tests in RELEASING.md.
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]
SCHEMAS = Path(__file__).resolve().parent / "schemas" / "agent-plugins-1.0.0"
AGENT_PLUGINS_SCHEMA = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"
KEBAB = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
errors = []


def check(condition, message):
    if not condition:
        errors.append(message)
    return condition


def load_json(relative, required=True):
    path = ROOT / relative
    if not path.exists() and not required:
        return None
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


# JSON Schema subset ----------------------------------------------------------------
# Supports exactly the keywords the vendored Agent Plugins schemas use. An unknown keyword is
# reported rather than ignored, so a schema upgrade cannot silently weaken the check.

JSON_TYPES = {"object": dict, "array": list, "string": str, "boolean": bool}
SCHEMA_KEYWORDS = {
    "$schema", "$id", "$defs", "$ref", "title", "description", "type", "const", "enum",
    "minLength", "maxLength", "pattern", "properties", "additionalProperties", "propertyNames",
    "items", "required", "oneOf", "not",
}


def schema_errors(schema, value, where, root_schema):
    found = []
    unknown = set(schema) - SCHEMA_KEYWORDS
    if unknown:
        return [f"{where}: schema keyword(s) {sorted(unknown)} not supported by check-package.py"]
    if "$ref" in schema:
        target = root_schema
        for part in schema["$ref"].lstrip("#/").split("/"):
            target = target[part]
        found += schema_errors(target, value, where, root_schema)
    if schema.get("type", "object") not in JSON_TYPES:
        return [f"{where}: schema type {schema['type']!r} not supported by check-package.py"]
    if "type" in schema and not (isinstance(value, JSON_TYPES[schema["type"]])
                                 and not (schema["type"] != "boolean" and isinstance(value, bool))):
        return found + [f"{where}: must be of type {schema['type']}"]
    if "const" in schema and value != schema["const"]:
        found.append(f"{where}: must equal {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        found.append(f"{where}: must be one of {schema['enum']}")
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", len(value)):
            found.append(f"{where}: length out of range")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            found.append(f"{where}: {value!r} does not match {schema['pattern']}")
    if isinstance(value, list) and "items" in schema:
        for index, item in enumerate(value):
            found += schema_errors(schema["items"], item, f"{where}[{index}]", root_schema)
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in value:
                found.append(f"{where}: missing required {key!r}")
        for key, item in value.items():
            if "propertyNames" in schema:
                found += schema_errors(schema["propertyNames"], key, f"{where} key {key!r}", root_schema)
            if key in properties:
                found += schema_errors(properties[key], item, f"{where}.{key}", root_schema)
            elif schema.get("additionalProperties") is False:
                found.append(f"{where}: unknown key {key!r}")
            elif isinstance(schema.get("additionalProperties"), dict):
                found += schema_errors(schema["additionalProperties"], item, f"{where}.{key}", root_schema)
    if "oneOf" in schema:
        matches = [not schema_errors(option, value, where, root_schema) for option in schema["oneOf"]]
        if matches.count(True) != 1:
            found.append(f"{where}: must match exactly one allowed shape")
    if "not" in schema and not schema_errors(schema["not"], value, where, root_schema):
        found.append(f"{where}: matches a disallowed shape")
    return found


def validate_against(schema_file, value, where):
    schema = json.loads((SCHEMAS / schema_file).read_text(encoding="utf-8"))
    errors.extend(schema_errors(schema, value, where, schema))


# Skill parsing ----------------------------------------------------------------------

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


def load_skills():
    """Return {skill folder: frontmatter} for every well-formed skill, reporting the rest."""
    skills = {}
    skills_root = ROOT / "skills"
    if not check(skills_root.is_dir(), "Missing skills directory"):
        return skills
    for child in sorted(skills_root.iterdir()):
        relative = child.relative_to(ROOT)
        if child.name == ".gitkeep":
            continue
        # Codex skips hidden folders, so a hidden skill would silently vanish there.
        if not check(child.is_dir() and not child.name.startswith("."),
                     f"{relative}: only visible skill folders belong in skills/"):
            continue
        skill_file = child / "SKILL.md"
        if not check(skill_file.is_file() and not skill_file.is_symlink(),
                     f"{relative}: missing SKILL.md (must be a regular file)"):
            continue
        text = skill_file.read_text(encoding="utf-8")
        if not check(text.startswith("---\n"), f"{relative}/SKILL.md: missing frontmatter"):
            continue
        try:
            skills[child] = parse_frontmatter(text)
        except ValueError as exc:
            errors.append(f"{relative}/SKILL.md: unreadable frontmatter ({exc})")
    return skills


manifest = load_json("plugin.json")
name = manifest.get("name", "")
version = manifest.get("version", "")
skills = load_skills()


# Shared core: Agent Plugins 1.0 and Agent Skills ---------------------------------------
# Sources: agent-plugins.org spec and vendored schemas; agentskills.io/specification.

check((ROOT / "plugin.json").is_file() and not (ROOT / "plugin.json").is_symlink(),
      "plugin.json must be a regular file, not a symlink")
validate_against("plugin.schema.json", manifest, "plugin.json")
for field in ("description", "author", "repository", "license", "keywords"):
    check(manifest.get(field), f"plugin.json: missing baseline field {field!r}")
check(isinstance(version, str) and re.fullmatch(r"\d+\.\d+\.\d+", version),
      f"plugin.json: version {version!r} is not X.Y.Z")
check(manifest.get("license") == "MIT" and (ROOT / "LICENSE").is_file(),
      "plugin.json: license must be MIT with a LICENSE file present")
check(version and version in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"),
      f"CHANGELOG.md does not mention version {version}")
for unwanted in ("dist", "VERSION"):
    check(not (ROOT / unwanted).exists(), f"Remove {unwanted}: not part of the package layout")

mcp = load_json("mcp.json", required=False)
if mcp is not None:
    validate_against("mcp.schema.json", mcp, "mcp.json")
    check(mcp.get("$schema") == AGENT_PLUGINS_SCHEMA.replace("plugin.schema", "mcp.schema"),
          "mcp.json: $schema must use the same Agent Plugins version as plugin.json")
    # Spec rule the schema leaves to prose: remote servers use https, plain http only on loopback.
    servers = mcp.get("mcpServers") if isinstance(mcp.get("mcpServers"), dict) else {}
    for server_name, server in servers.items():
        url = server.get("url") if isinstance(server, dict) else None
        if isinstance(url, str):
            check(re.match(r"https://", url) or re.match(r"http://(localhost|127\.0\.0\.1|\[::1\])(?:[:/]|$)", url),
                  f"mcp.json.mcpServers.{server_name}.url must be https (http only for localhost)")

for skill_dir, fields in skills.items():
    relative = skill_dir.relative_to(ROOT)
    skill_name = fields.get("name")
    check(isinstance(skill_name, str) and 1 <= len(skill_name) <= 64 and KEBAB.fullmatch(skill_name),
          f"{relative}: name must be 1-64 lowercase letters, digits and single hyphens")
    check(skill_name == skill_dir.name, f"{relative}: name {skill_name!r} must match its folder")
    description = fields.get("description")
    check(isinstance(description, str) and 1 <= len(description.strip()) <= 1024,
          f"{relative}: description must be 1-1024 characters")
    if "compatibility" in fields:
        check(isinstance(fields["compatibility"], str) and 1 <= len(fields["compatibility"]) <= 500,
              f"{relative}: compatibility must be 1-500 characters")
    if "metadata" in fields:
        check(isinstance(fields["metadata"], dict), f"{relative}: metadata must be a key-value map")
    check_self_contained(skill_dir)


# Claude Code --------------------------------------------------------------------------
# Sources: code.claude.com/docs/en/plugins and /plugin-marketplaces. Also run
# `claude plugin validate .` where the Claude Code CLI is installed.

RESERVED_CLAUDE_MARKETPLACES = {
    "claude-code-marketplace", "claude-code-plugins", "claude-plugins-official",
    "claude-plugins-community", "claude-community", "anthropic-marketplace",
    "anthropic-plugins", "agent-skills", "anthropic-agent-skills", "knowledge-work-plugins",
    "life-sciences", "claude-for-legal", "claude-for-financial-services",
    "financial-services-plugins", "first-party-plugins", "claude-tag-plugins", "healthcare",
    "npm", "pip", "uv", "cargo", "github", "gh",
}

claude = load_json(".claude-plugin/plugin.json")
for field in ("name", "version", "description", "author", "repository", "license", "keywords"):
    check(claude.get(field) == manifest.get(field),
          f".claude-plugin/plugin.json: {field!r} must match plugin.json")

claude_catalog = load_json(".claude-plugin/marketplace.json")
marketplace_name = claude_catalog.get("name", "")
check(isinstance(marketplace_name, str) and KEBAB.fullmatch(marketplace_name)
      and marketplace_name.lower() not in RESERVED_CLAUDE_MARKETPLACES,
      f".claude-plugin/marketplace.json: invalid or reserved name {marketplace_name!r}")
check(isinstance(claude_catalog.get("owner"), dict) and claude_catalog["owner"].get("name"),
      ".claude-plugin/marketplace.json: owner.name is required")
entry = single_plugin(claude_catalog, ".claude-plugin/marketplace.json")
check(entry.get("name") == name, ".claude-plugin/marketplace.json: plugin name must match plugin.json")
check(entry.get("source") == "./", ".claude-plugin/marketplace.json: plugin source must be \"./\"")


# ChatGPT / Codex ----------------------------------------------------------------------
# Sources: openai/codex codex-rs (core-plugins marketplace.rs, agent_plugin_manifest.rs,
# manifest.rs, store.rs; skills parser.rs) and the plugin-creator sample's validate_plugin.py.

CODEX_EXTENSION_KEYS = {"interface", "apps", "hooks", "onboardingSkill"}
CODEX_INTERFACE_KEYS = {
    "displayName", "shortDescription", "longDescription", "developerName", "category",
    "capabilities", "websiteURL", "websiteUrl", "privacyPolicyURL", "termsOfServiceURL",
    "defaultPrompt", "brandColor", "composerIcon", "logo", "logoDark", "screenshots",
}
CODEX_REQUIRED_INTERFACE = (
    "displayName", "shortDescription", "longDescription", "developerName", "category", "capabilities",
)

# Codex nulls are a hard load error; an unrecognised $schema makes it skip the root manifest.
for key, value in manifest.items():
    check(value is not None, f"plugin.json: {key!r} must not be null (Codex rejects nulls)")

extensions = manifest.get("extensions")
openai = extensions.get("com.openai") if isinstance(extensions, dict) else None
if check(isinstance(openai, dict), "plugin.json: missing extensions[\"com.openai\"] for Codex"):
    check(set(openai) <= CODEX_EXTENSION_KEYS,
          f"plugin.json: Codex ignores com.openai keys {sorted(set(openai) - CODEX_EXTENSION_KEYS)}")
    interface = openai.get("interface") if isinstance(openai.get("interface"), dict) else {}
    # The extension's interface replaces Codex's defaults wholesale, so nothing falls back.
    check(set(interface) <= CODEX_INTERFACE_KEYS,
          f"plugin.json: unknown com.openai.interface keys {sorted(set(interface) - CODEX_INTERFACE_KEYS)}")
    for key in CODEX_REQUIRED_INTERFACE:
        check(interface.get(key), f"plugin.json: com.openai.interface.{key} is required")
    check(isinstance(interface.get("capabilities"), list),
          "plugin.json: com.openai.interface.capabilities must be a list")
    if skills:
        check(interface.get("defaultPrompt"),
              "plugin.json: com.openai.interface.defaultPrompt is required once skills exist")
    prompts = interface.get("defaultPrompt", [])
    prompts = [prompts] if isinstance(prompts, str) else prompts
    check(isinstance(prompts, list) and len(prompts) <= 3
          and all(isinstance(p, str) and 0 < len(p) <= 128 for p in prompts),
          "plugin.json: com.openai.interface.defaultPrompt must be 1-3 prompts of at most 128 characters")
    for key in ("websiteURL", "websiteUrl", "privacyPolicyURL", "termsOfServiceURL"):
        if key in interface:
            check(str(interface[key]).startswith("https://"),
                  f"plugin.json: com.openai.interface.{key} must be an https URL")
    if "brandColor" in interface:
        check(re.fullmatch(r"#[0-9A-Fa-f]{6}", str(interface["brandColor"])),
              "plugin.json: com.openai.interface.brandColor must be #RRGGBB")
    for key in ("composerIcon", "logo", "logoDark", "screenshots"):
        for asset in (interface.get(key) if isinstance(interface.get(key), list) else [interface.get(key)]):
            if asset is not None:
                check(isinstance(asset, str) and asset.startswith("./") and ".." not in asset
                      and (ROOT / asset).is_file(),
                      f"plugin.json: com.openai.interface.{key} {asset!r} must be an existing ./ path")

check(not (ROOT / ".codex-plugin").exists(),
      "Remove .codex-plugin: Codex ignores it while extensions[\"com.openai\"] exists")

codex_catalog = load_json(".agents/plugins/marketplace.json")
check(re.fullmatch(r"[A-Za-z0-9_-]+", str(codex_catalog.get("name", ""))),
      ".agents/plugins/marketplace.json: name must match [A-Za-z0-9_-]+ or Codex skips every plugin")
entry = single_plugin(codex_catalog, ".agents/plugins/marketplace.json")
policy = entry.get("policy") if isinstance(entry.get("policy"), dict) else {}
check(entry.get("name") == name,
      ".agents/plugins/marketplace.json: plugin name must match plugin.json or Codex install fails")
check(entry.get("source") == {"source": "local", "path": "./"},
      ".agents/plugins/marketplace.json: source must be local with path \"./\"")
# An unknown policy value makes Codex reject the whole marketplace file.
check(policy.get("installation") in {"AVAILABLE", "INSTALLED_BY_DEFAULT", "NOT_AVAILABLE"},
      ".agents/plugins/marketplace.json: invalid policy.installation")
check(policy.get("authentication") in {"ON_INSTALL", "ON_USE"},
      ".agents/plugins/marketplace.json: invalid policy.authentication (ON_INSTALL or ON_USE)")
check(entry.get("category"), ".agents/plugins/marketplace.json: category is required")

for skill_dir, fields in skills.items():
    relative = skill_dir.relative_to(ROOT)
    check(len(f"{name}:{fields.get('name', '')}") <= 129,
          f"{relative}: Codex limits the qualified name plugin:skill to 129 characters")


# Cursor -------------------------------------------------------------------------------
# Sources: cursor.com/docs/reference/plugins and /docs/skills. Cursor reads the root
# plugin.json as an Agent Plugin, so the shared-core checks above cover its manifest.

CURSOR_SKILL_COLORS = {
    "default", "green", "cyan", "blue", "purple", "magenta", "orange", "yellow", "red", "brand",
}

for skill_dir, fields in skills.items():
    if "color" in fields:
        check(fields["color"] in CURSOR_SKILL_COLORS,
              f"{skill_dir.relative_to(ROOT)}: Cursor color must be one of {sorted(CURSOR_SKILL_COLORS)}")
for folder in ("rules", "agents", "commands"):
    check(not (ROOT / folder).exists(),
          f"Remove {folder}/: Cursor-only component that needs a .cursor-plugin adapter")


# Components with no checks yet -----------------------------------------------------------
# Each client reads these differently. Add checks for one before adding it to the package.

unchecked = [".cursor-plugin", "hooks", ".app.json", ".mcp.json"]
unchecked += [str(path.relative_to(ROOT)) for path in (ROOT / "skills").glob("*/agents/openai.yaml")]
for component in unchecked:
    check(not (ROOT / component).exists(),
          f"{component}: not yet covered by check-package.py; add its client checks first")
if isinstance(openai, dict):
    for key in ("apps", "hooks", "onboardingSkill"):
        check(key not in openai,
              f"plugin.json: com.openai.{key} not yet covered by check-package.py; add its checks first")


if errors:
    print("Package checks failed:", file=sys.stderr)
    for message in errors:
        print(f"  - {message}", file=sys.stderr)
    sys.exit(1)

print(f"Package checks passed: {name} {version} ({len(skills)} skill{'' if len(skills) == 1 else 's'})")
