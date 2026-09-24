"""Regression tests for scripts/check-package.py.

Each case copies the repository into a temporary directory, breaks one rule, and expects the
package check to fail with a specific message. Run with: python3 -m unittest discover -s tests
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CHECK = REPO / "scripts" / "check-package.py"
MCP_SCHEMA = "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json"


def edit_json(root, relative, change):
    path = root / relative
    data = json.loads(path.read_text())
    change(data)
    path.write_text(json.dumps(data, indent=2))


def interface(data):
    return data["extensions"]["com.openai"]["interface"]


def add_skill(root, name="good-skill", frontmatter=None, body="Use [the guide](references/guide.md).\n"):
    folder = root / "skills" / name
    (folder / "references").mkdir(parents=True)
    (folder / "references" / "guide.md").write_text("Guide.\n")
    frontmatter = frontmatter or f"name: {name}\ndescription: >\n  Checks a thing.\n  Use when asked.\n"
    (folder / "SKILL.md").write_text(f"---\n{frontmatter}---\n{body}")
    edit_json(root, "plugin.json", lambda d: interface(d).update(defaultPrompt="Run the check."))
    return folder


class PackageCheckTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "package"
        shutil.copytree(REPO, self.root, ignore=shutil.ignore_patterns(".git", "__pycache__"))

    def tearDown(self):
        self.tmp.cleanup()

    def run_check(self):
        return subprocess.run([sys.executable, str(CHECK), str(self.root)],
                              capture_output=True, text=True)

    def assert_passes(self):
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stderr)

    def assert_fails(self, message):
        result = self.run_check()
        self.assertNotEqual(result.returncode, 0, "expected the package check to fail")
        self.assertIn(message, result.stderr)

    # Passing packages -------------------------------------------------------------------

    def test_repository_passes(self):
        self.assert_passes()

    def test_well_formed_skill_passes(self):
        add_skill(self.root, frontmatter=(
            "name: good-skill\ndescription: >\n  Checks a thing.\n  Use when asked.\n"
            "metadata:\n  author: example\n  version: \"1.0\"\ncolor: blue\n"))
        self.assert_passes()

    def test_valid_mcp_json_passes(self):
        (self.root / "mcp.json").write_text(json.dumps({
            "$schema": MCP_SCHEMA,
            "mcpServers": {"scanner": {"type": "stdio", "command": "./bin/scanner", "args": ["--safe"]}},
        }))
        self.assert_passes()

    # Shared core: Agent Plugins manifest -----------------------------------------------

    def test_manifest_rejects_skills_field(self):
        edit_json(self.root, "plugin.json", lambda d: d.update(skills="./skills"))
        self.assert_fails("plugin.json: unknown key 'skills'")

    def test_manifest_rejects_other_schema_version(self):
        edit_json(self.root, "plugin.json",
                  lambda d: d.update({"$schema": "https://agent-plugins.org/schemas/9.0.0/plugin.schema.json"}))
        self.assert_fails("plugin.json.$schema: must equal")

    def test_manifest_rejects_string_author(self):
        edit_json(self.root, "plugin.json", lambda d: d.update(author="Jeremy Teo"))
        self.assert_fails("plugin.json.author: must be of type object")

    def test_manifest_rejects_invalid_name(self):
        edit_json(self.root, "plugin.json", lambda d: d.update(name="Defense_Factory"))
        self.assert_fails("plugin.json.name")

    def test_invalid_mcp_json_fails(self):
        (self.root / "mcp.json").write_text(json.dumps({
            "$schema": MCP_SCHEMA, "mcpServers": {"scanner": {"command": "./bin/scanner"}}}))
        self.assert_fails("mcp.json.mcpServers.scanner")

    def test_mcp_http_only_on_loopback(self):
        servers = {"remote": {"type": "streamable-http", "url": "http://example.com/mcp"},
                   "local": {"type": "streamable-http", "url": "http://127.0.0.1:8080/mcp"}}
        (self.root / "mcp.json").write_text(json.dumps({"$schema": MCP_SCHEMA, "mcpServers": servers}))
        result = self.run_check()
        self.assertIn("mcpServers.remote.url must be https", result.stderr)
        self.assertNotIn("mcpServers.local.url", result.stderr)

    # Shared core: skills ----------------------------------------------------------------

    def test_skill_name_rules(self):
        add_skill(self.root, name="bad--name")
        self.assert_fails("skills/bad--name: name must be 1-64 lowercase letters")

    def test_skill_name_must_match_folder(self):
        add_skill(self.root, frontmatter="name: other-name\ndescription: x\n")
        self.assert_fails("name 'other-name' must match its folder")

    def test_skill_needs_description(self):
        add_skill(self.root, frontmatter="name: good-skill\ndescription: >\n")
        self.assert_fails("description must be 1-1024 characters")

    def test_skill_needs_frontmatter(self):
        folder = add_skill(self.root)
        (folder / "SKILL.md").write_text("No frontmatter.\n")
        self.assert_fails("missing frontmatter")

    def test_skill_link_outside_folder(self):
        add_skill(self.root, body="See [contracts](../../docs/workflow-contracts.md).\n")
        self.assert_fails("'../../docs/workflow-contracts.md' points outside its skill folder")

    def test_skill_path_outside_folder(self):
        add_skill(self.root, body="Run ../../scripts/check-package.py first.\n")
        self.assert_fails("'../../scripts/check-package.py' points outside its skill folder")

    def test_skill_broken_link(self):
        add_skill(self.root, body="See [missing](references/missing.md).\n")
        self.assert_fails("link target 'references/missing.md' does not exist")

    @unittest.skipIf(os.name == "nt", "symlinks need extra privileges on Windows")
    def test_skill_symlink_outside_folder(self):
        folder = add_skill(self.root)
        (folder / "docs").symlink_to(self.root / "docs")
        self.assert_fails("symlink points outside its skill folder")

    def test_folder_without_skill_file(self):
        (self.root / "skills" / "empty").mkdir()
        self.assert_fails("skills/empty: missing SKILL.md")

    def test_hidden_skill_folder(self):
        add_skill(self.root, name=".hidden")
        self.assert_fails("skills/.hidden: only visible skill folders")

    # Claude Code --------------------------------------------------------------------------

    def test_claude_manifest_version_drift(self):
        edit_json(self.root, ".claude-plugin/plugin.json", lambda d: d.update(version="0.2.0"))
        self.assert_fails(".claude-plugin/plugin.json: 'version' must match plugin.json")

    def test_claude_reserved_marketplace_name(self):
        edit_json(self.root, ".claude-plugin/marketplace.json", lambda d: d.update(name="claude-plugins-official"))
        self.assert_fails("invalid or reserved name 'claude-plugins-official'")

    # ChatGPT / Codex ----------------------------------------------------------------------

    def test_codex_rejects_null_field(self):
        edit_json(self.root, "plugin.json", lambda d: d.update(homepage=None))
        self.assert_fails("'homepage' must not be null")

    def test_codex_needs_long_description(self):
        edit_json(self.root, "plugin.json", lambda d: interface(d).pop("longDescription"))
        self.assert_fails("com.openai.interface.longDescription is required")

    def test_codex_needs_default_prompt_once_skills_exist(self):
        add_skill(self.root)
        edit_json(self.root, "plugin.json", lambda d: interface(d).pop("defaultPrompt"))
        self.assert_fails("defaultPrompt is required once skills exist")

    def test_codex_default_prompt_limits(self):
        edit_json(self.root, "plugin.json", lambda d: interface(d).update(defaultPrompt="x" * 129))
        self.assert_fails("defaultPrompt must be 1-3 prompts of at most 128 characters")

    def test_codex_https_urls(self):
        edit_json(self.root, "plugin.json",
                  lambda d: interface(d).update(websiteURL="http://github.com/greenteajha/defense-factory-plugin"))
        self.assert_fails("websiteURL must be an https URL")

    def test_codex_unknown_interface_key(self):
        edit_json(self.root, "plugin.json", lambda d: interface(d).update(tagline="x"))
        self.assert_fails("unknown com.openai.interface keys ['tagline']")

    def test_codex_marketplace_name_charset(self):
        edit_json(self.root, ".agents/plugins/marketplace.json", lambda d: d.update(name="defense.factory"))
        self.assert_fails("Codex skips every plugin")

    def test_codex_authentication_values(self):
        edit_json(self.root, ".agents/plugins/marketplace.json",
                  lambda d: d["plugins"][0]["policy"].update(authentication="ON_FIRST_USE"))
        self.assert_fails("invalid policy.authentication")

    def test_codex_plugin_name_must_match(self):
        edit_json(self.root, ".agents/plugins/marketplace.json", lambda d: d["plugins"][0].update(name="other"))
        self.assert_fails("Codex install fails")

    def test_codex_plugin_fallback_manifest(self):
        (self.root / ".codex-plugin").mkdir()
        self.assert_fails("Remove .codex-plugin")

    # Cursor -------------------------------------------------------------------------------

    def test_cursor_skill_color(self):
        add_skill(self.root, frontmatter="name: good-skill\ndescription: x\ncolor: teal\n")
        self.assert_fails("Cursor color must be one of")

    def test_cursor_only_component(self):
        (self.root / "rules").mkdir()
        self.assert_fails("Remove rules/: Cursor-only component")

    # Components without checks ------------------------------------------------------------

    def test_unchecked_components_are_blocked(self):
        (self.root / "hooks").mkdir()
        folder = add_skill(self.root)
        (folder / "agents").mkdir()
        (folder / "agents" / "claude.yaml").write_text("x: 1\n")
        result = self.run_check()
        self.assertIn("hooks: not yet covered", result.stderr)
        self.assertIn("agents/claude.yaml: not yet covered", result.stderr)

    # Codex per-skill agents/openai.yaml ------------------------------------------------------

    def write_openai_yaml(self, text):
        folder = add_skill(self.root)
        (folder / "agents").mkdir()
        (folder / "agents" / "openai.yaml").write_text(text)

    def test_openai_yaml_valid(self):
        self.write_openai_yaml('interface:\n  display_name: "Good"\n  short_description: "Does good things"\n'
                               '  default_prompt: "Use $good-skill to do it."\npolicy:\n  allow_implicit_invocation: true\n')
        self.assert_passes()

    def test_openai_yaml_prompt_must_name_skill(self):
        self.write_openai_yaml('interface:\n  default_prompt: "Do it."\n')
        self.assert_fails("default_prompt must mention $good-skill")

    def test_openai_yaml_display_name_limit(self):
        self.write_openai_yaml(f'interface:\n  display_name: "{"x" * 65}"\n')
        self.assert_fails("interface.display_name must be 1-64 characters")

    def test_openai_yaml_unquoted_value(self):
        self.write_openai_yaml("interface:\n  display_name: Good\n")
        self.assert_fails("quote string values")

    def test_openai_yaml_unchecked_section(self):
        self.write_openai_yaml('dependencies:\n  tools: "x"\n')
        self.assert_fails("'dependencies' not yet covered")

    def test_openai_yaml_missing_icon(self):
        self.write_openai_yaml('interface:\n  icon_small: "./assets/icon.png"\n')
        self.assert_fails("interface.icon_small must be an existing ./assets/ file")


if __name__ == "__main__":
    unittest.main()
