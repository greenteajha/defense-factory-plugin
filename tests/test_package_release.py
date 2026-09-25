"""Tests for scripts/package-release.py, run against throwaway Git copies of this repository."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "package-release.py"
GIT_ENV = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.test",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.test"}


def git(root, *args):
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, env=GIT_ENV)


@unittest.skipUnless(shutil.which("git"), "git not installed")
class PackageReleaseTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name) / "repo"
        shutil.copytree(REPO, self.repo, ignore=shutil.ignore_patterns(".git", "build", "__pycache__", ".DS_Store"))
        git(self.repo, "init", "-q")
        self.commit("initial")
        self.version = json.loads((self.repo / "plugin.json").read_text())["version"]

    def tearDown(self):
        self.tmp.cleanup()

    def commit(self, message, *force_add):
        git(self.repo, "add", "-A")
        for path in force_add:
            git(self.repo, "add", "-f", path)
        git(self.repo, "commit", "-qm", message)

    def build(self, *args, out="out"):
        result = subprocess.run([sys.executable, str(SCRIPT), "--repo", str(self.repo),
                                 "--out-dir", str(Path(self.tmp.name) / out), *args],
                                capture_output=True, text=True)
        return result

    def names(self, file, out="out"):
        with zipfile.ZipFile(Path(self.tmp.name) / out / file) as archive:
            return set(archive.namelist())

    def test_builds_every_package(self):
        result = self.build()
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = json.loads(result.stdout)
        files = {package["file"] for package in summary["packages"]}
        self.assertEqual(files, {f"defense-factory-plugin-{target}-v{self.version}.zip"
                                 for target in ("chatgpt", "claude", "cursor")} | {f"threat-model-v{self.version}.zip"})
        sums = (Path(self.tmp.name) / "out" / "SHA256SUMS").read_text()
        self.assertEqual(len(sums.splitlines()), len(files))

    def test_chatgpt_package_is_plugin_only(self):
        self.assertEqual(self.build().returncode, 0)
        names = self.names(f"defense-factory-plugin-chatgpt-v{self.version}.zip")
        self.assertIn("plugin.json", names)
        self.assertIn("skills/threat-model/SKILL.md", names)
        self.assertFalse(any(name.startswith((".agents/", ".claude-plugin/", "tests/", "scripts/", ".github/"))
                             for name in names), sorted(names))
        self.assertNotIn("skills/.gitkeep", names)

    def test_claude_package_includes_its_adapter_only(self):
        self.assertEqual(self.build().returncode, 0)
        names = self.names(f"defense-factory-plugin-claude-v{self.version}.zip")
        self.assertIn(".claude-plugin/plugin.json", names)
        self.assertIn(".claude-plugin/marketplace.json", names)
        self.assertFalse(any(name.startswith(".agents/") for name in names))

    def test_skill_package_contains_the_skill_folder(self):
        self.assertEqual(self.build().returncode, 0)
        names = self.names(f"threat-model-v{self.version}.zip")
        self.assertIn("threat-model/SKILL.md", names)
        self.assertTrue(all(name.startswith("threat-model/") for name in names), sorted(names))

    def test_builds_are_reproducible(self):
        first, second = self.build(out="one"), self.build(out="two")
        self.assertEqual((first.returncode, second.returncode), (0, 0))
        self.assertEqual((Path(self.tmp.name) / "one" / "SHA256SUMS").read_text(),
                         (Path(self.tmp.name) / "two" / "SHA256SUMS").read_text())

    def test_unclassified_top_level_entry_fails(self):
        (self.repo / "notes.md").write_text("stray\n")
        self.commit("stray file")
        result = self.build()
        self.assertEqual(result.returncode, 1)
        self.assertIn("unclassified top-level entries ['notes.md']", result.stderr)

    def test_junk_is_never_packaged(self):
        junk = self.repo / "skills" / "threat-model" / "scripts" / "__pycache__"
        junk.mkdir()
        (junk / "x.cpython-39.pyc").write_bytes(b"\0")
        (self.repo / "skills" / "threat-model" / ".DS_Store").write_bytes(b"\0")
        self.commit("junk", "skills/threat-model/scripts/__pycache__", "skills/threat-model/.DS_Store")
        self.assertEqual(self.build().returncode, 0)
        names = self.names(f"threat-model-v{self.version}.zip")
        self.assertFalse(any("__pycache__" in name or name.endswith(".DS_Store") for name in names), sorted(names))

    def test_version_must_match_expectation(self):
        result = self.build("--expect-version", "9.9.9")
        self.assertEqual(result.returncode, 1)
        self.assertIn("does not match expected 9.9.9", result.stderr)

    def test_uncommitted_changes_are_not_packaged(self):
        (self.repo / "README.md").write_text("uncommitted edit\n")
        result = self.build()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("uncommitted changes are not packaged", result.stderr)
        with zipfile.ZipFile(Path(self.tmp.name) / "out" / f"defense-factory-plugin-chatgpt-v{self.version}.zip") as archive:
            self.assertNotEqual(archive.read("README.md"), b"uncommitted edit\n")

    def test_committed_tree_must_pass_package_check(self):
        manifest = json.loads((self.repo / "plugin.json").read_text())
        manifest["skills"] = "./skills"
        (self.repo / "plugin.json").write_text(json.dumps(manifest))
        self.commit("break manifest")
        result = self.build()
        self.assertEqual(result.returncode, 1)
        self.assertIn("package check failed", result.stderr)


if __name__ == "__main__":
    unittest.main()
