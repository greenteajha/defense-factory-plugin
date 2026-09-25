"""Tests for the threat-model skill's helper scripts, run against throwaway repositories."""

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "threat-model" / "scripts"
GIT_ENV = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.test",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.test"}
HAS_GIT = shutil.which("git") is not None


def run(script, *args, cwd=None):
    return subprocess.run([sys.executable, str(SCRIPTS / script), *args],
                          capture_output=True, text=True, cwd=cwd)


def git(root, *args):
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, env=GIT_ENV)


class ScriptTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "app"
        (self.root / "src" / "api").mkdir(parents=True)
        (self.root / "src" / "api" / "server.py").write_text("one\ntwo\nthree\n")
        (self.root / "SECURITY.md").write_text("# Root policy\nAuth bypass is critical.\n")
        (self.root / "src" / "api" / "SECURITY.md").write_text("# API policy\nDoS is out of scope.\n")

    def tearDown(self):
        self.tmp.cleanup()

    def init_git(self, remote=None):
        git(self.root, "init", "-q")
        git(self.root, "add", "-A")
        git(self.root, "commit", "-qm", "init")
        if remote:
            git(self.root, "remote", "add", "origin", remote)

    def identity(self, *args):
        result = run("target_identity.py", "--root", str(self.root), *args)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)


class TargetIdentityTest(ScriptTest):
    def test_sanitize_remote(self):
        spec = importlib.util.spec_from_file_location("target_identity", SCRIPTS / "target_identity.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for url in ("https://user:token@GitHub.com/Example/App.git?x=1#frag",
                    "git@github.com:Example/App.git", "ssh://git@github.com/Example/App/"):
            self.assertEqual(module.sanitize_remote(url), "github.com/Example/App", url)

    @unittest.skipUnless(HAS_GIT, "git not installed")
    def test_clean_checkout_uses_revision_and_remote_identity(self):
        self.init_git(remote="https://user:token@github.com/Example/App.git")
        data = self.identity()
        self.assertEqual(data["target_kind"], "git_revision")
        self.assertEqual(data["identity_source"], "remote")
        self.assertEqual(data["version"], data["revision"])
        expected = "sha256:" + hashlib.sha256(b"github.com/Example/App").hexdigest()
        self.assertEqual(data["target_id"], expected)
        self.assertNotIn("token", json.dumps(data))

    @unittest.skipUnless(HAS_GIT, "git not installed")
    def test_uncommitted_changes_use_stable_snapshot_digest(self):
        self.init_git()
        (self.root / "src" / "api" / "server.py").write_text("changed\n")
        first, second = self.identity("--scope", "src"), self.identity("--scope", "src")
        self.assertEqual(first["target_kind"], "git_worktree")
        self.assertTrue(first["version"].startswith("defense-factory-snapshot/v1:sha256:"))
        self.assertEqual(first["version"], second["version"])
        self.assertEqual(first["scope"], ["src"])
        (self.root / "src" / "api" / "server.py").write_text("changed again\n")
        self.assertNotEqual(self.identity("--scope", "src")["version"], first["version"])

    def test_plain_folder_is_directory_snapshot(self):
        data = self.identity()
        self.assertEqual(data["target_kind"], "directory_snapshot")
        self.assertEqual(data["identity_source"], "local-path")
        self.assertIsNone(data["revision"])
        self.assertTrue(data["version"].startswith("defense-factory-snapshot/v1:sha256:"))

    def test_scope_outside_root_is_rejected(self):
        result = run("target_identity.py", "--root", str(self.root), "--scope", str(Path(self.tmp.name)))
        self.assertEqual(result.returncode, 2)


class PrepareWorkspaceTest(ScriptTest):
    @unittest.skipUnless(HAS_GIT, "git not installed")
    def test_creates_self_ignoring_folder(self):
        self.init_git()
        result = run("prepare_workspace.py", "--root", str(self.root), "--run-id", "r1")
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(Path(data["stage_dir"]).name, "1-threat-model")
        self.assertTrue(data["git_ignored"])
        self.assertRegex(data["timestamp"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        self.assertTrue(Path(data["stage_dir"]).is_dir())
        self.assertIn("*", (self.root / ".defense-factory" / ".gitignore").read_text().splitlines())
        status = subprocess.run(["git", "-C", str(self.root), "status", "--porcelain"],
                                capture_output=True, text=True).stdout
        self.assertEqual(status, "")

    def test_non_git_target_needs_a_location(self):
        result = run("prepare_workspace.py", "--root", str(self.root))
        self.assertEqual(result.returncode, 2)
        self.assertIn("needs-location", result.stderr)

    @unittest.skipUnless(HAS_GIT, "git not installed")
    def test_unignored_custom_location_is_unsafe(self):
        self.init_git()
        result = run("prepare_workspace.py", "--root", str(self.root), "--out-dir", str(self.root / "reports"))
        self.assertEqual(result.returncode, 3)

    @unittest.skipUnless(HAS_GIT, "git not installed")
    def test_already_tracked_output_is_unsafe(self):
        (self.root / ".defense-factory").mkdir()
        (self.root / ".defense-factory" / "old.md").write_text("committed by mistake\n")
        self.init_git()
        result = run("prepare_workspace.py", "--root", str(self.root))
        self.assertEqual(result.returncode, 3)
        self.assertIn("already tracked", result.stderr)

    def test_invalid_run_id_is_rejected(self):
        result = run("prepare_workspace.py", "--root", str(self.root), "--out-dir", str(self.root / "o"),
                     "--run-id", "a/b")
        self.assertEqual(result.returncode, 2)


class ResolveSecurityMdTest(ScriptTest):
    def test_root_to_leaf_order(self):
        result = run("resolve_security_md.py", "--repo", str(self.root), "--scope", "src/api/server.py")
        self.assertEqual(result.returncode, 0, result.stderr)
        root_at = result.stdout.index("Policy from `SECURITY.md`")
        leaf_at = result.stdout.index("Policy from `src/api/SECURITY.md`")
        self.assertLess(root_at, leaf_at)
        self.assertIn("closest to the scope wins", result.stdout)

    def test_no_policy(self):
        (self.root / "SECURITY.md").unlink()
        (self.root / "src" / "api" / "SECURITY.md").unlink()
        result = run("resolve_security_md.py", "--repo", str(self.root))
        self.assertIn("No SECURITY.md policy applies", result.stdout)


class CheckCitationsTest(ScriptTest):
    def check(self, text):
        document = Path(self.tmp.name) / "model.md"
        document.write_text(text)
        result = run("check_citations.py", "--repo", str(self.root), str(document))
        return result.returncode, json.loads(result.stdout)

    def test_valid_citations_pass(self):
        code, data = self.check("See `src/api/server.py:2` and `src/api/server.py:1-3`.")
        self.assertEqual((code, data["checked"], data["invalid"]), (0, 2, []))

    def test_network_addresses_are_not_citations(self):
        code, data = self.check("Listens on `127.0.0.1:4173`, `0.0.0.0:80`, `localhost:3000`, `[::1]:443`; "
                                "see `src/api/server.py:1`.")
        self.assertEqual((code, data["checked"], data["invalid"]), (0, 1, []))

    def test_invalid_citations_fail(self):
        code, data = self.check("`src/api/server.py:9` `missing.py:1` `/etc/passwd:1` "
                                "`../outside.py:1` `src/api/server.py:3-2`")
        self.assertEqual(code, 1)
        problems = {item["citation"]: item["problem"] for item in data["invalid"]}
        self.assertIn("beyond the end", problems["src/api/server.py:9"])
        self.assertEqual(problems["missing.py:1"], "file does not exist")
        self.assertIn("relative", problems["/etc/passwd:1"])
        self.assertIn("..", problems["../outside.py:1"])
        self.assertEqual(problems["src/api/server.py:3-2"], "invalid line range")


if __name__ == "__main__":
    unittest.main()
