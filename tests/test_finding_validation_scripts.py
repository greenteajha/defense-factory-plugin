"""Tests for the finding-validation (stage 3) helper scripts, run against throwaway repositories.

The setup reuses the finding-discovery fixture to build a valid stage 2 findings.json, then
exercises the stage 3 pipeline: find_findings, start_validation, normalize/check/render, plus the
container helpers export_target and cleanup_run. Tests that need a container engine are skipped
when none is available; the clean-up safety test uses only volumes and networks, so it needs no
image and no network.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_finding_discovery_scripts import STAGE1_MODEL, SOURCE_FILES, GIT_ENV, RUN  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
FD = REPO / "skills" / "finding-discovery" / "scripts"
FV = REPO / "skills" / "finding-validation" / "scripts"
RAW_FD = REPO / "tests" / "fixtures" / "finding-discovery" / "findings-raw.json"
RAW_FV = REPO / "tests" / "fixtures" / "finding-validation" / "validations-raw.json"
EXAMPLE_FV = REPO / "skills" / "finding-validation" / "assets" / "validations-example.json"
HAS_GIT = shutil.which("git") is not None

sys.path.insert(0, str(FV))
import engine as engine_mod  # noqa: E402
ENGINE = engine_mod.docker_bin()
HAS_ENGINE = bool(ENGINE) and engine_mod.daemon_ok(ENGINE)


def fv(script, *args):
    return subprocess.run([sys.executable, str(FV / script), *args], capture_output=True, text=True)


def fd(script, *args):
    return subprocess.run([sys.executable, str(FD / script), *args], capture_output=True, text=True)


def git(root, *args):
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, env=GIT_ENV)


@unittest.skipUnless(HAS_GIT, "git is required")
class Stage3Test(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "app"
        for relative, count in SOURCE_FILES.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("".join(f"line {n}\n" for n in range(1, count + 1)))
        (self.root / "package-lock.json").write_text("{}\n")
        git(self.root, "init", "-q")
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "init")
        for stage in ("1-threat-model", "2-finding-discovery", "3-finding-validation"):
            self.assertEqual(fd("prepare_workspace.py", "--root", str(self.root), "--run-id", RUN, "--stage", stage).returncode, 0)
        run_dir = self.root / ".defense-factory" / "runs" / RUN
        self.s1, self.s2, self.s3 = (run_dir / "1-threat-model", run_dir / "2-finding-discovery",
                                     run_dir / "3-finding-validation")
        self.identity = json.loads(fd("target_identity.py", "--root", str(self.root)).stdout)
        (self.s1 / "threat-model.md").write_text(STAGE1_MODEL.format(
            run=RUN, scope="whole-repository",
            **{k: self.identity[k] for k in ("target_id", "target_kind", "version", "revision")}))
        (self.s2 / "security-guidance.md").write_text("# Resolved security policy\nNone.\n")
        self.assertEqual(fd("list_scope_files.py", "--root", str(self.root),
                            "--out", str(self.s2 / "scope-inventory.txt")).returncode, 0)
        data = json.loads(RAW_FD.read_text())
        for field in ("target_id", "target_kind", "version", "revision"):
            data["record"][field] = self.identity[field]
        data["threat_model"]["sha256"] = hashlib.sha256((self.s1 / "threat-model.md").read_bytes()).hexdigest()
        self.findings = self.s2 / "findings.json"
        self.findings.write_text(json.dumps(data, indent=2))
        self.assertEqual(fd("normalize_findings.py", "--repo", str(self.root), str(self.findings)).returncode, 0)
        code, problems = self.check_findings()
        self.assertEqual(code, 0, problems)
        self.validations = self.s3 / "validations.json"

    def tearDown(self):
        self.tmp.cleanup()

    # Helpers ------------------------------------------------------------------------------------

    def check_findings(self):
        result = fd("check_findings.py", "--repo", str(self.root), str(self.findings))
        return result.returncode, json.loads(result.stdout)["problems"]

    def start(self, *extra):
        return fv("start_validation.py", "--root", str(self.root), "--stage-dir", str(self.s3),
                  "--findings", str(self.findings), *extra)

    def check(self):
        result = fv("check_validations.py", "--repo", str(self.root), str(self.validations))
        return result.returncode, json.loads(result.stdout)["problems"]

    def fill(self, change=None, status="complete"):
        """Start a run, fill every entry as a clean verdict, apply change(data), and normalize."""
        self.assertEqual(self.start().returncode, 0)
        data = json.loads(self.validations.read_text())
        record = data["record"]
        record["actor"] = "Test agent (Claude Code)"
        record["model"] = "Test Model 1.0"
        record["tools"] = record["tools"].split("<fill")[0] + "docker 29.6.2"
        record["next_action"] = "Human triage."
        record["status"] = status
        data["environment"] = {
            "host_os": "darwin", "host_arch": "arm64", "engine": "docker", "engine_version": "29.6.2",
            "base_image": "python:3.12-slim", "base_image_digest": "sha256:" + "a" * 64,
            "emulation": "none", "code_source": "git-archive:" + (self.identity["revision"] or "HEAD"),
            "limits": {"memory": "2g", "cpus": "2", "pids": 512, "timeout_seconds": 600},
            "network_setup": "on", "network_testing": "off",
            "cleanup": {"label": "com.defensefactory.run=" + RUN,
                        "removed": {"containers": 1, "images": 1, "volumes": 0, "networks": 1}, "remaining": 0},
        }
        for index, entry in enumerate(data["validations"]):
            entry["control"] = "Benign request returned 200 at `src/api/routes.py:1`."
            entry["reachability"] = "Attacker input reached the sink at `src/api/upload.py:24`."
            entry["evidence"] = "Observed the effect."
            entry["counterevidence_or_proof_gap"] = "none"
            entry["setup_notes"] = "Installed deps; app started."
            entry["remaining_uncertainty"] = "none"
            entry["next_step"] = "none"
            if index % 2 == 0:
                entry.update(verdict="confirmed", method="interface-reproduction", reproduced=True,
                             repeat_confirmed=True, confidence={"level": "High", "reason": "Reproduced twice."},
                             rubric=[{"criterion": "exploit works", "result": "pass"}])
            else:
                entry.update(verdict="rejected", method="targeted-test", reproduced=True, repeat_confirmed=False,
                             confidence={"level": "Medium", "reason": "Control held."},
                             counterevidence_or_proof_gap="The allowlist blocked it.",
                             rubric=[{"criterion": "exploit works", "result": "fail"}])
        if change:
            change(data)
        self.validations.write_text(json.dumps(data, indent=2))
        self.assertEqual(fv("normalize_validations.py", str(self.validations)).returncode, 0,
                         fv("normalize_validations.py", str(self.validations)).stdout)
        return data

    def assert_check_fails(self, change, message, status="complete"):
        self.fill(change, status=status)
        code, problems = self.check()
        self.assertEqual(code, 1, problems)
        self.assertTrue(any(message in problem for problem in problems), problems)

    # find_findings.py ---------------------------------------------------------------------------

    def test_find_findings_selects_the_valid_record(self):
        result = fv("find_findings.py", "--root", str(self.root))
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["run_id"], RUN)
        self.assertEqual(report["finding_count"], 4)

    def test_find_findings_rejects_a_stale_record(self):
        (self.root / "src" / "api" / "routes.py").write_text("changed\n")
        git(self.root, "commit", "-aqm", "change")
        result = fv("find_findings.py", "--root", str(self.root))
        self.assertEqual(result.returncode, 1)
        self.assertIsNone(json.loads(result.stdout)["findings"])

    # start_validation.py ------------------------------------------------------------------------

    def test_start_writes_skeleton_and_inherits_authorization(self):
        result = self.start()
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report["authorization_inherited"])
        self.assertEqual(report["findings_selected"], ["FD-1", "FD-2", "FD-3", "FD-4"])
        data = json.loads(self.validations.read_text())
        self.assertEqual(data["record"]["source"], "validated-record")
        self.assertIsNone(data["environment"])
        self.assertTrue(data["record"]["authorization"].startswith(f"inherited from stage 2 run {RUN}: "))

    def test_start_never_overwrites(self):
        self.assertEqual(self.start().returncode, 0)
        self.assertEqual(self.start().returncode, 3)

    def test_start_subset_defers_the_rest(self):
        result = self.start("--finding", "FD-1")
        report = json.loads(result.stdout)
        self.assertEqual(report["findings_selected"], ["FD-1"])
        self.assertEqual(set(report["findings_deferred"]), {"FD-2", "FD-3", "FD-4"})
        gaps = json.loads(self.validations.read_text())["record"]["coverage_gaps"]
        self.assertTrue(any("FD-2" in gap for gap in gaps))

    def test_start_rejects_unknown_finding(self):
        result = self.start("--finding", "FD-99")
        self.assertEqual(result.returncode, 1)
        self.assertFalse(self.validations.exists())

    # check_validations.py -----------------------------------------------------------------------

    def test_skeleton_fails_on_placeholders(self):
        self.assertEqual(self.start().returncode, 0)
        self.assertEqual(fv("normalize_validations.py", str(self.validations)).returncode, 0)
        code, problems = self.check()
        self.assertEqual(code, 1)
        self.assertTrue(any("placeholder" in problem for problem in problems), problems)

    def test_clean_complete_run_passes(self):
        self.fill()
        code, problems = self.check()
        self.assertEqual(code, 0, problems)

    def test_complete_blocked_by_inconclusive_verdict(self):
        def change(data):
            data["validations"][0].update(verdict="inconclusive", method="static-assessment",
                                          reproduced=False, repeat_confirmed=False,
                                          confidence={"level": "Low", "reason": "static only"},
                                          counterevidence_or_proof_gap="no harness")
        self.assert_check_fails(change, "inconclusive")

    def test_static_assessment_cannot_be_high(self):
        def change(data):
            data["validations"][0].update(method="static-assessment", reproduced=False)
        self.assert_check_fails(change, "static-assessment cannot be High")

    def test_static_assessment_cannot_be_reproduced(self):
        def change(data):
            data["validations"][0].update(method="static-assessment", reproduced=True,
                                          confidence={"level": "Low", "reason": "x"})
        self.assert_check_fails(change, "never reproduced")

    def test_dynamic_method_must_be_reproduced(self):
        def change(data):
            data["validations"][0]["reproduced"] = False
        self.assert_check_fails(change, "reproduced must be true")

    def test_confirmed_needs_repeat(self):
        def change(data):
            data["validations"][0]["repeat_confirmed"] = False
        self.assert_check_fails(change, "reproduced once")

    def test_confirmed_needs_a_passing_criterion(self):
        def change(data):
            data["validations"][0]["rubric"] = [{"criterion": "exploit works", "result": "unknown"}]
        self.assert_check_fails(change, "criterion that passed")

    def test_confirmed_needs_reachability(self):
        def change(data):
            data["validations"][0]["reachability"] = "none"
        self.assert_check_fails(change, "reached")

    def test_rejected_needs_a_failing_criterion(self):
        def change(data):
            data["validations"][1]["rubric"] = [{"criterion": "exploit works", "result": "pass"}]
        self.assert_check_fails(change, "criterion that failed")

    def test_finding_key_must_match(self):
        def change(data):
            data["validations"][0]["finding_key"] = "wrong-key"
        self.assert_check_fails(change, "does not match")

    def test_supplied_finding_forbids_validated_record(self):
        def change(data):
            data["record"]["source"] = "supplied-finding"
        self.assert_check_fails(change, "must be null when source is supplied-finding")

    def test_blocked_has_no_validations_or_environment(self):
        self.assertEqual(self.start().returncode, 0)
        data = json.loads(self.validations.read_text())
        data["record"].update(actor="A", model="M 1.0", status="blocked",
                               next_action="User is not authorized.")
        data["record"]["tools"] = data["record"]["tools"].split("<fill")[0] + "none"
        data["validations"] = []
        data["environment"] = None
        self.validations.write_text(json.dumps(data, indent=2))
        self.assertEqual(fv("normalize_validations.py", str(self.validations)).returncode, 0)
        code, problems = self.check()
        self.assertEqual(code, 0, problems)

    # normalize / render / example ---------------------------------------------------------------

    def test_normalize_orders_and_numbers(self):
        self.fill()
        data = json.loads(self.validations.read_text())
        self.assertEqual([entry["id"] for entry in data["validations"]], ["VD-1", "VD-2", "VD-3", "VD-4"])
        self.assertEqual([entry["finding_id"] for entry in data["validations"]], ["FD-1", "FD-2", "FD-3", "FD-4"])

    def test_render_writes_report_and_citations_pass(self):
        self.fill()
        self.assertEqual(self.check()[0], 0)
        self.assertEqual(fv("render_validations.py", str(self.validations)).returncode, 0)
        report = self.s3 / "validation.md"
        self.assertTrue(report.is_file())
        self.assertEqual(fd("check_citations.py", "--repo", str(self.root), str(report)).returncode, 0)


class Stage3PureTest(unittest.TestCase):
    """Tests that need neither git nor an engine."""

    def test_shipped_example_is_the_normalized_fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "example.json"
            result = fv("normalize_validations.py", "--out", str(out), str(RAW_FV))
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertEqual(json.loads(out.read_text()), json.loads(EXAMPLE_FV.read_text()),
                             "assets/validations-example.json is stale; regenerate it from the raw fixture")

    def test_normalize_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            one, two = Path(tmp) / "one.json", Path(tmp) / "two.json"
            self.assertEqual(fv("normalize_validations.py", "--out", str(one), str(RAW_FV)).returncode, 0)
            self.assertEqual(fv("normalize_validations.py", "--out", str(two), str(one)).returncode, 0)
            self.assertEqual(one.read_text(), two.read_text())

    def test_environment_arch_normalization(self):
        sys.path.insert(0, str(FV))
        import check_environment  # noqa: E402
        self.assertEqual(check_environment.normalize_arch("x86_64"), "amd64")
        self.assertEqual(check_environment.normalize_arch("aarch64"), "arm64")


@unittest.skipUnless(HAS_ENGINE, "a container engine is required")
class CleanupSafetyTest(unittest.TestCase):
    """cleanup_run.py removes only labelled resources and never touches anything else."""

    def setUp(self):
        self.run_id = f"dftest{os.getpid()}"
        self.label = f"com.defensefactory.run={self.run_id}"
        self.created = []

    def tearDown(self):
        # Remove anything this test created that survived (the unlabelled controls).
        for kind, name in self.created:
            engine_mod.run(ENGINE, *( ["volume", "rm", "-f", name] if kind == "volume"
                                     else ["network", "rm", name]))

    def make(self, kind, name, labelled):
        args = [name] if kind == "network" else ["create", name] if False else None
        if kind == "volume":
            cmd = ["volume", "create"] + (["--label", self.label] if labelled else []) + [name]
        else:
            cmd = ["network", "create"] + (["--label", self.label] if labelled else []) + [name]
        result = engine_mod.run(ENGINE, *cmd)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.created.append((kind, name))

    def exists(self, kind, name):
        listers = {"volume": ["volume", "ls", "-q"], "network": ["network", "ls", "--format", "{{.Name}}"]}
        return name in engine_mod.run(ENGINE, *listers[kind]).stdout.split()

    def test_removes_only_labelled(self):
        keep_vol, keep_net = f"dfkeep_vol_{self.run_id}", f"dfkeep_net_{self.run_id}"
        drop_vol, drop_net = f"dfdrop_vol_{self.run_id}", f"dfdrop_net_{self.run_id}"
        self.make("volume", keep_vol, labelled=False)
        self.make("network", keep_net, labelled=False)
        self.make("volume", drop_vol, labelled=True)
        self.make("network", drop_net, labelled=True)

        result = fv("cleanup_run.py", "--run-id", self.run_id)
        self.assertEqual(result.returncode, 0, result.stdout)
        report = json.loads(result.stdout)
        # Volumes list by name; networks list by id. Assert removal by absence below.
        self.assertIn(drop_vol, report["removed"]["volumes"])
        self.assertEqual(len(report["removed"]["networks"]), 1)
        self.assertEqual(report["remaining"], {})

        self.assertFalse(self.exists("volume", drop_vol), "labelled volume should be gone")
        self.assertFalse(self.exists("network", drop_net), "labelled network should be gone")
        self.assertTrue(self.exists("volume", keep_vol), "unlabelled volume must survive")
        self.assertTrue(self.exists("network", keep_net), "unlabelled network must survive")

    def test_cleanup_is_idempotent(self):
        self.make("volume", f"dfdrop_vol_{self.run_id}", labelled=True)
        self.assertEqual(fv("cleanup_run.py", "--run-id", self.run_id).returncode, 0)
        self.assertEqual(fv("cleanup_run.py", "--run-id", self.run_id).returncode, 0)


class PrerequisiteCheckTest(unittest.TestCase):
    """check_environment.py reports each unmet prerequisite as: what is not met, and how to fix it."""

    REVIEW = REPO / "skills" / "defense-factory-review" / "scripts" / "check_environment.py"

    def check(self, *args, docker=None, script=None):
        env = {**os.environ}
        if docker is not None:
            env["DEFENSE_FACTORY_DOCKER"] = docker
        result = subprocess.run([sys.executable, str(script or FV / "check_environment.py"), *args],
                                capture_output=True, text=True, env=env)
        return result.returncode, json.loads(result.stdout)

    def assert_actionable(self, entry):
        for field in ("prerequisite", "problem", "verify"):
            self.assertTrue(entry[field].strip(), field)
        self.assertTrue(entry["fix"] and all(step.strip() for step in entry["fix"]))

    def test_docker_missing(self):
        code, report = self.check(docker="/nonexistent/docker")
        self.assertEqual(code, 1)
        self.assertFalse(report["ready"])
        self.assertEqual(len(report["unmet"]), 1)
        entry = report["unmet"][0]
        self.assert_actionable(entry)
        self.assertIn("installed", entry["prerequisite"])
        self.assertIn("docker.com", entry["fix"][0])

    def test_docker_not_running(self):
        code, report = self.check(docker="/usr/bin/false")
        self.assertEqual(code, 1)
        entry = report["unmet"][0]
        self.assert_actionable(entry)
        self.assertIn("running", entry["prerequisite"])
        self.assertTrue(any("remote or cloud session" in step for step in entry["fix"]))

    @unittest.skipUnless(HAS_ENGINE, "a container engine is required")
    def test_memory_below_floor(self):
        code, report = self.check("--min-memory-gb", "100000")
        self.assertEqual(code, 1)
        entry = report["unmet"][0]
        self.assert_actionable(entry)
        self.assertIn("memory", entry["prerequisite"].lower())
        self.assertTrue(any("Resources" in step for step in entry["fix"]))

    @unittest.skipUnless(HAS_ENGINE, "a container engine is required")
    def test_ready_has_nothing_unmet(self):
        code, report = self.check()
        self.assertEqual(code, 0)
        self.assertTrue(report["ready"])
        self.assertEqual(report["unmet"], [])

    def test_review_skill_copy_runs(self):
        code, report = self.check(docker="/nonexistent/docker", script=self.REVIEW)
        self.assertEqual(code, 1)
        self.assert_actionable(report["unmet"][0])


@unittest.skipUnless(HAS_GIT, "git is required")
class ExportTargetTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "app"
        (self.root / "src").mkdir(parents=True)
        (self.root / "src" / "main.py").write_text("print('hi')\n")
        (self.root / "README.md").write_text("readme\n")
        git(self.root, "init", "-q")
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "init")

    def tearDown(self):
        self.tmp.cleanup()

    def test_git_archive_export(self):
        out = Path(self.tmp.name) / "ctx"
        result = fv("export_target.py", "--root", str(self.root), "--out", str(out), "--run-id", "r1")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report["code_source"].startswith("git-archive:"))
        self.assertTrue((out / "src" / "main.py").is_file())
        self.assertEqual(report["run_label"], "com.defensefactory.run=r1")

    def test_copied_files_for_non_git(self):
        shutil.rmtree(self.root / ".git")
        out = Path(self.tmp.name) / "ctx2"
        result = fv("export_target.py", "--root", str(self.root), "--out", str(out), "--run-id", "r2")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["code_source"], "copied-files")
        self.assertTrue((out / "src" / "main.py").is_file())

    def test_refuses_nonempty_out(self):
        out = Path(self.tmp.name) / "ctx3"
        out.mkdir()
        (out / "x").write_text("x")
        self.assertEqual(fv("export_target.py", "--root", str(self.root), "--out", str(out), "--run-id", "r3").returncode, 2)


if __name__ == "__main__":
    unittest.main()
