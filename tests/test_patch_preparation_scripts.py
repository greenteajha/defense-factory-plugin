"""Tests for the patch-preparation (stage 4) helper scripts.

The outcome rules are tested as a pure function against hand-built patch entries. The pipeline
tests build a real stage 3b run with the attack-path test harness (FD-1 reportable, FD-3 deferred),
then start, fill, normalize, check, and render a stage 4 record, breaking one rule per test.
"""

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_finding_discovery_scripts import RUN  # noqa: E402
import test_finding_validation_scripts as tfv  # noqa: E402  (module import: its TestCases are not re-collected here)
import test_attack_path_scripts as tap  # noqa: E402  (reused to build a real stage 3b record)

REPO = Path(__file__).resolve().parents[1]
SKILL = REPO / "skills" / "patch-preparation"
PP = SKILL / "scripts"
RAW = REPO / "tests" / "fixtures" / "patch-preparation" / "patches-raw.json"
EXAMPLE = SKILL / "assets" / "patches-example.json"
FD = REPO / "skills" / "finding-discovery" / "scripts"

sys.path.insert(0, str(PP))
import check_patches  # noqa: E402
import normalize_patches as npp  # noqa: E402


def pp(script, *args):
    return subprocess.run([sys.executable, str(PP / script), *args], capture_output=True, text=True)


def a_fixed_patch(**overrides):
    """A minimal patch entry whose fixed outcome passes check_outcome."""
    patch = {
        "id": "PP-1", "analysis_id": "AP-1", "finding_id": "FD-1", "finding_key": "k", "title": "t",
        "severity": "high", "priority": "P1", "outcome": "fixed",
        "locations": [{"path": "a.py", "start_line": 1, "end_line": 1, "role": "root_control"}],
        "vulnerable_path": "path", "security_invariant": "inv", "patch_strategy": "fix",
        "patch_ref": "patches/FD-1.patch", "files_changed": ["a.py"], "tests_added": ["t.py"],
        "gates": [{"gate": "build", "result": "pass"}, {"gate": "reproduction blocked", "result": "pass"}],
        "reproduction_before": "crashed", "reproduction_after": "blocked", "legitimate_behavior": "ok",
        "candidate_review": "reviewed", "remaining_risk": "none",
        "confidence": {"level": "High", "reason": "reproduced"},
    }
    patch.update(overrides)
    return patch


class OutcomeTest(unittest.TestCase):
    def problems(self, patch):
        found = []
        check_patches.check_outcome(patch, found)
        return found

    def test_fixed_passes_when_gates_pass(self):
        self.assertEqual(self.problems(a_fixed_patch()), [])

    def test_fixed_needs_every_gate_to_pass(self):
        patch = a_fixed_patch(gates=[{"gate": "build", "result": "pass"}, {"gate": "repro", "result": "fail"}])
        self.assertTrue(any("every verification gate to pass" in p for p in self.problems(patch)))

    def test_fixed_needs_a_written_patch(self):
        self.assertTrue(any("written patch" in p for p in self.problems(a_fixed_patch(patch_ref=None))))

    def test_fixed_needs_a_test(self):
        self.assertTrue(any("focused test" in p for p in self.problems(a_fixed_patch(tests_added=[]))))

    def test_fixed_needs_reproduction_after(self):
        self.assertTrue(any("no longer reproduces" in p for p in self.problems(a_fixed_patch(reproduction_after="unknown"))))

    def test_no_change_writes_no_patch(self):
        patch = a_fixed_patch(outcome="no_change", patch_ref="patches/x.patch", files_changed=[], tests_added=[],
                              gates=[])
        self.assertTrue(any("writes no patch" in p for p in self.problems(patch)))

    def test_no_change_changes_no_file(self):
        patch = a_fixed_patch(outcome="no_change", patch_ref=None, files_changed=["a.py"], tests_added=[], gates=[])
        self.assertTrue(any("changes no file" in p for p in self.problems(patch)))

    def test_no_change_passes(self):
        patch = a_fixed_patch(outcome="no_change", patch_ref=None, files_changed=[], tests_added=[], gates=[])
        self.assertEqual(self.problems(patch), [])

    def test_blocked_needs_a_proof_gap(self):
        patch = a_fixed_patch(outcome="blocked", patch_ref=None, files_changed=[], tests_added=[], gates=[])
        self.assertTrue(any("proof_gap" in p for p in self.problems(patch)))

    def test_inconclusive_is_never_high_confidence(self):
        patch = a_fixed_patch(outcome="inconclusive", patch_ref=None, files_changed=[], tests_added=[], gates=[],
                              proof_gap="gate could not run", confidence={"level": "High", "reason": "x"})
        self.assertTrue(any("High confidence" in p for p in self.problems(patch)))


class ExampleTest(unittest.TestCase):
    def test_shipped_example_is_the_normalized_fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "example.json"
            result = pp("normalize_patches.py", "--out", str(out), str(RAW))
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertEqual(json.loads(out.read_text()), json.loads(EXAMPLE.read_text()),
                             "assets/patches-example.json is stale; regenerate it from the raw fixture")

    def test_normalize_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            one, two = Path(tmp) / "one.json", Path(tmp) / "two.json"
            self.assertEqual(pp("normalize_patches.py", "--out", str(one), str(RAW)).returncode, 0)
            self.assertEqual(pp("normalize_patches.py", "--out", str(two), str(one)).returncode, 0)
            self.assertEqual(one.read_text(), two.read_text())

    def test_example_patches_follow_the_outcome_rules(self):
        for patch in json.loads(EXAMPLE.read_text())["patches"]:
            problems = []
            check_patches.check_outcome(patch, problems)
            self.assertEqual(problems, [], patch["id"])


@unittest.skipUnless(tfv.HAS_GIT, "git is required")
class Stage4Test(unittest.TestCase):
    def setUp(self):
        self.s3b = tap.Stage3bTest("test_filled_record_passes_and_renders")
        self.s3b.setUp()
        self.s3b.fill()  # FD-1 reportable (medium/P2), FD-3 deferred; status complete, checked
        code, problems = self.s3b.check()
        self.assertEqual(code, 0, problems)
        self.root = self.s3b.root
        self.attack_paths = self.s3b.record
        result = subprocess.run([sys.executable, str(FD / "prepare_workspace.py"), "--root", str(self.root),
                                 "--run-id", RUN, "--stage", "4-patch-preparation"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.stage = self.s3b.stage.parent / "4-patch-preparation"
        self.record = self.stage / "patches.json"

    def tearDown(self):
        self.s3b.tearDown()

    def start(self, *extra):
        return pp("start_patches.py", "--root", str(self.root), "--stage-dir", str(self.stage),
                  "--attack-paths", str(self.attack_paths), *extra)

    def check(self):
        result = pp("check_patches.py", "--repo", str(self.root), str(self.record))
        return result.returncode, json.loads(result.stdout)["problems"]

    def fill(self, change=None):
        """Start, fill the FD-1 patch as a fixed outcome and the environment, apply change, normalize."""
        self.assertEqual(self.start().returncode, 0)
        (self.stage / "patches").mkdir(exist_ok=True)
        (self.stage / "patches" / "FD-1.patch").write_text("stub diff\n")
        data = json.loads(self.record.read_text())
        record = data["record"]
        record.update(actor="Test agent", model="Test Model 1.0", status="complete",
                      next_action="Stage 5: human review of the patch for FD-1.")
        record["tools"] = record["tools"].split("<fill")[0] + "normalize/check/render_patches.py"
        data["environment"] = {
            "host_os": "linux", "host_arch": "x86_64", "engine": "docker", "engine_version": "29.0",
            "base_image": "python:3.12-slim", "base_image_digest": "sha256:" + "1" * 64, "emulation": "none",
            "code_source": "copied-files",
            "limits": {"memory": "2g", "cpus": "2", "pids": 256, "timeout_seconds": 300},
            "network_setup": "on", "network_testing": "off",
            "cleanup": {"label": f"com.defensefactory.run={RUN}",
                        "removed": {"containers": 1, "images": 1, "volumes": 0, "networks": 0}, "remaining": 0},
        }
        for p in data["patches"]:
            p.update(outcome="fixed",
                     vulnerable_path="Attacker input reaches the sink.",
                     security_invariant="The boundary holds.",
                     patch_strategy="Normalize and contain at the shared boundary.",
                     patch_ref="patches/FD-1.patch", files_changed=["src/api/upload.py"],
                     tests_added=["tests/test_upload.py: the crafted input is rejected"],
                     gates=[{"gate": "build", "result": "pass"},
                            {"gate": "reproduction blocked", "result": "pass"},
                            {"gate": "legitimate control", "result": "pass"},
                            {"gate": "existing tests", "result": "pass"}],
                     reproduction_before="Per stage 3, the input reached the sink.",
                     reproduction_after="The same input is now rejected.",
                     legitimate_behavior="A normal request still works.",
                     candidate_review="Fresh review: no surviving route.",
                     remaining_risk="Siblings are separate findings.",
                     confidence={"level": "High", "reason": "Reproduced before and after."})
            p.pop("proof_gap", None)
        if change:
            change(data)
        self.record.write_text(json.dumps(data, indent=2))
        result = pp("normalize_patches.py", str(self.record))
        self.assertEqual(result.returncode, 0, result.stdout)
        return json.loads(self.record.read_text())

    def assert_check_fails(self, change, message):
        self.fill(change)
        code, problems = self.check()
        self.assertEqual(code, 1, problems)
        self.assertTrue(any(message in p for p in problems), problems)

    def patch(self, data, finding):
        return next(p for p in data["patches"] if p["finding_id"] == finding)

    # find_attack_paths.py / start_patches.py ----------------------------------------------------

    def test_find_attack_paths_selects_the_record(self):
        result = pp("find_attack_paths.py", "--root", str(self.root))
        self.assertEqual(result.returncode, 0, result.stdout)
        report = json.loads(result.stdout)
        self.assertEqual((report["run_id"], report["reportable"], report["not_reportable"]), (RUN, 1, 1))

    def test_start_selects_reportable_and_lists_the_rest(self):
        result = self.start()
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["patches"], ["FD-1"])
        self.assertEqual(report["not_eligible"], ["FD-3"])
        self.assertTrue(report["authorization_inherited"])
        data = json.loads(self.record.read_text())
        self.assertIsNone(data["environment"])
        self.assertTrue(data["record"]["authorization"].startswith(f"inherited from stage 3b run {RUN}: "))

    def test_start_never_overwrites(self):
        self.assertEqual(self.start().returncode, 0)
        self.assertEqual(self.start().returncode, 3)

    def test_start_refuses_a_non_reportable_finding(self):
        self.assertEqual(self.start("--finding", "FD-3").returncode, 1)
        self.assertFalse(self.record.exists())

    # check_patches.py ---------------------------------------------------------------------------

    def test_skeleton_fails_on_placeholders(self):
        self.assertEqual(self.start().returncode, 0)
        self.assertEqual(pp("normalize_patches.py", str(self.record)).returncode, 0)
        code, problems = self.check()
        self.assertEqual(code, 1)
        self.assertTrue(any("placeholder" in p for p in problems), problems)

    def test_filled_record_passes_and_renders(self):
        data = self.fill()
        code, problems = self.check()
        self.assertEqual(code, 0, problems)
        self.assertEqual([(p["id"], p["finding_id"], p["outcome"]) for p in data["patches"]], [("PP-1", "FD-1", "fixed")])
        self.assertEqual(pp("render_patches.py", str(self.record)).returncode, 0)
        report = self.stage / "patches.md"
        result = subprocess.run([sys.executable, str(FD / "check_citations.py"), "--repo", str(self.root), str(report)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_fixed_needs_gates_to_pass(self):
        self.assert_check_fails(lambda d: self.patch(d, "FD-1")["gates"].append({"gate": "extra", "result": "fail"}),
                                "every verification gate to pass")

    def test_severity_must_match_stage3b(self):
        self.assert_check_fails(lambda d: self.patch(d, "FD-1").update(severity="critical"),
                                "does not match the stage 3b analysis")

    def test_priority_must_match_stage3b(self):
        self.assert_check_fails(lambda d: self.patch(d, "FD-1").update(priority="P0"),
                                "does not match the stage 3b analysis")

    def test_locations_must_not_change(self):
        self.assert_check_fails(lambda d: self.patch(d, "FD-1")["locations"][0].update(start_line=99),
                                "locations must be the stage 3b analysis's locations")

    def test_non_reportable_analysis_is_not_patched(self):
        def change(d):
            extra = copy.deepcopy(self.patch(d, "FD-1"))
            extra.update(analysis_id="AP-2", finding_id="FD-3", finding_key="k3", severity="low", priority="P3")
            extra["finding_fingerprint"] = None
            d["patches"].append(extra)
        self.assert_check_fails(change, "not reportable")

    def test_not_eligible_must_match(self):
        self.assert_check_fails(lambda d: d["not_eligible"].pop(), "not_eligible must list exactly")

    def test_complete_needs_full_coverage(self):
        self.assert_check_fails(lambda d: d["patches"].pop(), "neither patched nor named")

    def test_complete_rejects_an_inconclusive_outcome(self):
        def change(d):
            p = self.patch(d, "FD-1")
            p.update(outcome="inconclusive", proof_gap="gate could not run",
                     confidence={"level": "Low", "reason": "unverified"})
        self.assert_check_fails(change, "blocked or inconclusive")

    def test_blocked_record_has_no_environment(self):
        self.assert_check_fails(
            lambda d: (d["record"].update(status="blocked"), d.__setitem__("environment", d["environment"]))[0],
            "blocked record")

    def test_stage3b_record_edited_afterwards(self):
        self.fill()
        text = self.attack_paths.read_text()
        self.attack_paths.write_text(text.replace('"open_questions"', '"open_questions_x"', 1)
                                     if '"open_questions"' in text else text + " ")
        code, problems = self.check()
        self.assertEqual(code, 1)
        self.assertTrue(any("validated_record.sha256" in p or "attack-paths.json" in p for p in problems), problems)


if __name__ == "__main__":
    unittest.main()
