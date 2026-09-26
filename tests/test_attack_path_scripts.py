"""Tests for the attack-path-analysis (stage 3b) helper scripts.

The severity policy is tested cell by cell against an independent copy of the matrix. The pipeline
tests build a real stage 3 run with the finding-validation test harness (FD-1 confirmed, FD-2 and
FD-4 rejected, FD-3 inconclusive), then start, fill, normalize, check, and render a stage 3b record,
breaking one rule per test.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_finding_discovery_scripts import RUN  # noqa: E402
import test_finding_validation_scripts as tfv  # noqa: E402  (module import: its TestCases are not re-collected here)

REPO = Path(__file__).resolve().parents[1]
SKILL = REPO / "skills" / "attack-path-analysis"
AP = SKILL / "scripts"
RAW = REPO / "tests" / "fixtures" / "attack-path-analysis" / "attack-paths-raw.json"
EXAMPLE = SKILL / "assets" / "attack-paths-example.json"
FD = REPO / "skills" / "finding-discovery" / "scripts"

sys.path.insert(0, str(AP))
import check_attack_paths  # noqa: E402
import normalize_attack_paths as nap  # noqa: E402


def ap(script, *args):
    return subprocess.run([sys.executable, str(AP / script), *args], capture_output=True, text=True)


# An independent copy of the policy, so an accidental edit to MATRIX fails here.
EXPECTED = {
    ("high", "high"): "high", ("high", "medium"): "medium", ("high", "low"): "low", ("high", "unknown"): "medium",
    ("medium", "high"): "medium", ("medium", "medium"): "low", ("medium", "low"): "low", ("medium", "unknown"): "low",
    ("low", "high"): "low", ("low", "medium"): "low", ("low", "low"): "low", ("low", "unknown"): "low",
    ("unknown", "high"): "medium", ("unknown", "medium"): "low", ("unknown", "low"): "low", ("unknown", "unknown"): "low",
}
RATINGS = ("high", "medium", "low", "unknown", "ignore")


class PolicyTest(unittest.TestCase):
    def rate(self, impact, likelihood, criteria=False, suppression=None):
        return nap.expected_severity({"impact": impact, "likelihood": likelihood,
                                      "critical_criteria_met": criteria, "suppression": suppression})

    def test_every_matrix_cell(self):
        for impact in RATINGS:
            for likelihood in RATINGS:
                want = "ignore" if "ignore" in (impact, likelihood) else EXPECTED[(impact, likelihood)]
                self.assertEqual(self.rate(impact, likelihood), want, (impact, likelihood))

    def test_critical_needs_the_criteria(self):
        self.assertEqual(self.rate("high", "high", criteria=True), "critical")
        self.assertEqual(self.rate("high", "high", criteria=False), "high")
        self.assertEqual(self.rate("medium", "high", criteria=True), "medium")

    def test_override_replaces_the_matrix_but_not_suppression(self):
        override = {"severity": "high", "row": "High: a visited page reading intelligence (TM-H1)", "reason": "fits"}
        base = {"impact": "medium", "likelihood": "medium", "critical_criteria_met": False, "calibration_override": override}
        self.assertEqual(nap.expected_severity({**base, "suppression": None}), "high")
        self.assertEqual(nap.expected_severity({**base, "suppression": "out-of-scope"}), "ignore")
        self.assertEqual(nap.matrix_severity(base), "low")

    def test_suppression_always_ignores(self):
        for reason in ("self-only-impact", "no-realistic-attacker-path", "out-of-scope"):
            self.assertEqual(self.rate("high", "high", criteria=True, suppression=reason), "ignore")

    def test_never_below_low_unless_ignored(self):
        for impact in RATINGS[:4]:
            for likelihood in RATINGS[:4]:
                self.assertIn(self.rate(impact, likelihood), ("critical", "high", "medium", "low"))

    def test_priority_mapping(self):
        for severity, priority in (("critical", "P0"), ("high", "P1"), ("medium", "P2"), ("low", "P3"),
                                   ("ignore", None), ("unknown", None)):
            self.assertEqual(nap.priority_for({"severity": severity, "decision": "deferred"}), priority)
        self.assertIsNone(nap.priority_for({"severity": "high", "decision": "ignore"}))


class ExampleTest(unittest.TestCase):
    def test_shipped_example_is_the_normalized_fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "example.json"
            result = ap("normalize_attack_paths.py", "--out", str(out), str(RAW))
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertEqual(json.loads(out.read_text()), json.loads(EXAMPLE.read_text()),
                             "assets/attack-paths-example.json is stale; regenerate it from the raw fixture")

    def test_normalize_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            one, two = Path(tmp) / "one.json", Path(tmp) / "two.json"
            self.assertEqual(ap("normalize_attack_paths.py", "--out", str(one), str(RAW)).returncode, 0)
            self.assertEqual(ap("normalize_attack_paths.py", "--out", str(two), str(one)).returncode, 0)
            self.assertEqual(one.read_text(), two.read_text())

    def test_example_follows_the_policy(self):
        for analysis in json.loads(EXAMPLE.read_text())["analyses"]:
            problems = []
            check_attack_paths.check_policy(analysis, problems)
            self.assertEqual(problems, [], analysis["id"])


@unittest.skipUnless(tfv.HAS_GIT, "git is required")
class Stage3bTest(unittest.TestCase):
    def setUp(self):
        self.s3 = tfv.Stage3Test("test_clean_complete_run_passes")
        self.s3.setUp()

        def make_fd3_inconclusive(data):
            entry = next(v for v in data["validations"] if v["finding_id"] == "FD-3")
            entry.update(verdict="inconclusive", method="static-assessment", reproduced=False, repeat_confirmed=False,
                         confidence={"level": "Low", "reason": "static only"},
                         counterevidence_or_proof_gap="Could not exercise the route.",
                         rubric=[{"criterion": "exploit works", "result": "unknown"}])
        self.s3.fill(make_fd3_inconclusive, status="inconclusive")
        code, problems = self.s3.check()
        self.assertEqual(code, 0, problems)
        self.root = self.s3.root
        result = subprocess.run([sys.executable, str(FD / "prepare_workspace.py"), "--root", str(self.root),
                                 "--run-id", RUN, "--stage", "3b-attack-path-analysis"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.stage = self.s3.s3.parent / "3b-attack-path-analysis"
        self.record = self.stage / "attack-paths.json"

    def tearDown(self):
        self.s3.tearDown()

    def start(self, *extra):
        return ap("start_attack_paths.py", "--root", str(self.root), "--stage-dir", str(self.stage),
                  "--validations", str(self.s3.validations), *extra)

    def check(self):
        result = ap("check_attack_paths.py", "--repo", str(self.root), str(self.record))
        return result.returncode, json.loads(result.stdout)["problems"]

    def fill(self, change=None):
        """Start, fill both analyses consistently with the policy, apply change(data), and normalize."""
        self.assertEqual(self.start().returncode, 0)
        data = json.loads(self.record.read_text())
        record = data["record"]
        record.update(actor="Test agent", model="Test Model 1.0", status="complete",
                      next_action="Stage 4 for FD-1.")
        record["tools"] = record["tools"].split("<fill")[0] + "normalize/check/render_attack_paths.py"
        for a in data["analyses"]:
            a["facts"].update(in_scope="yes", security_vulnerability="yes", product_surface="yes", vector="remote", auth_scope="public",
                              cross_boundary="yes", preconditions="plausible", attacker_input_control="yes",
                              exposure="Served on the app's listener.", identity="Any user.", impact_surface="Server files.",
                              target_reach="One service.", controls="None before the write.", secrets="none",
                              blind_spots="Deployment network policy.")
            a["attacker_steps"] = ["Send the crafted input.", "Reach the sink."]
            a["dataflow"] = "input -> handler -> sink"
            a["reachability"] = "user -> route -> sink"
            a["counterevidence"] = [{"fact": "exposure", "evidence": "Binds to 127.0.0.1 by default.", "dispositive": False}]
            a["severity_rationale"] = "Per the policy and stage 1's calibration table."
            a["change_conditions"] = "Higher if code execution follows."
            if a["verdict"] == "confirmed":
                a.update(impact="high", likelihood="medium", severity="medium", decision="reportable",
                         confidence={"level": "High", "reason": "Reproduced in stage 3."})
                del a["proof_gap"]
            else:
                a.update(impact="medium", likelihood="unknown", severity="low", decision="deferred",
                         proof_gap="The route could not be exercised in stage 3.",
                         confidence={"level": "Low", "reason": "Static only."})
        if change:
            change(data)
        self.record.write_text(json.dumps(data, indent=2))
        result = ap("normalize_attack_paths.py", str(self.record))
        self.assertEqual(result.returncode, 0, result.stdout)
        return json.loads(self.record.read_text())

    def assert_check_fails(self, change, message):
        self.fill(change)
        code, problems = self.check()
        self.assertEqual(code, 1, problems)
        self.assertTrue(any(message in p for p in problems), problems)

    def analysis(self, data, finding):
        return next(a for a in data["analyses"] if a["finding_id"] == finding)

    # find_validations.py / start_attack_paths.py ------------------------------------------------

    def test_find_validations_selects_the_record(self):
        result = ap("find_validations.py", "--root", str(self.root))
        self.assertEqual(result.returncode, 0, result.stdout)
        report = json.loads(result.stdout)
        self.assertEqual((report["run_id"], report["eligible"], report["rejected"]), (RUN, 2, 2))

    def test_start_splits_eligible_and_rejected(self):
        result = self.start()
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["analyses"], ["FD-1", "FD-3"])
        self.assertEqual(sorted(report["not_eligible"]), ["FD-2", "FD-4"])
        self.assertTrue(report["authorization_inherited"])
        data = json.loads(self.record.read_text())
        self.assertIsNotNone(data["threat_model"])
        self.assertIsNotNone(data["security_guidance"])
        self.assertTrue(data["record"]["authorization"].startswith(f"inherited from stage 3 run {RUN}: "))

    def test_start_never_overwrites(self):
        self.assertEqual(self.start().returncode, 0)
        self.assertEqual(self.start().returncode, 3)

    def test_start_refuses_a_rejected_finding(self):
        self.assertEqual(self.start("--finding", "FD-2").returncode, 1)
        self.assertFalse(self.record.exists())

    # check_attack_paths.py ------------------------------------------------------------------------

    def test_skeleton_fails_on_placeholders(self):
        self.assertEqual(self.start().returncode, 0)
        self.assertEqual(ap("normalize_attack_paths.py", str(self.record)).returncode, 0)
        code, problems = self.check()
        self.assertEqual(code, 1)
        self.assertTrue(any("placeholder" in p for p in problems), problems)

    def test_filled_record_passes_and_renders(self):
        data = self.fill()
        code, problems = self.check()
        self.assertEqual(code, 0, problems)
        self.assertEqual([(a["id"], a["finding_id"], a["priority"]) for a in data["analyses"]],
                         [("AP-1", "FD-1", "P2"), ("AP-2", "FD-3", "P3")])
        self.assertEqual(ap("render_attack_paths.py", str(self.record)).returncode, 0)
        report = self.stage / "attack-paths.md"
        result = subprocess.run([sys.executable, str(FD / "check_citations.py"), "--repo", str(self.root), str(report)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_severity_must_follow_the_matrix(self):
        self.assert_check_fails(lambda d: self.analysis(d, "FD-1").update(severity="high"),
                                "must be the policy result")

    def test_critical_needs_the_criteria(self):
        self.assert_check_fails(lambda d: self.analysis(d, "FD-1").update(likelihood="high", severity="critical"),
                                "must be the policy result 'high'")

    def test_inconclusive_is_never_reportable(self):
        def change(d):
            self.analysis(d, "FD-3").update(decision="reportable", severity="low")
            self.analysis(d, "FD-3").pop("proof_gap")
        self.assert_check_fails(change, "always deferred")

    def test_deferred_needs_a_proof_gap(self):
        self.assert_check_fails(lambda d: self.analysis(d, "FD-3").pop("proof_gap"), "proof_gap")

    def test_ignore_needs_a_reason(self):
        self.assert_check_fails(lambda d: self.analysis(d, "FD-1").update(decision="ignore", severity="ignore"),
                                "needs a suppression reason, an 'ignore' rating, or dispositive counterevidence")

    def test_ignore_with_suppression_passes(self):
        self.fill(lambda d: self.analysis(d, "FD-1").update(
            decision="ignore", severity="ignore", suppression="self-only-impact"))
        code, problems = self.check()
        self.assertEqual(code, 0, problems)

    def test_scope_gate_needs_suppression(self):
        self.assert_check_fails(lambda d: self.analysis(d, "FD-1")["facts"].update(security_vulnerability="no"),
                                "scope gate")

    def test_product_surface_gate_needs_suppression(self):
        self.assert_check_fails(lambda d: self.analysis(d, "FD-1")["facts"].update(product_surface="no"), "scope gate")

    def test_cited_calibration_override_passes(self):
        def change(d):
            self.analysis(d, "FD-1").update(severity="high", calibration_override={
                "severity": "high", "row": "High: a visited web page reading intelligence through the loopback API",
                "reason": "Stage 1 rates this situation High for this target; the facts match the row."})
        self.fill(change)
        code, problems = self.check()
        self.assertEqual(code, 0, problems)
        self.assertEqual(ap("render_attack_paths.py", str(self.record)).returncode, 0)
        self.assertIn("Calibrated by stage 1's table to **high**", (self.stage / "attack-paths.md").read_text())

    def test_override_equal_to_matrix_is_rejected(self):
        self.assert_check_fails(lambda d: self.analysis(d, "FD-1").update(calibration_override={
            "severity": "medium", "row": "Medium row", "reason": "same"}), "same severity as the matrix")

    def test_override_cannot_be_ignored(self):
        self.assert_check_fails(lambda d: self.analysis(d, "FD-1").update(
            decision="ignore", severity="ignore", suppression="out-of-scope",
            calibration_override={"severity": "high", "row": "High row", "reason": "x"}), "cannot be combined with a suppression")

    def test_locations_must_not_change(self):
        self.assert_check_fails(lambda d: self.analysis(d, "FD-1")["locations"][0].update(start_line=2),
                                "locations must be the stage 2 finding's locations")

    def test_rejected_finding_is_not_analysed(self):
        def change(d):
            extra = json.loads(json.dumps(self.analysis(d, "FD-1")))
            extra.update(validation_id="VD-2", finding_id="FD-2")
            d["analyses"].append(extra)
        self.assert_check_fails(change, "was rejected in stage 3")

    def test_not_eligible_must_match_the_rejected(self):
        self.assert_check_fails(lambda d: d["not_eligible"].pop(), "not_eligible must list exactly")

    def test_complete_needs_full_coverage(self):
        self.assert_check_fails(lambda d: d["analyses"].pop(), "neither analysed nor named")

    def test_stage3_record_edited_afterwards(self):
        self.fill()
        text = self.s3.validations.read_text()
        self.s3.validations.write_text(text.replace('"open_questions": []', '"open_questions": ["edited"]'))
        code, problems = self.check()
        self.assertEqual(code, 1)
        self.assertTrue(any("validated_record.sha256" in p for p in problems), problems)


if __name__ == "__main__":
    unittest.main()
