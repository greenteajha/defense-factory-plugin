"""Tests for the finding-discovery skill's helper scripts, run against throwaway repositories.

The fixture is a committed Git repository with a stage 1 model that passes check_model.py, a
scope inventory, and tests/fixtures/finding-discovery/findings-raw.json (the example as an agent
would write it) with the real target identity filled in. Each test breaks one rule.
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

REPO = Path(__file__).resolve().parents[1]
SKILL = REPO / "skills" / "finding-discovery"
SCRIPTS = SKILL / "scripts"
EXAMPLE = SKILL / "assets" / "findings-example.json"
RAW = REPO / "tests" / "fixtures" / "finding-discovery" / "findings-raw.json"
RUN = "20260925T060000Z"
GIT_ENV = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.test",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.test"}
HAS_GIT = shutil.which("git") is not None

SOURCE_FILES = {"src/api/routes.py": 40, "src/api/upload.py": 40, "src/api/auth.py": 20,
                "src/lib/fetch.py": 20, "config/defaults.py": 5, "src/legacy/export.py": 10}

STAGE1_MODEL = """---
record_version: 1
stage: 1-threat-model
status: complete
run_id: "{run}"
timestamp: "2026-01-01T00:00:00Z"
actor: "Test agent"
model: "Example Model 1.0"
skill_version: "threat-model/sha256:0123456789abcdef"
target_id: "{target_id}"
target_kind: "{target_kind}"
version: "{version}"
revision: "{revision}"
scope: {scope}
authorization: "requested by the user in session on 2026-09-25: \\"Threat model this repository\\""
output_location: "default .defense-factory (Git-ignored)"
source: generated
inputs: []
independent_review: independent
tools: "Python 3.12"
evidence: "citations in this file"
assumptions: []
coverage_gaps: []
open_questions: 2
hypotheses: {{critical: 0, high: 1, medium: 1, low: 2}}
next_action: "Stage 2: finding discovery."
---

# Threat model: demo

## 1. Overview
Text.
## 2. Threat model, trust boundaries, and assumptions
Text.
## 3. Attack surface, mitigations, and attacker stories

| ID | Priority | Confidence | Scenario and capability gain | Evidence |
| --- | --- | --- | --- | --- |
| TM-H1 | High | Medium: prefix check | Archive import escapes the import folder | `src/api/upload.py:24` |
| TM-H2 | Medium | Low | URL fetch reaches internal hosts | `src/lib/fetch.py:10` |
| TM-H3 | Low | Low | Admin routes without a role check | `src/api/auth.py:3` |
| TM-H4 | Low | Low | Legacy export leaks reports | `src/legacy/export.py:1` |

## 4. Severity calibration
Text.
## Canonical summary
Text.
## Coverage gaps
- None.
## Open questions
1. Is DEBUG ever enabled?
2. Can the service account write outside the data folder?
"""


def run(script, *args):
    return subprocess.run([sys.executable, str(SCRIPTS / script), *args], capture_output=True, text=True)


def git(root, *args):
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, env=GIT_ENV)


@unittest.skipUnless(HAS_GIT, "git is required")
class FindingDiscoveryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "app"
        for relative, count in SOURCE_FILES.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("".join(f"line {number}\n" for number in range(1, count + 1)))
        (self.root / "package-lock.json").write_text("{}\n")
        git(self.root, "init", "-q")
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "init")
        for stage in ("1-threat-model", "2-finding-discovery"):
            result = run("prepare_workspace.py", "--root", str(self.root), "--run-id", RUN, "--stage", stage)
            self.assertEqual(result.returncode, 0, result.stderr)
        run_dir = self.root / ".defense-factory" / "runs" / RUN
        self.stage1, self.stage2 = run_dir / "1-threat-model", run_dir / "2-finding-discovery"
        self.model = self.stage1 / "threat-model.md"
        self.findings = self.stage2 / "findings.json"
        (self.stage2 / "security-guidance.md").write_text("# Resolved security policy\nNone.\n")
        self.identity = json.loads(run("target_identity.py", "--root", str(self.root)).stdout)
        self.write_model()
        result = run("list_scope_files.py", "--root", str(self.root), "--out", str(self.stage2 / "scope-inventory.txt"))
        self.assertEqual(result.returncode, 0, result.stderr)

    def tearDown(self):
        self.tmp.cleanup()

    # Helpers ------------------------------------------------------------------------------------

    def write_model(self, scope="whole-repository"):
        identity = {field: self.identity[field] for field in ("target_id", "target_kind", "version", "revision")}
        self.model.write_text(STAGE1_MODEL.format(run=RUN, scope=scope, **identity))

    def raw(self, sha=True):
        """The raw fixture with the real target identity and model digest."""
        data = json.loads(RAW.read_text())
        for field in ("target_id", "target_kind", "version", "revision"):
            data["record"][field] = self.identity[field]
        if sha:
            data["threat_model"]["sha256"] = hashlib.sha256(self.model.read_bytes()).hexdigest()
        return data

    def write(self, data):
        self.findings.write_text(json.dumps(data, indent=2))

    def normalize(self, data=None):
        if data is not None:
            self.write(data)
        return run("normalize_findings.py", "--repo", str(self.root), str(self.findings))

    def normalized(self, change=None):
        """Normalize the fixture, apply change(data), and normalize again (as the agent would).

        If the change makes normalization fail, the changed file is left for check_findings.py to
        report on."""
        result = self.normalize(self.raw())
        self.assertEqual(result.returncode, 0, result.stdout)
        data = json.loads(self.findings.read_text())
        if change:
            change(data)
            self.normalize(data)
        return data

    def check(self):
        result = run("check_findings.py", "--repo", str(self.root), str(self.findings))
        return result.returncode, json.loads(result.stdout)["problems"]

    def assert_check_fails(self, change, message):
        self.normalized(change)
        code, problems = self.check()
        self.assertEqual(code, 1)
        self.assertTrue(any(message in problem for problem in problems), problems)

    def row(self, data, ref):
        return next(row for row in data["reconciliation"] if row["ref"] == ref)

    # list_scope_files.py ------------------------------------------------------------------------

    def test_inventory_lists_source_and_records_exclusions(self):
        (self.root / "node_modules" / "lib").mkdir(parents=True)
        (self.root / "node_modules" / "lib" / "index.js").write_text("x\n")
        (self.root / "static").mkdir()
        (self.root / "static" / "app.min.js").write_text("x\n")
        (self.root / "logo.png").write_bytes(b"\x89PNG\0\0data")
        (self.root / "docs").mkdir()
        (self.root / "docs" / "notes.md").write_text("notes\n")
        (self.root / "link.py").symlink_to(self.root / "src" / "api" / "auth.py")
        out = self.stage2 / "inventory-test.txt"
        result = run("list_scope_files.py", "--root", str(self.root), "--exclude", "docs", "--out", str(out))
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(out.read_text().splitlines(), sorted(SOURCE_FILES))
        rules = {entry["rule"]: entry["count"] for entry in report["excluded"]}
        self.assertEqual(rules, {"binary file": 1, "dependency lockfile": 1, "minified or generated bundle": 1,
                                 "symbolic link": 1, "user exclusion: docs": 1, "vendored dependency folder": 1})
        self.assertEqual(report["included"], len(SOURCE_FILES))

    def test_inventory_respects_scope_and_plain_folders(self):
        shutil.rmtree(self.root / ".git")
        out = Path(self.tmp.name) / "inventory.txt"
        result = run("list_scope_files.py", "--root", str(self.root), "--scope", "src/api", "--out", str(out))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(out.read_text().splitlines(), ["src/api/auth.py", "src/api/routes.py", "src/api/upload.py"])

    def test_inventory_rejects_scope_outside_root(self):
        result = run("list_scope_files.py", "--root", str(self.root), "--scope", "..", "--out", str(self.stage2 / "x.txt"))
        self.assertEqual(result.returncode, 2)

    # normalize_findings.py ----------------------------------------------------------------------

    def test_shipped_example_is_the_normalized_fixture(self):
        self.write(json.loads(RAW.read_text()))
        out = Path(self.tmp.name) / "example.json"
        result = run("normalize_findings.py", "--repo", str(self.root), "--out", str(out), str(self.findings))
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(out.read_text(), EXAMPLE.read_text(),
                         "assets/findings-example.json is stale: regenerate it from the raw fixture")

    def test_numbering_merging_and_references(self):
        result = self.normalize(self.raw())
        report = json.loads(result.stdout)
        self.assertEqual(result.returncode, 0, report)
        self.assertEqual(report["merged"], [{"kept": "archive-member-path-zip", "absorbed": ["archive-member-path-zip-copy"]}])
        data = json.loads(self.findings.read_text())
        ids = {finding["key"]: finding["id"] for finding in data["findings"]}
        self.assertEqual(ids, {"archive-member-path-zip": "FD-1", "archive-member-path-tar": "FD-2",
                               "login-next-redirect": "FD-3", "debug-endpoint-environment": "FD-4"})
        zip_finding = data["findings"][0]
        self.assertEqual(zip_finding["merged_from"], ["archive-member-path-zip-copy"])
        self.assertEqual(zip_finding["discovered_by"], ["baseline", "investigator"])
        self.assertEqual(zip_finding["confidence"]["level"], "High")
        self.assertEqual(zip_finding["cwe_ids"], ["CWE-22"])
        self.assertEqual([location["role"] for location in zip_finding["locations"]],
                         ["entrypoint", "source", "root_control", "sink"])
        self.assertEqual(zip_finding["hypothesis_priority"], "High")
        self.assertIsNone(data["findings"][2]["hypothesis_priority"])
        self.assertEqual(data["findings"][1]["related"], ["FD-1"])
        self.assertEqual(self.row(data, "TM-H1")["findings"], ["FD-1", "FD-2"])
        self.assertEqual([row["ref"] for row in data["reconciliation"]], ["TM-H1", "TM-H2", "TM-H3", "TM-H4", "SEED-1"])
        self.assertEqual([question["number"] for question in data["stage1_open_questions"]], [1, 2])

    def test_normalizing_twice_changes_nothing(self):
        self.normalized()
        first = self.findings.read_text()
        result = self.normalize()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.findings.read_text(), first)

    def test_fingerprint_ignores_line_numbers(self):
        before = self.normalized()["findings"][1]["fingerprint"]
        data = self.raw()
        for location in data["findings"][2]["locations"]:
            location["start_line"] += 1
        self.normalize(data)
        after = json.loads(self.findings.read_text())["findings"][1]["fingerprint"]
        self.assertEqual(before, after)

    def test_invalid_locations_are_rejected_and_nothing_is_written(self):
        data = self.raw()
        data["findings"][0]["locations"][0]["path"] = "/etc/passwd"
        data["findings"][2]["locations"][0]["start_line"] = 999
        data["seeds"][0]["locations"][0]["path"] = "src/missing.py"
        self.write(data)
        before = self.findings.read_text()
        result = self.normalize()
        problems = json.loads(result.stdout)["problems"]
        self.assertEqual(result.returncode, 1)
        self.assertTrue(any("path must be relative" in problem for problem in problems), problems)
        self.assertTrue(any("beyond the end of the file" in problem for problem in problems), problems)
        self.assertTrue(any("file does not exist" in problem for problem in problems), problems)
        self.assertEqual(self.findings.read_text(), before)

    def test_affected_location_must_be_in_scope(self):
        data = self.raw()
        data["record"]["scope"] = ["src/lib"]
        problems = json.loads(self.normalize(data).stdout)["problems"]
        self.assertTrue(any("inside the record's scope" in problem for problem in problems), problems)

    def test_schema_errors_are_reported(self):
        data = self.raw()
        del data["findings"][0]["counterevidence"]
        data["findings"][1]["severity"] = "High"
        data["findings"][2]["status"] = "confirmed"
        problems = json.loads(self.normalize(data).stdout)["problems"]
        self.assertIn("findings.json.findings[0]: missing field 'counterevidence'", problems)
        self.assertIn("findings.json.findings[1]: unknown field 'severity'", problems)
        self.assertIn('findings.json.findings[2].status: must be "unvalidated"', problems)

    def test_unknown_reference_is_rejected(self):
        data = self.raw()
        self.row(data, "TM-H1")["findings"].append("no-such-finding")
        problems = json.loads(self.normalize(data).stdout)["problems"]
        self.assertTrue(any("'no-such-finding' is not a finding key" in problem for problem in problems), problems)

    def test_duplicate_keys_are_rejected(self):
        data = self.raw()
        data["findings"][3]["key"] = data["findings"][4]["key"]
        problems = json.loads(self.normalize(data).stdout)["problems"]
        self.assertTrue(any("key is used by more than one finding" in problem for problem in problems), problems)

    def test_schema_uses_only_supported_keywords(self):
        sys.path.insert(0, str(SCRIPTS))
        try:
            import normalize_findings
        finally:
            sys.path.remove(str(SCRIPTS))
        schema = normalize_findings.load_schema()
        self.assertEqual(normalize_findings.unsupported_keywords(schema), [])
        schema["$defs"]["text"]["format"] = "uri"
        self.assertEqual(normalize_findings.unsupported_keywords(schema),
                         ["schema.$defs.text: unsupported keyword 'format'"])

    # check_findings.py --------------------------------------------------------------------------

    def test_valid_record_passes(self):
        self.normalized()
        self.assertEqual(self.check(), (0, []))

    def test_unnormalized_record_fails(self):
        self.write(self.raw())
        code, problems = self.check()
        self.assertEqual(code, 1)
        self.assertEqual(problems, ["findings.json is not in normalized form; run normalize_findings.py first"])

    def test_placeholder_and_generic_model_fail(self):
        def change(data):
            data["record"]["actor"] = "<agent and client>"
            data["record"]["model"] = "Claude"
        self.assert_check_fails(change, "record.actor still holds a template placeholder")
        self.assertIn("record.model must name the exact model", "\n".join(self.check()[1]))

    def test_code_change_makes_record_and_model_stale(self):
        self.normalized()
        (self.root / "src" / "api" / "auth.py").write_text("changed\n" * 20)
        git(self.root, "commit", "-q", "-am", "change")
        code, problems = self.check()
        self.assertEqual(code, 1)
        self.assertTrue(any(problem.startswith("record: version") for problem in problems), problems)
        self.assertTrue(any(problem.startswith("stage 1 model is stale or inconsistent: version") for problem in problems), problems)

    def test_security_guidance_must_be_saved(self):
        self.normalized()
        (self.stage2 / "security-guidance.md").unlink()
        self.assertIn("security-guidance.md is missing from the stage folder; save the resolve_security_md.py output there",
                      self.check()[1])

    def test_record_cannot_predate_the_model(self):
        self.assert_check_fails(lambda data: data["record"].update(timestamp="2025-12-31T23:59:59Z"),
                                "record.timestamp is earlier than the stage 1 model's timestamp")

    def test_model_edited_after_it_was_read(self):
        self.normalized()
        self.model.write_text(self.model.read_text() + "\n")
        code, problems = self.check()
        self.assertIn("threat_model.sha256 does not match the stage 1 model: it changed after it was read", problems)

    def test_missing_model_is_reported(self):
        self.normalized()
        self.model.unlink()
        code, problems = self.check()
        self.assertEqual(code, 1)
        self.assertTrue(any("cannot read the stage 1 model" in problem for problem in problems), problems)

    def test_scope_wider_than_stage1(self):
        self.write_model(scope='["src/api"]')
        self.assert_check_fails(lambda data: data["threat_model"].update(
            sha256=hashlib.sha256(self.model.read_bytes()).hexdigest()),
            "record.scope is wider than the stage 1 model's scope")

    def test_every_hypothesis_needs_one_row(self):
        self.assert_check_fails(lambda data: data["reconciliation"].remove(self.row(data, "TM-H3")),
                                "TM-H3: no reconciliation row")

    def test_row_for_unknown_hypothesis(self):
        self.assert_check_fails(lambda data: data["reconciliation"].append(
            {"ref": "TM-H9", "disposition": "open-question", "note": "?"}),
            "TM-H9: reconciliation row for an unknown hypothesis or seed")

    def test_row_and_origin_must_agree(self):
        def change(data):
            self.row(data, "SEED-1")["findings"] = ["FD-3", "FD-4"]
        self.assert_check_fails(change, "SEED-1: lists FD-4, whose origin does not include SEED-1")

    def test_origin_must_be_listed_in_its_row(self):
        self.assert_check_fails(lambda data: self.row(data, "TM-H1").update(findings=["FD-1"]),
                                "FD-2: origin TM-H1, but the TM-H1 row does not list it")

    def test_no_finding_needs_evidence(self):
        self.assert_check_fails(lambda data: self.row(data, "TM-H3").pop("evidence"),
                                "TM-H3: no-finding needs evidence")

    def test_not_investigated_must_be_a_coverage_gap(self):
        self.assert_check_fails(lambda data: data["record"].update(coverage_gaps=["src/legacy/ not reviewed."]),
                                "TM-H4: not-investigated must also be named in record.coverage_gaps")

    def test_high_priority_not_investigated_blocks_complete(self):
        def change(data):
            self.row(data, "TM-H1").update(disposition="not-investigated", note="Skipped.")
            self.row(data, "TM-H1").pop("findings")
            data["record"]["coverage_gaps"].append("TM-H1: skipped.")
            for finding in data["findings"][:2]:
                finding["origin"] = ["open-ended"]
        self.assert_check_fails(change, "status cannot be complete: TM-H1 (High) was not investigated")

    def test_open_ended_stands_alone(self):
        self.assert_check_fails(lambda data: data["findings"][3].update(origin=["open-ended", "TM-H2"]),
                                "open-ended cannot be combined with other origins")

    def test_merged_key_appears_once(self):
        self.assert_check_fails(lambda data: data["findings"][1].update(merged_from=["archive-member-path-zip-copy"]),
                                "merged key 'archive-member-path-zip-copy' appears in both FD-1 and FD-2")

    def test_stage1_questions_carried_forward(self):
        self.assert_check_fails(lambda data: data["stage1_open_questions"].pop(),
                                "stage1_open_questions must carry forward questions 1 to 2 exactly once")

    def test_inherited_authorization_rules(self):
        self.assert_check_fails(lambda data: data["record"].update(run_id="other-run", authorization=data["record"]["authorization"]),
                                "inherited authorization is only valid in the stage 1 model's own run")
        self.assert_check_fails(lambda data: data["record"].update(
            authorization=f"inherited from stage 1 run {RUN}: the user said it was fine"),
            "inherited authorization must repeat the stage 1 record's authorization value exactly")

    def test_session_authorization_needs_a_quote(self):
        self.assert_check_fails(lambda data: data["record"].update(run_id="other-run", authorization="the user asked for it"),
                                "record.authorization must quote the user's request")

    def narrow_scan(self, data):
        data["record"].update(source="narrow-scan", scope=["src/api"], authorization='requested by the user in session on 2026-09-25: "Just look for security bugs in src/api"',
                              coverage_gaps=["No threat model: narrow scan of the named paths."])
        data["threat_model"] = None
        data["reconciliation"] = [self.row(data, "SEED-1")]
        data["stage1_open_questions"] = []
        for finding in data["findings"]:
            if finding["origin"] != ["SEED-1"]:
                finding["origin"] = ["open-ended"]

    def test_narrow_scan_passes(self):
        self.normalized(self.narrow_scan)
        self.normalize()
        self.assertEqual(self.check(), (0, []))

    def test_narrow_scan_needs_named_paths(self):
        def change(data):
            self.narrow_scan(data)
            data["record"]["scope"] = "whole-repository"
        self.assert_check_fails(change, "a narrow scan names paths")

    def test_narrow_scan_must_say_there_is_no_model(self):
        def change(data):
            self.narrow_scan(data)
            data["record"]["coverage_gaps"] = []
        self.assert_check_fails(change, "record.coverage_gaps must say that no threat model was used")

    def test_complete_coverage_needs_every_file_reviewed(self):
        self.assert_check_fails(lambda data: data["coverage"].update(completeness="complete", remaining=[]),
                                "coverage is complete but 1 inventory file(s) were not reviewed")

    def test_partial_coverage_must_account_for_every_file(self):
        self.assert_check_fails(lambda data: data["coverage"]["reviewed_files"].remove("src/lib/fetch.py"),
                                "1 inventory file(s) are neither reviewed nor listed in coverage.remaining")

    def test_reviewed_files_come_from_the_inventory(self):
        def change(data):
            data["coverage"]["reviewed_files"].append("package-lock.json")
            data["coverage"]["remaining"].append({"paths": ["src/nowhere"], "reason": "x"})
        self.assert_check_fails(change, "coverage.reviewed_files are not in the scope inventory: package-lock.json")
        self.assertIn("coverage.remaining path 'src/nowhere' matches nothing in the scope inventory", self.check()[1])

    def test_blocked_record_needs_no_body_but_no_findings(self):
        def blocked(data):
            data["record"].update(status="blocked", next_action="Blocked: the user did not confirm authorization.")
        self.assert_check_fails(blocked, "a blocked record has no findings")
        self.normalized(lambda data: (blocked(data), data.update(findings=[], reconciliation=[])))
        self.assertEqual(self.check(), (0, []))

    # find_threat_model.py -----------------------------------------------------------------------

    def find(self, *args):
        result = run("find_threat_model.py", "--root", str(self.root), *args)
        return result.returncode, json.loads(result.stdout)

    def test_find_selects_the_newest_usable_model(self):
        code, report = self.find()
        self.assertEqual((code, report["threat_model"], report["run_id"]), (0, str(self.model.resolve()), RUN))
        newer = self.root / ".defense-factory" / "runs" / "newer" / "1-threat-model" / "threat-model.md"
        newer.parent.mkdir(parents=True)
        newer.write_text(self.model.read_text().replace(RUN, "newer").replace("2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z"))
        broken = self.root / ".defense-factory" / "runs" / "zz-broken" / "1-threat-model" / "threat-model.md"
        broken.parent.mkdir(parents=True)
        broken.write_text(self.model.read_text().replace("2026-01-01T00:00:00Z", "2026-03-01T00:00:00Z")
                          .replace("open_questions: 2", "open_questions: 5"))
        code, report = self.find()
        self.assertEqual((code, report["run_id"]), (0, "newer"))
        self.assertEqual([model["run_id"] for model in report["models"]], ["zz-broken", "newer", RUN])
        self.assertFalse(report["models"][0]["usable"])

    def test_find_reports_stale_models(self):
        (self.root / "src" / "api" / "auth.py").write_text("changed\n" * 20)
        git(self.root, "commit", "-q", "-am", "change")
        code, report = self.find()
        self.assertEqual((code, report["threat_model"]), (1, None))
        self.assertTrue(report["models"][0]["problems"][0].startswith("stale: version"), report)

    def test_find_without_runs(self):
        shutil.rmtree(self.root / ".defense-factory" / "runs")
        self.assertEqual(self.find(), (1, {"threat_model": None, "run_id": None, "scope": None, "status": None,
                                           "timestamp": None, "models": []}))

    # start_findings.py --------------------------------------------------------------------------

    def start(self, *args, stage_dir=None):
        return run("start_findings.py", "--root", str(self.root), "--stage-dir", str(stage_dir or self.stage2), *args)

    def test_start_prefills_record_from_the_model(self):
        (self.stage2 / "scope-inventory.txt").unlink()
        result = self.start("--threat-model", str(self.model))
        report = json.loads(result.stdout)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertTrue(report["authorization_inherited"])
        self.assertEqual([item["id"] for item in report["hypotheses"]], ["TM-H1", "TM-H2", "TM-H3", "TM-H4"])
        data = json.loads(self.findings.read_text())
        record = data["record"]
        self.assertEqual((record["run_id"], record["source"], record["scope"], record["version"]),
                         (RUN, "stage-1-record", "whole-repository", self.identity["version"]))
        self.assertTrue(record["skill_version"].startswith("finding-discovery/sha256:"))
        self.assertEqual(record["authorization"],
                         f'inherited from stage 1 run {RUN}: requested by the user in session on 2026-09-25: "Threat model this repository"')
        self.assertEqual(record["output_location"], "default .defense-factory (Git-ignored)")
        self.assertEqual(data["threat_model"], {"path": "../1-threat-model/threat-model.md",
                                                "sha256": hashlib.sha256(self.model.read_bytes()).hexdigest(), "run_id": RUN})
        self.assertEqual([row["ref"] for row in data["reconciliation"]], ["TM-H1", "TM-H2", "TM-H3", "TM-H4"])
        self.assertIn("High hypothesis", data["reconciliation"][0]["note"])
        self.assertIn("Is DEBUG ever enabled?", data["stage1_open_questions"][0]["note"])
        self.assertEqual(data["coverage"]["exclusions"],
                         [{"pattern": "dependency lockfile", "reason": "1 file(s) excluded by list_scope_files.py"}])
        self.assertEqual((self.stage2 / "scope-inventory.txt").read_text().splitlines(), sorted(SOURCE_FILES))
        self.assertEqual(self.normalize().returncode, 0)
        code, problems = self.check()
        self.assertEqual(code, 1)
        self.assertIn("record.actor still holds a '<fill:' placeholder from start_findings.py", problems)
        self.assertIn("reconciliation[0].note still holds a '<fill:' placeholder from start_findings.py", problems)

    def test_start_never_overwrites(self):
        self.write({"existing": True})
        self.assertEqual(self.start("--threat-model", str(self.model)).returncode, 3)
        self.assertEqual(json.loads(self.findings.read_text()), {"existing": True})

    def test_start_refuses_stale_invalid_or_narrower_model(self):
        (self.root / "src" / "api" / "auth.py").write_text("changed\n" * 20)
        git(self.root, "commit", "-q", "-am", "change")
        result = self.start("--threat-model", str(self.model))
        self.assertEqual(result.returncode, 1)
        self.assertTrue(any(problem.startswith("stage 1 model is stale: version") for problem in json.loads(result.stdout)["problems"]))
        self.assertFalse(self.findings.exists())

        self.identity = json.loads(run("target_identity.py", "--root", str(self.root)).stdout)
        self.write_model(scope='["src/api"]')
        self.model.write_text(self.model.read_text().replace("open_questions: 2", "open_questions: 3"))
        problems = json.loads(self.start("--threat-model", str(self.model), "--scope", "src").stdout)["problems"]
        self.assertTrue(any("fails check_model.py" in problem for problem in problems), problems)
        self.assertIn("the requested scope is wider than the stage 1 model's scope", problems)
        self.assertFalse(self.findings.exists())

    def test_start_narrow_scan(self):
        self.assertEqual(self.start().returncode, 2)
        self.assertEqual(self.start("--scope", ".").returncode, 2)
        result = self.start("--scope", "src/api")
        self.assertEqual(result.returncode, 0, result.stdout)
        data = json.loads(self.findings.read_text())
        self.assertEqual((data["record"]["source"], data["record"]["scope"], data["threat_model"]),
                         ("narrow-scan", ["src/api"], None))
        self.assertEqual((data["reconciliation"], data["stage1_open_questions"]), ([], []))
        self.assertIn("<fill:", data["record"]["authorization"])
        self.assertTrue(data["record"]["coverage_gaps"][0].startswith("No threat model"))
        self.assertEqual((self.stage2 / "scope-inventory.txt").read_text().splitlines(),
                         ["src/api/auth.py", "src/api/routes.py", "src/api/upload.py"])

    def test_start_in_another_run_does_not_inherit_authorization(self):
        result = run("prepare_workspace.py", "--root", str(self.root), "--run-id", "other-run", "--stage", "2-finding-discovery")
        other = Path(json.loads(result.stdout)["stage_dir"])
        report = json.loads(self.start("--threat-model", str(self.model), stage_dir=other).stdout)
        self.assertFalse(report["authorization_inherited"])
        self.assertIn("<fill:", json.loads((other / "findings.json").read_text())["record"]["authorization"])

    def test_start_fill_normalize_check_render(self):
        """The whole helper sequence an agent follows, with the fixture standing in for its work."""
        self.assertEqual(self.start("--threat-model", str(self.model)).returncode, 0)
        data, raw = json.loads(self.findings.read_text()), self.raw()
        for field in ("status", "actor", "model", "tools", "inputs", "independent_baseline", "assumptions", "coverage_gaps", "next_action"):
            data["record"][field] = raw["record"][field]
        for field in ("seeds", "findings", "reconciliation", "stage1_open_questions", "open_questions"):
            data[field] = raw[field]
        for field in ("reviewed_files", "completeness", "remaining"):
            data["coverage"][field] = raw["coverage"][field]
        result = self.normalize(data)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.check(), (0, []))
        self.assertEqual(run("render_findings.py", str(self.findings)).returncode, 0)
        citations = run("check_citations.py", "--repo", str(self.root), str(self.stage2 / "findings.md"))
        self.assertEqual(citations.returncode, 0, citations.stdout)

    # render_findings.py -------------------------------------------------------------------------

    def test_render_writes_checkable_markdown(self):
        self.normalized()
        result = run("render_findings.py", str(self.findings))
        self.assertEqual(result.returncode, 0, result.stdout)
        markdown = (self.stage2 / "findings.md").read_text()
        sys.path.insert(0, str(SCRIPTS))
        try:
            import normalize_findings
        finally:
            sys.path.remove(str(SCRIPTS))
        header, body = normalize_findings.split_model(markdown)
        self.assertEqual(header["stage"], "2-finding-discovery")
        self.assertEqual(header["findings"], {"high": "1", "medium": "1", "low": "2"})
        self.assertEqual(header["reconciliation"],
                         {"findings": "2", "no-finding": "1", "open-question": "1", "not-investigated": "1"})
        self.assertEqual(header["coverage"], "partial")
        self.assertTrue(header["threat_model_ref"].startswith("../1-threat-model/threat-model.md sha256:"))
        self.assertIn("### FD-1: ZIP import writes members outside the import folder", body)
        self.assertIn("## Boundaries the threat model missed", body)
        self.assertIn("- FD-4: Debug route returns environment variable names and values", body)
        self.assertIn("- root_control: `src/api/upload.py:24-26`", body)
        citations = run("check_citations.py", "--repo", str(self.root), str(self.stage2 / "findings.md"))
        self.assertEqual(citations.returncode, 0, citations.stdout)
        self.assertGreater(json.loads(citations.stdout)["checked"], 10)

    def test_render_refuses_unnormalized_input(self):
        self.write(self.raw())
        result = run("render_findings.py", str(self.findings))
        self.assertEqual(result.returncode, 1)
        self.assertFalse((self.stage2 / "findings.md").exists())

    def test_render_blocked_record(self):
        self.normalized(lambda data: (data["record"].update(status="blocked", next_action="Blocked: no authorization."),
                                      data.update(findings=[], reconciliation=[])))
        result = run("render_findings.py", str(self.findings))
        self.assertEqual(result.returncode, 0, result.stdout)
        markdown = (self.stage2 / "findings.md").read_text()
        self.assertIn("Blocked. Blocked: no authorization.", markdown)
        self.assertNotIn("## Findings", markdown)


if __name__ == "__main__":
    unittest.main()
