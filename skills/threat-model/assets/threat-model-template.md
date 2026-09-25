---
record_version: 1
stage: 1-threat-model
status: complete            # complete | inconclusive | blocked
run_id: "<run id>"
timestamp: "<UTC ISO 8601>"
actor: "<agent and client; requesting user if known>"
model: "<exact model and version the client reports, e.g. Claude Opus 5.5; or unknown>"
skill_version: "<skill_version printed by prepare_workspace.py>"
target_id: "<from target_identity.py>"
target_kind: "<git_revision | git_worktree | directory_snapshot>"
version: "<commit, or snapshot digest>"
revision: "<commit, if any>"
scope: whole-repository      # or a list of repository-relative paths
authorization: "<who confirmed, when, how; quote the user's words>"
output_location: "<default .defense-factory (Git-ignored) | user-chosen: path (ignored or not)>"
source: generated           # generated | reused | supplied | supplied-revised | repository-guidance
inputs: []                  # labels of supplied models, knowledge bases, user context, policies
independent_review: independent   # independent | not-independent | not-performed: <reason>
tools: "<helpers and versions used, or 'helpers not used: reason'>"
evidence: "citations in this file; security-guidance.md"
assumptions: []
coverage_gaps: []
open_questions: 0
hypotheses: {critical: 0, high: 0, medium: 0, low: 0}
next_action: "Stage 2: candidate discovery, starting from the highest-priority hypotheses."
---

# Threat model: <product or repository name>

> Hypotheses in this document are unvalidated. Treat this file as sensitive.

## 1. Overview

<Intended use, users, supported deployments, primary components, and important data flows.>

| Component | Responsibility | Source |
| --- | --- | --- |
| | | `path:line` |

<Include the effective-resource table when configuration changes a security boundary. Delete it otherwise.>

| Deployment or workflow | Resource or capability | Configuration and precedence | Safe effective value or location | Readers, writers, or recipients | Enforcing control | Evidence or unknowns |
| --- | --- | --- | --- | --- | --- | --- |

<Optional: a small Mermaid diagram of trust zones and component relationships, when it makes them clearer.>

## 2. Threat model, trust boundaries, and assumptions

- **Protected assets and security objectives:** <data, identities, privileges, integrity guarantees; enforceable invariants, including limits the user asked for>
- **Actors and starting capabilities:** <each actor, what they control, what they cannot do>
- **Trust boundaries:** <boundary crossings, data or authority transferred, expected control, evidence>
- **Established controls:** <control, enforcing component, evidence>
- **Deployment prerequisites and exclusions:** <...>
- **Documentation versus configuration discrepancies:** <both sides, with evidence>
- **Unknowns:** <see Open questions>

## 3. Attack surface, mitigations, and attacker stories

All rows are hypotheses unless marked otherwise by a later stage.

| ID | Priority | Confidence | Scenario and capability gain | Prerequisites | Impact | Existing controls | Mitigation | Evidence | STRIDE |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| TM-H1 | High | Medium: <why> | | | | | | `path:line` | |

Boundaries with no hypothesis, and why no new capability exists:

- <boundary>: <control and evidence>

## 4. Severity calibration

| Level | Examples in this target | Counterexamples | What changes severity |
| --- | --- | --- | --- |
| Critical | | | |
| High | | | |
| Medium | | | |
| Low | | | |

Out of scope or unsupported stories: <...>. Confidence and missing evidence are recorded per hypothesis and do not lower impact.

## Canonical summary

- **summary:** <purpose, main components and data flow, normal deployment>
- **assets:** <...>
- **trustBoundaries:** <actors, transferred data or authority, expected controls, `path:line`>
- **attackerCapabilities:** <realistic starting capabilities, absent privileges, what a boundary failure would add>
- **securityObjectives:** <enforceable invariants>
- **assumptions:** <deployment prerequisites, exclusions, discrepancies, material unknowns>

## Coverage gaps

- <path or component>: <why it was not reviewed or not reviewable>

## Open questions

1. <question, why it matters, what evidence would resolve it>
