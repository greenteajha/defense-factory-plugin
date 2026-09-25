# Provider-neutral workflow contracts

These contracts describe the intended six-stage defensive workflow. They are the design basis for the plugin's skills; version 0.3.0 implements stage 1 as the `threat-model` skill and stage 2 as the `finding-discovery` skill; stages 3 to 6 are not implemented yet. The orchestrating client may run one requested stage or the full sequence when each stage is implemented. It must preserve status and evidence at handoffs.

## Shared record

Every stage records: repository and revision; authorized scope; stage and status (`complete`, `rejected`, `inconclusive`, or `blocked`); actor and timestamp; evidence references; assumptions; tool and environment provenance; next action. Store excerpts only when needed for review. Do not put credentials, exploit secrets, or private vulnerability details in a public repository or issue.

## 1. Scope and threat model

- **Entry and inputs:** Authorized repository access, target revision, requested scope, source/configuration, and available history.
- **Output and evidence:** Reviewable system map, assets, entry points, trust boundaries, attack-path hypotheses, file/line references, and explicit unknowns.
- **Completion:** A reviewer can trace each important claim to evidence and choose which hypotheses to investigate.
- **Blocked or inconclusive:** Missing authorization, unavailable source, unclear scope, or insufficient architecture context. Mark coverage gaps; never present a partial map as exhaustive.
- **Gate and retention:** Require access authorization before inspection. Retain only the map, necessary references, and review notes under the target organization's policy.

## 2. Finding discovery

- **Entry and inputs:** Stage-1 context or an explicit narrow scan request; source and relevant security policy.
- **Output and evidence:** Deduplicated unvalidated findings with source/sink path, affected revision, exposure assumptions, and counterevidence.
- **Completion:** Each finding has a reproducible investigation question; findings remain unvalidated until stage 3.
- **Blocked or inconclusive:** Tool or coverage gaps are recorded; unsupported guesses are discarded or marked uncertain.
- **Gate and retention:** Respect scan scope and tool permissions. Store minimal source excerpts in controlled finding storage.

## 3. Isolated validation

- **Entry and inputs:** Unvalidated finding, expected behavior, and an authorized, reproducible test environment.
- **Output and evidence:** `confirmed`, `rejected`, or `inconclusive`; setup details, test steps, observed result, and counterevidence.
- **Completion:** A confirmed finding has repeatable evidence. Failure to provision or execute a test is inconclusive, not rejection.
- **Blocked or inconclusive:** Unsafe environment, absent dependencies, or non-reproducible result.
- **Gate and retention:** Use an isolated environment and approved test scope. Remove temporary state after evidence is captured under policy.

## 4. Patch preparation

- **Entry and inputs:** Confirmed finding, root-cause analysis, target revision, and expected behavior.
- **Output and evidence:** Focused patch, tests for the weakness and normal behavior, results, and remaining risk.
- **Completion:** Patch is reviewable and tests run or failures are clearly explained.
- **Blocked or inconclusive:** Root cause unknown, unsafe patch, or missing runnable checks.
- **Gate and retention:** Follow repository write permissions. Preserve patch and test evidence in a private review channel if the finding is sensitive.

## 5. Human review and change proposal

- **Entry and inputs:** Patch, validation evidence, test results, and repository review policy.
- **Output and evidence:** Pull request or equivalent review record and a human decision to approve, revise, or decline.
- **Completion:** The decision and reviewed revision are recorded. A proposed or merged patch does not prove deployment.
- **Blocked or inconclusive:** No reviewer, denied write access, or unresolved review concerns.
- **Gate and retention:** Require human review before merge. Use private channels for sensitive details and the host's authorization for external writes.

## 6. Post-remediation revalidation

- **Entry and inputs:** Reviewed fix, merged revision, original reproduction procedure, and deployment identity when relevant.
- **Output and evidence:** `fixed`, `still vulnerable`, or `inconclusive`, with code-level and deployed-state results distinguished.
- **Completion:** Original weakness is independently retested against the relevant code and, where required, deployed version; closure evidence is recorded.
- **Blocked or inconclusive:** Deployment unverified, environment mismatch, or test unavailable. Keep the finding open.
- **Gate and retention:** Require approved access to deployed systems. Keep only evidence necessary for audit and follow the organization's deletion schedule.

## Adapter boundary

The core contracts name capabilities, not vendors: repository read/write, isolated execution, issue or pull-request proposal, human approval, evidence storage, and deployed-state check. Claude, ChatGPT/Codex, and Cursor adapters may translate their installation and tool APIs into these capabilities. They must not change the meaning of a status or bypass a gate. This package currently has no bundled MCP server, credentials, code-writing automation, or production-check adapter.
