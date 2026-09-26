# Attack-path method

Three steps per finding, in this order and kept separate: **facts**, then **calibration**, then **policy**. Discovery is not reopened, and once the facts are written, severity is not re-argued.

## 1. Facts

1. **Scope gate.** Record in `facts`:
   - whether this is a real security vulnerability (`security_vulnerability`), not a correctness bug or a false positive;
   - whether it is in scope under the threat model (`in_scope`);
   - whether it sits on a product surface or production workflow (`product_surface`). Developer scripts, tests, examples, and tooling the threat model excludes are `no`.

   A `no` on any of these gate facts needs a suppression reason in step 3 (normally `not-a-security-vulnerability` or `out-of-scope`).
2. **Structured facts.** Fill every field of `facts` from repository evidence and the stage 3 record. [facts-checklist.md](facts-checklist.md) defines each one. Use `unknown` rather than guessing.
3. **Attack path.** Write the numbered `attacker_steps`, from the attacker's starting position to the outcome. Then write:
   - the **dataflow**: source → transformations → sink → outcome;
   - the **reachability**: attacker → entry point → preconditions → outcome.

   Reuse stage 3's evidence by reference: cite the stage 3 validation ID and its artifacts. A finding confirmed through the real interface has proven reachability, so say so. Do not restate stage 3's test inputs, their sizes, or their contents here. Never invent a step the code does not support.

   **Write at the level of a vulnerability report.** Say what the attacker does and gains, for example "hosts a page that submits a run to the local API". Never include payloads, exploit code, working request bodies, or step-by-step weaponisation. Those belong, at most, in stage 3's saved artifacts, never in this record.
4. **Counterevidence pass.** Do this before anything is final. For the interpretive facts (in scope, vector, auth scope, exposure, cross-boundary, preconditions, impact surface), look for evidence that the path is out of scope, internal-only, admin-only, not cross-boundary, or not reachable. Record each check as `{fact, evidence, dispositive}`.
   - Mark evidence **dispositive** only when it settles the question on its own.
   - "Nothing found" is also a valid entry, if it says what was checked.
   - **Missing ingress or deployment evidence is never dispositive.** It is a proof gap.

## 2. Calibration

Rate **impact** and **likelihood** separately, each `high`, `medium`, `low`, `ignore`, or `unknown`. Follow [severity-policy.md](severity-policy.md):

- Start from stage 2's `hypothesis_priority`.
- Adjust with the facts, stage 1's calibration table for this target, and the resolved security policy.
- Rate likelihood mainly from the vector.
- Apply the escalators and downgrades.
- Set `critical_criteria_met` to `true` only when the finding meets the critical criteria in the policy.
- Record a `suppression` reason when a hard suppression applies, or when the reportability gate fails.

**Keep confidence separate from impact.** An unproven high-impact path is high impact with low confidence, not medium severity. Record confidence in `confidence`, never by lowering impact.

### Using stage 1's calibration table

1. Choose the impact and likelihood that **describe the facts**. Never pick them backwards to reach a level.
2. Find the row of stage 1's table that covers this finding: its `TM-H` origin, or a matching example or counterexample.
3. Compare that row's level with the matrix result:
   - **They agree:** cite the row in `severity_rationale`. Nothing else is needed.
   - **They differ, and the row fits the facts** (the target's owner rates this situation differently from the generic matrix): record a `calibration_override` with the row's level, the row quoted, and why it applies. The override becomes the severity. It may not be combined with a suppression or an `ignore` decision. This is the one sanctioned exception to the matrix, as in Codex Security, where the threat model is the only lever that can justify one.
   - **They differ, and stage 3's evidence contradicts the row, or contradicts one of stage 1's "out of scope or unsupported" notes** (for example, stage 1 called something unsupported that stage 3 reproduced): follow the evidence, keep the matrix result, and add an open question so the next stage 1 run corrects the model.

   Before comparing, make sure a precondition the row already names was not counted again in likelihood ([severity-policy.md](severity-policy.md#likelihood)). Most apparent disagreements come from that.
4. **No row covers the finding** (common for open-ended findings): use the generic policy, and say so in the rationale.

## 3. Policy (mechanical)

The severity follows from what steps 1 and 2 recorded:

1. a suppression reason → `ignore`;
2. otherwise, the impact × likelihood matrix in [severity-policy.md](severity-policy.md), with `critical` only when `critical_criteria_met` is `true`.

`check_attack_paths.py` recomputes this and rejects any severity that disagrees. If you think the result is wrong, the facts or ratings are wrong: fix those, never the severity alone.

## Decisions

| Decision | When | Requires |
| --- | --- | --- |
| `reportable` | A `confirmed` finding with a real severity | severity equal to the policy result (`critical` to `low`); no suppression |
| `ignore` | The policy result is `ignore`, or counterevidence is dispositive | severity `ignore`, plus the suppression reason, an `ignore` rating, or dispositive counterevidence |
| `deferred` | Proof is missing: always for an `inconclusive` verdict, and for a `confirmed` one only when a fact needed to rate it cannot even be bounded (for example, whether the vulnerable code ships in any build) | the exact `proof_gap`, and a provisional severity (the policy result) or `unknown` |

For a `deferred` finding whose **impact** is `unknown`, set the severity to `unknown`, not the matrix's provisional result: an unbounded risk must not be ranked low by default. Use the provisional policy result only when impact is known.

**A confirmed finding that depends on configuration or victim behaviour is still `reportable`.** A non-default bind address, an `http:` base URL, or the victim visiting a page while the tool runs are preconditions: record them in `preconditions` and `exposure`, and let them lower the likelihood. They are not reasons to defer.

For every decision, also write:

- `severity_rationale`, citing stage 1's calibration table and the policy;
- `change_conditions`: the concrete evidence that would raise or lower the severity;
- `confidence`. An `inconclusive` finding is never `High` confidence.

## Findings that depend on another finding

Some findings are realistically delivered only through another one. For example, a rate-limit weakness may be reachable only through a cross-site request finding, or one credential leak may add little beyond another. Rate each on its own path:

- record the dependency in `preconditions`, and let likelihood follow the delivering path's vector;
- do not lower impact for it;
- name the enabling finding in `change_conditions` (for example, "falls to low if FD-4 is fixed").

## Siblings and instances

Analyse each finding on its own, even when a neighbouring finding in the same family tells a cleaner story. Independently attackable instances keep separate analyses. Their locations, including the `root_control` line, stay exactly as stage 2 recorded them.
