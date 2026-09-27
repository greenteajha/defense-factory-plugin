# Patch-preparation method

How to prepare and verify one fix, inside the disposable container, and reach an outcome backed by evidence. The outcome is `fixed`, `no_change`, `blocked`, or `inconclusive`, and it is earned by evidence, never by how simple the fix looks. The diff is recorded; it is never applied to the user's working tree.

## Order the work

Prepare fixes in priority order: P0 first, then P1, P2, P3. Within a run's time budget, spend effort where it changes the outcome. Do not let a hard fix for a low-priority finding consume the budget for a high-priority one; record what you did not reach in `coverage_gaps`.

## Judgment order

Hold these in order, and never trade an earlier one for a later one:

1. the current state is correctly classified (vulnerable, already safe, or unproven);
2. the fix completely closes the broken security boundary;
3. legitimate behaviour and compatibility are preserved;
4. the target's own checks pass;
5. the fix follows the repository's conventions;
6. the patch contains only the necessary scope.

## Investigate before patching

With a fresh read-only pass (a sub-agent when the client offers one; otherwise a stated second pass), establish from the code: the source-to-sink path and the shared enforcement boundary; the affected entry points and any alternate representations or parser transitions; the legitimate workflows and public behaviour the fix must preserve; and the repository's conventions and existing helpers. Reuse stage 2's `root_control` location and stage 3's reproduction rather than rediscovering them.

## Prepare the fix

1. **Trace the reported path.** If the current code is already safe on inspection, record `no_change` with the evidence (what you re-ran, what it showed) and stop; write no patch.
2. **Establish the before-state.** Run stage 3's reproduction through the boundary, plus one legitimate control, in the container.
3. **Implement the smallest repository-native fix** at the shared boundary. Do not broaden into cleanup, refactoring, or sibling findings, and never weaken a control to make a test pass.
4. **Challenge the patch.** Inspect every direct caller and both outcomes of any condition you changed.

## The verification gates

Run these in order; the outcome is `fixed` only when every gate passes:

1. **Build / type check** — the target's own build or type check succeeds.
2. **The reproduction is now blocked** — stage 3's malicious input no longer reaches the sink or produces the impact. Try alternate representations of the same attack, not just the exact input.
3. **A legitimate control still works** — a benign, in-scope operation on the same path still behaves correctly.
4. **The target's own checks pass** — its existing tests and lint, and any refactoring safety net the project documents.
5. **Minimal scope** — the diff changes only what the fix needs.

Add at least one focused test that exercises the vulnerable path and asserts the safe behaviour; code inspection alone is not enough for `fixed`. **Setup failures are never counterevidence.** If a gate cannot run — the app will not build, a dependency is missing, the finding needs a non-Linux runtime — record the proof gap and set the outcome to `inconclusive`, never `fixed`.

## Review the patch candidate

With a fresh read-only pass, reconstruct the invariant and look for: routes that still reach the sink through another entry point; equivalent representations or parser boundaries the fix misses; concrete legitimate input the fix would break; and any public-contract or error/state change. Record the result in `candidate_review`.

## The outcome bar

- **`fixed`** — a written patch, at least one file changed, a focused test added, every gate passed, and evidence (before and after) that the issue no longer reproduces while legitimate behaviour still works. Confidence is set from that evidence.
- **`no_change`** — the code is already safe on the reported path; no patch is written and no file changes. State why in `patch_strategy`.
- **`blocked`** — no safe minimal fix could be produced: the root cause is unclear, a correct fix would change intended behaviour, or the finding cannot be fixed without broadening scope. Record the exact `proof_gap`; write no verified fix.
- **`inconclusive`** — a fix was attempted but the gates could not run or the result is ambiguous. Record the exact `proof_gap`. An `inconclusive` outcome is never High confidence.

Record `remaining_risk` for every outcome: a fix that closes the reported path may leave sibling entry points or related findings open.

## Never

- Never apply, stage, commit, or push the diff to the user's working tree; the diff under `patches/` is the deliverable.
- Never weaken a security control to make a test pass.
- Never "fix" behaviour the resolved SECURITY.md policy marks as intended.
- Never report `fixed` until every gate has passed.
