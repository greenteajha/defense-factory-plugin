# Static finding assessment

Use this when a test cannot run — the app will not build with bounded effort, a prerequisite or internal service is unavailable, or dynamic execution is disproportionate to the finding — and the verdict must rest on code reading. It does not define the verdict labels or the record format; [validation-format.md](validation-format.md) owns those. Record the result as `method: static-assessment`, `reproduced: false`.

## Assess the tuple

For the finding, establish the smallest useful tuple:

- **source**: the attacker-controlled input, external trigger, or trusted operator input the finding names.
- **control**: the guard, validator, sanitizer, authorization check, configuration gate, or missing control that decides the outcome.
- **sink**: the dangerous operation, broken control, or impact point.
- **reachable path**: the code or configuration path that connects source, control, and sink under the stated preconditions.
- **boundary**: the product surface and trust boundary that make the path security-relevant.
- **counterevidence**: static facts that weaken, defeat, or scope the finding.
- **proof gaps**: the facts that could not be established without running the code.

Dependency presence, a string match, or a partial call chain is not an assessment. A useful static assessment states both what was found and what remains unproven.

## Search the smallest evidence set first

1. The finding's own `locations`, and any advisory or scanner locations.
2. Dependency manifests, build metadata, deploy configuration, and generated-artifact boundaries.
3. The affected functions, routes, handlers, parser entry points, CLI commands, and package APIs.
4. Nearby guards, validators, sanitizers, authorization checks, and feature flags.
5. Product-surface evidence: `SECURITY.md`, supported-version docs, threat models, comments, and tests that clarify intended behaviour.

Prefer exact `path:line` references over broad claims. If evidence is absent, record the absence as a proof gap, unless the absence itself defeats the finding.

## Classify the boundary before treating a path as real

- **product surface**: hosted service, library API, CLI, local developer UI, plugin hook, example, test fixture, docs, generated code, vendored code, or unknown.
- **source trust**: untrusted user input, tenant data, remote attacker input, trusted operator input, trusted developer configuration, local-only input, an intentional extension point, or unknown.
- Check whether untrusted input can actually reach the bug.

## Confidence and verdict

Calibrate confidence from evidence quality, and never above `Medium` for a static assessment:

- **Medium**: an exact source/control/sink path with stated preconditions and relevant boundary evidence, and no material unresolved counterevidence.
- **Low**: a plausible but incomplete path, or significant ambiguity in the call chain, configuration, version, deployment, or boundary.

A static assessment reaches `confirmed` only when the code shows the failing control and the reachable path directly; it reaches `rejected` only when the code shows the control holds on the exact path; otherwise the verdict is `inconclusive` with the exact proof gap. Missing runtime, environment, or deployment facts are proof gaps to state, never facts to fill in.
