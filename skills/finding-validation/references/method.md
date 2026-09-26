# Validation method

How to decide a verdict for one finding, with evidence, inside the disposable container. The verdict is `confirmed`, `rejected`, or `inconclusive`, and it is earned by evidence, never by how dangerous the bug class sounds.

## Order the work

Validate findings in priority order: `hypothesis_priority` first (Critical, High, Medium, Low), then `confidence` (High, Medium, Low), then by ID. Within a run's time budget, spend effort where it changes the outcome: once a repeated pattern has one strong proof, validate its siblings by checking the same source, control, sink, and impact rather than deepening the one proof. Do not let a hard build for a low-value finding consume the budget for high-value ones.

## Write the rubric before running

For each finding, before running anything, turn its `investigation_question` into up to five concrete pass/fail criteria: the input or state to set up, the expected safe behaviour, and the behaviour that would confirm the finding. Include a realistic-interface criterion when the app exposes an HTTP, CLI, message, file, or other user-reachable interface. Record each criterion's result (`pass`, `fail`, or `unknown`) in the entry's `rubric`.

## Choose the strongest feasible method

In this order, use the strongest one that is feasible with bounded setup:

1. **Realistic-interface reproduction** — drive the app through its real interface (HTTP, CLI, file parser, RPC, message queue, plugin hook, package API) with crafted input that reaches the suspected sink.
2. **Targeted test** — add or adapt the smallest focused test in the target's own harness that exercises the vulnerable path and asserts the vulnerable behaviour.
3. **Crash / sanitizer** — for crash, memory-corruption, parser-confusion, or denial-of-service classes, build a debug variant and produce a crashing PoC; use ASan or valgrind when the build supports it.
4. **Debugger trace** — a non-interactive `gdb`/`lldb` trace that shows the source-to-sink path when runtime is available but the chain is unclear.
5. **Static assessment** — when dynamic execution is blocked or disproportionate after bounded attempts, fall back to the code-reading method in [static-finding-assessment.md](static-finding-assessment.md). Recorded as `method: static-assessment`, `reproduced: false`.

Keep commands short, bounded, and non-interactive. Invoke debuggers non-interactively (`gdb -q -batch -ex run -ex bt -ex quit`; `lldb -b -o run -o bt -o quit`). Consult the target's own `README`, `AGENTS.md`, setup and test docs, build files, and package metadata to find the prerequisites and start-up steps.

### Browser-origin findings (rebinding, CSRF, private-network access)

Some findings depend on a browser sending a request to a local service — DNS rebinding against a loopback bind, cross-site requests with no Origin check, or private-network-access reachability. Validate these at the **HTTP layer**, not by automating a browser:

- Drive the running app with the requests such a browser would send — the same method, path, body, and the `Host`, `Origin`, and `Content-Type` headers the attacker page would carry — using the target's own dependencies stubbed on the run's internal network. This is a realistic-interface reproduction of the part the server controls.
- The verdict is decided by the server's response: whether it accepts the request and serves the result, and whether the suspect sink is reached (the three evidence requirements below still apply). A server that accepts a foreign `Host` or cross-site request and serves the response confirms the server-side weakness.
- Record the browser's own behaviour — whether a given browser actually permits the rebinding or the cross-origin request under its DNS-pinning and private-network-access rules — as a stated proof gap in `remaining_uncertainty`, not as something to reproduce here. Do not build or drive a browser to force the rebinding step.

A server-side confirmation with that browser proof gap stated can still be `confirmed`; keep the gap explicit so a reader knows the end-to-end browser step was not exercised.

## The three evidence requirements for a verdict

- **Run a harmless control first.** Establish the safe baseline: the same operation on benign input, or a nearby safe sibling path. A `confirmed` verdict is a change from a known-good control, not an artefact of setup. Record it in `control`.
- **Show the suspect code was reached.** Capture evidence that the attacker-controlled input actually reached the suspected sink (a log line, a trace, an assertion, an added marker). A verdict without reachability evidence stays `inconclusive`. Record it in `reachability`.
- **Repeat a confirmation once.** Before recording `confirmed`, reproduce the result a second time so a one-off is not mistaken for a reliable finding. Set `repeat_confirmed: true`.

## The verdict bar

- **`confirmed`** — the exploit criterion passed, against a control that held, with reachability shown and the confirmation repeated. A static-only confirmation is allowed when the static evidence is decisive, but its confidence is bounded (never High) and its proof gap is stated.
- **`rejected`** — positive evidence that the finding does not hold against the current controls: the control caught the attack, the input was contained, or the sink was not reached, with the exact control named. A rejected verdict has a rubric criterion that failed. A neighbouring stronger finding, a stricter deployment assumption, or missing downstream configuration is a precondition or proof gap, not a rejection.
- **`inconclusive`** — the test could not settle it: setup was blocked, the path was unreachable in bounded time, the finding needs a non-Linux runtime, or it lies outside the validated scope. Record the exact proof gap.

**Setup failures are never counterevidence.** If prerequisites will not install, the app will not build, or a service is unavailable, record what blocked runtime proof in `setup_notes` and fall back to the static assessment; the verdict is `inconclusive`, never `rejected`.

## Calibrate confidence from the evidence

Set `confidence` from the strongest evidence actually obtained, not the bug class: High for a reproduced PoC or crash with a passing control; Medium for a partial or single-run reproduction, or a strong static trace with a stated gap; Low for static-only or weak evidence. A `static-assessment` is never High.

## Class-specific proof tuples

Match the rubric and the reproduction to the class. For each, prove attacker-controlled input + the failing or missing control + the dangerous sink or impact:

- authz / tenant / object / state change: attacker path + missing or wrong guard + protected object, comparison, or state transition.
- injection / path traversal / upload / open redirect: attacker-controlled bytes + sanitizer/canonicalization/allowlist result + dangerous sink or context.
- XSS / template / SSTI: attacker value + escaping or template context + browser or server-side execution sink.
- deserialization / code execution: attacker-controlled serialized or code bytes + unsafe loader or evaluator + execution or object-construction effect.
- SSRF / callback: attacker-controlled destination + destination-control bypass + internal/LAN/metadata fetch or server-side side effect.
- archive extraction / restore / file copy: attacker-controlled member path + missing containment before the write + write outside the intended root (including into trusted config or peer directories).
- parser / file-format DoS: untrusted document or message + unchecked cast, allocation, recursion, or loop + crash, denial of service, or parser confusion.
- auth protocol / assertion binding: attacker-controlled token, assertion, or protocol state + the exact validator semantics + a mismatch between the validated object and the consumed object.

Use a nearby safe path as a negative control where feasible, but the existence of a safe sibling never suppresses a vulnerable one.
