# Severity policy

Severity measures the realistic security impact of a validated finding for this target. It is not a label for the bug class. A scary sink, a scanner's label, or a long speculative chain does not raise it.

## Levels

| Level | Meaning | Priority |
| --- | --- | --- |
| `critical` | An immediate, likely threat that demands attention now | P0 |
| `high` | A realistic in-scope attacker path with major security impact, without a long speculative chain | P1 |
| `medium` | Real security impact, limited by reach, preconditions, or scope | P2 |
| `low` | Real but minor security impact | P3 |
| `ignore` | Not a reportable security issue for this target | none |
| `unknown` | Only for `deferred`: not enough proof to rate | none |

A `high` or `critical` rating needs all of the following:

- an in-scope component;
- a realistic attacker;
- a reasonable in-scope surface;
- a credible path;
- major impact;
- a result a reputable auditor or bug-bounty triager would likely accept.

## Calibrate against the target first

**Stage 1's severity calibration table comes first.** It lists examples and counterexamples per level for *this* target. Where it speaks to a finding, follow it over the generic examples below, and cite it in the severity rationale.

## Typical examples (generic)

- **Critical:**
  - remote code execution;
  - account takeover;
  - breaking tenant isolation;
  - severe data exposure;
  - SQL injection with data access;
  - sandbox escape.
- **High:**
  - server-side request forgery to internal services;
  - cross-site request forgery on important actions;
  - valid hard-coded credentials;
  - cryptographic forgery;
  - supply-chain compromise;
  - XML external entity file read.
- **Usually not high or critical:**
  - open redirect;
  - missing security headers;
  - self-XSS;
  - transient or self-inflicted denial of service;
  - issues that need an operator mistake.

## Impact

Rate what the attacker gains across a boundary:

- **high** for major confidentiality, integrity, or availability impact on in-scope assets;
- **medium** for a real but bounded gain;
- **low** for a minor gain;
- **ignore** for no security gain;
- **unknown** when the evidence does not settle it.

## Likelihood

Rate mainly from the vector, then adjust for preconditions by a fixed rule:

| Vector | Usual likelihood |
| --- | --- |
| `remote` | high |
| `local_network` | medium |
| `localhost` | low |
| `none` | adds no likelihood (`ignore` unless other facts give one) |
| `unknown` | unknown |

| `preconditions` | Adjustment |
| --- | --- |
| `plausible` | none |
| `unlikely` | one step down (high → medium, medium → low) |
| `unachievable` | a hard suppression, `unrealistic-preconditions` (severity `ignore`) |
| `unknown` | none; name the missing fact in `blind_spots` |

**Do not count a precondition twice.** When the stage 1 row you cite already names the precondition (for example, "a *visited* web page reading intelligence", or "when deployed beyond loopback as the README anticipates"), the row's level has already priced it in. Treat it as `plausible` and do not lower likelihood again for it. With this rule, a `calibration_override` is needed only when the target's owner genuinely rates a situation differently from the generic matrix, which should be rare.

## Escalators toward critical

`critical_criteria_met` is a **necessary** condition for `critical`, not a trigger. Set it to `true` only when all of the following hold:

- the impact is high;
- at least one escalator below holds;
- the finding matches stage 1's Critical row (or, when stage 1 has no such row, a generic critical example);
- no Critical counterexample in stage 1's table describes it. A matching counterexample vetoes `true`.

Name the escalator in the severity rationale. The escalators:

- unauthenticated or internet reach;
- zero-click;
- cross-tenant impact;
- compromise of signing, identity, or cloud credentials;
- persistence or mass exploitation;
- proven code execution.

## The one exception: a cited stage 1 calibration

The matrix is the default. When stage 1's severity calibration table rates this situation differently for this target, and the row fits the facts, record a `calibration_override` quoting the row. That level becomes the severity, as described in [method.md](method.md). The override can't be combined with a suppression, and it must differ from the matrix result.

## Downgrades

Lower impact or likelihood for any of these, unless the privilege gain itself *is* the issue:

- narrower objects, or same-tenant only;
- internal-only or localhost-only reach;
- self-only effect;
- constrained or unlikely preconditions;
- an attacker who is already privileged.

**Do not suppress a finding only because its surface is private.** If a real authorization, trust-boundary, or identity control fails in a product workflow, lower the likelihood or confidence instead.

## Hard suppression (applied first; the result is `ignore`)

Record the reason in `suppression`:

| Reason | When |
| --- | --- |
| `not-a-security-vulnerability` | A correctness bug or false positive with no security impact |
| `out-of-scope` | Outside the threat model or declared out of scope by the security policy |
| `self-only-impact` | The only person affected is the attacker |
| `unrealistic-preconditions` | The preconditions are unachievable or highly unrealistic |
| `privileged-attacker` | Needs an operator, developer, physical access, or a protected write path the attacker does not have |
| `no-realistic-attacker-path` | The reportability gate fails: no realistic lower-privileged, in-scope attacker can reach it |

## The matrix (after suppression)

| Impact ↓ / Likelihood → | high | medium | low | unknown | ignore |
| --- | --- | --- | --- | --- | --- |
| **high** | critical if `critical_criteria_met`, else high | medium | low | medium | ignore |
| **medium** | medium | low | low | low | ignore |
| **low** | low | low | low | low | ignore |
| **unknown** | medium | low | low | low | ignore |
| **ignore** | ignore | ignore | ignore | ignore | ignore |

A finding that is not ignored never falls below `low`. "Low" is a downgrade, never a reason to discard. `check_attack_paths.py` recomputes this table from the recorded ratings, suppression, and criteria.
