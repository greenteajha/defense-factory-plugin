# Filling attack-paths.json

The format is specified by [../assets/attack-paths.schema.json](../assets/attack-paths.schema.json). [../assets/attack-paths-example.json](../assets/attack-paths-example.json) is a filled, normalized example; a test regenerates it from a raw fixture so it cannot go stale.

## Top level

| Field | Contents |
| --- | --- |
| `record` | The shared stage record ([record-and-status.md](record-and-status.md)), with stage `3b-attack-path-analysis` and source `validated-record` |
| `validated_record` | Path, sha256, and run ID of the stage 3 `validations.json` |
| `threat_model` | Path and sha256 of the stage 1 model, or `null` |
| `security_guidance` | Path and sha256 of the resolved security policy, or `null` |
| `analyses` | One per eligible finding |
| `not_eligible` | The rejected findings |
| `open_questions` | Anything left open |

`start_attack_paths.py` fills the identity, the references, the copied locations, and `not_eligible`. You fill the rest.

## Each analysis

Leave these exactly as the skeleton wrote them:

- `validation_id`, `finding_id`, `finding_key`, `finding_fingerprint`, `title`, `verdict`;
- `locations`. `check_attack_paths.py` compares them with the stage 2 finding.

Fill these:

- **`facts`:** every field; see [facts-checklist.md](facts-checklist.md).
- **`attacker_steps`:** one step per entry, in order.
- **`dataflow`, `reachability`:** see [method.md](method.md).
- **`counterevidence`:** one entry per interpretive fact checked, each with `dispositive: true` or `false`.
- **`impact`, `likelihood`:** `high` / `medium` / `low` / `ignore` / `unknown`.
- **`critical_criteria_met`:** `true` only when the critical criteria in [severity-policy.md](severity-policy.md) are met.
- **`suppression`:** `null`, or one of the reasons in the severity policy.
- **`calibration_override`** (optional): `{severity, row, reason}`. Use it only when stage 1's calibration table rates this situation differently from the matrix and the row fits the facts ([method.md](method.md)). Otherwise leave it out.
- **`severity`:** the policy result (see below).
- **`decision`:** `reportable`, `ignore`, or `deferred`, following the decision rules in [method.md](method.md).
- **`severity_rationale`, `change_conditions`, `confidence`:** always.
- **`proof_gap`:** required for `deferred`. **Delete the field** for the other decisions if you have nothing to record; a leftover `<fill: ...>` fails the check.

Do not set `id` or `priority`. The normalizer assigns them:

- `id`: `AP-n`, in priority order;
- `priority`: P0 to P3 from the severity; none for `ignore`, `unknown`, or an `ignore` decision.

## Status

| Status | When |
| --- | --- |
| `complete` | Every eligible finding has exactly one analysis or is named in `coverage_gaps`, and the checks pass |
| `inconclusive` | Some eligible findings could not be analysed, or the run stopped early |
| `blocked` | Not authorized, or no usable stage 3 record: no analyses |

## Normalize, check, render

1. Run `scripts/normalize_attack_paths.py <attack-paths.json>`.
2. Run `scripts/check_attack_paths.py --repo <repo root> <attack-paths.json>`. Fix every problem and normalize again until both pass.
3. Run `scripts/render_attack_paths.py <attack-paths.json>`.
4. Run `scripts/check_citations.py --repo <repo root> <stage_dir>/attack-paths.md`.

Common failures:

- **A severity that differs from the policy result.** Fix the facts or ratings, not the severity.
- **`reportable` on an `inconclusive` finding.** It must be `deferred`.
- **`ignore` with no reason.** Add a suppression, an `ignore` rating, or dispositive counterevidence.
- **A `deferred` decision without a proof gap.**
- **Changed `locations`.**
- **A leftover `<fill: ...>`.**
- **A hostname and port in backticks** (for example `` `attacker.test:4173` ``). `check_citations.py` reads any backticked `name:number` as a file citation. Write hosts and ports without backticks, or as "port 4173".
