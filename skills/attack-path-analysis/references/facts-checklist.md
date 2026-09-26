# Facts and counterevidence checklist

Every field of `facts` is required. Use `unknown` when the evidence does not settle it, and name the missing evidence in `blind_spots`.

| Fact | Values | What decides it |
| --- | --- | --- |
| `security_vulnerability` | yes / no / unknown | A real security impact across a trust boundary, not a correctness bug, a style issue, or a false positive. |
| `in_scope` | yes / no / unknown | In scope under the threat model and the resolved security policy. |
| `product_surface` | yes / no / unknown | Whether the code ships to users or runs in a production workflow. Developer scripts, tests, examples, and tooling the threat model excludes are `no`, which needs a suppression reason. |
| `vector` | remote / local_network / localhost / none / unknown | **Where the attacker starts**, decided from listeners and bind addresses, ingress, load balancers, ports, manifests, routing, and network policy, not from the bug class. For an attack delivered through the victim's browser (cross-site requests, DNS rebinding) the attacker is `remote` even when the listener is localhost: record the localhost listener in `exposure` and "the victim visits the attacker's page while the tool runs" in `preconditions`. For an on-path attacker between the tool and an upstream service, use `local_network` or `remote` for where they sit. When reach depends on configuration (a non-default bind address), rate the vector **under the configuration the finding needs**: `remote` if the project documents or anticipates internet exposure, `local_network` if it anticipates a LAN or team setup. Record the default in `exposure`, and the non-default setting in `preconditions` (`plausible` when documented, `unlikely` otherwise). |
| `auth_scope` | public / internal-only / admin-only / not-applicable / unknown | Who can reach the entry point before any control applies. It describes the endpoint's **own** access control: an endpoint with no authentication is `public`, even when it listens only on loopback and is reached through the victim's browser. Use `not-applicable` for outbound or transport findings (the tool sends a credential over cleartext, or trusts an upstream response), where there is no inbound entry point. |
| `cross_boundary` | yes / no / unknown | Whether the attacker gains something across an identity, tenant, privilege, or trust boundary, rather than affecting only themselves. |
| `preconditions` | plausible / unlikely / unachievable / unknown | What must already be true: configuration, prior access, user action, timing. `unachievable` needs a suppression reason. |
| `attacker_input_control` | yes / plausible / no / unknown | Whether the attacker controls the input that reaches the sink. For disclosure or transport findings with no sink the attacker feeds (for example, passively reading a credential sent in cleartext), record `no`; it does not lower the severity. |
| `exposure` | text | Where the entry point is served and to whom, with evidence. |
| `identity` | text | Who the attacker is, and which identity or trust boundary they cross. |
| `impact_surface` | text | What is affected: data, runtime, identity, network, build, or other. |
| `target_reach` | text | One service, a shared component, a whole fleet, or unknown. |
| `controls` | text | Existing controls and mitigations on this path, and why they fail or hold. |
| `secrets` | text | Secrets involved, by **name and location only**, never their values, or `none`. |
| `blind_spots` | text | What could not be seen from the repository, for example the deployment's network policy. |

## Counterevidence pass

For each interpretive fact, look for evidence that:

- the path is **out of scope**, or covered by a stated policy exception;
- the entry point is **internal-only** or **admin-only** in practice;
- the effect is **not cross-boundary** (self-only);
- the input is **not attacker-controlled**, or the preconditions are **unrealistic**;
- an existing control **defeats** the path.

Record each check as `{fact, evidence, dispositive}`. It is **dispositive** only when it settles the question on its own. Examples:

- **dispositive:** a route no listener serves; an explicit exclusion of that code or story in the threat model's scope, for `in_scope`;
- **not dispositive:** a comment saying "internal only"

Missing evidence, such as no deployment manifest or no ingress configuration in the repository, is never dispositive. Record it in `blind_spots` and in the proof gap.
