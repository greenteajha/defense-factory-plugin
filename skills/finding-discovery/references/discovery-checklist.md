# Discovery checklist

Rules that keep discovery specific and complete. Most of them exist because one real weakness often has several independently reachable instances, and collapsing them loses the ones a fix would miss.

## General

- Read the code before deciding anything. Trust the code over comments, commit messages, documentation, or the threat model's narrative.
- Split findings by root cause, not by wording. Keep independently reachable instances as separate findings, even when they share a helper or a route; give siblings of the same family and anchor distinct `instance` values.
- When a dangerous sink has several call sites with their own source or closest control, record each reachable one as a finding. Call sites that pass through the same broken control are locations of one finding (see deduplication in `finding-format.md`).
- When evidence crosses a wrapper into a shared sink or control, include both: the wrapper as `entrypoint`, the shared line as `root_control` or `sink`. The shared helper does not replace the caller-specific line.
- When a concrete subclass, strategy, handler, converter, or operation selects attacker-controlled behavior and delegates to a shared control, include that concrete method as `concrete_implementation` next to the shared one. Do not substitute the abstract base class.
- If a claim says a shared parser, guard, or loader affects "all", "every", or "any" implementation, list the concrete implementations that make it true. Do not leave them in prose.
- Split a broad family ("all deserialization variants", "all unauthenticated mutations") into findings keyed by the concrete function, route branch, sink statement, API mode, parser variant, or protected action.
- When one route exposes several dangerous operations of the same family (for example `execute`, `executemany`, and `executescript`; several `load` variants; create, delete, and reset actions), record each operation an attacker can trigger independently.
- Do not merge findings with different sinks, closest controls, or impacts only because they share a route or helper. Command execution, SSRF, file impact, parser behavior, script injection, and authorization impact stay separate.
- For a repeated template, configuration pattern, or query builder, record each affected file and line, and note nearby safe instances as counterevidence rather than findings.
- For recursive placeholder or template expansion, include the line that enables recursion or evaluation as well as the render or evaluation line.
- Give CWE IDs when the class is clear; leave the list empty otherwise.

## Seeds

- Keep a seeded file, class, package, or hunk open until local evidence closes it. If you open or search a seed target, its reconciliation row must say what you found.
- Do not replace a seeded construct with an easier neighboring issue. If a broader finding shares the seed's source, control, and impact, add the seed's anchor as a location of that finding; otherwise close the seed separately.

## Deserialization, parsers, and object models

- For shared deserialization, class resolution, template, or auth controls, use the resolver, filter, allowlist, denylist, or guard line as `root_control` when callers prove reachability. Do not anchor only on the most dramatic transport.
- Enumerate the concrete codecs, deserializers, converters, and container handlers a parser registers (arrays, collections, maps, beans, enums, exceptions, generic objects). A top-level configuration finding does not close a handler that recursively parses or constructs objects from attacker data.
- For file-format object models, check the helpers that convert or walk attacker-controlled structures: array, dictionary, and number conversions, getters, iterators, size calculations, unchecked casts, and allocation loops. These start as coverage items, not findings. Record a finding when malformed input plausibly reaches a helper whose missing type, size, shape, recursion, or numeric check causes a crash, exhaustion, confusion, or bypass.
- Do not dismiss a deterministic parser crash as mere robustness when untrusted input can reach it and abort a service, worker, pipeline, or security negotiation. Dismissal needs concrete containment evidence, such as caller-side recovery or an equivalent earlier check.
- For XML, enumerate default parser factories, converters, validators, transformers, and parse entry points separately. A safe sibling parser is counterevidence only for itself. Hardening that is best effort, silently fails, or covers only the default factory does not clear caller-supplied factories or readers.

## Structured edits and duplicated controls

- For patch, edit, or apply APIs (JSON Patch, document edits, configuration mutation), enumerate each request-selected operation, such as add, remove, replace, move, copy, and test. Keep each operation's path transform, append, wildcard, or binding line visible when it feeds a shared evaluator.
- Inspect operation-specific helpers, not just the top-level handler. Special branches (append, wildcard, fallback, copy or move source, defaults, type resolution) that bypass or narrow the shared validator are root controls of their own.
- When an allowlist, denylist, or resolver is duplicated across core, server, client, plugin, or import packages, include each runtime copy that implements the same broken control.

## Queries, requests, and commands

- For query languages (SQL, NoSQL, LDAP, XPath and similar), do not dismiss a finding because the endpoint already takes user data, because it is an insert or update, or because a later business check may limit the effect. If input reaches query syntax or operators, record it with the later check as counterevidence.
- For outbound requests (URL importers, webhooks and callbacks, preview fetchers, redirect-following clients), enumerate each attacker-selectable destination and its closest allow, deny, or redirect control. Do not dismiss SSRF because fetching is the feature, the filter is optional or empty by default, or a louder file issue exists nearby.
- For command or action runners, enumerate every attacker-controllable argument type and execution mode: type maps, denylists, template substitution, shell wrapping, direct execution, API argument intake, and client-only constraints. Covering some argument types does not close the others.
- Stored client, tenant, application, identity-provider, or imported configuration values are cross-boundary input when they are later rendered, evaluated, parsed, or used for authorization. Do not dismiss them solely because the writer is outside this repository, unless the code shows they are trusted-only.

## Files and archives

- For static-file and resource serving, include the allowlist, matcher, canonicalization, URL decoding, and resource-selection line. Do not replace a vulnerable legacy handler with a safer sibling.
- For restore, import, export, backup, admin, or login-named routes, verify the actual middleware and decorator behavior before assuming authentication. An optional or configuration-dependent login wrapper leaves the route anonymous when that configuration is absent.
- For filesystem operations (restore, import, export, extraction, copy, move, download, open, key or config fetch), keep the decode, join, normalize, canonicalize, prefix-strip, extension-check, and destination-selection lines visible for each reachable operation.
- For archive extraction, keep the member name, destination join, containment check, and write call as root controls. A later copy, manifest check, or file selection does not help if the write already happened. Claims that a library normalizes paths need code showing per-entry containment before the write, including symbolic links, hard links, and metadata. Overwriting trusted files inside the application's own root still counts.
- Keep an archive-member finding with a precise source-to-write tuple even when confidence is only medium, and even when a cleaner traversal or authorization issue exists nearby.

## Authentication and authorization

- Enumerate public webhook, status, callback, and API endpoints that read protected objects, start jobs, or change state. Handle them separately from nearby credential or configuration issues.
- For stateful authentication protocols, include the line that installs or reuses a principal, credential, token, issuer, or protocol state after a transition (pre-authentication, TLS upgrade, redirect, assertion, identity provider). A missing rebind or re-authentication is a root control when the wrong identity can result.
- In SSO and SAML code, keep response and assertion validators separate from generic claims checks. Include assertion selection, list indexing, cloning, signed-object lookup, subject confirmation, recipient, audience, destination, ACS URL, and issuer binding lines.
- When a validator loops to find a valid object and a separate line later selects, clones, serializes, or returns an object (first, last, or fixed index), treat the selection line as the broken control until the code proves both are the same object.
- For realms and authenticators (LDAP, Kerberos, PAM, SAML, OAuth or OIDC, custom), enumerate the concrete implementations before recording a generic HTTP authentication finding. Keep bind, rebind, and credential-installation lines visible.
- In protocol-heavy code, inspect version, capability, feature, and negotiation helpers (version comparison, matching, parsing, splitting) and close each validator or parser pair explicitly.
- For self-service update routes, include the guard that compares the requested object with the stored one. Missing checks on identity, trust state, tenant membership, roles, groups, or account-recovery fields are root controls.

## Deprecated and opt-in behavior

- In frameworks and libraries, do not dismiss a finding only because the API is deprecated, opt-in, or documented as dangerous. Record that as a precondition, and keep the finding when shipped code has a bypassable control on a plausible cross-boundary path.
