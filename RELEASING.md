# Release workflow

The canonical package lives on `main`. Use pull requests for changes to behavior, contracts, adapters, or metadata. One version applies to all host adapters.

1. Classify the change under Semantic Versioning: patch for corrections without behavior changes, minor for backward-compatible capabilities or contract additions, major for incompatible contract or packaging changes. Before 1.0, describe any breaking change prominently.
2. Update `plugin.json`, `.claude-plugin/plugin.json`, and `CHANGELOG.md` to the same version. Keep the root manifest authoritative.
3. Run `python3 scripts/check-package.py`. Review the file inventory for secrets and unnecessary assets. Confirm the skill's positive trigger, non-trigger, missing-access behavior, and evidence output.
4. On every claimed client surface, install the exact candidate commit and verify skill discovery, activation, expected output, and safe behavior when prerequisites are missing. Record client versions and results in release notes. If a surface cannot be tested, mark it unverified and do not claim support there.
5. Merge the reviewed change to `main`. Create an annotated `vX.Y.Z` tag on the tested commit and publish a GitHub Release with changes, compatibility results, known limitations, and the source archive. Never move a published tag; issue a new version for corrections.
6. Recheck the released archive and installation routes. Keep previous tags and releases for rollback. Promote a release to a marketplace only after that marketplace's own review and installation test.

## Release record template

```text
Version / commit:
Change summary:
Package check:
Claude Code (version, install, activation, missing access):
ChatGPT desktop or Codex local (version, install, activation, missing access):
Cursor (version, install, activation, missing access):
Known limitations:
Rollback tag:
```
