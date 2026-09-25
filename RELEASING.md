# Release workflow

The canonical package lives on `main`. Use pull requests for changes to behavior, contracts, adapters, or metadata. One version applies to all host adapters.

1. Classify the change under Semantic Versioning: patch for corrections without behavior changes, minor for backward-compatible capabilities or contract additions, major for incompatible contract or packaging changes. Before 1.0, describe any breaking change prominently.
2. Update `plugin.json`, `.claude-plugin/plugin.json`, and `CHANGELOG.md` to the same version. Keep the root manifest authoritative.
3. If a file under `shared/` changed, run `python3 scripts/sync-shared.py` so every skill's copy matches its master (edit only the master; see `shared/README.md`). Run `python3 scripts/check-package.py`, `python3 -m unittest discover -s tests`, and `claude plugin validate .`. Build the packages with the external plugin packager (see Packages). Review the file inventory for secrets and unnecessary assets. Confirm each skill's positive trigger, non-trigger, missing-access behavior, and evidence output.
4. On every claimed client surface, install the exact candidate commit, using the matching package for file-based routes (for example the `-chatgpt-` zip for ChatGPT's Upload plugin archive), and verify skill discovery, activation, expected output, and safe behavior when prerequisites are missing. Record client versions and results in release notes. If a surface cannot be tested, mark it unverified and do not claim support there.
5. Merge the reviewed change to `main`. Create an annotated `vX.Y.Z` tag on the tested commit and push it. Build the packages from the tag with the plugin packager (`--ref vX.Y.Z --expect-version X.Y.Z`), then publish a GitHub Release with the packages, `SHA256SUMS`, changes, compatibility results, and known limitations. Never move a published tag; issue a new version for corrections.
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

## Packages

Packages are built by a separate plugin packager that lives outside this repository (`package_plugin.py`). Run it from the folder that contains both (or from inside this repository with no path); it builds one package per file-based install route from a single commit and writes them next to the repository, in `defense-factory-plugin-packages/vX.Y.Z/`:

```bash
python3 plugin-packager/package_plugin.py defense-factory-plugin --ref vX.Y.Z --expect-version X.Y.Z
```

Never upload the repository itself: ChatGPT's Upload plugin archive rejects an archive that contains `.agents/plugins/marketplace.json`.

| Package | Install route |
| --- | --- |
| `<plugin>-chatgpt-vX.Y.Z.zip` | ChatGPT desktop / Codex: Add, then Upload plugin archive |
| `<plugin>-claude-vX.Y.Z.zip` | Claude Code without Git: unzip, then `claude --plugin-dir <folder>` or `/plugin marketplace add <folder>` |

Git-based routes (Claude Code and Codex marketplaces, ChatGPT's Add a marketplace, Cursor's GitHub Repository) read the repository directly and need no package. No per-skill zips are built. When a new top-level file or folder is added, the packager stops until it is classified as plugin, adapter, or repository content. This repository's `scripts/check-package.py` runs as part of every package build.
