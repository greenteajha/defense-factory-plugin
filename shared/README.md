# Shared skill resources

Master copies of files that two or more skills use. Clients never read this folder: each skill that uses a file gets its own committed copy, so every install route (whole plugin, single skill folder, per-skill zip) works without links outside the skill.

- `shared/<folder>/<file>` is copied to `skills/<skill>/<folder>/<file>`, where `<folder>` is `references`, `assets`, or `scripts`.
- [manifest.json](manifest.json) lists every master file and the skills that receive it.
- Edit only the master, then run `python3 scripts/sync-shared.py` to update the copies.
- `python3 scripts/check-package.py` (and CI) fails when a copy is missing or differs from its master, a master file is not in the manifest, the manifest names a missing file or skill, or a skill holds a file at a shared path without being listed for it.
