#!/usr/bin/env python3
"""Remove every container, image, volume, and network a stage 3 run created, and nothing else.

Stage 3 labels every resource it creates with com.defensefactory.run=<run_id>. This script
removes resources **only** by that label. It never removes a resource that does not carry the
label, and it never runs a bare prune, so other containers, images, and volumes on the same
engine (for example a MISP stack) are never touched. Safe to run after a failed run and safe to
run twice: a run that created nothing removes nothing.

Prints one JSON object: run_id, engine, label, removed ({containers, images, volumes, networks}
as lists of ids), remaining (anything still carrying the label after clean-up), problems.

Exit codes: 0 clean (nothing carrying the label remains); 1 something could not be removed or no
engine is available; 2 bad arguments. Standard library only; Python 3.9+.
"""

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import engine as engine_mod  # noqa: E402  (this skill's scripts folder)

RUN_ID = re.compile(r"^[A-Za-z0-9._-]+$")


def ids(engine, kind, label):
    """Resource ids of one kind carrying the label. Empty on any engine error."""
    listers = {
        "containers": ["ps", "-aq", "--filter", f"label={label}"],
        "images": ["images", "-q", "--filter", f"label={label}"],
        "volumes": ["volume", "ls", "-q", "--filter", f"label={label}"],
        "networks": ["network", "ls", "-q", "--filter", f"label={label}"],
    }
    result = engine_mod.run(engine, *listers[kind], timeout=60)
    if result.returncode != 0:
        return []
    # De-duplicate while keeping order; image queries can repeat an id across tags.
    out = []
    for line in result.stdout.split("\n"):
        value = line.strip()
        if value and value not in out:
            out.append(value)
    return out


def remove(engine, kind, identifiers, problems):
    """Remove resources of one kind by id. Never touches anything not passed in."""
    if not identifiers:
        return []
    commands = {
        "containers": ["rm", "-f", "-v"],
        "images": ["rmi", "-f"],
        "volumes": ["volume", "rm", "-f"],
        "networks": ["network", "rm"],
    }
    removed = []
    for identifier in identifiers:
        result = engine_mod.run(engine, *commands[kind], identifier, timeout=120)
        if result.returncode == 0:
            removed.append(identifier)
        else:
            problems.append(f"could not remove {kind[:-1]} {identifier}: {result.stderr.strip()}")
    return removed


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run-id", required=True, help="the run whose labelled resources to remove")
    parser.add_argument("--docker", help="path to the docker executable (default: auto-detect)")
    args = parser.parse_args()
    if not RUN_ID.fullmatch(args.run_id):
        parser.exit(2, "error: --run-id may contain only letters, digits, '.', '_' and '-'\n")

    docker = args.docker or engine_mod.docker_bin()
    if docker and not engine_mod.daemon_ok(docker):
        docker = None
    label = engine_mod.run_label(args.run_id)
    report = {"run_id": args.run_id, "engine": "docker" if docker else None, "label": label,
              "removed": {}, "remaining": {}, "problems": []}
    if docker is None:
        report["problems"].append("Docker with a running daemon is not available")
        print(json.dumps(report, indent=2))
        return 1

    # Containers first (they hold images and volumes), then images, volumes, networks.
    for kind in ("containers", "images", "volumes", "networks"):
        report["removed"][kind] = remove(docker, kind, ids(docker, kind, label), report["problems"])
    for kind in ("containers", "images", "volumes", "networks"):
        left = ids(docker, kind, label)
        if left:
            report["remaining"][kind] = left
            report["problems"].append(f"{len(left)} {kind} still carry {label} after clean-up")

    print(json.dumps(report, indent=2))
    return 1 if report["problems"] else 0


if __name__ == "__main__":
    sys.exit(main())
