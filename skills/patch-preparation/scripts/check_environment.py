#!/usr/bin/env python3
"""Check the prerequisites for stage 3 (Docker) before a Defense Factory run starts anything.

Stage 3 uses Docker Desktop only. Docker is located from the PATH or a standard install location
(so a running Docker Desktop is found even when the shell PATH is minimal), and its daemon must
answer with enough memory. Nothing in stage 3 ever runs the target on the host.

Every prerequisite that is not met is reported in `unmet` as one entry with:
  prerequisite  what is needed, and for which stage
  problem       what is wrong on this computer, in plain words
  fix           the steps the user takes to fix it, in order
  verify        a command the user can run to confirm the fix
Present `unmet` to the user as written: for each entry, what is not met and how to fix it.

Prints one JSON object: ready, engine, engine_path, engine_version, daemon_running, host_os,
host_arch, engine_arch, mem_bytes, mem_floor_bytes, meets_floor, emulation_available, unmet,
warnings, problems, remediation (the last two repeat `unmet` as flat text).

Exit codes: 0 ready; 1 a prerequisite is not met; 2 bad arguments.
Standard library only; Python 3.9+. Read-only: starts and changes nothing.
"""

import argparse
import json
import platform
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import engine as engine_mod  # noqa: E402  (this skill's scripts folder)

DEFAULT_FLOOR_GB = 4
ARCH_ALIASES = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}
DOCKER_URL = "https://www.docker.com/products/docker-desktop/"


def normalize_arch(value):
    return ARCH_ALIASES.get(str(value or "").strip().lower(), str(value or "").strip().lower() or None)


def info_json(docker):
    """`docker info` as a dict, or None."""
    result = engine_mod.run(docker, "info", "--format", "{{json .}}", timeout=60)
    if result.returncode != 0 or not result.stdout.strip():
        return None
    try:
        data = json.loads(result.stdout)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def read_mem_and_arch(info):
    """(mem_bytes, engine_arch) from a docker info dict."""
    if not info:
        return None, None
    mem = info.get("MemTotal")
    arch = info.get("Architecture")
    mem = mem if isinstance(mem, int) and mem > 0 else None
    return mem, normalize_arch(arch)


def engine_version(docker):
    result = engine_mod.run(docker, "version", "--format", "{{.Server.Version}}", timeout=60)
    version = result.stdout.strip() if result.returncode == 0 else ""
    if not version:
        result = engine_mod.run(docker, "--version", timeout=30)
        version = result.stdout.strip() if result.returncode == 0 else ""
    return version or "unknown"


def docker_missing():
    return {
        "prerequisite": "Docker Desktop, installed (needed for stage 3, isolated validation)",
        "problem": "Docker was not found on this computer: not on the PATH and not in a standard install location.",
        "fix": [
            f"Download and install Docker Desktop from {DOCKER_URL}.",
            "Open Docker Desktop once and wait until it shows that the engine is running.",
            "If Docker is already installed in a non-standard location, set DEFENSE_FACTORY_DOCKER to the full path of the docker program.",
        ],
        "verify": "docker info",
    }


def daemon_down(docker):
    return {
        "prerequisite": "Docker Desktop, running (needed for stage 3, isolated validation)",
        "problem": f"Docker is installed ({docker}) but its engine is not responding, or this session cannot reach it.",
        "fix": [
            "Open Docker Desktop and wait until it shows that the engine is running.",
            "If Docker Desktop is already running and this still fails, this session cannot reach Docker on your "
            "computer (for example a remote or cloud session). Run the review from a session on this computer, "
            "such as Claude Code, instead.",
        ],
        "verify": "docker info",
    }


def memory_low(mem_bytes, floor_bytes, floor_gb):
    have = mem_bytes / (1 << 30)
    return {
        "prerequisite": f"At least {floor_gb:g} GB of memory for Docker (needed for stage 3, isolated validation)",
        "problem": f"Docker currently has {have:.1f} GB of memory; stage 3 needs at least {floor_gb:g} GB.",
        "fix": [
            "Open Docker Desktop and go to Settings, then Resources.",
            f"Set Memory to at least {floor_gb:g} GB.",
            "Click Apply & restart, and wait until the engine is running again.",
        ],
        "verify": "docker info --format '{{.MemTotal}}'",
    }


def finish(report):
    report["problems"] = [entry["problem"] for entry in report["unmet"]]
    report["remediation"] = [" ".join(entry["fix"]) for entry in report["unmet"]]
    report["ready"] = not report["unmet"]
    print(json.dumps(report, indent=2))
    return 0 if report["ready"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--min-memory-gb", type=float, default=DEFAULT_FLOOR_GB,
                        help=f"memory floor Docker must offer (default: {DEFAULT_FLOOR_GB})")
    args = parser.parse_args()
    if args.min_memory_gb < 0:
        parser.exit(2, "error: --min-memory-gb must not be negative\n")
    floor = int(args.min_memory_gb * (1 << 30))

    report = {
        "ready": False, "engine": "docker", "engine_path": None, "engine_version": None,
        "daemon_running": False, "host_os": platform.system().lower(), "host_arch": normalize_arch(platform.machine()),
        "engine_arch": None, "mem_bytes": None, "mem_floor_bytes": floor, "meets_floor": None,
        "emulation_available": None, "unmet": [], "warnings": [], "problems": [], "remediation": [],
    }

    docker = engine_mod.docker_bin()
    if docker is None:
        report["unmet"].append(docker_missing())
        return finish(report)
    report["engine_path"] = docker

    if not engine_mod.daemon_ok(docker):
        report["engine_version"] = engine_version(docker)
        report["unmet"].append(daemon_down(docker))
        return finish(report)

    mem_bytes, engine_arch = read_mem_and_arch(info_json(docker))
    report.update(engine_version=engine_version(docker), daemon_running=True,
                  engine_arch=engine_arch or report["host_arch"], mem_bytes=mem_bytes)
    report["emulation_available"] = (engine_arch or report["host_arch"]) != report["host_arch"] or None

    if mem_bytes is None:
        report["warnings"].append("Could not read how much memory Docker has; continuing, but keep the run small.")
    elif mem_bytes < floor:
        report["meets_floor"] = False
        report["unmet"].append(memory_low(mem_bytes, floor, args.min_memory_gb))
    else:
        report["meets_floor"] = True
    return finish(report)


if __name__ == "__main__":
    sys.exit(main())
