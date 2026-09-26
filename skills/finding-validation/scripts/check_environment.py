#!/usr/bin/env python3
"""Check that Docker is available before stage 3 runs anything.

Stage 3 uses Docker Desktop only. Docker is located from the PATH or a standard install location
(so a running Docker Desktop is found even when the shell PATH is minimal), and its daemon must
answer. Nothing in stage 3 ever runs the target on the host: if Docker is not usable, or its
memory is below the floor, this stops the stage and says what to install or start.

Prints one JSON object: ready, engine, engine_path, engine_version, daemon_running, host_os,
host_arch, engine_arch, mem_bytes, mem_floor_bytes, meets_floor, emulation_available, problems,
remediation.

Exit codes: 0 ready; 1 not ready (Docker missing, daemon down, or below the memory floor); 2 bad
arguments. Standard library only; Python 3.9+. Read-only: starts and changes nothing.
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


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--min-memory-gb", type=float, default=DEFAULT_FLOOR_GB,
                        help=f"memory floor Docker must offer (default: {DEFAULT_FLOOR_GB})")
    args = parser.parse_args()
    if args.min_memory_gb < 0:
        parser.exit(2, "error: --min-memory-gb must not be negative\n")
    floor = int(args.min_memory_gb * (1 << 30))

    host_os = platform.system().lower()
    host_arch = normalize_arch(platform.machine())
    report = {
        "ready": False, "engine": "docker", "engine_path": None, "engine_version": None,
        "daemon_running": False, "host_os": host_os, "host_arch": host_arch, "engine_arch": None,
        "mem_bytes": None, "mem_floor_bytes": floor, "meets_floor": None,
        "emulation_available": None, "problems": [], "remediation": [],
    }

    docker = engine_mod.docker_bin()
    if docker is None:
        report["problems"].append("Docker was not found on PATH or in a standard install location")
        report["remediation"].append(
            "install and start Docker Desktop (https://www.docker.com/products/docker-desktop/), then retry; "
            "if Docker is installed, set DEFENSE_FACTORY_DOCKER to its full path. Stage 3 never runs the target on the host")
        print(json.dumps(report, indent=2))
        return 1
    report["engine_path"] = docker

    if not engine_mod.daemon_ok(docker):
        report["engine_version"] = engine_version(docker)
        report["problems"].append("Docker is installed but its daemon is not responding")
        report["remediation"].append("start Docker Desktop (open the app and wait until it reports running), then retry")
        print(json.dumps(report, indent=2))
        return 1

    info = info_json(docker)
    mem_bytes, engine_arch = read_mem_and_arch(info)
    report.update(engine_version=engine_version(docker), daemon_running=True,
                  engine_arch=engine_arch or host_arch, mem_bytes=mem_bytes)
    report["emulation_available"] = (engine_arch or host_arch) != host_arch or None

    if mem_bytes is None:
        report["meets_floor"] = None
        report["problems"].append("could not read the memory available to Docker; proceeding, but keep the run small")
    elif mem_bytes < floor:
        report["meets_floor"] = False
        report["problems"].append(
            f"Docker offers {mem_bytes // (1 << 20)} MiB, below the {floor // (1 << 20)} MiB floor")
        report["remediation"].append(
            f"raise Docker Desktop's memory limit to at least {args.min_memory_gb} GB in Settings > Resources, then retry")
        print(json.dumps(report, indent=2))
        return 1
    else:
        report["meets_floor"] = True

    report["ready"] = True
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
