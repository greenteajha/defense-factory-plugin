#!/usr/bin/env python3
"""Check that a disposable container engine is available before stage 3 runs anything.

Detects one usable engine (docker, podman, or nerdctl; never Apple `container`), checks its
daemon answers, and reports the architecture and the memory the engine can use. Nothing in stage 3
ever runs the target on the host: if no engine is usable, or memory is below the floor, this stops
the stage and says exactly what to install or start.

Prints one JSON object: ready, engine, engine_path, engine_version, daemon_running, host_os,
host_arch, engine_arch, mem_bytes, mem_floor_bytes, meets_floor, emulation_available, problems,
remediation, engines_seen.

Exit codes: 0 ready; 1 not ready (no engine, daemon down, or below the memory floor); 2 bad
arguments. Standard library only; Python 3.9+. Read-only: starts and changes nothing.
"""

import argparse
import json
import platform
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import engine as engine_mod  # noqa: E402  (this skill's scripts folder)

DEFAULT_FLOOR_GB = 4
ARCH_ALIASES = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}


def normalize_arch(value):
    return ARCH_ALIASES.get(str(value or "").strip().lower(), str(value or "").strip().lower() or None)


def info_json(name):
    """`<engine> info` as a dict, or None. docker/nerdctl put memory at MemTotal; podman nests it."""
    result = engine_mod.run(name, "info", "--format", "{{json .}}", timeout=60)
    if result.returncode != 0 or not result.stdout.strip():
        return None
    try:
        data = json.loads(result.stdout)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def read_mem_and_arch(info):
    """(mem_bytes, engine_arch) from an info dict, tolerating docker/nerdctl and podman shapes."""
    if not info:
        return None, None
    host = info.get("host") if isinstance(info.get("host"), dict) else {}
    mem = info.get("MemTotal", host.get("memTotal"))
    arch = info.get("Architecture") or host.get("arch")
    mem = mem if isinstance(mem, int) and mem > 0 else None
    return mem, normalize_arch(arch)


def engine_version(name):
    result = engine_mod.run(name, "version", "--format", "{{.Server.Version}}", timeout=60)
    version = result.stdout.strip() if result.returncode == 0 else ""
    if not version:
        result = engine_mod.run(name, "--version", timeout=30)
        version = result.stdout.strip() if result.returncode == 0 else ""
    return version or "unknown"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--min-memory-gb", type=float, default=DEFAULT_FLOOR_GB,
                        help=f"memory floor the engine must offer (default: {DEFAULT_FLOOR_GB})")
    args = parser.parse_args()
    if args.min_memory_gb < 0:
        parser.exit(2, "error: --min-memory-gb must not be negative\n")
    floor = int(args.min_memory_gb * (1 << 30))

    host_os = platform.system().lower()
    host_arch = normalize_arch(platform.machine())
    seen = engine_mod.available_engines()
    report = {
        "ready": False, "engine": None, "engine_path": None, "engine_version": None,
        "daemon_running": False, "host_os": host_os, "host_arch": host_arch, "engine_arch": None,
        "mem_bytes": None, "mem_floor_bytes": floor, "meets_floor": None,
        "emulation_available": None, "problems": [], "remediation": [], "engines_seen": seen,
    }

    if not seen:
        report["problems"].append("no container engine found on PATH")
        report["remediation"].append(
            "install and start one of Docker Desktop, Podman, Colima, or Rancher Desktop, then retry; "
            "stage 3 never runs the target on the host")
        print(json.dumps(report, indent=2))
        return 1

    # Prefer the first engine whose daemon answers; fall back to the first seen for the report.
    chosen = next((name for name in seen if engine_mod.daemon_ok(name)), None)
    if chosen is None:
        name = seen[0]
        report.update(engine=name, engine_path=shutil.which(name), engine_version=engine_version(name))
        report["problems"].append(f"the {name} engine is installed but its daemon is not responding")
        report["remediation"].append(f"start the {name} engine (open its app or run its service), then retry")
        print(json.dumps(report, indent=2))
        return 1

    info = info_json(chosen)
    mem_bytes, engine_arch = read_mem_and_arch(info)
    report.update(engine=chosen, engine_path=shutil.which(chosen), engine_version=engine_version(chosen),
                  daemon_running=True, engine_arch=engine_arch or host_arch, mem_bytes=mem_bytes)
    report["emulation_available"] = (engine_arch or host_arch) != host_arch or None

    if mem_bytes is None:
        report["meets_floor"] = None
        report["problems"].append(
            f"could not read the memory available to {chosen}; proceeding, but keep the run small")
    elif mem_bytes < floor:
        report["meets_floor"] = False
        report["problems"].append(
            f"{chosen} offers {mem_bytes // (1 << 20)} MiB, below the {floor // (1 << 20)} MiB floor")
        report["remediation"].append(
            f"raise the engine's memory limit to at least {args.min_memory_gb} GB in its settings, then retry")
        print(json.dumps(report, indent=2))
        return 1
    else:
        report["meets_floor"] = True

    report["ready"] = True
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
