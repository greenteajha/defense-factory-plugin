#!/usr/bin/env python3
"""Build an image or run a container for a stage 3 run with the safety flags always applied.

Every build and run a stage 3 run performs must carry the run label, and every run must carry a
memory limit, a CPU limit, a PID limit, a network setting, and a wall-clock timeout. Applying them
by hand on each `docker` call is error-prone: one unlabelled or unbounded container defeats the
label-only clean-up and the resource limits. This helper builds the `docker` argument list for you
so the label and the limits cannot be forgotten, and it never uses `--rm` by default, so the
container it starts stays labelled until `cleanup_run.py` removes it — which keeps the clean-up
receipt an accurate count of what the run created.

Two modes:
  build --run-id ID --tag TAG --context DIR [--dockerfile PATH] [--platform P]
  run   --run-id ID --image IMG [--name NAME] [--network none|<name>] [--memory 2g] [--cpus 2]
        [--pids 256] [--timeout 300] [--env K=V ...] [--volume SPEC ...] [--rm] -- CMD [ARG ...]

Prints one JSON object describing what it did (mode, image or container name, exit code, whether it
timed out). On a `run` timeout it stops the container (so a hang is bounded) and reports exit 124;
the container, still labelled, remains for clean-up unless `--rm` was given. Standard library only;
Python 3.9+.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import engine as engine_mod  # noqa: E402  (this skill's scripts folder)

RUN_ID = re.compile(r"^[A-Za-z0-9._-]+$")
_NAME_SAFE = re.compile(r"[^A-Za-z0-9_.-]+")


def safe_name(run_id):
    """A docker-legal container name for this run, with a short random suffix."""
    stem = _NAME_SAFE.sub("-", run_id).lower().strip("-._") or "run"
    return f"df-{stem}-{os.urandom(3).hex()}"


def build_build_argv(run_id, tag, context, dockerfile=None, platform=None):
    """The `docker build` argument list, with the run labels always included."""
    argv = ["build", *engine_mod.label_args(run_id), "-t", tag]
    if dockerfile:
        argv += ["-f", dockerfile]
    if platform:
        argv += ["--platform", platform]
    argv.append(context)
    return argv


def build_run_argv(run_id, image, name, network="none", memory="2g", cpus="2", pids=256,
                   envs=(), volumes=(), rm=False, command=()):
    """The `docker run` argument list, with the run labels and every limit always included."""
    argv = ["run", "--name", name, *engine_mod.label_args(run_id),
            "--memory", memory, "--cpus", str(cpus), "--pids-limit", str(pids),
            "--network", network]
    if rm:
        argv.append("--rm")
    for pair in envs:
        argv += ["--env", pair]
    for spec in volumes:
        argv += ["--volume", spec]
    argv.append(image)
    argv += list(command)
    return argv


def _strip_leading_ddash(command):
    return command[1:] if command and command[0] == "--" else command


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--docker", help="path to the docker executable (default: auto-detect)")
    sub = parser.add_subparsers(dest="mode", required=True)

    b = sub.add_parser("build", help="build an image with the run labels")
    b.add_argument("--run-id", required=True)
    b.add_argument("--tag", required=True)
    b.add_argument("--context", required=True)
    b.add_argument("--dockerfile")
    b.add_argument("--platform")

    r = sub.add_parser("run", help="run a container with the run labels and every limit")
    r.add_argument("--run-id", required=True)
    r.add_argument("--image", required=True)
    r.add_argument("--name")
    r.add_argument("--network", default="none")
    r.add_argument("--memory", default="2g")
    r.add_argument("--cpus", default="2")
    r.add_argument("--pids", type=int, default=256)
    r.add_argument("--timeout", type=int, default=300, help="wall-clock seconds before the container is stopped")
    r.add_argument("--env", action="append", default=[], metavar="K=V")
    r.add_argument("--volume", action="append", default=[], metavar="SPEC")
    r.add_argument("--rm", action="store_true", help="remove the container on exit (default: keep it labelled for clean-up)")
    r.add_argument("command", nargs=argparse.REMAINDER, help="-- CMD [ARG ...] to run in the container")
    args = parser.parse_args()

    if not RUN_ID.fullmatch(args.run_id):
        parser.exit(2, "error: --run-id may contain only letters, digits, '.', '_' and '-'\n")

    docker = args.docker or engine_mod.docker_bin()
    report = {"mode": args.mode, "engine": "docker" if docker else None, "problems": []}
    if docker is None or not engine_mod.daemon_ok(docker):
        report["problems"].append("Docker with a running daemon is not available")
        print(json.dumps(report, indent=2))
        return 1

    if args.mode == "build":
        argv = build_build_argv(args.run_id, args.tag, args.context, args.dockerfile, args.platform)
        result = subprocess.run([docker, *argv])
        report.update(tag=args.tag, exit_code=result.returncode)
        if result.returncode == 0:
            got = engine_mod.run(docker, "image", "inspect", "--format", "{{.Id}}", args.tag, timeout=60)
            report["image"] = got.stdout.strip() if got.returncode == 0 else None
        else:
            report["problems"].append("docker build failed")
        print(json.dumps(report, indent=2))
        return 0 if result.returncode == 0 else 1

    # run
    name = args.name or safe_name(args.run_id)
    command = _strip_leading_ddash(args.command)
    argv = build_run_argv(args.run_id, args.image, name, network=args.network, memory=args.memory,
                          cpus=args.cpus, pids=args.pids, envs=args.env, volumes=args.volume,
                          rm=args.rm, command=command)
    report.update(container=name, network=args.network, timed_out=False)
    try:
        result = subprocess.run([docker, *argv], timeout=args.timeout)
        report["exit_code"] = result.returncode
    except subprocess.TimeoutExpired:
        report["timed_out"] = True
        report["exit_code"] = 124
        engine_mod.run(docker, "stop", "-t", "5", name, timeout=30)
        report["problems"].append(f"container {name} exceeded {args.timeout}s and was stopped")
    print(json.dumps(report, indent=2), file=sys.stderr)
    return 0 if report.get("exit_code") == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
