#!/usr/bin/env python3
"""Shared helpers for driving a Docker-compatible container engine, used by the stage 3 scripts.

Not a command-line tool: it is imported by check_environment.py, export_target.py, and
cleanup_run.py so all three agree on which engine to use, how to run it, and the run label.

The engine is one of docker, podman, or nerdctl (Docker Desktop and Colima present docker;
Podman presents podman; Rancher Desktop presents nerdctl or docker). Apple `container` is never
used. Set DEFENSE_FACTORY_ENGINE to force one. Only commands the three CLIs share are used.

Standard library only; Python 3.9+.
"""

import os
import shutil
import subprocess

ENGINES = ("docker", "podman", "nerdctl")
# The label every resource a run creates must carry, so clean-up can find them and touch nothing else.
RUN_LABEL_KEY = "com.defensefactory.run"
KIND_LABEL_KEY = "com.defensefactory"
KIND_LABEL_VALUE = "validation"


def run_label(run_id):
    return f"{RUN_LABEL_KEY}={run_id}"


def label_args(run_id):
    """The --label arguments every build and run must include."""
    return ["--label", run_label(run_id), "--label", f"{KIND_LABEL_KEY}={KIND_LABEL_VALUE}"]


def available_engines():
    """Engine names found on PATH, honouring DEFENSE_FACTORY_ENGINE first."""
    forced = os.environ.get("DEFENSE_FACTORY_ENGINE", "").strip()
    order = ([forced] if forced else []) + [name for name in ENGINES if name != forced]
    return [name for name in order if shutil.which(name)]


def run(engine, *args, timeout=None, text=True):
    """Run one engine command. Returns the CompletedProcess; never raises on a non-zero exit."""
    try:
        return subprocess.run([engine, *args], capture_output=True, text=text, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess([engine, *args], returncode=124, stdout=exc.stdout or "",
                                           stderr=(exc.stderr or "") + f"\ntimed out after {timeout}s")


def daemon_ok(engine):
    """True when the engine's daemon answers `info`."""
    return run(engine, "info", timeout=60).returncode == 0
