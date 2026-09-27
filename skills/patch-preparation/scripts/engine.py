#!/usr/bin/env python3
"""Shared helper for driving Docker (Docker Desktop), used by the stage 3 scripts.

Not a command-line tool: it is imported by check_environment.py, export_target.py, and
cleanup_run.py so all three agree on how to find and run Docker and on the run label.

Stage 3 uses Docker Desktop only (never Apple `container`). Docker is located from the PATH first,
then from the usual install locations, so a running Docker Desktop is found even when the shell
PATH is minimal — for example a non-interactive or remote shell where /usr/local/bin is absent.
Set DEFENSE_FACTORY_DOCKER to force a specific docker executable.

Standard library only; Python 3.9+.
"""

import os
import shutil
import subprocess

# The label every resource a run creates must carry, so clean-up can find them and touch nothing else.
RUN_LABEL_KEY = "com.defensefactory.run"
KIND_LABEL_KEY = "com.defensefactory"
KIND_LABEL_VALUE = "validation"

# Standard Docker CLI locations, checked after PATH. Covers Docker Desktop on macOS (Intel and
# Apple silicon), the Docker.app bundle, the user bin, and Docker Desktop on Windows.
_CANDIDATES = (
    "/usr/local/bin/docker",
    "/opt/homebrew/bin/docker",
    os.path.expanduser("~/.docker/bin/docker"),
    "/Applications/Docker.app/Contents/Resources/bin/docker",
    "C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe",
)


def docker_bin():
    """Absolute path to the docker CLI (PATH, a forced override, or a standard location), or None."""
    forced = os.environ.get("DEFENSE_FACTORY_DOCKER", "").strip()
    if forced:
        return forced if (shutil.which(forced) or os.path.exists(forced)) else None
    found = shutil.which("docker")
    if found:
        return found
    for path in _CANDIDATES:
        if os.path.exists(path) and os.access(path, os.X_OK):
            return path
    return None


def run_label(run_id):
    return f"{RUN_LABEL_KEY}={run_id}"


def label_args(run_id):
    """The --label arguments every build and run must include."""
    return ["--label", run_label(run_id), "--label", f"{KIND_LABEL_KEY}={KIND_LABEL_VALUE}"]


def run(docker, *args, timeout=None, text=True):
    """Run one docker command. Returns the CompletedProcess; never raises on a non-zero exit."""
    try:
        return subprocess.run([docker, *args], capture_output=True, text=text, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess([docker, *args], returncode=124, stdout=exc.stdout or "",
                                           stderr=(exc.stderr or "") + f"\ntimed out after {timeout}s")


def daemon_ok(docker):
    """True when Docker's daemon answers `info`."""
    return run(docker, "info", timeout=60).returncode == 0
