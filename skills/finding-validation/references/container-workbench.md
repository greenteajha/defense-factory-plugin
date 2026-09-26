# The container workbench

Stage 3 tests every finding inside **one disposable container per run** on the user's own computer. The workbench is a clean, throwaway bench: it installs the target's prerequisites, runs the app, runs the tests, and is then deleted entirely. It is a relaxed isolation standard — a disposable bench, not kernel-level isolation — chosen deliberately over remote servers, Kubernetes, and cloud sandboxes.

## Engine abstraction

`scripts/check_environment.py` detects one usable engine CLI from `docker`, `podman`, or `nerdctl` (Docker Desktop and Colima present `docker`; Podman presents `podman`; Rancher Desktop presents `nerdctl` or `docker`). Apple `container` is never used. Set `DEFENSE_FACTORY_ENGINE` to force one. Run `check_environment.py` **first**: if no engine is usable, the daemon is down, or memory is below the floor, stop and report exactly what to install or start. Never run the target on the host.

Use only commands the three CLIs share: `build`, `run` with `--label`/`--memory`/`--cpus`/`--pids-limit`/`--network`, `image inspect --format '{{.Id}}'` for digests, and label-filtered `ps`/`images`/`volume ls`/`network ls` with `rm`.

## Build the workbench with no personal data

- **Code in, never mounted.** Run `scripts/export_target.py --root <target> --scope <path> --out <stage_dir>/container-build --run-id <run_id>`. For a clean Git checkout it takes the committed bytes with `git archive` (also avoiding Windows line-ending drift); for a dirty worktree or a non-Git target it copies the reviewed files. It records `code_source` and prints the `--label` arguments. Copy the context into the image with a `COPY`; never bind-mount the user's tree, so the container cannot write back to the host.
- **Nothing personal inside.** No credentials, SSH agent, engine socket, or host environment variables. The only host paths involved are the run's own build context and an output-only directory the run created. Choose a plain published base image for the target's stack and record its digest (`image inspect`).
- **Native architecture first.** Build and run for the host's native arch. Fall back to emulation (`--platform linux/amd64`) only when an image or prerequisite is unavailable natively, and record it in `environment.emulation`. An application that cannot run in a Linux container at all is `inconclusive` with that reason — never a rejection.

## Two phases

1. **Setup — network on.** Install prerequisites and bring the app up, with the network on so package managers work.
2. **Testing — network off by default.** After setup succeeds, turn the network off for the test container (`--network none`), unless a finding's test needs a run-local sink, which stays on the run's own internal network only (`network_testing: internal-only`). Never contact external hosts during testing. Record `network_setup` and `network_testing`.

## Limits

Run every container with a memory limit, a CPU limit, a PID limit (`--pids-limit`), and a wall-clock timeout. Record them in `environment.limits`. Do not kill a command that is making progress (output, growing artifacts, rising resource use) for slowness alone, but let the timeout bound a hang.

## Label everything; clean up by label only

`export_target.py` prints the two labels every build and run must carry: `com.defensefactory.run=<run_id>` and `com.defensefactory=validation`. Pass them to **every** `build` and `run` (and to any `volume create` / `network create`). Nothing the run creates may be unlabelled.

At the end of the run, **and after any failure**, run `scripts/cleanup_run.py --run-id <run_id>`. It removes only resources carrying the run label, lists what it removed, refuses to touch anything unlabelled, and never runs a bare prune. This is what keeps the user's other containers — including their MISP stack — untouched. Record the result in `environment.cleanup`; if anything labelled remains, that is a stage failure — report it and never remove unlabelled resources to compensate.

## What is recorded

Every verdict is backed by the run's `environment` block: host OS and architecture, engine and version, base image and digest, emulation, code source, limits, the two network settings, and the clean-up receipt. This lets a later reader reproduce the bench and see that it left nothing behind.
