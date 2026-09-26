# The container workbench

Stage 3 tests every finding inside **one disposable container per run** on the user's own computer. The workbench is a clean, throwaway bench: it installs the target's prerequisites, runs the app, runs the tests, and is then deleted entirely. It is a relaxed isolation standard — a disposable bench, not kernel-level isolation — chosen deliberately over remote servers, Kubernetes, and cloud sandboxes.

## Engine abstraction

`scripts/check_environment.py` detects Docker (Docker Desktop). Docker is located from the PATH first, then from standard install locations (`/usr/local/bin/docker`, `/opt/homebrew/bin/docker`, `~/.docker/bin/docker`, the Docker.app bundle), so a running Docker Desktop is found even when the shell PATH is minimal — for example a non-interactive or remote shell. Set `DEFENSE_FACTORY_DOCKER` to force a specific docker executable. Apple `container` is never used. Run `check_environment.py` **first**: if Docker is missing, the daemon is down, or memory is below the floor, stop and report exactly what to install or start. Never run the target on the host.

Uses `build`, `run` with `--label`/`--memory`/`--cpus`/`--pids-limit`/`--network`, `image inspect --format '{{.Id}}'` for digests, and label-filtered `ps`/`images`/`volume ls`/`network ls` with `rm`.

## Build and run through the helper

Do every `build` and `run` through `scripts/run_container.py` rather than calling `docker` by hand, so the run label and the limits cannot be forgotten:

- `run_container.py build --run-id <run_id> --tag <tag> --context <stage_dir>/container-build` builds the workbench image with both labels applied, and prints the built image id.
- `run_container.py run --run-id <run_id> --image <tag> [--network none|<net>] [--memory 2g] [--cpus 2] [--pids 256] [--timeout 300] [--env K=V ...] [--volume <host>:<path> ...] -- <cmd> ...` runs one test container with both labels, all four limits, the chosen network, and a wall-clock timeout that stops the container if it hangs.

By default the helper does **not** pass `--rm`, so each test container stays labelled until `cleanup_run.py` removes it; this keeps the clean-up receipt an accurate count of what the run created. Calling `docker` directly is allowed for one-off inspection, but any container, image, volume, or network it creates must still carry both labels (`engine.label_args` / the arguments `export_target.py` prints), or clean-up will not find it.

## Build the workbench with no personal data

- **Code in, never mounted.** Run `scripts/export_target.py --root <target> --scope <path> --out <stage_dir>/container-build --run-id <run_id>`. For a clean Git checkout it takes the committed bytes with `git archive` (also avoiding Windows line-ending drift); for a dirty worktree or a non-Git target it copies the reviewed files. It records `code_source` and prints the `--label` arguments. Copy the context into the image with a `COPY`; never bind-mount the user's tree, so the container cannot write back to the host.
- **Nothing personal inside.** No credentials, SSH agent, engine socket, or host environment variables. The only host paths involved are the run's own build context and an output-only directory the run created. Choose a plain published base image for the target's stack and record its digest. Read the digest with `docker image inspect --format '{{index .RepoDigests 0}}' <ref>`; when BuildKit pulled the base image without keeping a local copy that has a `RepoDigests` entry, fall back to `docker buildx imagetools inspect <ref>` (its `Digest:` line), and if neither is available record the local image id from `image inspect --format '{{.Id}}'` and note in `environment.base_image_digest` that it is the local id, not a registry digest.

## Workbench layout

Keep every file the run creates under the stage folder, in this fixed layout, so a later reader finds it in the same place each run:

- `container-build/` — the build context `export_target.py` wrote (the reviewed code). Referenced by the image's `COPY`; never edited by hand.
- `workbench/` — everything the run authors: the `Dockerfile`, and a `harness/` directory holding the stub services, test scripts, and any focused tests. Nothing here is part of the target.
- `artifacts/<finding_id>/` — the proof-of-concept inputs, logs, and other evidence for each finding, referenced from that finding's `artifacts` list. Regular files only; never secrets.
- `out/` (or a per-finding output directory) — mounted into test containers read-write as the only writable host path, so container output lands beside the run without touching the target tree.
- **Native architecture first.** Build and run for the host's native arch. Fall back to emulation (`--platform linux/amd64`) only when an image or prerequisite is unavailable natively, and record it in `environment.emulation`. An application that cannot run in a Linux container at all is `inconclusive` with that reason — never a rejection.

## Two phases

1. **Setup — network on.** Install prerequisites and bring the app up, with the network on so package managers work.
2. **Testing — network off by default.** After setup succeeds, turn the network off for the test container (`--network none`), unless a finding's test needs a run-local sink, which stays on the run's own internal network only (`network_testing: internal-only`). Never contact external hosts during testing. Record `network_setup` and `network_testing`.

## Limits

Run every container with a memory limit, a CPU limit, a PID limit (`--pids-limit`), and a wall-clock timeout. Record them in `environment.limits`. Do not kill a command that is making progress (output, growing artifacts, rising resource use) for slowness alone, but let the timeout bound a hang.

## Label everything; clean up by label only

`export_target.py` prints the two labels every build and run must carry: `com.defensefactory.run=<run_id>` and `com.defensefactory=validation`. Pass them to **every** `build` and `run` (and to any `volume create` / `network create`). Nothing the run creates may be unlabelled.

At the end of the run, **and after any failure**, run `scripts/cleanup_run.py --run-id <run_id>`. It removes only resources carrying the run label, lists what it removed, refuses to touch anything unlabelled, and never runs a bare prune. This is what keeps the user's other containers untouched. Record the result in `environment.cleanup`; if anything labelled remains, that is a stage failure — report it and never remove unlabelled resources to compensate.

## What is recorded

Every verdict is backed by the run's `environment` block: host OS and architecture, engine and version, base image and digest, emulation, code source, limits, the two network settings, and the clean-up receipt. This lets a later reader reproduce the bench and see that it left nothing behind.
