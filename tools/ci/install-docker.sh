#!/usr/bin/env bash
#
# Install the Docker client and daemon on a self-hosted runner.
#
# The runner images do not ship Docker, so almost every job that builds
# anything begins by installing it. That block had been pasted into
# fourteen steps across six workflows, and the paste is what broke when
# the fleet moved from `debian-12` to `debian-13` (GitHub issue #564).
#
# Trixie splits what bookworm's `docker.io` 20.10.24 shipped as one
# package into three, and keeps the two that matter here as mere
# *Recommends* -- which the runners do not install:
#
#   - `docker.io` 26.1.5 is the daemon only; its sole binary is
#     `/usr/bin/docker-init`.
#   - `docker-cli` is the client, `/usr/bin/docker`. Without it every
#     container step fails with `docker: not found`.
#   - `docker-buildx` is the BuildKit builder. Every workflow here sets
#     `DOCKER_BUILDKIT: 1`, and the docker 26 client implements
#     `docker build` under BuildKit by delegating to this plugin, so
#     without it a build refuses to run rather than falling back to the
#     legacy builder: "BuildKit is enabled but the buildx component is
#     missing or broken".
#
# Both failures land several apt-seconds after a step named "Install
# Docker" reported success, in lint, build-and-test, coverage-fuzz and
# differential-fuzz. Fourteen copies meant fourteen places to notice it.
#
# Neither package exists before trixie, so this script requires a
# `debian-13` runner. That is every runner that calls it; a job that
# moves back to an older image needs the bookworm spelling instead, and
# will say so loudly rather than silently.
#
# Any additional packages a caller needs from the same apt run are
# passed as arguments, which saves a second `apt-get update`:
#
#   tools/ci/install-docker.sh qemu-utils

set -e

sudo apt-get update
sudo apt-get install -y docker.io docker-cli docker-buildx "$@"
sudo systemctl start docker
sudo chmod 666 /var/run/docker.sock

echo "docker installed: $(docker --version)"
echo "buildx installed: $(docker buildx version)"
