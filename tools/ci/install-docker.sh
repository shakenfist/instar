#!/usr/bin/env bash
#
# Install the Docker client and daemon on a self-hosted runner.
#
# The runner images do not ship Docker, so almost every job that builds
# anything begins by installing it. That block had been pasted into
# fourteen steps across six workflows, and the paste is what broke when
# the fleet moved from `debian-12` to `debian-13` (GitHub issue #564):
#
#   - On bookworm, `docker.io` 20.10.24 ships `/usr/bin/docker` itself,
#     so `apt-get install -y docker.io` was enough.
#   - On trixie, `docker.io` 26.1.5 is the daemon only -- its sole
#     binary is `/usr/bin/docker-init`. The client moved to a separate
#     `docker-cli` package, which `docker.io` merely *Recommends*, and
#     the runners do not install recommends.
#
# The result was `docker: not found` in lint, build-and-test,
# coverage-fuzz and differential-fuzz, several apt-seconds after a step
# named "Install Docker" reported success. Fourteen copies meant
# fourteen places to notice it.
#
# `docker-cli` exists in trixie and later, not in bookworm, so this
# script requires a `debian-13` runner. That is every runner that calls
# it; a job that moves back to an older image needs the bookworm
# spelling instead, and will say so loudly rather than silently.
#
# Any additional packages a caller needs from the same apt run are
# passed as arguments, which saves a second `apt-get update`:
#
#   tools/ci/install-docker.sh qemu-utils

set -e

sudo apt-get update
sudo apt-get install -y docker.io docker-cli "$@"
sudo systemctl start docker
sudo chmod 666 /var/run/docker.sock

echo "docker installed: $(docker --version)"
