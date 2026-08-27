#!/usr/bin/env bash
#
# Install the GitHub CLI on a self-hosted runner, if it is not there
# already.
#
# The [self-hosted, debian-12] runners do not ship `gh`, so any workflow
# that files an issue or opens a PR from those runners has to install it
# first. On 2026-08-24 the rust-nightly-bump job validated the candidate
# nightly, committed it and pushed the branch, then died with
# "bump-rust-nightly.sh: line 176: gh: command not found" -- the PR was
# never opened and the whole run was marked failed, after 11 minutes of
# successful validation work. coverage-fuzz and differential-fuzz had
# each grown their own copy of this install block; rust-nightly-bump had
# none. This script is the single copy all three now call.
#
# Safe to call unconditionally: it is a no-op when gh is already present.

set -e

if command -v gh >/dev/null 2>&1; then
    echo "gh already installed: $(gh --version | head -1)"
    exit 0
fi

sudo mkdir -p -m 755 /etc/apt/keyrings
wget -qO- https://cli.github.com/packages/githubcli-archive-keyring.gpg \
    | sudo tee /etc/apt/keyrings/githubcli-archive-keyring.gpg >/dev/null
sudo chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
    | sudo tee /etc/apt/sources.list.d/github-cli.list >/dev/null

sudo apt-get update
sudo apt-get install -y gh

echo "gh installed: $(gh --version | head -1)"
