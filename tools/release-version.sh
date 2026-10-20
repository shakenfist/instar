#!/bin/bash
# Read, set and check the release version of a Rust repository: the
# version in one Cargo.toml, which the release tag must name, and the
# matching entry in Cargo.lock, which must agree with it because the
# release builds from the lockfile.
#
# Usage:
#   tools/release-version.sh get [CARGO_TOML|-]
#   tools/release-version.sh set X.Y.Z
#   tools/release-version.sh check GITHUB_REF
#   tools/release-version.sh at COMMIT X.Y.Z
#
# get prints the version, from the version file or from standard input.
# set rewrites the version file; Cargo.lock is left to the build tooling
# (propose-release.sh runs it next). check is release.yml's check-version
# job: Cargo.lock must agree with the version file, and a tag vX.Y.Z must
# name the version. A ref that is not a tag, from a workflow_dispatch dry
# run, has no version to compare with, so check says so and passes once
# the two files agree. at runs the same checks against a commit rather
# than the working tree, for tag-release.sh, so that a local branch or an
# uncommitted edit cannot stand in for what merged.
#
# The files are read with awk rather than cargo, so that this runs on a
# host and a runner with no Rust toolchain.
#
# Template source: shakenfist/development/templates/release-automation-rust/

set -euo pipefail

# --- per-repository settings ---

# The Cargo.toml whose version is the release's version. Where the
# crates inherit one version from [workspace.package], that is the
# workspace's root Cargo.toml, and its [workspace.package] version is
# read. Otherwise it is the main crate's own Cargo.toml, and its
# [package] version is read.
VERSION_FILE='src/vmm/Cargo.toml'

# The committed Cargo.lock, and the crate whose entry in it must carry
# the version. Leave both empty in a repository that commits no
# Cargo.lock.
CARGO_LOCK=''
LOCKED_CRATE=''

# --- end of per-repository settings ---

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

err() { echo "error: $*" >&2; exit 1; }

# Prints the [workspace.package] version where there is one, and the
# [package] version otherwise. A crate that inherits its version has
# `version.workspace = true` in [package], which is not a quoted version
# and so is never mistaken for one. awk reads to the end rather than
# exiting at a match, so that a writer piping into it is never killed by
# SIGPIPE.
read_version() {
    awk '
        /^\[/ { table = $0; next }
        /^version *= *"/ {
            v = $0
            sub(/^version *= *"/, "", v)
            sub(/".*$/, "", v)
            if (table == "[workspace.package]" && ws == "") ws = v
            if (table == "[package]" && pkg == "") pkg = v
        }
        END {
            if (ws != "") print ws
            else if (pkg != "") print pkg
        }
    '
}

# Prints the version Cargo.lock records for LOCKED_CRATE: the version
# line that follows its name in its [[package]] entry.
read_locked() {
    awk -v crate="${LOCKED_CRATE}" '
        $0 == "name = \"" crate "\"" { found = 1; next }
        found && /^version = / {
            v = $0
            sub(/^version = "/, "", v)
            sub(/".*$/, "", v)
            if (locked == "") locked = v
            found = 0
        }
        END { print locked }
    '
}

# Checks that the version and the lockfile agree, given both files'
# contents, and prints the version. The caller compares it with a tag.
agree() {
    local toml="$1" lock="$2" version locked
    version="$(printf '%s\n' "${toml}" | read_version)"
    [[ -n "${version}" ]] || err "no [workspace.package] or [package] version in ${VERSION_FILE}"
    if [[ -n "${CARGO_LOCK}" ]]; then
        locked="$(printf '%s\n' "${lock}" | read_locked)"
        [[ "${locked}" == "${version}" ]] \
            || err "${CARGO_LOCK} has ${LOCKED_CRATE} ${locked:-<none>} but ${VERSION_FILE} has ${version}"
    fi
    echo "${version}"
}

[[ $# -ge 1 ]] || err "usage: $0 get|set|check|at ..."
COMMAND="$1"
shift

case "${COMMAND}" in
    get)
        SOURCE="${1:-${VERSION_FILE}}"
        if [[ "${SOURCE}" == "-" ]]; then
            VERSION="$(read_version)"
        else
            VERSION="$(read_version < "${SOURCE}")"
        fi
        [[ -n "${VERSION}" ]] || err "no [workspace.package] or [package] version in ${SOURCE}"
        echo "${VERSION}"
        ;;

    set)
        [[ $# -eq 1 ]] || err "usage: $0 set X.Y.Z"
        NEW="$1"
        [[ "${NEW}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || err "version must be X.Y.Z, got: ${NEW}"
        # Two passes over the same file: the first finds which table holds
        # the version, so that the second rewrites the line get reads.
        BUMPED="$(mktemp)"
        trap 'rm -f "${BUMPED}"' EXIT
        awk -v version="${NEW}" '
            NR == FNR {
                if (/^\[/) table = $0
                else if (table == "[workspace.package]" && /^version *= *"/) ws = 1
                next
            }
            /^\[/ { table = $0 }
            !done && table == (ws ? "[workspace.package]" : "[package]") && /^version *= *"/ {
                sub(/"[^"]*"/, "\"" version "\"")
                done = 1
            }
            { print }
        ' "${VERSION_FILE}" "${VERSION_FILE}" > "${BUMPED}"
        cat "${BUMPED}" > "${VERSION_FILE}"
        [[ "$(read_version < "${VERSION_FILE}")" == "${NEW}" ]] \
            || err "setting ${VERSION_FILE} to ${NEW} did not take"
        ;;

    check)
        [[ $# -eq 1 ]] || err "usage: $0 check GITHUB_REF"
        REF="$1"
        TOML="$(cat "${VERSION_FILE}")"
        LOCK=''
        [[ -z "${CARGO_LOCK}" ]] || LOCK="$(cat "${CARGO_LOCK}")"
        ACTUAL="$(agree "${TOML}" "${LOCK}")"
        echo "Ref: ${REF}"
        echo "Version in ${VERSION_FILE}: ${ACTUAL}"
        case "${REF}" in
            refs/tags/v*) ;;
            *)
                echo "Not a release tag, so there is no version to compare; building ${ACTUAL} without publishing"
                exit 0
                ;;
        esac
        TAG="${REF#refs/tags/}"
        if [[ "${ACTUAL}" != "${TAG#v}" ]]; then
            echo "::error::Version mismatch: tag ${TAG} expects ${TAG#v} but ${VERSION_FILE} has ${ACTUAL}"
            exit 1
        fi
        echo "Tag ${TAG} matches the version"
        ;;

    at)
        [[ $# -eq 2 ]] || err "usage: $0 at COMMIT X.Y.Z"
        COMMIT="$1"
        WANT="$2"
        TOML="$(git show "${COMMIT}:${VERSION_FILE}")" || err "no ${VERSION_FILE} at ${COMMIT}"
        LOCK=''
        if [[ -n "${CARGO_LOCK}" ]]; then
            LOCK="$(git show "${COMMIT}:${CARGO_LOCK}")" || err "no ${CARGO_LOCK} at ${COMMIT}"
        fi
        ACTUAL="$(agree "${TOML}" "${LOCK}")"
        [[ "${ACTUAL}" == "${WANT}" ]] || err "${COMMIT} is at ${ACTUAL}, not ${WANT}"
        ;;

    *)
        err "unknown command ${COMMAND}; use get, set, check or at"
        ;;
esac
