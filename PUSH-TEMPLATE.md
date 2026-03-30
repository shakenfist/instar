Thanks for your work on this. I appreciate it. Some final checks
before I push:

## Code quality

 * Did the changes introduce any significant amount of duplicated
   code? Are there any missed opportunities for code reuse or
   refactoring?
 * Should any new code be extracted into a shared crate in
   `src/crates/`? Look for logic that a second guest operation
   would likely need (e.g. format parsing, I/O helpers, memory
   layout constants).
 * Are there any TODO comments we should address as part of this
   work?
 * Please ensure all source code is wrapped at 120 characters.
 * Do not write large scripts (more than five or so lines) in CI
   workflow steps. Write them to a shell script in `tools/` and
   call them from there. Note that this might sometimes require
   copying the script to the target node.
 * Please confirm that any potentially mis-usable scripting and
   images, such as adversarial images and CVE reproductions, are
   in the `shakenfist/imago-testdata` repository, not the
   `shakenfist/imago` repository.

## Tests

 * Is there unit and functional test coverage for the changes?
   This should include normal and adversarial cases.
 * Are we sure that all Rust and Python tests are run by both the
   pre-commit hooks and CI? We've had historical problems with
   missing the guest operation Rust code, for example.
 * All tests should pass. We need to fix any failing tests now
   before we push.
 * What tests are skipped? Could we reduce that number?
 * Run `make lint` (or `./scripts/check-rust.sh check`) and
   confirm clean output.
 * Run `pre-commit run --all-files` and confirm all hooks pass.
 * Are there any changes in `shakenfist/imago-testdata` that we
   need to commit?

## Documentation

 * Has `docs/` been updated? It is very important that the
   documentation be accurate and complete.
 * Specifically, has the commentary in `docs/commentary/` been
   reviewed against this change? If architectural decisions or
   data flow have changed, update the relevant commentary
   document.
 * Has `ARCHITECTURE.md` been updated if this change adds or
   modifies a guest operation, shared crate, or VMM component?
 * Has `README.md` been updated if build instructions, project
   structure, or setup steps have changed?
 * There is also a change log at `CHANGELOG.md`. Should any of
   the changes in this branch be included in that change log?
 * Is all deferred work and pre-existing errors listed in a plan
   file?
 * Has the phase plan status been updated in the master plan's
   Execution table?
 * Has all deferred work from both the phase plans and the master
   plan also been reflected in the relevant plan file's known
   gaps section? We likely won't refer to the phase plan again,
   so we need to make sure these are centrally tracked.

## Security review

 * Review these changes as both a security reviewer and an
   experienced developer and correct any errors you find.

## Build verification

 * Does `make imago` build successfully?
 * Does `make check-binary-sizes` pass? Guest binaries must fit
   within the 384KB memory region.
 * If `.devcontainer/` was modified, does the devcontainer still
   build?
