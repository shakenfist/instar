#!/bin/bash

# Address automated review comments on a PR using Claude Code.
#
# This script reads structured review JSON (from the automated reviewer) and
# uses Claude Code to address each actionable item individually.
# Each valid fix gets its own commit.
#
# The review JSON can be:
# 1. Provided directly via --review-json FILE
# 2. Extracted automatically from the PR's review comments (embedded in a
#    <details> section by the automated reviewer)
#
# Usage:
#   tools/address-comments-with-claude.sh [options]
#
# Options:
#   --pr NUMBER         PR number to address (required in CI, auto-detected
#                       locally)
#   --review-json FILE  Path to review.json (optional, extracted from PR if
#                       not provided)
#   --max-turns N       Maximum Claude turns per item (default: 30)
#   --ci                CI mode: output machine-readable status, no colors
#   --dry-run           Don't make commits, just show what would be done
#   --output-dir DIR    Directory for output files (default: temp dir)
#   --help              Show this help message
#
# Environment:
#   GITHUB_TOKEN        Required for fetching reviews and posting comments
#   GITHUB_REPOSITORY   Repository in owner/repo format (set by GitHub Actions)
#
# Exit codes:
#   0 - Comments addressed successfully
#   1 - Error occurred
#
# Examples:
#   # Address comments (extracts JSON from PR review comment automatically)
#   tools/address-comments-with-claude.sh --pr 123
#
#   # Address comments using explicit review JSON file
#   tools/address-comments-with-claude.sh --pr 123 --review-json review.json
#
#   # Dry run to see what would be done
#   tools/address-comments-with-claude.sh --pr 123 --dry-run

set -e

# Support running from a different directory than where the tools are located.
# This is used in CI where we checkout trusted tools from the base branch
# separately from the PR code.
#
# Environment:
#   TOOLS_DIR   - Directory containing the trusted tools (render-review.py, etc.)
#                 If not set, defaults to the directory containing this script.
#   WORK_DIR    - Directory to operate in (where the code to modify is).
#                 If not set, defaults to the parent of the tools directory.

script_dir=$(cd "$(dirname "$0")" && pwd)
tools_dir="${TOOLS_DIR:-${script_dir}}"
work_dir="${WORK_DIR:-$(cd "${script_dir}/.." && pwd)}"

cd "${work_dir}"

# The staging helper anchors itself at the top level and the index
# check below is repo-wide whatever the cwd, so the per-item git calls
# have to agree with them rather than with ${work_dir}.
repo_top=$(git rev-parse --show-toplevel 2>/dev/null || echo "${work_dir}")

# Default options
pr_number=""
review_json=""
max_turns=30
ci_mode=false
dry_run=false
output_dir=""

# Colors for output (disabled in CI mode)
setup_colors() {
    if [ "${ci_mode}" = true ]; then
        RED=''
        GREEN=''
        YELLOW=''
        BLUE=''
        CYAN=''
        NC=''
    else
        RED='\033[0;31m'
        GREEN='\033[0;32m'
        YELLOW='\033[1;33m'
        BLUE='\033[0;34m'
        CYAN='\033[0;36m'
        NC='\033[0m'
    fi
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --pr)
            pr_number="$2"
            shift 2
            ;;
        --review-json)
            review_json="$2"
            shift 2
            ;;
        --max-turns)
            max_turns="$2"
            shift 2
            ;;
        --ci)
            ci_mode=true
            shift
            ;;
        --dry-run)
            dry_run=true
            shift
            ;;
        --output-dir)
            output_dir="$2"
            shift 2
            ;;
        --help|-h)
            head -42 "$0" | tail -39
            exit 0
            ;;
        -*)
            echo "Unknown option: $1"
            exit 1
            ;;
        *)
            shift
            ;;
    esac
done

setup_colors

# Sanitize user-controlled input for safe use in commit messages and logs
# - Removes control characters
# - Limits length
# - Replaces problematic characters
sanitize_input() {
    local input="$1"
    local max_length="${2:-200}"

    # Remove control characters (except newline for descriptions)
    # Replace backticks and dollar signs to prevent command substitution
    local sanitized
    sanitized=$(printf '%s' "${input}" | \
        tr -d '\000-\010\013\014\016-\037' | \
        sed 's/`/'"'"'/g; s/\$/S/g')

    # Truncate to max length
    if [ "${#sanitized}" -gt "${max_length}" ]; then
        sanitized="${sanitized:0:${max_length}}..."
    fi

    printf '%s' "${sanitized}"
}

# Sanitize for use in commit message first line (stricter: single line, short)
sanitize_commit_subject() {
    local input="$1"
    # Remove newlines, limit to 50 chars for subject line
    printf '%s' "${input}" | tr -d '\n\r' | \
        sed 's/`/'"'"'/g; s/\$/S/g' | cut -c1-50
}

# Validate --max-turns is a positive integer
if ! [[ "${max_turns}" =~ ^[0-9]+$ ]] || [ "${max_turns}" -lt 1 ]; then
    echo -e "${RED}Error: --max-turns must be a positive integer${NC}"
    exit 1
fi

# Create output directory
if [ -z "${output_dir}" ]; then
    output_dir=$(mktemp -d)
    cleanup_output=true
else
    mkdir -p "${output_dir}"
    cleanup_output=false
fi

cleanup() {
    if [ "${cleanup_output}" = true ]; then
        rm -rf "${output_dir}"
    fi
}
trap cleanup EXIT

# Abandon whatever the current item left behind, so the next item's
# commit contains only its own work. Every path that gives up on an
# item has to call this: without it, edits from an item Claude failed
# or disagreed with are staged by the next item and committed under
# that item's review id and rationale.
#
# The work is in tools/ci/reset-autofix-worktree.sh so it can be
# tested; see the header there for what it discards and what it keeps.
reset_worktree() {
    "${resetter}" "${work_dir}" || echo "Reset failed; the next item may inherit this one's edits"
}

# CI mode output helper
ci_output() {
    local key="$1"
    local value="$2"
    if [ "${ci_mode}" = true ]; then
        echo "${key}=${value}"
    fi
}

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Shaken Fist Review Comment Addresser${NC}"
echo -e "${BLUE}========================================${NC}"
echo

# Step 1: Validate environment
echo -e "${YELLOW}Step 1: Validating environment...${NC}"

if ! command -v gh &> /dev/null; then
    echo -e "${RED}Error: GitHub CLI (gh) not found${NC}"
    exit 1
fi

# Locate the claude binary. Honour CLAUDE_BIN if set, then look on PATH,
# then fall back to the default install location used by the official
# installer (~/.local/bin/claude is not always on PATH for non-login
# shells like the GitHub Actions runner).
if [ -n "${CLAUDE_BIN:-}" ]; then
    claude_bin="${CLAUDE_BIN}"
elif command -v claude &> /dev/null; then
    claude_bin="claude"
elif [ -x "${HOME}/.local/bin/claude" ]; then
    claude_bin="${HOME}/.local/bin/claude"
else
    claude_bin=""
fi
if [ -z "${claude_bin}" ] || \
        { ! command -v "${claude_bin}" &> /dev/null && \
          ! [ -x "${claude_bin}" ]; }; then
    echo -e "${RED}Error: Claude Code CLI not found (${claude_bin:-not set})${NC}"
    echo "Install with: npm install -g @anthropic-ai/claude-code"
    echo "Or set CLAUDE_BIN to the path of an existing install."
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo -e "${RED}Error: jq not found${NC}"
    exit 1
fi

# Checked up front rather than at the call sites: if the stager is
# missing, every item silently falls back to whatever Claude happened
# to stage, which is the defect this script was fixed for (#510); if
# the resetter is missing, an abandoned item's edits are committed
# under the next item's review id. Better to refuse to start than to
# reproduce either quietly.
stager="${tools_dir}/ci/stage-autofix-changes.sh"
resetter="${tools_dir}/ci/reset-autofix-worktree.sh"
for helper in "${stager}" "${resetter}"; do
    if [ ! -x "${helper}" ]; then
        echo -e "${RED}Error: helper not found or not executable: ${helper}${NC}"
        echo "TOOLS_DIR must point at a tools/ directory containing ci/."
        exit 1
    fi
done

# Get PR number if not provided
if [ -z "${pr_number}" ]; then
    # Try to get from GitHub Actions event
    if [ -n "${GITHUB_EVENT_PATH}" ] && [ -f "${GITHUB_EVENT_PATH}" ]; then
        pr_number=$(jq -r '.pull_request.number // .issue.number // empty' \
            "${GITHUB_EVENT_PATH}" 2>/dev/null || true)
    fi

    # Try to get from current branch
    if [ -z "${pr_number}" ]; then
        pr_number=$(gh pr view --json number -q '.number' 2>/dev/null || true)
    fi

    if [ -z "${pr_number}" ]; then
        echo -e "${RED}Error: Could not determine PR number${NC}"
        echo "Use --pr NUMBER to specify explicitly"
        exit 1
    fi
fi

echo -e "${GREEN}✓ Addressing comments on PR #${pr_number}${NC}"
echo

# Step 2: Get review JSON
echo -e "${YELLOW}Step 2: Loading review JSON...${NC}"

if [ -n "${review_json}" ]; then
    # Validate the provided path for security
    # Check it's a regular file (not a device, symlink to sensitive file, etc.)
    if [ ! -f "${review_json}" ]; then
        echo -e "${RED}Error: Review JSON file not found: ${review_json}${NC}"
        exit 1
    fi

    # Resolve to absolute path and check for path traversal attempts
    resolved_path=$(realpath "${review_json}" 2>/dev/null)
    if [ -z "${resolved_path}" ]; then
        echo -e "${RED}Error: Could not resolve path: ${review_json}${NC}"
        exit 1
    fi

    # Ensure it's a regular file (after symlink resolution)
    if [ ! -f "${resolved_path}" ]; then
        echo -e "${RED}Error: Path does not resolve to a file: ${review_json}${NC}"
        exit 1
    fi

    # Verify it looks like JSON (basic sanity check)
    if ! head -1 "${resolved_path}" | grep -q '^[[:space:]]*{'; then
        echo -e "${RED}Error: File does not appear to be JSON: ${review_json}${NC}"
        exit 1
    fi

    echo "Using provided review JSON: ${resolved_path}"
    cp "${resolved_path}" "${output_dir}/review.json"
else
    # Extract review JSON from the most recent automated review comment on
    # the PR
    echo "No review JSON provided, extracting from PR review comments..."

    repo="${GITHUB_REPOSITORY:-$(gh repo view --json nameWithOwner \
        -q '.nameWithOwner')}"

    # Find the most recent review comment from github-actions[bot] that
    # contains embedded JSON. The JSON is in a <details> section with a
    # ```json code block.
    jq_filter='[.[] | select(.user.login == "github-actions[bot]"'
    jq_filter+=' and (.body | contains("Machine-readable review data")))]'
    jq_filter+=' | last | .body'
    review_body=$(gh api "repos/${repo}/pulls/${pr_number}/reviews" \
        --jq "${jq_filter}" 2>/dev/null || true)

    if [ -z "${review_body}" ] || [ "${review_body}" == "null" ]; then
        err_msg="Error: Could not find automated review comment"
        err_msg+=" with embedded JSON"
        echo -e "${RED}${err_msg}${NC}"
        echo "Ensure the PR has been reviewed by the automated reviewer."
        exit 1
    fi

    # Extract JSON from between ```json and ``` markers within the
    # <details> section
    # shellcheck disable=SC2016  # Single quotes intentional - matching literal backticks
    echo "${review_body}" | sed -n '/<details>/,/<\/details>/p' | \
        sed -n '/^```json$/,/^```$/p' | \
        sed '1d;$d' > "${output_dir}/review.json"

    if [ ! -s "${output_dir}/review.json" ]; then
        echo -e "${RED}Error: Could not extract JSON from review comment${NC}"
        echo "The review comment may not have embedded JSON data."
        exit 1
    fi

    echo "Extracted review JSON from PR comment"
fi

# Validate the JSON
echo "Validating review JSON..."
validate_cmd="${tools_dir}/render-review.py"
if ! python3 "${validate_cmd}" --validate "${output_dir}/review.json"; then
    echo -e "${RED}Error: Invalid review JSON${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Review JSON is valid${NC}"
echo

# Step 3: Extract actionable items
echo -e "${YELLOW}Step 3: Extracting actionable items...${NC}"

# Extract items with action=fix or action=document
jq_filter='[.items[] | select(.action == "fix" or .action == "document")]'
actionable_items=$(jq -c "${jq_filter}" "${output_dir}/review.json")
item_count=$(echo "${actionable_items}" | jq 'length')

echo -e "${GREEN}Found ${item_count} actionable items${NC}"
ci_output "items_found" "${item_count}"
echo

if [ "${item_count}" -eq 0 ]; then
    msg="No actionable items (action=fix or action=document) in review"
    echo -e "${YELLOW}${msg}${NC}"
    exit 0
fi

# Save each item to a separate file for processing
for i in $(seq 0 $((item_count - 1))); do
    item_file="${output_dir}/item-$((i + 1)).json"
    echo "${actionable_items}" | jq ".[$i]" > "${item_file}"
    item_title=$(jq -r '.title' "${item_file}")
    item_action=$(jq -r '.action' "${item_file}")
    echo "  $((i + 1)). [${item_action}] ${item_title}"
done
echo

# Step 4: Address each item with Claude
echo -e "${YELLOW}Step 4: Addressing items with Claude Code...${NC}"
echo

# Initialize summary tracking
summary_file="${output_dir}/summary.md"
cat > "${summary_file}" << 'EOF'
## Review Comments Addressed

| # | Issue | Status | Commit | Notes |
|---|-------|--------|--------|-------|
EOF

addressed_count=0
skipped_count=0

for i in $(seq 1 "${item_count}"); do
    item_file="${output_dir}/item-${i}.json"

    # Extract and sanitize values from review JSON
    # These values come from the automated review which is derived from PR data
    item_id=$(jq -r '.id' "${item_file}")
    item_title_raw=$(jq -r '.title' "${item_file}")
    item_action=$(jq -r '.action' "${item_file}")
    item_category=$(jq -r '.category' "${item_file}")
    item_severity=$(jq -r '.severity // "N/A"' "${item_file}")
    item_description_raw=$(jq -r '.description // ""' "${item_file}")
    item_location=$(jq -r '.location // ""' "${item_file}")
    item_suggestion_raw=$(jq -r '.suggestion // ""' "${item_file}")

    # Sanitize user-controlled content
    item_title=$(sanitize_input "${item_title_raw}" 100)
    item_description=$(sanitize_input "${item_description_raw}" 500)
    item_suggestion=$(sanitize_input "${item_suggestion_raw}" 500)

    # Validate item_id is numeric
    if ! [[ "${item_id}" =~ ^[0-9]+$ ]]; then
        echo -e "${RED}Warning: Invalid item ID, skipping${NC}"
        continue
    fi

    # Validate action is one of the expected values
    if [[ ! "${item_action}" =~ ^(fix|document|consider|none)$ ]]; then
        echo -e "${RED}Warning: Invalid action '${item_action}', skipping${NC}"
        continue
    fi

    echo -e "${CYAN}----------------------------------------${NC}"
    item_header="Item ${i}/${item_count}: [${item_action}] ${item_title}"
    echo -e "${CYAN}${item_header}${NC}"
    echo "  Category: ${item_category}, Severity: ${item_severity}"
    if [ -n "${item_location}" ] && [ "${item_location}" != "null" ]; then
        echo "  Location: ${item_location}"
    fi
    echo

    if [ "${dry_run}" = true ]; then
        echo -e "${YELLOW}[DRY RUN] Would address this item with Claude${NC}"
        row="| ${item_id} | ${item_title} | ⏸️ Dry run | - | - |"
        echo "${row}" >> "${summary_file}"
        continue
    fi

    # Build Claude prompt for this specific item
    cat > "${output_dir}/claude-prompt-${i}.txt" << PROMPT_EOF
You are addressing a specific review comment on PR #${pr_number} for the Shaken Fist instar project.

## Context

First, read AGENTS.md and ARCHITECTURE.md to understand the project structure.

## The Review Item to Address

**Title**: ${item_title}
**Category**: ${item_category}
**Severity**: ${item_severity}
**Action Required**: ${item_action}
**Location**: ${item_location}

**Description**:
${item_description}

**Suggestion**:
${item_suggestion}

## Your Task

1. Analyze this specific review item
2. Determine if it's a valid issue that should be addressed
3. If valid:
   - Make the necessary code changes
   - Run \`pre-commit run --all-files\` to validate formatting
   - Do NOT stage and do NOT commit - CI stages the files you
     modify, delete or create, and makes the commit
   - Do NOT edit anything under \`.github/workflows/\`; a commit
     touching one cannot be pushed with the token CI holds, and the
     push at the end of the run would fail

4. If you disagree with the comment or it's not actionable:
   - Explain your rationale clearly
   - Do NOT make any changes

## CRITICAL OUTPUT FORMAT

You MUST end your response with exactly one of these markers:

If you made changes:
\`\`\`
CHANGE_SUMMARY_START
<One-line summary of what you changed, max 50 chars, imperative mood>
CHANGE_SUMMARY_END
\`\`\`

If you disagree or the item is not actionable:
\`\`\`
DISAGREEMENT_START
<Your rationale for why this should not be changed>
DISAGREEMENT_END
\`\`\`

## Rules

- Focus ONLY on this specific item - do not address other issues
- Do NOT run cargo commands directly - use \`make instar\`, \`make test\`, \`make lint\`
- Keep changes minimal and focused
- If the fix requires changes you're unsure about, explain and skip
PROMPT_EOF

    # Run Claude for this item
    echo "Running Claude Code..."
    claude_output_file="${output_dir}/claude-output-${i}.txt"

    if ! "${claude_bin}" -p "$(cat "${output_dir}/claude-prompt-${i}.txt")" \
        --dangerously-skip-permissions \
        --max-turns "${max_turns}" \
        --output-format text > "${claude_output_file}" 2>&1; then
        echo -e "${RED}Claude failed for item ${i}${NC}"
        row="| ${item_id} | ${item_title} | ❌ Error | - |"
        row+=" Claude execution failed |"
        echo "${row}" >> "${summary_file}"
        skipped_count=$((skipped_count + 1))
        reset_worktree
        continue
    fi

    # Stage what Claude changed, before the index is read below. Claude
    # Code edits the working tree and does not reliably stage, so an
    # unstaged fix used to reach the `git diff --cached` test empty and
    # be recorded as "No changes needed" -- the same defect that stopped
    # the fuzz autofix workflow opening a single PR in four months
    # (issue #510).
    #
    # --tracked-only, not the full check: that mode refuses an attempt
    # that created a file, which is right for an unattended fuzz fix and
    # wrong here, where a review item can legitimately ask for a new
    # file and the result lands on a pull request a human reads. New
    # files stay Claude's job, which is why the prompt still asks for
    # them explicitly. The mode does keep .github/workflows/ out of the
    # index, because a commit touching one cannot be pushed with the
    # token this workflow holds -- and that failure would land at the
    # push, discarding every other item's commit with it.
    #
    # Run from ${tools_dir} so this is the trusted copy checked out from
    # the base branch, not the PR's own.
    #
    # A failure here is an item-level error, not a warning. In
    # --tracked-only mode the stager exits non-zero only on a usage
    # error or a REPO_DIR that is not a work tree, under which nothing
    # is staged at all -- so continuing would reach the empty-index
    # branch and report "modified no file", which is the #510 misreport
    # again by another route.
    if ! "${stager}" --tracked-only "${work_dir}"; then
        echo -e "${RED}Staging failed for item ${i}${NC}"
        row="| ${item_id} | ${item_title} | ❌ Error | - |"
        row+=" Staging failed |"
        echo "${row}" >> "${summary_file}"
        skipped_count=$((skipped_count + 1))
        reset_worktree
        continue
    fi

    # Notes appended to this item's summary row, for things a
    # maintainer reading the PR comment has to know but that do not
    # change the outcome.
    row_notes=""

    # --tracked-only stages tracked edits and nothing else, so a file
    # Claude created is invisible to it. Left untracked, that file
    # would be missing from a commit that references it, behind a row
    # saying "Fixed" -- #510 again, narrowed to new files.
    #
    # This is where the two autofix paths diverge. The fuzz autofix
    # refuses an attempt that created a file, because a wrong guess
    # there ships an unreviewed branch; here a review item can
    # legitimately ask for a new file, and the result lands on a pull
    # request a human reads before it goes anywhere. Opting out of the
    # refusal is not a reason to opt out of the detection, so the files
    # are staged and named rather than silently dropped.
    #
    # Editor and merge leftovers are skipped, matching ARTIFACT_NAMES
    # in the stager: `pre-commit run --all-files` is in the prompt and
    # its hooks produce these routinely. Anything under
    # .github/workflows/ is skipped too -- the stager has just
    # unstaged the tracked ones, and adding an untracked one back
    # would break the push for every other item's commit.
    new_files=()
    while IFS= read -r -d '' f; do
        case "${f}" in
            .github/workflows/*) continue ;;
        esac
        if [[ "${f}" =~ (^|/)(\.#[^/]*|[^/]*~|[^/]*\.(orig|rej|bak|tmp|swp|swo))$ ]]; then
            continue
        fi
        new_files+=("${f}")
    done < <(git -C "${repo_top}" ls-files --others --exclude-standard -z)

    if [ ${#new_files[@]} -gt 0 ]; then
        echo -e "${YELLOW}Claude created files it did not stage:${NC}"
        printf '    %s\n' "${new_files[@]}"
        git -C "${repo_top}" add -- "${new_files[@]}"
        row_notes+=" Also staged new file(s) Claude left untracked:"
        row_notes+=" $(printf '%s, ' "${new_files[@]}" | sed 's/, $//')."
    fi

    # Read before the index check below, so the empty-index branch can
    # tell "Claude changed nothing" from "Claude changed only a
    # workflow file and CI just threw it away". Both untracked and
    # modified, because `git diff HEAD` cannot see a file that was
    # created.
    workflow_edits=$(
        {
            git -C "${repo_top}" diff HEAD --name-only -- '.github/workflows/'
            git -C "${repo_top}" ls-files --others --exclude-standard \
                -- '.github/workflows/'
        } | LC_ALL=C sort -u | tr '\n' ' ' | sed 's/ $//'
    )
    if [ -n "${workflow_edits}" ]; then
        echo -e "${YELLOW}Discarding .github/workflows/ edit(s): ${workflow_edits}${NC}"
        row_notes+=" Discarded .github/workflows/ edit(s) that cannot be"
        row_notes+=" pushed with the CI token: ${workflow_edits}."
    fi

    # The rows below are markdown table cells.
    row_notes="${row_notes//|/\\|}"

    # Check for disagreement
    if grep -q "DISAGREEMENT_START" "${claude_output_file}"; then
        rationale=$(sed -n '/DISAGREEMENT_START/,/DISAGREEMENT_END/p' \
            "${claude_output_file}" | grep -v "DISAGREEMENT" | grep -v '```')

        echo -e "${YELLOW}Claude disagreed with this item${NC}"
        echo "Rationale: ${rationale}"

        # Escape for markdown table
        rationale_escaped=$(echo "${rationale}" | tr '\n' ' ' | sed 's/|/\\|/g')
        row="| ${item_id} | ${item_title} | ⏭️ Skipped | - |"
        row+=" ${rationale_escaped} |"
        echo "${row}" >> "${summary_file}"
        skipped_count=$((skipped_count + 1))
        reset_worktree
        continue
    fi

    # Check for change summary
    if grep -q "CHANGE_SUMMARY_START" "${claude_output_file}"; then
        change_summary_raw=$(sed -n '/CHANGE_SUMMARY_START/,/CHANGE_SUMMARY_END/p' \
            "${claude_output_file}" | grep -v "CHANGE_SUMMARY" | grep -v '```' | \
            head -1 | xargs)
        # Sanitize the change summary for use in commit message subject
        change_summary=$(sanitize_commit_subject "${change_summary_raw}")

        # Check if there are actually staged changes
        # With CI staging on Claude's behalf, an empty index means it
        # modified no tracked file and staged no new one -- not that it
        # forgot to stage.
        if [ -z "$(git diff --cached --name-only)" ]; then
            # "Modified no file" is wrong when the whole fix was a
            # workflow edit: Claude did modify a file, and CI discarded
            # it a moment ago because a commit touching
            # .github/workflows/ cannot be pushed with this workflow's
            # token. That needs a maintainer to apply it by hand, which
            # is a different response to "Claude did nothing", and the
            # reset below is about to destroy the evidence.
            if [ -n "${workflow_edits}" ]; then
                echo -e "${YELLOW}Item edited .github/workflows/ only; not pushable${NC}"
                row="| ${item_id} | ${item_title} | ⚠️ Not pushable | - |"
                row+=" Edited \`${workflow_edits}\` only; a commit touching"
                row+=" .github/workflows/ cannot be pushed with the CI token,"
                row+=" so this needs applying by hand |"
            else
                echo -e "${YELLOW}Claude reported a change but modified no file${NC}"
                row="| ${item_id} | ${item_title} | ⏭️ Skipped | - |"
                row+=" Reported a change but modified no file |"
            fi
            echo "${row}" >> "${summary_file}"
            skipped_count=$((skipped_count + 1))
            reset_worktree
            continue
        fi

        echo -e "${GREEN}Changes staged, creating commit...${NC}"
        echo "Summary: ${change_summary}"

        # Create the commit message in a temp file for safer handling
        # Using printf with %s avoids shell expansion issues
        commit_msg_file="${output_dir}/commit-msg-${i}.txt"
        {
            printf '%s.\n\n' "${change_summary}"
            printf 'Addresses review item %s: %s\n\n' "${item_id}" "${item_title}"
            printf 'Category: %s\n' "${item_category}"
            printf 'Severity: %s\n\n' "${item_severity}"
            printf 'Prompt: @shakenfist-bot please address comments on PR #%s\n\n' \
                "${pr_number}"
            printf 'Signed-off-by: Michael Still <mikal@stillhq.com>\n'
            printf 'Assisted-By: Claude Code\n'
            printf 'Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>\n'
        } > "${commit_msg_file}"

        git commit -F "${commit_msg_file}"
        commit_sha=$(git rev-parse --short HEAD)

        echo -e "${GREEN}Created commit: ${commit_sha}${NC}"
        row="| ${item_id} | ${item_title} | ✅ Fixed |"
        row+=" \`${commit_sha}\` | ${change_summary}${row_notes} |"
        echo "${row}" >> "${summary_file}"
        addressed_count=$((addressed_count + 1))
    else
        echo -e "${YELLOW}No clear outcome from Claude${NC}"
        row="| ${item_id} | ${item_title} | ⚠️ Unclear | - |"
        row+=" No summary marker found |"
        echo "${row}" >> "${summary_file}"
        skipped_count=$((skipped_count + 1))
        reset_worktree
    fi

    echo
done

echo -e "${CYAN}----------------------------------------${NC}"
echo

# Step 5: Summary
echo -e "${YELLOW}Step 5: Summary${NC}"
echo
echo -e "${GREEN}Addressed: ${addressed_count}${NC}"
echo -e "${YELLOW}Skipped: ${skipped_count}${NC}"
echo

ci_output "items_addressed" "${addressed_count}"
ci_output "items_skipped" "${skipped_count}"

# Display summary table
echo "Summary of changes:"
cat "${summary_file}"
echo

# Output summary file path for CI to use
echo "${summary_file}"
