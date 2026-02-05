#!/bin/bash

# Address automated review comments on a PR using Claude Code.
#
# This script reads structured review JSON (from the automated reviewer) and
# uses Claude Code to address each actionable item individually.
# Each valid fix gets its own commit.
#
# Usage:
#   tools/address-comments-with-claude.sh [options]
#
# Options:
#   --pr NUMBER         PR number to address (required in CI, auto-detected locally)
#   --review-json FILE  Path to review.json (downloaded from artifacts in CI)
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
#   # Address comments using review JSON from artifact
#   tools/address-comments-with-claude.sh --pr 123 --review-json review.json
#
#   # CI mode (review JSON provided by workflow)
#   tools/address-comments-with-claude.sh --ci --pr 123 --review-json review.json
#
#   # Dry run to see what would be done
#   tools/address-comments-with-claude.sh --pr 123 --review-json review.json --dry-run

set -e

topdir=$(cd "$(dirname "$0")/.." && pwd)
cd "${topdir}"

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

if ! command -v claude &> /dev/null; then
    echo -e "${RED}Error: Claude Code CLI not found${NC}"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo -e "${RED}Error: jq not found${NC}"
    exit 1
fi

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

if [ -n "${review_json}" ] && [ -f "${review_json}" ]; then
    echo "Using provided review JSON: ${review_json}"
    cp "${review_json}" "${output_dir}/review.json"
else
    # Try to download from the most recent automated review workflow artifacts
    echo "No review JSON provided, attempting to download from GitHub artifacts..."

    # Find the most recent successful review workflow run for this PR
    run_id=$(gh api "repos/${GITHUB_REPOSITORY:-$(gh repo view --json nameWithOwner -q '.nameWithOwner')}/actions/workflows/sanity-checks.yml/runs" \
        --jq "[.workflow_runs[] | select(.head_sha == \"$(gh pr view ${pr_number} --json headRefOid -q '.headRefOid')\" and .conclusion == \"success\")] | .[0].id" \
        2>/dev/null || true)

    if [ -n "${run_id}" ] && [ "${run_id}" != "null" ]; then
        echo "Found workflow run: ${run_id}"
        # Download artifact
        gh run download "${run_id}" -n "review-json-${pr_number}" -D "${output_dir}/artifact" 2>/dev/null || true

        if [ -f "${output_dir}/artifact/review.json" ]; then
            mv "${output_dir}/artifact/review.json" "${output_dir}/review.json"
            echo "Downloaded review.json from artifacts"
        fi
    fi

    if [ ! -f "${output_dir}/review.json" ]; then
        echo -e "${RED}Error: Could not find review JSON${NC}"
        echo "Provide --review-json FILE or ensure the review workflow uploaded an artifact"
        exit 1
    fi
fi

# Validate the JSON
echo "Validating review JSON..."
if ! python3 "${topdir}/tools/render-review.py" --validate "${output_dir}/review.json"; then
    echo -e "${RED}Error: Invalid review JSON${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Review JSON is valid${NC}"
echo

# Step 3: Extract actionable items
echo -e "${YELLOW}Step 3: Extracting actionable items...${NC}"

# Extract items with action=fix or action=document
actionable_items=$(jq -c '[.items[] | select(.action == "fix" or .action == "document")]' \
    "${output_dir}/review.json")
item_count=$(echo "${actionable_items}" | jq 'length')

echo -e "${GREEN}Found ${item_count} actionable items${NC}"
ci_output "items_found" "${item_count}"
echo

if [ "${item_count}" -eq 0 ]; then
    echo -e "${YELLOW}No actionable items (action=fix or action=document) in review${NC}"
    exit 0
fi

# Save each item to a separate file for processing
for i in $(seq 0 $((item_count - 1))); do
    echo "${actionable_items}" | jq ".[$i]" > "${output_dir}/item-$((i + 1)).json"
    item_title=$(jq -r '.title' "${output_dir}/item-$((i + 1)).json")
    item_action=$(jq -r '.action' "${output_dir}/item-$((i + 1)).json")
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
    item_id=$(jq -r '.id' "${item_file}")
    item_title=$(jq -r '.title' "${item_file}")
    item_action=$(jq -r '.action' "${item_file}")
    item_category=$(jq -r '.category' "${item_file}")
    item_severity=$(jq -r '.severity // "N/A"' "${item_file}")
    item_description=$(jq -r '.description // ""' "${item_file}")
    item_location=$(jq -r '.location // ""' "${item_file}")
    item_suggestion=$(jq -r '.suggestion // ""' "${item_file}")

    echo -e "${CYAN}----------------------------------------${NC}"
    echo -e "${CYAN}Item ${i}/${item_count}: [${item_action}] ${item_title}${NC}"
    echo "  Category: ${item_category}, Severity: ${item_severity}"
    if [ -n "${item_location}" ] && [ "${item_location}" != "null" ]; then
        echo "  Location: ${item_location}"
    fi
    echo

    if [ "${dry_run}" = true ]; then
        echo -e "${YELLOW}[DRY RUN] Would address this item with Claude${NC}"
        echo "| ${item_id} | ${item_title} | ⏸️ Dry run | - | - |" >> "${summary_file}"
        continue
    fi

    # Build Claude prompt for this specific item
    cat > "${output_dir}/claude-prompt-${i}.txt" << PROMPT_EOF
You are addressing a specific review comment on PR #${pr_number} for the Shaken Fist imago project.

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
   - Stage your changes with \`git add\`
   - Do NOT commit - I will handle the commit

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
- Do NOT run cargo commands directly - use \`make imago\`, \`make test\`, \`make lint\`
- Keep changes minimal and focused
- If the fix requires changes you're unsure about, explain and skip
PROMPT_EOF

    # Run Claude for this item
    echo "Running Claude Code..."
    claude_output_file="${output_dir}/claude-output-${i}.txt"

    if ! claude -p "$(cat "${output_dir}/claude-prompt-${i}.txt")" \
        --dangerously-skip-permissions \
        --max-turns "${max_turns}" \
        --output-format text > "${claude_output_file}" 2>&1; then
        echo -e "${RED}Claude failed for item ${i}${NC}"
        echo "| ${item_id} | ${item_title} | ❌ Error | - | Claude execution failed |" >> "${summary_file}"
        ((skipped_count++))
        continue
    fi

    # Check for disagreement
    if grep -q "DISAGREEMENT_START" "${claude_output_file}"; then
        rationale=$(sed -n '/DISAGREEMENT_START/,/DISAGREEMENT_END/p' \
            "${claude_output_file}" | grep -v "DISAGREEMENT" | grep -v '```')

        echo -e "${YELLOW}Claude disagreed with this item${NC}"
        echo "Rationale: ${rationale}"

        # Escape for markdown table
        rationale_escaped=$(echo "${rationale}" | tr '\n' ' ' | sed 's/|/\\|/g')
        echo "| ${item_id} | ${item_title} | ⏭️ Skipped | - | ${rationale_escaped} |" >> "${summary_file}"
        ((skipped_count++))
        continue
    fi

    # Check for change summary
    if grep -q "CHANGE_SUMMARY_START" "${claude_output_file}"; then
        change_summary=$(sed -n '/CHANGE_SUMMARY_START/,/CHANGE_SUMMARY_END/p' \
            "${claude_output_file}" | grep -v "CHANGE_SUMMARY" | grep -v '```' | \
            head -1 | xargs)

        # Check if there are actually staged changes
        if [ -z "$(git diff --cached --name-only)" ]; then
            echo -e "${YELLOW}No changes were staged${NC}"
            echo "| ${item_id} | ${item_title} | ⏭️ Skipped | - | No changes needed |" >> "${summary_file}"
            ((skipped_count++))
            continue
        fi

        echo -e "${GREEN}Changes staged, creating commit...${NC}"
        echo "Summary: ${change_summary}"

        # Create the commit
        commit_msg=$(cat << COMMIT_EOF
${change_summary}.

Addresses review item #${item_id}: ${item_title}

Category: ${item_category}
Severity: ${item_severity}

Prompt: @shakenfist-bot please address comments on PR #${pr_number}

Signed-off-by: Michael Still <mikal@stillhq.com>
Assisted-By: Claude Code
Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
COMMIT_EOF
)

        git commit -m "${commit_msg}"
        commit_sha=$(git rev-parse --short HEAD)

        echo -e "${GREEN}Created commit: ${commit_sha}${NC}"
        echo "| ${item_id} | ${item_title} | ✅ Fixed | \`${commit_sha}\` | ${change_summary} |" >> "${summary_file}"
        ((addressed_count++))
    else
        echo -e "${YELLOW}No clear outcome from Claude${NC}"
        echo "| ${item_id} | ${item_title} | ⚠️ Unclear | - | No summary marker found |" >> "${summary_file}"
        ((skipped_count++))

        # Reset any unstaged changes
        git checkout -- . 2>/dev/null || true
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
