#!/bin/bash
set -euo pipefail

group=$1
shift
if git diff --quiet -- "$@"; then
    echo "$group pins are current."
    exit 0
fi
fingerprint=$(git diff -- "$@" | sha256sum | cut -c1-12)
branch="pins-$group-$fingerprint"
if [ "$(gh pr list --head "$branch" --state all --json number --jq length)" -gt 0 ]; then
    echo "PR for these $group pins already exists."
    exit 0
fi
body=$(mktemp)
trap 'rm -f "$body"' EXIT
{
    echo "Update $group pins from upstream release metadata."
    echo
    echo '```diff'
    git diff --stat -- "$@"
    echo '```'
} > "$body"
git config user.name 'github-actions[bot]'
git config user.email 'github-actions[bot]@users.noreply.github.com'
git checkout -b "$branch"
git add -- "$@"
git commit -m "build: update $group pins"
git push -u origin "$branch"
gh pr create --base "$BASE_BRANCH" --head "$branch" --title "build: update $group pins" --body-file "$body"
# GITHUB_TOKEN PRs do not trigger pull_request workflows.
gh workflow run build.yml --ref "$branch"
