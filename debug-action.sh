#!/bin/bash

# Debug script to help diagnose comment update issues
echo "=== HanCover Action Debug Information ==="
echo "Date: $(date)"
echo "Branch: $(git branch --show-current)"
echo "Commit: $(git rev-parse HEAD)"
echo ""

echo "=== Environment Variables ==="
echo "GITHUB_EVENT_NAME: $GITHUB_EVENT_NAME"
echo "GITHUB_REF: $GITHUB_REF"
echo "GITHUB_SHA: $GITHUB_SHA"
echo "GITHUB_REPOSITORY: $GITHUB_REPOSITORY"
echo ""

if [ -n "$GITHUB_EVENT_PATH" ] && [ -f "$GITHUB_EVENT_PATH" ]; then
    echo "=== GitHub Event Payload ==="
    echo "Event path: $GITHUB_EVENT_PATH"
    echo "Pull request number:"
    cat "$GITHUB_EVENT_PATH" | jq -r '.pull_request.number // "Not a PR"'
    echo "Action:"
    cat "$GITHUB_EVENT_PATH" | jq -r '.action // "N/A"'
    echo ""
fi

echo "=== Coverage Files ==="
ls -la coverage/ 2>/dev/null || echo "No coverage directory found"
echo ""

echo "=== Running HanCover Action ==="
INPUT_FILES="coverage/lcov.info" \
INPUT_WARN_ONLY="true" \
INPUT_COMMENT_MODE="update" \
GITHUB_TOKEN="${GITHUB_TOKEN:-$INPUT_GITHUB_TOKEN}" \
node dist/index.js

echo ""
echo "=== Debug Complete ==="
