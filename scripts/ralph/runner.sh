#!/usr/bin/env bash
# Ralph Loop runner — Rust edition
# Reads user stories with passes:false, implements them via Claude Code agents,
# marks them passes:true, loops until all stories pass.
set -euo pipefail

STORIES_DIR="$(cd "$(dirname "$0")/../../docs/user-stories" && pwd)"
MAX_ITERATIONS="${MAX_ITERATIONS:-50}"
ITERATION=0

# Find all story files with passes:false
find_pending() {
    find "$STORIES_DIR" -name "*.json" | while read -r f; do
        if python3 -c "
import json, sys
stories = json.load(open('$f'))
if any(not s.get('passes', True) for s in stories):
    print('$f')
" 2>/dev/null; then :; fi
    done
}

BASELINE_PROMPT="$(cat <<'EOF'
You are implementing features for the chat4n6 Rust forensic tool.
Read agents.md for coding guidelines.
Read docs/user-stories/ for stories with passes:false.
For each story:
  1. Write failing tests (RED commit: git -c commit.gpgsign=false commit)
  2. Implement to make them pass (GREEN commit)
  3. Set "passes": true in the story JSON and commit that too
  4. Move to the next story
Run cargo test -p <crate> to verify each step.
When all stories in your batch pass, output: FINISHED
EOF
)"

while true; do
    PENDING=$(find_pending)
    if [ -z "$PENDING" ]; then
        echo "[ralph] All stories pass. Loop complete."
        exit 0
    fi

    ITERATION=$((ITERATION + 1))
    if [ "$ITERATION" -gt "$MAX_ITERATIONS" ]; then
        echo "[ralph] Max iterations ($MAX_ITERATIONS) reached. Stories remaining:"
        echo "$PENDING"
        exit 1
    fi

    echo "[ralph] Iteration $ITERATION — pending stories:"
    echo "$PENDING" | sed 's|.*/docs/user-stories/||'
    echo ""

    # Pick the next pending story file
    NEXT_STORY=$(echo "$PENDING" | head -1)
    STORY_NAME=$(basename "$NEXT_STORY" .json)

    PROMPT="$BASELINE_PROMPT

Implement this story next: $NEXT_STORY

$(cat "$NEXT_STORY")"

    claude --permission-mode bypassPermissions --verbose \
        "$(printf '%s' "$PROMPT")"

    echo "[ralph] Iteration $ITERATION complete. Checking story status..."
done
