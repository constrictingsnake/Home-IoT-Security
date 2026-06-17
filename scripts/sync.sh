#!/usr/bin/env bash
# Push the repo to GitHub AND mirror it to the Google Drive folder in one shot.
#
# Uses your LOCAL rclone OAuth remote (set up via `rclone config`), so Drive writes are
# owned by you — no service-account quota problem, no GitHub secret needed.
#
# Run from anywhere:  bash scripts/sync.sh
# Prereqs: an rclone remote named below (rclone config), and a clean `git push` (commit first).

set -euo pipefail
cd "$(dirname "$0")/.."

REMOTE="gdrive"                                   # your rclone remote name (from `rclone config`)
FOLDER_ID="12WLdXfSyNmUPaC8cifqxsBH0bIuOprUJ"     # target Drive folder ID (not secret)

# --- preflight: make sure the rclone remote exists ---
if ! rclone listremotes 2>/dev/null | grep -qx "${REMOTE}:"; then
  echo "ERROR: rclone remote '${REMOTE}:' not found. Run 'rclone config' (see CLAUDE.md)." >&2
  exit 1
fi

# --- 1) GitHub ---
echo "==> git push origin $(git branch --show-current)"
git push origin HEAD

# --- 2) Google Drive ---
# copy (not sync) so it never DELETES from Drive. NEVER upload secrets or git internals:
echo "==> rclone copy -> Drive folder ${FOLDER_ID}"
rclone copy ./ "${REMOTE}:" \
  --drive-root-folder-id "$FOLDER_ID" \
  --exclude "/.git/**" \
  --exclude "/.env" \
  --exclude "*.key" \
  --exclude "__pycache__/**" --exclude "*.pyc" \
  --exclude "/.venv/**" --exclude "/venv/**" --exclude "/env/**" \
  --exclude "/.claude/**" \
  --exclude ".DS_Store" \
  --exclude "*.log" \
  --fast-list -v

echo "==> done — pushed to GitHub and mirrored to Drive."
