#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# One-shot: initialize git, make the first commit, create the GitHub repo,
# and push. Run this from a normal macOS Terminal (NOT inside any sandbox) —
# it needs your GitHub credentials.
#
# Prereqs:
#   - gh CLI installed and authenticated:  brew install gh && gh auth login
#   - OR a Personal Access Token + manual `git remote add` (see bottom)
# -----------------------------------------------------------------------------
set -euo pipefail

REPO_DIR="${REPO_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
REPO_NAME="${REPO_NAME:-pentagent}"
VISIBILITY="${VISIBILITY:-public}"   # public | private

cd "$REPO_DIR"
echo "Working in: $REPO_DIR"

# Remove any half-initialized .git from a previous failed run inside a cloud
# sync folder (OneDrive, iCloud) — those can leave an index.lock Linux can't
# unlink. In Finder/Terminal you can force-delete it with sudo if needed.
if [[ -d .git ]]; then
  echo "Found existing .git — delete it? [y/N]"
  read -r ans
  if [[ "$ans" == "y" || "$ans" == "Y" ]]; then
    rm -rf .git
  fi
fi

# 1. init
git init -q -b main
git config user.name  "${GIT_USER_NAME:-$(git config --global user.name  || echo 'Tristan Vaquero')}"
git config user.email "${GIT_USER_EMAIL:-$(git config --global user.email || echo 'tristanvaquero@gmail.com')}"

# 2. sanity check: what's about to be committed?
echo ""
echo "=== files that WILL be committed ==="
git add -A
git diff --cached --stat | tail -n +1
echo ""
echo "=== sanity check: engagement files MUST be ignored ==="
for f in \
    config/scope.underarmour.yaml \
    config/scope.juiceshop.yaml \
    config/config.ollama.yaml \
    runs/ \
    .venv/ ; do
  if git ls-files --error-unmatch "$f" >/dev/null 2>&1; then
    echo "  !! LEAKED: $f  (aborting)"
    exit 1
  else
    echo "  ok ignored: $f"
  fi
done

# 3. commit
git commit -q -m "Initial commit: pentagent — AI-assisted authorized pentesting agent

Hybrid heuristic + LLM planner, SQLite knowledge graph, hash-chained audit
log, ScopeGuard, and wrappers for nmap/httpx/subfinder/amass/ffuf/gobuster/
nuclei/sqlmap/nikto/katana. Typer CLI with fast/standard/deep profiles.
Multi-model LLM support (Anthropic / OpenAI / Ollama-compatible local).

Authorized use only. See README.md Ethics & legal section."

echo ""
echo "=== local commit OK ==="
git log --oneline -1

# 4. push via gh (preferred)
if command -v gh >/dev/null 2>&1; then
  echo ""
  echo "Creating $VISIBILITY GitHub repo '$REPO_NAME' via gh CLI..."
  gh repo create "$REPO_NAME" \
      --"$VISIBILITY" \
      --source . \
      --push \
      --description "AI-assisted penetration testing agent for authorized offensive security work. Hybrid heuristic+LLM planner, typed knowledge graph, hash-chained audit log." \
      --disable-wiki
  echo ""
  echo "✓ Pushed. Visit: $(gh repo view --json url -q .url)"
else
  cat <<'MSG'

gh CLI not found. Finish manually:

  1. Create the repo on GitHub: https://github.com/new
     - name: pentagent
     - visibility: public
     - DO NOT add a README/LICENSE/gitignore (this repo already has them)

  2. Add remote and push:
     git remote add origin https://github.com/<your-username>/pentagent.git
     git push -u origin main

If git push prompts for a password, use a Personal Access Token:
  https://github.com/settings/tokens  (classic, "repo" scope)
MSG
fi
