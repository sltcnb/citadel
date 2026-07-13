#!/usr/bin/env bash
# Citadel deploy-time tool fetcher.
#
# Reads tools/versions.yaml and clones / checks-out each tool repo at its PINNED
# ref into its path. Idempotent: clones when missing, fetches + checks out the
# pinned ref when present. By default skips tools marked `vendored: true` (they
# already live in-tree); pass --force to externalise/refresh them too.
#
#   scripts/fetch_tools.sh                 # fetch external (non-vendored) tools
#   scripts/fetch_tools.sh --force         # also (re)fetch vendored tools
#   scripts/fetch_tools.sh --print         # just show the resolved plan
#
# Designed to run in a CI/deploy step before `docker build` / `helm install`.
set -uo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
MANIFEST="$ROOT/tools/versions.yaml"

FORCE=0; PRINT=0
for a in "$@"; do
  case "$a" in
    --force) FORCE=1 ;;
    --print) PRINT=1 ;;
    *) echo "unknown arg: $a" >&2; exit 2 ;;
  esac
done

[ -f "$MANIFEST" ] || { echo "manifest not found: $MANIFEST" >&2; exit 1; }

# Resolve the manifest to TSV: name<TAB>url<TAB>ref<TAB>path<TAB>vendored
PLAN="$(python3 - "$MANIFEST" <<'PY'
import sys, yaml
m = yaml.safe_load(open(sys.argv[1]))
org = m.get("org", "")
for t in m.get("tools", []):
    url = f"https://github.com/{org}/{t['repo']}.git"
    print("\t".join([t["name"], url, str(t.get("ref", m.get("default_ref", "main"))),
                     t["path"], "1" if t.get("vendored") else "0"]))
PY
)" || { echo "failed to parse manifest" >&2; exit 1; }

# Never block on an interactive credential prompt -- an unreachable/private repo
# should cleanly "skip", not hang asking for a GitHub username/password.
export GIT_TERMINAL_PROMPT=0
export GIT_SSH_COMMAND="ssh -oBatchMode=yes"

rc=0
while IFS=$'\t' read -r name url ref path vendored; do
  [ -n "$name" ] || continue
  if [ "$PRINT" = 1 ]; then
    printf '  %-9s %-40s %-8s %s%s\n' "$name" "$url" "$ref" "$path" \
      "$([ "$vendored" = 1 ] && echo '  (vendored)')"
    continue
  fi
  if [ "$vendored" = 1 ] && [ "$FORCE" != 1 ]; then
    echo "skip $name (vendored in-tree; --force to refetch)"; continue
  fi
  dest="$ROOT/$path"
  if [ -d "$dest/.git" ]; then
    echo "fetch $name -> $path @ $ref"
    git -C "$dest" fetch --tags --quiet origin && git -C "$dest" checkout --quiet "$ref" || { echo "  ! $name fetch/checkout failed"; rc=1; }
  elif git ls-remote "$url" >/dev/null 2>&1; then
    echo "clone $name -> $path @ $ref"
    mkdir -p "$(dirname "$dest")"
    git clone --quiet "$url" "$dest" && git -C "$dest" checkout --quiet "$ref" || { echo "  ! $name clone failed"; rc=1; }
  else
    echo "skip $name ($url not reachable -- provision the repo or keep vendored)"
  fi
done <<< "$PLAN"

exit $rc
