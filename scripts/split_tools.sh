#!/usr/bin/env bash
# Externalise every vendored tool into its own git repo.
#
# Reads tools/versions.yaml and, for each tool, runs `git subtree split` on its
# path -- producing a branch `split/<repo>` whose history is just that tool's
# commits, README at the repo root, ready to push to github.com/<org>/<repo>.
# A local tag `<repo>/<ref>` is laid on each split head so the pinned ref in
# versions.yaml exists in the new repo from day one.
#
#   scripts/split_tools.sh              # (re)create all split branches + tags
#   scripts/split_tools.sh --push       # also push each to github.com/<org>/<repo>
#   scripts/split_tools.sh --print      # show the plan, do nothing
#
# Splits are deterministic: rerunning after new commits to a tool updates the
# branch in place (subtree split reuses prior mapping). Pushing again then
# fast-forwards the external repo's main.
set -euo pipefail
cd "$(dirname "$0")/.."
MANIFEST="tools/versions.yaml"

PUSH=0; PRINT=0
for a in "$@"; do
  case "$a" in
    --push)  PUSH=1 ;;
    --print) PRINT=1 ;;
    *) echo "unknown arg: $a" >&2; exit 2 ;;
  esac
done

# name<TAB>repo<TAB>ref<TAB>path
PLAN="$(python3 - "$MANIFEST" <<'PY'
import sys, yaml
m = yaml.safe_load(open(sys.argv[1]))
for t in m.get("tools", []):
    print("\t".join([t["name"], t["repo"],
                     str(t.get("ref", m.get("default_ref", "main"))), t["path"]]))
PY
)"
ORG="$(python3 -c "import yaml,sys;print(yaml.safe_load(open('$MANIFEST'))['org'])")"

if [ "$PRINT" != 1 ] && { ! git diff --quiet || ! git diff --cached --quiet; }; then
  echo "working tree not clean -- commit or stash first" >&2; exit 1
fi

# The standalone contracts repo carries the language-neutral schemas; they are
# vendored from the platform's contracts/ dir and must not drift.
if [ "$PRINT" != 1 ] && ! diff -rq contracts tools/citadel_contracts/contracts >/dev/null 2>&1; then
  echo "contracts/ and tools/citadel_contracts/contracts/ differ -- sync (cp -R contracts/* tools/citadel_contracts/contracts/) and commit first" >&2
  exit 1
fi

while IFS=$'\t' read -r name repo ref path; do
  [ -n "$name" ] || continue
  url="git@github.com:$ORG/$repo.git"
  if [ "$PRINT" = 1 ]; then
    printf '  %-14s %-28s %-8s %s\n' "$name" "$url" "$ref" "$path"
    continue
  fi
  echo "-- split $name ($path -> split/$repo)"
  git subtree split --prefix="$path" -b "split/$repo" >/dev/null
  git tag -f "$repo/$ref" "split/$repo" >/dev/null
  if [ "$PUSH" = 1 ]; then
    echo "   push -> $url (main + $ref)"
    git push "$url" "refs/heads/split/$repo:refs/heads/main" \
                    "+refs/tags/$repo/$ref:refs/tags/$ref"
  else
    echo "   push with: git push $url refs/heads/split/$repo:refs/heads/main '+refs/tags/$repo/$ref:refs/tags/$ref'"
  fi
done <<< "$PLAN"

[ "$PRINT" = 1 ] || echo "done -- $(git branch --list 'split/*' | wc -l | tr -d ' ') split branches ready"
