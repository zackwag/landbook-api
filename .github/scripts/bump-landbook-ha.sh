#!/usr/bin/env bash
# Opens a landbook-ha PR bumping its exact landbook-api pin to VERSION.
# Home Assistant never upgrades a requirement the installed version already
# satisfies, so that pin is the only way a release reaches landbook-ha users.
# The PR is left for review: a bump can need integration changes, and
# landbook-ha's tests mock this client, so green CI doesn't prove the pair.
#
# Env: VERSION (e.g. 0.10.0), GH_TOKEN (contents + pull-requests write on
# zackwag/landbook-ha). DRY_RUN=1 stops after rewriting the manifest.
set -euo pipefail

repo=zackwag/landbook-ha
manifest=custom_components/landbook/manifest.json
pin_prefix="landbook-api=="

if [ -z "${GH_TOKEN:-}" ]; then
  echo "::error::LANDBOOK_HA_TOKEN isn't set; bump ${pin_prefix}${VERSION} in $repo by hand" >&2
  exit 1
fi

# landbook-ha's CI installs exactly the pinned version, so wait until PyPI
# serves it rather than opening a PR whose CI can't install it yet.
on_pypi=false
for _ in $(seq 1 20); do
  if curl -fsS -o /dev/null "https://pypi.org/pypi/landbook-api/${VERSION}/json"; then
    on_pypi=true
    break
  fi
  sleep 15
done
if [ "$on_pypi" != true ]; then
  echo "::warning::landbook-api $VERSION still isn't on PyPI; the bump PR's CI may fail until it is"
fi

workdir=$(mktemp -d)
git clone --quiet --depth 1 "https://x-access-token:${GH_TOKEN}@github.com/${repo}.git" "$workdir"
cd "$workdir"

current=$(jq -r --arg p "$pin_prefix" \
  '.requirements[] | select(startswith($p)) | ltrimstr($p)' "$manifest")
if [ -z "$current" ]; then
  echo "::error::No exact ${pin_prefix}X.Y.Z requirement in ${repo}'s $manifest" >&2
  exit 1
fi
if [ "$current" = "$VERSION" ]; then
  echo "$repo already pins $VERSION"
  exit 0
fi

tmp=$(mktemp)
jq --arg p "$pin_prefix" --arg v "$VERSION" \
  '.requirements |= map(if startswith($p) then $p + $v else . end)' \
  "$manifest" >"$tmp"
mv "$tmp" "$manifest"

if [ "${DRY_RUN:-0}" = 1 ]; then
  git --no-pager diff
  exit 0
fi

branch="deps/landbook-api-$VERSION"
title="fix(deps): bump landbook-api to $VERSION"
git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git switch --quiet -c "$branch"
git commit --quiet -am "$title"
git push --quiet --force origin "$branch"

if [ -z "$(gh pr list --repo "$repo" --head "$branch" --json number -q '.[].number')" ]; then
  gh pr create --repo "$repo" --base main --head "$branch" --title "$title" --body "$(
    cat <<EOF
Bumps the \`landbook-api\` pin from \`$current\` to \`$VERSION\`.

Release notes: [v$VERSION](https://github.com/zackwag/landbook-api/releases/tag/v$VERSION)

Before merging, check the release notes for anything this integration should adopt or that changes behavior, and push those changes to this branch. Retitle to \`feat(deps):\` if it adds user-facing functionality.
EOF
  )"
fi

# Older bump PRs are superseded by this one.
gh pr list --repo "$repo" --state open --json number,headRefName \
  --jq ".[] | select(.headRefName | startswith(\"deps/landbook-api-\")) | select(.headRefName != \"$branch\") | .number" |
  while read -r number; do
    gh pr close "$number" --repo "$repo" --delete-branch --comment "Superseded by the bump to $VERSION."
  done
