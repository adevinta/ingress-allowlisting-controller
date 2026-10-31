#!/usr/bin/env bash
# Prints the version HEAD (a main commit) is released as, or nothing when it needs no release:
# it is released already, or nothing that gets deployed changed since the last release (only
# CI, docs, tests or hack/ scripts). Skipped changes go into the next real release. Reasons go to stderr.
# Needs the tags (fetch-depth: 0). Used by build.yaml and release-pending.yaml.
set -euo pipefail

first_version=v0.1.6
semver='^v[0-9]+\.[0-9]+\.[0-9]+$'

if released=$(git tag --points-at HEAD | grep -E "$semver"); then
  echo "$(git rev-parse HEAD) is released as $(xargs <<<"$released")" >&2
  exit 0
fi

latest=$(git tag -l 'v*' | grep -E "$semver" | sort -V | tail -1 || true)
if [ -z "$latest" ]; then
  echo "$first_version"
  exit 0
fi

# Paths that change neither the image nor the chart.
deployed=$(git diff --name-only "$latest" HEAD | while read -r path; do
  case "$path" in
    .github/*|docs/*|hack/*|test/*|*.md|*_test.go) ;;
    *) echo "$path" ;;
  esac
done)
if [ -z "$deployed" ]; then
  echo "only CI, docs, tests or hack/ changed since $latest, no release" >&2
  exit 0
fi

IFS=. read -r major minor patch <<<"${latest#v}"
echo "v${major}.${minor}.$((patch + 1))"
