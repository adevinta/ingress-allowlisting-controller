#!/usr/bin/env bash
# Prints the version HEAD (a main commit) is released as, or nothing when it needs no release:
# it is released already, or nothing that gets deployed changed since the last release (only
# CI, docs, tests or hack/ scripts). Skipped changes go into the next real release. Reasons go to stderr.
# A breaking change since the last release makes the next minor (v0.x) or major (v1+) version
# instead of a patch, so deployments following a minor (v0.1.*) never get it.
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
    .github/*|docs/*|hack/*|test/*|*.md|*_test.go|.gitignore) ;;
    *) echo "$path" ;;
  esac
done)
if [ -z "$deployed" ]; then
  echo "only CI, docs, tests or hack/ changed since $latest, no release" >&2
  exit 0
fi

# A breaking change, in Conventional Commits style or ours, in a commit title or (squash merges
# list every commit) a body line: "type!:", "type(scope)!:", "type(breaking):", or a line starting
# with "BREAKING", each possibly after the "* " of a squash commit's list.
breaking='^[[:space:]*-]*([a-z]+(\([^)]*\))?!:|[a-z]+\(breaking\):|BREAKING)'
IFS=. read -r major minor patch <<<"${latest#v}"
# Read first: with pipefail, grep -q stopping early would fail git log with SIGPIPE.
messages=$(git log --format='%B' "$latest..HEAD")
if grep -qE "$breaking" <<<"$messages"; then
  if [ "$major" -eq 0 ]; then
    echo "breaking change since $latest, next minor" >&2
    echo "v0.$((minor + 1)).0"
  else
    echo "breaking change since $latest, next major" >&2
    echo "v$((major + 1)).0.0"
  fi
  exit 0
fi
echo "v${major}.${minor}.$((patch + 1))"
