#!/usr/bin/env bash
# Lints the workflows clearcutt-factory init writes (the golden files in
# internal/factory/testdata/init, which TestInitGolden keeps equal to what
# init writes) as adopters run them: actionlint in each, as a repository of
# its own, so a workflow's calls of the repository's own workflows
# (./.github/workflows/…) resolve. zizmor audits them from ci.yml.
#
# Usage: .github/scripts/init-lint.sh (needs actionlint and git)
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
fail=0
for dir in "$root"/internal/factory/testdata/init/*/; do
  name=$(basename "$dir")
  tmp=$(mktemp -d)
  cp -R "$dir." "$tmp/"
  git -C "$tmp" init -q
  if (cd "$tmp" && actionlint); then
    echo "ok   $name"
  else
    echo "FAIL $name"
    fail=1
  fi
  rm -rf "$tmp"
done
exit "$fail"
