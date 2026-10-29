#!/usr/bin/env bash
# Runs action.yml's "Choose the version" step, as the action has it, and
# checks which clearcutt-factory it installs: the version input, else the
# release tag it is used at, else the release tagged at the commit it is
# pinned to (the newest, if several are), else its own source.
#
# Usage: .github/scripts/action-version_test.sh (needs bash and yq v4)
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
yq -e '.runs.steps[] | select(.name == "Choose the version") | .run' "$root/action.yml" > "$tmp/step.sh"

# git ls-remote stands in for the repository's tags: an annotated v0.4.1
# and a lightweight v0.4.2 on one commit, v0.10.0 on another, and a
# non-release tag on a third.
mkdir -p "$tmp/bin"
cat > "$tmp/bin/git" <<'GIT'
#!/usr/bin/env bash
[ "$1 $2" = "ls-remote --tags" ] || { echo "unexpected git $*" >&2; exit 1; }
printf '%s\t%s\n' \
  1111111111111111111111111111111111111111 refs/tags/v0.4.1 \
  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 'refs/tags/v0.4.1^{}' \
  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa refs/tags/v0.4.2 \
  bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb refs/tags/v0.10.0 \
  cccccccccccccccccccccccccccccccccccccccc refs/tags/nightly
GIT
chmod +x "$tmp/bin/git"

fail=0
# version input|action ref|want
while IFS='|' read -r input ref want; do
  : > "$tmp/output"
  PATH="$tmp/bin:$PATH" INPUT=$input ACTION_REF=$ref GITHUB_OUTPUT=$tmp/output \
    bash --noprofile --norc -eo pipefail "$tmp/step.sh" > /dev/null
  got=$(sed -n 's/^version=//p' "$tmp/output")
  if [ "$got" != "$want" ]; then
    echo "FAIL: version '$input', ref '$ref': got '$got', want '$want'"
    fail=1
  fi
done <<'CASES'
|v0.4.1|v0.4.1
v0.3.0|v0.4.1|v0.3.0
source|v0.4.1|source
|main|source
||source
|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|v0.4.2
|bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb|v0.10.0
|cccccccccccccccccccccccccccccccccccccccc|source
|dddddddddddddddddddddddddddddddddddddddd|source
|1111111111111111111111111111111111111111|v0.4.1
v0.3.0|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|v0.3.0
CASES
if [ "$fail" = 0 ]; then
  echo "action-version: ok"
fi
exit "$fail"
