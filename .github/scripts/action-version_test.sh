#!/usr/bin/env bash
# Runs action.yml's "Choose the version" and "Install clearcutt-factory"
# steps, as the action has them, and checks which clearcutt-factory it
# installs: the version input, else the release tag it is used at, else
# the release whose tag points at exactly the commit it is pinned to (the
# newest, if several do), its signature made by the release workflow
# running at that commit; else, with a notice, its own source at that
# commit. A failed tag lookup fails the step rather than building from
# source.
#
# Usage: .github/scripts/action-version_test.sh (needs bash and yq v4)
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
yq -e '.runs.steps[] | select(.name == "Choose the version") | .run' "$root/action.yml" > "$tmp/choose.sh"
yq -e '.runs.steps[] | select(.name == "Install clearcutt-factory") | .run' "$root/action.yml" > "$tmp/install.sh"

# git ls-remote stands in for the repository's tags (unless LS_REMOTE_FAILS):
# an annotated v0.4.1 (tag object 1111…) and a lightweight v0.4.2 on commit
# aaaa…, a higher v0.10.0 on commit bbbb…, a non-release tag on cccc…, and
# an annotated v0.3.0 whose tag object is eeee… on commit ffff….
mkdir -p "$tmp/bin"
cat > "$tmp/bin/git" <<'GIT'
#!/usr/bin/env bash
[ "$1 $2" = "ls-remote --tags" ] || { echo "unexpected git $*" >&2; exit 1; }
[ -z "${LS_REMOTE_FAILS:-}" ] || { echo "fatal: unable to access 'https://github.com/northcutted/clearcutt-factory/'" >&2; exit 128; }
printf '%s\t%s\n' \
  1111111111111111111111111111111111111111 refs/tags/v0.4.1 \
  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 'refs/tags/v0.4.1^{}' \
  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa refs/tags/v0.4.2 \
  bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb refs/tags/v0.10.0 \
  cccccccccccccccccccccccccccccccccccccccc refs/tags/nightly \
  eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee refs/tags/v0.3.0 \
  ffffffffffffffffffffffffffffffffffffffff 'refs/tags/v0.3.0^{}'
GIT
chmod +x "$tmp/bin/git"

fail=0
# version input|action ref|want version|want commit (bound to the signature)|want notice
while IFS='|' read -r input ref want commit notice; do
  : > "$tmp/output"
  if ! PATH="$tmp/bin:$PATH" INPUT=$input ACTION_REF=$ref GITHUB_OUTPUT=$tmp/output \
    bash --noprofile --norc -eo pipefail "$tmp/choose.sh" > "$tmp/log" 2>&1; then
    echo "FAIL: version '$input', ref '$ref': the step failed"; cat "$tmp/log"; fail=1
    continue
  fi
  got=$(sed -n 's/^version=//p' "$tmp/output")
  got_commit=$(sed -n 's/^commit=//p' "$tmp/output")
  if [ "$got" != "$want" ] || [ "$got_commit" != "$commit" ]; then
    echo "FAIL: version '$input', ref '$ref': got '$got' (commit '$got_commit'), want '$want' (commit '$commit')"
    fail=1
  fi
  if [ -n "$notice" ] && ! grep -q "^::notice::.*$ref.*from source" "$tmp/log"; then
    echo "FAIL: ref '$ref': no notice that it builds from source"; cat "$tmp/log"; fail=1
  elif [ -z "$notice" ] && grep -q '^::notice::' "$tmp/log"; then
    echo "FAIL: version '$input', ref '$ref': an unexpected notice"; cat "$tmp/log"; fail=1
  fi
done <<'CASES'
|v0.4.1|v0.4.1||
v0.3.0|v0.4.1|v0.3.0||
source|v0.4.1|source||
|main|source||
||source||
|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|v0.4.2|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|
|bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb|v0.10.0|bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb|
|ffffffffffffffffffffffffffffffffffffffff|v0.3.0|ffffffffffffffffffffffffffffffffffffffff|
|cccccccccccccccccccccccccccccccccccccccc|source||notice
|dddddddddddddddddddddddddddddddddddddddd|source||notice
|1111111111111111111111111111111111111111|source||notice
|eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee|source||notice
v0.3.0|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|v0.3.0||
CASES

# The tag lookup failing is an error, not a reason to build from source.
: > "$tmp/output"
if PATH="$tmp/bin:$PATH" LS_REMOTE_FAILS=1 INPUT= ACTION_REF=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa GITHUB_OUTPUT=$tmp/output \
  bash --noprofile --norc -eo pipefail "$tmp/choose.sh" > "$tmp/log" 2>&1; then
  echo "FAIL: ls-remote failed, but the step passed with $(cat "$tmp/output")"; fail=1
elif ! grep -q '^::error::could not list' "$tmp/log" || [ -s "$tmp/output" ]; then
  echo "FAIL: ls-remote failed: want an ::error:: and no version"; cat "$tmp/log" "$tmp/output"; fail=1
fi

# The install step: cosign stands in, and fails when the certificate's
# workflow SHA isn't the one given (the release workflow ran at SIGNED_AT);
# curl writes a binary that prints its version.
cat > "$tmp/bin/cosign" <<'COSIGN'
#!/usr/bin/env bash
printf '%s\n' "$*" > "$COSIGN_ARGS"
case "$*" in
  *"--certificate-identity https://github.com/northcutted/clearcutt-factory/.github/workflows/release.yml@refs/tags/$VERSION "*) ;;
  *) echo "wrong identity: $*" >&2; exit 1 ;;
esac
if [[ "$*" =~ --certificate-github-workflow-sha\ ([0-9a-f]+) ]] && [ "${BASH_REMATCH[1]}" != "$SIGNED_AT" ]; then
  echo "error: expected GitHub Workflow SHA ${BASH_REMATCH[1]}, got $SIGNED_AT" >&2; exit 1
fi
COSIGN
cat > "$tmp/bin/curl" <<'CURL'
#!/usr/bin/env bash
while [ $# -gt 0 ]; do case "$1" in -o) out=$2; shift 2 ;; *) shift ;; esac; done
printf '#!/bin/sh\necho "clearcutt-factory %s"\n' "$VERSION" > "$out"
CURL
chmod +x "$tmp/bin/cosign" "$tmp/bin/curl"
# version|commit pinned to|commit the release workflow signed at|want (ok, or fail)|want the workflow SHA checked
while IFS='|' read -r version commit signed want checked; do
  rm -rf "$tmp/run"; mkdir -p "$tmp/run"; : > "$tmp/run/path"
  if PATH="$tmp/bin:$PATH" VERSION=$version COMMIT=$commit SIGNED_AT=$signed SRC=$root REPO=northcutted/clearcutt-factory \
    RUNNER_TEMP=$tmp/run GITHUB_PATH=$tmp/run/path COSIGN_ARGS=$tmp/run/cosign \
    bash --noprofile --norc -eo pipefail "$tmp/install.sh" > "$tmp/log" 2>&1; then got=ok; else got=fail; fi
  if [ "$got" != "$want" ]; then
    echo "FAIL: install $version pinned at '$commit', signed at $signed: got $got, want $want"; cat "$tmp/log"; fail=1
  fi
  if [ -n "$checked" ] && ! grep -q -- "--certificate-github-workflow-sha $commit" "$tmp/run/cosign"; then
    echo "FAIL: install $version pinned at $commit: the workflow SHA isn't checked: $(cat "$tmp/run/cosign")"; fail=1
  elif [ -z "$checked" ] && grep -q -- '--certificate-github-workflow-sha' "$tmp/run/cosign"; then
    echo "FAIL: install $version not pinned by commit: a workflow SHA is checked: $(cat "$tmp/run/cosign")"; fail=1
  fi
done <<'CASES'
v0.4.2|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|ok|checked
v0.4.2|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|9999999999999999999999999999999999999999|fail|checked
v0.4.2||9999999999999999999999999999999999999999|ok|
CASES

if [ "$fail" = 0 ]; then
  echo "action-version: ok"
fi
exit "$fail"
