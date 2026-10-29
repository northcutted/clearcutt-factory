#!/usr/bin/env bash
# Runs notify.yml's "Estate changed?", "Dependents by layer digest, from the
# estate report", and "Find dependents" steps, as the workflow has them,
# with stand-ins for clearcutt-verify and gh, and checks who gets which
# dispatch: a run image's dependents come from the estate report (layer
# digest) when it answers for the image, else from the topic search; build
# images, stacks, and profiles always from the topic search; the estate
# repository gets clearcutt.estate-changed when anything was published or
# changed is true; the publishing repository never gets its own events.
#
# Usage: .github/scripts/notify-dependents_test.sh (needs bash, jq, and yq v4)
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

wf=$root/.github/workflows/notify.yml
for step in "What to announce" "Estate changed?" "Dependents by layer digest, from the estate report" "Find dependents"; do
  slug=$(tr -c 'A-Za-z' - <<<"$step")
  yq -e ".jobs.notify.steps[] | select(.name == \"$step\") | .run" "$wf" > "$tmp/$slug.sh"
done
run_step() { # step, then env assignments
  local slug
  slug=$(tr -c 'A-Za-z' - <<<"$1")
  shift
  env "$@" PATH="$tmp/bin:$PATH" RUNNER_TEMP="$tmp/run" GITHUB_OUTPUT="$tmp/run/output" GITHUB_REPOSITORY=acme/platform GITHUB_SHA=abc123 OWNER=acme \
    bash --noprofile --norc -eo pipefail "$tmp/$slug.sh"
}

# Stand-ins. gh search prints the topic's repositories (the platform
# itself included); clearcutt-verify estate pull writes a report unless
# PULL_FAILS, and estate dependents prints $tmp/deps/<base with / as _>.
mkdir -p "$tmp/bin" "$tmp/deps"
cat > "$tmp/bin/gh" <<'GH'
#!/usr/bin/env bash
if [ "$1 $2" = "search repos" ]; then printf '%s\n' acme/platform acme/checkout acme/catalog acme/storefront; exit 0; fi
echo "unexpected gh $*" >&2; exit 1
GH
cat > "$tmp/bin/clearcutt-verify" <<CV
#!/usr/bin/env bash
case "\$*" in
  "estate pull "*)
    [ -z "\${PULL_FAILS:-}" ] || exit 1
    case "\$*" in *"--certificate-identity https://github.com/acme/estate/.github/workflows/estate.yml@refs/heads/main --certificate-oidc-issuer https://token.actions.githubusercontent.com"*) ;; *) echo "unchecked signer: \$*" >&2; exit 1 ;; esac
    out=\$(sed -E 's/.*--output ([^ ]+).*/\1/' <<<"\$*"); mkdir -p "\$out"; echo '{}' > "\$out/estate-report.json" ;;
  "--format json estate dependents "*)
    base=\$(sed -E 's/.*--base ([^ ]+).*/\1/' <<<"\$*")
    f="$tmp/deps/\${base//\//_}"
    [ -f "\$f" ] || exit 1
    cat "\$f" ;;
  *) echo "unexpected clearcutt-verify \$*" >&2; exit 1 ;;
esac
CV
chmod +x "$tmp/bin/gh" "$tmp/bin/clearcutt-verify"
# run-go: two apps built on it, one twice (two images), with a .git URL.
cat > "$tmp/deps/r_run-go" <<'J'
{"base": "r/run-go", "dependents": [
  {"imageId": "a", "source": {"url": "https://github.com/acme/checkout", "basis": "provenance"}},
  {"imageId": "b", "source": {"url": "https://github.com/Acme/billing.git", "basis": "label"}},
  {"imageId": "c", "source": {"url": "https://github.com/acme/checkout/", "basis": "label"}}]}
J
# run-node: nothing built on it.
echo '{"base": "r/run-node", "dependents": []}' > "$tmp/deps/r_run-node"
# run-python: a dependent from another owner, so the topic search stands.
echo '{"base": "r/run-python", "dependents": [{"imageId": "x", "source": {"url": "https://github.com/mallory/x"}}]}' > "$tmp/deps/r_run-python"
# run-rust: a dependent without a source, so the topic search stands. (run-java: the report can't tell.)
echo '{"base": "r/run-rust", "dependents": [{"imageId": "y"}]}' > "$tmp/deps/r_run-rust"

published='[
  {"kind": "image", "image": "r/run-go@sha256:1", "repository": "r/run-go", "digest": "sha256:1", "roles": ["run"]},
  {"kind": "image", "image": "r/run-node@sha256:2", "repository": "r/run-node", "digest": "sha256:2", "roles": ["run"]},
  {"kind": "image", "image": "r/run-python@sha256:3", "repository": "r/run-python", "digest": "sha256:3", "roles": ["run"]},
  {"kind": "image", "image": "r/run-rust@sha256:4", "repository": "r/run-rust", "digest": "sha256:4", "roles": ["run"]},
  {"kind": "image", "image": "r/run-java@sha256:5", "repository": "r/run-java", "digest": "sha256:5", "roles": ["run"]},
  {"kind": "image", "image": "r/build-go@sha256:6", "repository": "r/build-go", "digest": "sha256:6", "roles": ["build"]},
  {"kind": "stack", "image": "r/stacks/go@sha256:7", "repository": "r/stacks/go", "digest": "sha256:7"}
]'

fail=0
check() { # name, want (sorted "repo event image" lines)
  local got
  got=$(jq -r -R 'split("\t") | "\(.[0]) \(.[1] | fromjson | "\(.event_type) \(.client_payload.image // .client_payload.source)")"' "$tmp/run/targets" | sort)
  if [ "$got" != "$(sort <<<"$2")" ]; then
    echo "FAIL: $1"
    diff <(sort <<<"$2") <(echo "$got") || true
    fail=1
  fi
}
scenario() { # published, estate, changed, estate-report, signer, [PULL_FAILS=1]
  rm -rf "$tmp/run"; mkdir -p "$tmp/run"; : > "$tmp/run/output"
  run_step "What to announce" PUBLISHED="$1" > /dev/null
  run_step "Estate changed?" ESTATE="$2" CHANGED="$3" PUBLISHED="$1" > /dev/null
  if [ -n "$4" ] && grep -qx 'any=true' "$tmp/run/output"; then
    run_step "Dependents by layer digest, from the estate report" ESTATE_REPORT="$4" SIGNER="$5" ${6:+PULL_FAILS=1} > "$tmp/run/report.log" 2>&1
  fi
  run_step "Find dependents" GH_TOKEN=x TOPIC=clearcutt-app REPOSITORIES= ESTATE="$2" \
    ESTATE_SEND="$(sed -n 's/^send=//p' "$tmp/run/output")" > /dev/null
}
signer=https://github.com/acme/estate/.github/workflows/estate.yml@refs/heads/main
topic() { for r in acme/checkout acme/catalog acme/storefront; do echo "$r $1 $2"; done; }

# With the report: run-go wakes only the apps built on it; run-node none;
# the others, the topic.
scenario "$published" estate false ghcr.io/acme/estate:latest "$signer"
check "estate report" "acme/checkout clearcutt.run-image-published r/run-go@sha256:1
Acme/billing clearcutt.run-image-published r/run-go@sha256:1
$(topic clearcutt.run-image-published r/run-python@sha256:3)
$(topic clearcutt.run-image-published r/run-rust@sha256:4)
$(topic clearcutt.run-image-published r/run-java@sha256:5)
$(topic clearcutt.build-image-published r/build-go@sha256:6)
$(topic clearcutt.stack-published r/stacks/go@sha256:7)
acme/estate clearcutt.estate-changed acme/platform"
if ! grep -q 'r/run-python: no repository of the owner: x' "$tmp/run/report.log"; then
  echo "FAIL: another owner's dependent isn't named"; cat "$tmp/run/report.log"; fail=1
fi

# Without it, or when it can't be pulled or verified, or without a signer: the topic, for everything.
everything="$(topic clearcutt.run-image-published r/run-go@sha256:1)
$(topic clearcutt.run-image-published r/run-node@sha256:2)
$(topic clearcutt.run-image-published r/run-python@sha256:3)
$(topic clearcutt.run-image-published r/run-rust@sha256:4)
$(topic clearcutt.run-image-published r/run-java@sha256:5)
$(topic clearcutt.build-image-published r/build-go@sha256:6)
$(topic clearcutt.stack-published r/stacks/go@sha256:7)"
scenario "$published" "" false "" ""
check "no estate report" "$everything"
scenario "$published" "" false ghcr.io/acme/estate:latest "$signer" fail
check "unreadable estate report" "$everything"
scenario "$published" "" false ghcr.io/acme/estate:latest https://github.com/acme/other/.github/workflows/x.yml@refs/heads/main
check "another signer" "$everything"
scenario "$published" "" false ghcr.io/acme/estate:latest ""
check "no signer" "$everything"

# An app's own publish: no dependents; the estate, by name in the owner or OWNER/NAME.
scenario '[{"kind": "app", "image": "r/svc@sha256:a", "repository": "r/svc", "digest": "sha256:a"}]' acme/estate false "" ""
check "an app publishes" "acme/estate clearcutt.estate-changed acme/platform"
scenario '[]' estate true "" ""
check "a rebase (changed)" "acme/estate clearcutt.estate-changed acme/platform"
scenario '[]' estate false "" ""
check "nothing happened" ""
if [ -s "$tmp/run/targets" ] || grep -q '^repositories=' "$tmp/run/output"; then
  echo "FAIL: nothing happened, but something is dispatched"; fail=1
fi

if [ "$fail" = 0 ]; then
  echo "notify-dependents: ok"
fi
exit "$fail"
