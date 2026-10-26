# Changelog

ClearCutt Factory is pre-1.0; see [docs/stability.md](docs/stability.md) for
what may change between releases.

## Unreleased

### Breaking

**Tags move only to a signed, fully attested image, and never back.**
`build --push` and `rebase --push` pushed with the tags, then signed, so a
cosign or Rekor failure left `latest` on an unsigned image; a rebase re-run
then saw the image "already on the newest base" and left it so. Images are
now pushed by digest, signed, and attested, and only then tagged. "Already
published" means the org's image signers verify the signature (index and
every platform image), the recipe or rebase record, and each platform's
SBOM and vulnerability report; a run adds whatever is missing and signs
nothing twice, so the next run completes one that failed partway. A
rebase that finds the image already on the newest base does the same,
and refuses an image with neither a recipe nor a rebase record from the
org's signer (rebuild it), or one it has no signer to check against
(`signing.verify` or a trust policy): `rebase --push` used to say "nothing
to do" without looking. The check for a newer image under the tag now
applies to new images too, so a re-run of an older job no longer moves
`latest` back (`--force-tags` still does, for a rollback). `result.json`
is written before the push and again once the image is published, before
its tags move (with the `$GITHUB_OUTPUT` values), so a failure after that
still leaves the record the reproduce and notify steps read; `published`
is true when the run pushed the image or added anything to it. Checking a
published image now takes a cosign call per signature and attestation
instead of one. `stack push` and `profile push` likewise push by digest,
sign, and only then move the tag.

**A smoke test's container has no network unless the test asks.** It had
the runtime's default network, which on a self-hosted runner reaches
whatever that machine does. A command test now runs with `--network none`;
`spec.test.network: true` gives it the default network. An HTTP test keeps
the default network, which publishing its port needs.

**Only the default branch publishes.** `images.yml` pushed and signed on
every event but pull requests, so a `workflow_dispatch` from any branch
published images the signer identity trusts, and the verify block `init`
writes named the repository but no ref. Now `images.yml` and `fleet.yml`
push, sign, and attest, and `fleet.yml` and `update-locks.yml` open pull
requests, only in runs on the default branch (where `schedule`,
`repository_dispatch`, and `workflow_run` always run), or on the ref the new
`publish-ref` input names (a bash glob, such as `refs/heads/release/*`);
elsewhere they build and check (`fleet.yml` runs `rebase --check`;
`update-locks.yml` reports without proposing). `init` writes
`sourceRef: refs/heads/<branch>` into the signer, with the origin remote's
default branch, or `--default-branch`, or `main`. Existing profiles: add
`sourceRef` to `signing.verify` (or the trust policy's signers) yourself.

**Only the source reaches the build context and the signed recipe.**
Copying an app's source (and directories in `files:`) left out `.git`,
`/out`, and factory's own files, and nothing else, so a local
`build --push` could embed a stray `.env` in the recipe, which holds the
context's contents up to 2 MiB. In a git work tree only the files git
tracks are copied now (`build` names what it left out: commit what the
build needs); elsewhere, what `.gitignore` files ignore is left out; and in
both, what a `.dockerignore` at the directory's root excludes, as Docker
reads it. A source in a git work tree needs `git` on `PATH`.

**apk packages are checked against the lock's checksums at build.** The
lock recorded each apk package's APKINDEX checksum, but the build only
asked apk for the pinned versions, so a repository that rebuilt a package
under the same version changed the image without failing it, although
the README said packages were pinned by version and hash. Each platform's
install now ends by checking every package apk installed against apk's
database, which records the APKINDEX checksum (`Q1…`, a SHA-1 over the
package's signed control section, which holds the SHA-256 of its files),
and fails naming the package that differs. The checksums differ per
architecture, so a multi-platform image now installs in one stage per
architecture. A lock without checksums can't be rendered; `lock --update`
writes them. Every apk image's Containerfile changes, so it builds a new
digest once: re-render (`clearcutt-factory render`) and commit.

**Locks carry a content digest and the release that wrote them.** A lock
edited by hand (a digest, URL, checksum, or version changed) was read as it
was: `loadLocked` checked only that the manifest's inputs matched. Every
lock now records `contentDigest`, the sha256 of the rest of the file, and
`generator`, the clearcutt-factory that last wrote it. A lock whose digest
doesn't match is refused by every command that reads it, including `lock`
(nothing in it is reused; `lock --update` resolves every input again, and
shows the edit as a change). A lock without a digest, written by an
earlier release, is refused by `render`, `build`, `verify`, and `rebase`
until `clearcutt-factory lock` rewrites it, which keeps its pins: run it
once per manifest after upgrading (the examples are re-locked here). A
lock a newer minor release wrote is refused with a message naming both
versions, as is one this release can't decode when any newer release
wrote it, instead of a `field … not found` error.

**The lock is written only once its Containerfile renders, and both are
written atomically.** `lock` wrote the lock, then rendered, so a resolution
the Containerfile can't hold left a lock on disk that `render` and `build`
refused. It now renders first, and writes each file to a temporary file
beside it that is renamed over the old one, so a failed write leaves the
previous lock and Containerfile intact.

**A rebase refuses an app whose layers would delete files of the new
base.** The check read whiteouts against the old base only, so an app
layer that deleted a path the old base lacked and the new base has (an
opaque directory, say) was rebased, and the result lacked the new base's
files. Such whiteouts are a violation now ("app layers would delete files
of the new base"), like the files an app layer would hide.

**`policy.allowedHosts` covers apk repositories, and `allowedRegistries`
matches whole path segments.** apk packages have no URL of their own, so
the repositories they come from went unchecked; they are checked now, so
a profile with `allowedHosts` must list its apk repositories' hosts
(`apk.cgr.dev` for Wolfi and Chainguard). An `allowedRegistries` entry was a
string prefix, so `ghcr.io/acme` allowed `ghcr.io/acme-evil/app`; an entry
now covers itself and the paths below it (with a tag or digest), and a
repository's list must lie within the shared profile's the same way.
Entries ending in `/` mean what they did.

**`build --push` and `rebase --push` refuse `--no-scan` under a shared
profile**, which would publish past the platform's vulnerability gate.

**Values the Containerfile can't hold are refused.** `spec.user`,
`spec.workdir`, environment variable names, the paths of `oci` tools, and
other values were printed into the Containerfile as they were, and
`policy.requireNonRoot` read the raw string, so `user: "65532\nUSER 0"`
passed the policy and ran the image as root. Loading a manifest (and
rendering, for locks edited by hand) now refuses: a `user` that isn't a
name or ID with an optional `:group`; a `workdir`, `oci` tool `path`, tool
`dest`, stack `appDir`, or cache that isn't an absolute path without
spaces, quotes, `$`, `\`, globs, commas, or `=`; environment names that
aren't letters, digits, `_`, `.`, and `-`; newlines and other control
characters in environment and label values, label keys, file
destinations, and `extract`; control characters other than tabs and
newlines in `run` scripts and stack steps; and lock values (image
references, digests, versions, package names, checksums, URLs, nix store
paths) that don't have their expected form. `requireNonRoot` also counts
`00` and other spellings of ID 0 as root. A script that holds the heredoc
delimiter `FACTORY_EOF` gets another one, `FACTORY_EOF_` and the start of
its sha256, so it can't end its heredoc and add instructions; other
Containerfiles are unchanged. `FuzzRender` renders arbitrary values and
checks with BuildKit's own parser that the Containerfile has exactly the
instructions a plain input gives, with each value unchanged.

### Added

**A trust policy may name `estate` signers.** clearcutt-verify's trust
policy gains a signer role `estate` (who signs estate report bundles). The
same file is factory's `signing.trustPolicy`, and factory refused any role
but `image` and `stack`; it now loads a policy with `estate` signers and
leaves them out of what it checks images and stacks against. A role it
doesn't know is still refused.

**Every flag has a help string, and a bad command line prints the usage
once.** `clearcutt-factory <command> -h` lists the command's flags with what
each does. A flag that doesn't exist, a stray argument, or an unknown
command printed the usage twice (once from the flag package, once from
main); it now prints what was wrong and the usage, once, and exits 2. The
`cmd/` package and `internal/diff` (which explains why a reproduction
differs) have tests.

**CI publishes with the real cosign.** Every cosign interaction in the
tests was a fake. A `cosign` job now publishes a two-platform image to a
`registry:3` service through factory's publish path, signed with a key and
no transparency log, and checks with `cosign verify` and
`cosign verify-attestation` that the index and each platform image are
signed, that the recipe and each platform's SBOM and vulnerability report
are attached, and that `latest` names the signed digest; then a publish
that cosign fails partway leaves `latest` alone, and the next run attaches
only what is missing (`TestEndToEndCosign`). The end-to-end job also builds
an image, pushes it to a local registry with `build --push`, and checks its
signature and attestations with cosign.

**The reusable workflows are linted and hardened.** CI runs actionlint and
zizmor (online audits) on every workflow and the action, with the findings
this repository keeps justified inline or in `.github/zizmor.yml`. Every job
has a `timeout-minutes`; `setup-qemu-action` installs a binfmt image pinned
by digest instead of `tonistiigi/binfmt:latest`; checkouts drop their
credentials (`persist-credentials: false`) except the one in `fleet.yml`
and `update-locks.yml` that pushes the pull request's branch; every `${{ }}`
in a `run:` block went to `env:`; `GITHUB_ENV` is no longer written (the
action writes one fixed directory to `GITHUB_PATH`, with syft and grype
linked into it); and `release.yml` builds without the Go cache.

**A failed build shows what the failing step printed.** Without `-v`,
`build` showed the build log's last 40 lines, which BuildKit fills with
its summary and the Containerfile around the failing instruction, so the
step's own error (the package an apk check names, say) was cut off. It
now shows that step's output first, then the summary.

**`policy.requireOfflineBuildTools`** runs the scripts of `from: build`
tools with no network (`RUN --network=none`), so they can use only what
their builder image holds. Off by default; a repository can't turn it off
when its shared profile turns it on.

## v0.3.0

**`lock --update-package` moves only the packages it names
([#59](https://github.com/northcutted/clearcutt-factory/issues/59)).**
Releasing a hold or taking a CVE fix re-resolved every package of the image,
so the pull request also carried unrelated updates (openssl-4.0 r6 → r7 in
the showcase's CVE drill). `clearcutt-factory lock --update-package
NAME[,NAME…]` (repeatable) re-resolves the named apk, apt, or dnf packages
and whatever their new versions need, and keeps every other package at its
pin. When that isn't possible (the new versions need a kept package at
another version, or a kept version is gone from the repositories), it fails
and names the packages that would have to move. For apt, kept packages come
from the Debian snapshots they were locked from. `lock --update` and
`update-locks.yml` still update everything.

**Apps hear about a publish before its reproduction finishes
([#60](https://github.com/northcutted/clearcutt-factory/issues/60)).** A job
that calls `images.yml` ends only when every job in it has, so `notify` waited
for the second-runner reproduction: about 2m20s on the critical path of the
showcase's CVE drill. `images.yml` takes two new inputs: `reproduce: false`
publishes without reproducing, and `published` (the first call's output)
builds nothing and only reproduces what it lists. `init`'s workflow now calls
it both ways, so `notify` and `fleet` start as soon as the images are
published while the reproduction runs beside them. The reproduction is still
signed by `images.yml`, so trust policies need no change, and a failed one
still fails the run. Existing callers are unchanged (`reproduce` defaults to
`true`); to notify early, follow `init`'s workflow or
[docs/adopting.md](docs/adopting.md#waking-the-apps-when-the-platform-publishes).
Jobs that read reproduction attestations (an estate report) should need the
`reproduce` job too.

**A refused rebase's pull request is titled as a rebuild
([#57](https://github.com/northcutted/clearcutt-factory/issues/57)).** When
`fleet.yml` can't rebase an app, its pull request moves the lock to the
newest run image and the stack's newest build image, so merging it rebuilds
the app with a new toolchain. It was titled like a routine pin ("Pin catalog
to the newest run image"); it is now "Rebuild catalog on the newest run and
build images". The branch is the same, so a later safe rebase takes it over
and retitles it as a pin.

**A shared profile's signer can be rotated
([#54](https://github.com/northcutted/clearcutt-factory/issues/54)).**
`extends.signers` lists several signers, any one of which may sign the
shared profile; `extends.signer` is the same with one entry, and setting
both is an error. A repository lists the new signer beside the old one,
the platform switches, and the repository drops the old signer once its
locks pin versions the new one signed; from then on a version only the old
signer signed fails to load. Each signer is checked as `signer` is (no
`sourceMatchesImage`).

**The platform repository can extend the profile it publishes by path
([#55](https://github.com/northcutted/clearcutt-factory/issues/55)).**
`extends: {path: org/profile.yaml}` extends the repository's own shared
profile, so the platform repository builds under what it publishes (even
before the first publish) instead of a copy that can drift. The merge rules
are the same. It names no signer and nothing is verified, since it is the
repository's own file; `path` with `ref`, `signer`, or `signers` is an
error, and the path and every file the profile names must be inside the
repository. Each lock pins it as `profile: {path, digest}`, where the digest
is the one `profile push` publishes it at (so it covers the trust policy,
keys, and VEX it names, and matches the published digest); the lock is
stale when any of them changes, until `lock` pins the new digest.

**Loading a shared profile no longer runs cosign every time, outside CI
([#56](https://github.com/northcutted/clearcutt-factory/issues/56)).**
A successful signature check of a shared profile is remembered on the
machine for 24 hours, per pinned digest and signer (a key file by its
content), so commands skip `cosign` and a pinned profile loads offline. CI
(`CI=true` or `GITHUB_ACTIONS=true`) still checks on every load, as do the
new `--reverify` flag and `CLEARCUTT_FACTORY_REVERIFY=1`
(`CLEARCUTT_FACTORY_REVERIFY=0` lets CI reuse checks); `init --extends`
always checks, and failures are never remembered. Only `cosign` is
skipped: the profile is still read at the pinned digest, and the profile
cache now keeps each artifact's manifest beside its files and checks both
against the digest before use, so a cached copy that was changed is
fetched again instead of loading (before, a cached copy was trusted once
its digest's signature checked out). Profiles cached by v0.2.0 are fetched
again once.

## v0.2.0

**Rebased images get SLSA build provenance
([#52](https://github.com/northcutted/clearcutt-factory/issues/52)).** A
fleet rebase pushes a new digest. It was signed and carried a rebase record,
but it had no SLSA provenance, so a verifier that requires provenance
(clearcutt-verify's `required: [provenance]`) failed every rebased image.
`fleet.yml` now attests build provenance for the digest it pushes, the way
`images.yml` attests builds: `actions/attest-build-provenance`, pushed to
the registry and signed by `fleet.yml`, when `gh attestation verify
--signer-workflow …/fleet.yml` finds none yet. A new `provenance` input
(default `true`) turns it off. When `images.yml` rebases an app build onto
a newer base, it now attests the rebased image too (the one the tags point
at), not only the image it built. **Callers of `fleet.yml` must now grant
`attestations: write`.** `init`'s workflow and `docs/adopting.md` grant it.
Images rebased before this release fail a provenance requirement until their
next rebase or build.

**The bot's pull requests work for a manifest at the repository root
([#51](https://github.com/northcutted/clearcutt-factory/issues/51)).**
`update-locks.yml` and `fleet.yml` named the branch after the manifest's
directory. For an `app.yaml` at the root that directory is `.`, and
`factory/update/.` isn't a valid branch name, so no pull request opened. A
root manifest's branch is now named after its file (`factory/rebase/root-app`,
`factory/update/root-image`). Only its own files (the manifest, its lock, and
its Containerfile) are committed, not the whole checkout. Manifests in
directories keep their branches. A leading `./` in a glob, or a character git
refuses in branch names, no longer breaks them.

**One org profile for every repository
([#14](https://github.com/northcutted/clearcutt-factory/issues/14)).**
`clearcutt-factory profile push -f PROFILE --ref REF` publishes an org
profile as a signed OCI artifact
(`application/vnd.clearcutt.factory.org-profile.v1`) with the trust policy,
public keys, and VEX documents it names, and, like `stack push`, only moves
the tag when the profile is unchanged and `signing.profile` has signed it.
An app repository's `factory.org.yaml` extends it with `extends: {ref,
signer}`: `signer` (who may sign the shared profile) is stated in the app
repository, and the profile is verified against it whenever it is loaded,
at the digest each manifest's lock now pins (`profile:`); `lock --update`
moves the pin, and a lock that doesn't pin the profile its org profile
extends is stale. What the shared profile sets is fixed; a repository adds
what it leaves unset and may tighten the gate and policy, and anything
that would loosen or change them is an error naming the field
(`docs/adopting.md` lists the rules). Org profiles take
`vulnerabilities.vex`, applied to every scan; under a shared profile, a
repository's own VEX (its profile's and its manifests' `spec.vex`) is
refused unless the shared profile sets `vulnerabilities.allowLocalVEX`.
`init --extends REF --extends-identity ID` (or `--extends-key`) checks the
shared profile's signature and writes a profile that extends it, and
`notify.yml` sends `clearcutt.profile-published` for `kind: profile`, which
`init`'s workflow answers with the lock-update job. Existing workflows: add
`clearcutt.profile-published` to the `repository_dispatch` types and the
`update-locks` condition.

**A platform repository wakes the apps that build on it
([#13](https://github.com/northcutted/clearcutt-factory/issues/13)).**
`images.yml` has an output, `published`: what the run newly published, as a
JSON array of `{manifest, kind, image, repository, digest, tags}`. The new
reusable `notify.yml` takes it (or stacks a job of yours pushed; `stack push`
now writes `image`, `repository`, and `digest` to `$GITHUB_OUTPUT`) and sends
`repository_dispatch` to the owner's repositories with the topic
`clearcutt-app`: `clearcutt.run-image-published` for images and
`clearcutt.stack-published` for stacks, with the payload `{image,
repository, digest, tags, source}`. `init`'s workflow notifies after
publishing and answers the events with `fleet.yml` and `update-locks.yml`,
treating the payload as a hint. Dispatching needs a GitHub App installed on
the dependents, or a `CLEARCUTT_BOT_TOKEN` that can write to them.

**A GitHub App can open the bot's pull requests
([#17](https://github.com/northcutted/clearcutt-factory/issues/17)).**
`update-locks.yml` and `fleet.yml` take a GitHub App (its Client ID or App ID
in the `app-id` input or a `CLEARCUTT_APP_ID` variable, and its key in a
`CLEARCUTT_APP_PRIVATE_KEY` secret) and mint a token in each job with
`actions/create-github-app-token`: it expires within the hour and reaches
only the repository's contents and pull requests. The App wins over
`CLEARCUTT_BOT_TOKEN`, which still works, and either over `GITHUB_TOKEN`.
`docs/adopting.md` shows how to create the App.

**Reproductions are attested
([#16](https://github.com/northcutted/clearcutt-factory/issues/16)).**
`verify --image --attest` signs a `…/reproduction/v1` attestation onto an
image that reproduced: how (`recipe-rebuild` or `rebase-repeat`), the digest
it gave, the recipe or rebase record it started from (by statement digest),
the factory and BuildKit versions, the run and machine, and when.
`images.yml`'s second-runner rebuild and `fleet.yml`'s repeat of each rebase
attest their matches, so verifiers can show that an image was reproduced
without rebuilding it. The reproduce job now asks for `packages: write` and
`id-token: write`, which callers of `images.yml` already grant.

**Secrets reach the reusable workflows from other organizations.**
`secrets: inherit` passes secrets only to workflows in the caller's own
organization or enterprise, so the workflow `init` wrote never handed
`CLEARCUTT_BOT_TOKEN` or the registry credentials to ClearCutt Factory's
workflows. The reusable workflows now declare their optional secrets, and
`init` passes them by name. Existing workflows: replace `secrets: inherit`
with the names, as `docs/adopting.md` shows.

**The BuildKit container can reach a registry on this machine
([#40](https://github.com/northcutted/clearcutt-factory/issues/40)).**
`builder.config` mounts a `buildkitd.toml` (relative to the org profile)
into the BuildKit container: registry mirrors, plain-HTTP or insecure
registries, CA certificates. `builder.network` sets its network (e.g.
`host`). Before, a base in a local or plain-HTTP registry could be locked
but not built, short of a custom BuildKit image or `builder.addr`.
`docs/adopting.md` shows both for Linux and for Docker or Podman in a VM.

**Stacks can have a signing key of their own
([#41](https://github.com/northcutted/clearcutt-factory/issues/41)).** In
key mode, `signing.key` signed stacks too, so a separate stack signer
(`signing.stacks.key`) needed a second org profile. `signing.stackKey` signs
stacks instead (relative to the profile, or a KMS URI), and `stack push
--key` signs with a given key whatever `signing.mode` says.

**`stack push` signs a stack once
([#44](https://github.com/northcutted/clearcutt-factory/issues/44)).** It
pushed and signed every time, so re-running it on an unchanged stack added
another signature to the same digest. When the registry already has the
digest and one of the org's stack signers signed it (or signing is off), it
now only moves the tag, as `build --push` does. With no stack signer
configured it can't tell, and signs again.

**Signing and verifying without a transparency log
([#43](https://github.com/northcutted/clearcutt-factory/issues/43)).** The
example profile documented `--tlog-upload=false`, which cosign 3 deprecates;
`docs/adopting.md` now shows a cosign signing config that names no log.
Signers verified with keys take `tlog: false` (in `signing.verify`,
`signing.stacks`, and a trust policy's signers, as clearcutt-verify's trust
policy does), which verifies that key's signatures and attestations with
cosign `--insecure-ignore-tlog`; keyless signers can't set it. `verify
--image --key K --insecure-ignore-tlog` does the same on the command line.

**The rebase record names the smoke test that ran.** A rebase from the app
manifest runs the app's smoke test on every platform before it publishes,
but the record didn't say so, so verifiers counted no test on rebased
images. The record now has `test`: the app's `spec.test` as declared and
each platform's result. It is absent when no test ran (`rebase --image`,
`--no-test`). README documents the record's fields.

**`policy.requireSignedStacks` holds wherever a stack is used.** Only `lock`
checked the stack's signature: `render`, `build`, `verify`, and `rebase` used
whatever version the lock pinned, so a pull request that edited
`app.lock.yaml` to an unsigned stack digest passed CI. Every command that
loads an app now checks the pinned version.

**Stack signers name their repository.** A stack names no source repository,
so a stack signer with `sourceMatchesImage` could never verify one (with
`signing.stacks` unset, `signing.verify`'s applied to stacks too). Such a
signer is now an error when the org profile loads: in `signing.stacks`
always, and under `policy.requireSignedStacks` also in the trust policy's
stack signers or in `signing.verify` standing in for `signing.stacks`.

**Trust policy keys are relative to the trust policy**, as keys in `signing`
are to the org profile, instead of to the working directory.

`rebase --check --update-lock` moved the lock although `--check` only
reports; the combination is now an error. The check whether an image is
already published falls back to GET when a registry rejects HEAD, as
resolving a digest did.

**Apps build on non-root build images
([#38](https://github.com/northcutted/clearcutt-factory/issues/38)).**
`policy.requireNonRoot` applies to the images a platform builds for its
stacks, but the app build stage ran the steps as the build image's user, so
on a non-root build image the first step failed at `mkdir -p /out`, steps
couldn't write the source, and cache mounts were root-owned. The build stage
now runs as root (`USER 0`): it never ships, and the app still runs as the
stack's or app's `user`. Files the steps write to `/out` are owned by root,
as they were with root build images, which these builds still produce
unchanged.

**factory's own files are no longer in an app's source
([#42](https://github.com/northcutted/clearcutt-factory/issues/42)).** With
the default `source`, the app's `app.lock.yaml` and `app.Containerfile` (and
a `factory.org.yaml` beside them) were copied into `/src` and recorded in the
recipe, so a pull request that only pinned a new base changed the build's
input. They are now left out like `.git`. Apps that excluded them in
`spec.exclude` can drop those entries. The recipe's context changes once; an
image changes only if its steps copied those files into `/out`.

**A rebase equals a rebuild of its pinned lock
([#39](https://github.com/northcutted/clearcutt-factory/issues/39)).** A
rebased app never had the digest of the same app built from source on the
new base, though the layers and config were the same: `rebase` wrote
manifests in another JSON layout than BuildKit (compact, fields in
go-containerregistry's order) and copied the new base's layer descriptors
verbatim, with the `buildkit/rewritten-timestamp` annotations factory-built
run images carry, which a BuildKit build on that base drops. So merging the
fleet's pin pull request republished every rebased app under a new digest,
and rebuilding an older lock never found the published image. Rebases now
write manifests and indexes as BuildKit does and keep only the layer
annotations BuildKit keeps, and `build --push` treats an image the fleet
rebased (signed, with its rebase record) as already published, as `rebase
--push` does a built one. `verify --image` still repeats rebases recorded by
earlier versions (in their format). Images rebased before this release are
republished once, at the next build from their pinned lock.

**SLSA provenance for every published image.** `images.yml` skipped
provenance on this repository's own push builds (its `provenance` input is
empty outside `workflow_call`, and the condition read empty as false). It now
attests any published digest that lacks provenance, so an image pushed without
it (the step failed, or was skipped) gets it on the next run, and unchanged
images that have it get no new attestation. Existing provenance counts when
`images.yml` signed it (`gh attestation verify --signer-workflow`; in a
calling repository the signer is the called workflow, not the caller's) in a
run of the repository being built.

**Every published image is reproduced.** `images.yml`'s reproduce job was
skipped entirely when any manifest failed to build. It now rebuilds each image
that was published; the failed build still fails the run.

**Runs no longer race.** `images.yml`, `fleet.yml`, and `update-locks.yml`
(and CI here) run one at a time per ref: publishing, rebasing, and lock
updates wait for the run before them instead of racing on tags and pull
requests, and a pull request's newer run cancels the older one.

**`fleet.yml` keeps a valid pin pull request open.** A rebase that failed
before pinning the lock (a registry error, say) left the lock unchanged, and
that closed the app's open pull request; only a rebase that finishes with
nothing to pin closes it now. After the images workflow, `fleet.yml` runs only
for a push to `main`, not for pull requests whose branch is named `main`.

`scripts/release.sh` also moves the install instructions (`go install` and
the download) to the release. The docs now say that GitHub holds CI on the
bot's pull requests for approval until `CLEARCUTT_BOT_TOKEN` is set.

**A refused rebase moves the build image too
([#29](https://github.com/northcutted/clearcutt-factory/issues/29)).** When
`rebase -f app.yaml --update-lock` was refused, it moved only the run image's
pin, so the rebuild meant to replace the app ran in the old build image and
could link libraries the new run image no longer has (`libxml2.so.2` after
the run image moved to `libxml2.so.16`, say). The lock now also moves to the
stack's newest build image, and a registry stack to its newest version; the
builder pins stay. After a successful rebase the build image stays pinned,
as before: the app's layer was built with it.

**Republishing an image doesn't move tags backwards
([#15](https://github.com/northcutted/clearcutt-factory/issues/15)).** After
the fleet rebased an app, a push to the app's `main` before the pin pull
request merged rebuilt the original image from the old lock, and publishing
it moved `latest` back to the unpatched base. A tag now stays where it is,
with a warning, when it holds a newer image than the one published again:
that image rebased onto a newer build of its base, or an image created later
(built from a newer lock). `build` and `rebase` take `--force-tags` to move
it anyway.

**A push before the pin pull request merges doesn't ship on the old base
([#35](https://github.com/northcutted/clearcutt-factory/issues/35)).** A
build from changed source used the old lock, so the new image was on the
unpatched base and took `latest` from the fleet's rebase until the fleet ran
again (and only if the whole images workflow succeeded). When a tag of an
app holds an image on a newer build of its base, `build --push` now pushes
the new image by digest only, rebases it onto the base's newest build with
the fleet's checks, smoke test, and signed rebase record, and tags that. If
it can't be rebased, the tags stay and the build fails with what to do. The
images workflow repeats the rebase from its record.

**The fleet doesn't take tags from newer publishes, and a failed repeat
still opens the pin pull request
([#37](https://github.com/northcutted/clearcutt-factory/issues/37)).** A
rebase that started before a push to `main` published could finish after it
and move `latest` back to the rebased older build. `rebase --push` now moves
a tag only if it still holds what it held when the rebase started; otherwise
it pushes the result by digest only and leaves the tag, and the next fleet
run rebases the new image. Where the registry supports conditional requests,
the tag is written with an ETag precondition, closing the gap between the
check and the write. In `fleet.yml`, the pull request that pins the lock is
opened even when repeating the rebase fails, marked as not independently
reproduced.

## v0.1.1

**Signatures from the reusable workflows verify in other repositories
([#11](https://github.com/northcutted/clearcutt-factory/issues/11)).** The
reusable workflows sign with their own identity, so the identity `init`
wrote never matched: in a calling repository, `verify --image` failed in the
reproduce and fleet jobs, and unchanged images were republished on every run.
A signer can now bind signatures to the repository whose run made them
(`sourceRepository`, or `sourceMatchesImage` with `sourceRepositoryOwner`, and
`sourceRef`), checked by cosign, and accept an exact `certificateIdentity`.
`init` writes the reusable workflows' identity bound to the repository.
Existing org profiles: replace `certificateIdentityRegexp` in `signing.verify`
as `docs/adopting.md` shows.

**A stack signer of its own
([#12](https://github.com/northcutted/clearcutt-factory/issues/12)).**
`signing.stacks` is who may sign registry stacks for
`policy.requireSignedStacks`; it defaults to `signing.verify`.

**One trust policy shared with clearcutt-verify.** `signing.trustPolicy` names
a `clearcutt.dev/v1` `TrustPolicy` file whose signers (with roles `image` and
`stack`) replace `verify` and `stacks`; clearcutt-verify reads the same file.

`verify --image` takes `--certificate-identity` and
`--certificate-github-workflow-repository`.

## v0.1.0

The first release of ClearCutt Factory, the build side of
[ClearCutt](https://github.com/northcutted/clearcutt).

**Images.** `lock`, `render`, `build`, and `verify` turn a YAML manifest into
an image that rebuilds bit for bit. Every input is pinned: base and builder
images by digest; apk, apt, and dnf packages (dependencies included) by
version and file hash; release downloads, Go modules, and Nix store paths.
Builds run on a pinned BuildKit, are smoke-tested on every platform, scanned,
gated, and on push signed keylessly with SBOM, vulnerability, and recipe
attestations. `verify --image` rebuilds an image from its signed recipe.

**Apps on stacks.** A stack names the build image, steps, and run image; an
app adds its source. Stacks can be published to a registry with `stack push`
and named by reference from any repository; locks pin them by digest, and
`policy.requireSignedStacks` accepts only signed ones.

**Rebase.** `rebase` moves an image's own layers onto a newer build of its
base after checking that is safe, records the rebase so anyone can repeat it,
and with `-f app.yaml --update-lock` keeps the app's lock on the same base.

**Fleet maintenance.** Reusable workflows build and publish
(`images.yml`), open weekly lock-update pull requests (`update-locks.yml`),
and keep apps on the newest run image (`fleet.yml`). Unchanged images aren't
republished, and an update that resolves the same content proposes nothing.

**Adopting it.** `init` scaffolds an org profile, an example image, and a
workflow. The action (`uses: northcutted/clearcutt-factory@v0.1.0`) installs a
signature-verified binary with cosign, syft, and grype. JSON Schemas for
manifests, stacks, and the org profile are in `schemas/`.
