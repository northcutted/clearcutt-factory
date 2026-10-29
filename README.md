<img src="assets/icon.svg" width="64" height="64" alt="">

# ClearCutt Factory

`clearcutt-factory` turns a short YAML manifest into a purpose-built OCI image
that is **reproducible bit-for-bit**, **signed**, and shipped with **SBOMs**,
**vulnerability reports**, and a **signed recipe** (the exact Containerfile,
lockfile, and build settings) that anyone can use to rebuild it and get the
same digest.

It is the build side of ClearCutt, a family of tools for the OCI images you
run: ClearCutt Factory builds and maintains them;
[clearcutt-verify](https://github.com/northcutted/clearcutt-verify) checks
an estate whatever built it (which images are built on which, how stale they
are, what can be proven about them) and writes a report;
[clearcutt-portal](https://github.com/northcutted/clearcutt-portal) publishes
that report as a website.

Distro packages come from the base image's own package manager — **apk**
(Wolfi, Chainguard, Alpine), **apt** (Debian, Ubuntu), or **dnf** (Fedora,
RHEL/UBI, Amazon Linux, Rocky, Alma) — with every package pinned by version and
hash, and the hash checked when the image is built. Everything else — release binaries, **Nix** packages, tools inside other
images, Go programs, arbitrary build steps — is declared inline as a *tool*, so
there is no package recipe to write for each third-party binary.

```
image.yaml ──lock──▶ image.lock.yaml + image.Containerfile ──build──▶ image + attestations
 (intent)            (every input pinned by hash)                    SBOM · vulns · recipe · signature
```

Applications build the same way on **stacks** you define: a stack names the
toolchain image, the build steps, and the run image apps ship on, so an app
manifest is little more than its source directory (like Cloud Native
Buildpacks, but the buildpack is yours). When the run image is rebuilt,
**`clearcutt-factory rebase`** moves each app onto it in seconds without
rebuilding the app, after checking that this is safe.

## Quick start

Install a signed release binary from
[Releases](https://github.com/northcutted/clearcutt-factory/releases) (see
[docs/adopting.md](docs/adopting.md#1-install) to verify it), or
`go install github.com/northcutted/clearcutt-factory/cmd/clearcutt-factory@v0.4.1`.
Building needs Docker or Podman (BuildKit runs inside a container, pinned by
digest); scanning and signing need `syft`, `grype`, and `cosign` on `PATH`.

Set up your own repository (an org profile, an example image, a GitHub
Actions workflow that publishes and maintains everything, and a Dependabot
configuration):

```sh
clearcutt-factory init
```

An organization sets up its platform, app, and estate repositories with
`init --platform`, `init --app`, and `init --estate`: the platform's images,
stack, shared profile and owner-scoped trust policy, and workflows; an app
that is its `app.yaml` plus a short caller of `app.yml`; and the estate's
clearcutt-verify and clearcutt-portal workflow
([adopting](docs/adopting.md#init-for-a-platform-its-apps-and-its-estate)).

`clearcutt-factory doctor` checks that this machine can build: docker or
podman (and that it sees the repository and `--out`), BuildKit and QEMU for
every platform, syft, grype, and cosign, registry push access, the GitHub
App, and that this binary is the release the workflows pin; each failure
comes with its fix ([adopting](docs/adopting.md#1-install)).
[docs/adopting.md](docs/adopting.md) walks through the rest. To try the
examples here:

```sh
clearcutt-factory lock   -f examples/platform-tools/image.yaml   # pin everything; writes lock + Containerfile
clearcutt-factory build  -f examples/platform-tools/image.yaml   # build, SBOM, scan, gate (local only)
clearcutt-factory build  -f examples/platform-tools/image.yaml --push   # …and push, sign, attest
clearcutt-factory verify -f examples/platform-tools/image.yaml --digest sha256:…   # rebuild from scratch, compare
clearcutt-factory verify --image ghcr.io/acme/platform-tools@sha256:…              # rebuild from the signed recipe

clearcutt-factory build  -f examples/hello-app/app.yaml           # an app, built on examples/stacks/go.yaml
clearcutt-factory rebase -f examples/hello-app/app.yaml --push --update-lock   # move it onto the newest run image, test, re-pin
```

Commit `image.yaml`, `image.lock.yaml`, and `image.Containerfile`. Reviewers see
exact version and hash changes in the lock diff and the resulting build steps in
the Containerfile diff.

JSON Schemas for manifests, stacks, and the org profile are in
[`schemas/`](schemas); start a file with
`# yaml-language-server: $schema=…/schemas/manifest.schema.json` (as `init`
does) and editors complete and check it.

## The manifest

```yaml
apiVersion: factory.clearcutt.dev/v1alpha1
kind: Image
extends: ../base.yaml            # optional: layer on a team/org base manifest
metadata:
  name: platform-tools           # ref defaults to <org registry>/<name>
spec:
  base: cgr.dev/chainguard/wolfi-base:latest   # or debian:trixie-slim, amazonlinux:2023, …
  platforms: [linux/amd64, linux/arm64]
  packages: [bash, git, jq]      # installed with the base's package manager (apk, apt, or dnf)
  tools:
    - name: kubectl              # plain download
      from: url
      version: 1.37.1
      url: https://dl.k8s.io/release/v{{version}}/bin/{{os}}/{{arch}}/kubectl
      checksum: "{{url}}.sha256"
    - name: gh                   # GitHub release asset, binary pulled from the archive
      from: github-release
      repo: cli/cli
      version: 2.102.0
      asset: gh_{{version}}_{{os}}_{{arch}}.tar.gz
      checksums: gh_{{version}}_checksums.txt
      extract: gh_{{version}}_{{os}}_{{arch}}/bin/gh
    - name: crane                # copied out of another image
      from: oci
      image: gcr.io/go-containerregistry/crane:latest
      path: /ko-app/crane
    - name: yq                   # compiled with a pinned Go toolchain
      from: go
      package: github.com/mikefarah/yq/v4
      version: v4.54.1
    - name: ripgrep              # from nixpkgs, on any base (even distroless)
      from: nix
      package: ripgrep           # attribute path, e.g. python3Packages.black
      nixpkgs: nixos-26.05       # branch, tag, commit, or github:owner/repo/ref
    - name: awscli               # escape hatch: any script; write outputs to /out
      from: build
      image: python:3.13
      run: pip install --prefix=/out/usr/local awscli==2.0.0
  files:
    - {src: config/, dst: /etc/platform-tools/}
  env: {KUBECONFIG: /home/nonroot/.kube/config}
  labels: {org.opencontainers.image.source: https://github.com/acme/images}
  user: "65532"
  entrypoint: [/bin/bash]
  vex: [vex/triaged.openvex.json] # OpenVEX statements applied to scans (for this image, or a package anywhere)
  test:                          # smoke test, run in every platform image before pushing
    command: [/usr/local/bin/kubectl, version, --client]   # must exit 0
    # http: {port: 8080, path: /healthz}   # or: start the image, expect a non-error answer
    # timeout: 60s
    # network: true              # a command test runs with no network unless this; an http test always has one
```

| Tool source | Pinned by | Verified against |
|---|---|---|
| `url` | sha256 per platform | `sha256:` in the manifest, or a `checksum:` file URL |
| `github-release` | sha256 per platform | `checksums:` asset, else the digest GitHub reports for the asset |
| `oci` | image digest | content addressing |
| `go` | module version + toolchain image digest | the Go checksum database |
| `nix` | nixpkgs commit + store path and closure per platform | cache.nixos.org's ed25519 signature on every store path, checked at lock and again by `nix copy` at build |
| `build` | builder image digest | nothing — the lock marks it `unverified`; with `policy.requireOfflineBuildTools` the script runs with no network |

Placeholders: `{{version}}`, `{{os}}`, `{{arch}}` (renamed per tool with
`archMap: {amd64: x86_64}`), `{{name}}`, plus `{{tag}}` and `{{asset}}` for
GitHub releases and `{{url}}` in `checksum:`. Unknown placeholders are errors.
Tools with no checksum source are hashed on first download ("TOFU") and are
rejected unless the org profile sets `policy.allowTOFU: true`.

Tools install to `/usr/local/bin/<name>` with mode `0755` unless `dest:` and
`mode:` say otherwise.

## Packages

`clearcutt-factory lock` resolves packages with the distribution's own solver, run inside
the digest-pinned base image (apt and dnf run in a container; apk is resolved
in Go from the signed APKINDEX). The lock records every package that will be
installed. For apt and dnf it records each file's URL and sha256, and the
build downloads exactly those files with `ADD --checksum` and installs them
offline, never asking a repository what is current. For apk it records each
package's APKINDEX checksum (apk's `Q1…`: a SHA-1 over the package's signed
control section, which holds the SHA-256 of its files); the build has apk
install the pinned versions from the locked repositories, then checks every
one against apk's database, which records the checksum of each installed
package, so a package rebuilt under the same version fails the build.

| Manager | Detected from | Resolution | Pinned download URL | Signatures checked at lock |
|---|---|---|---|---|
| apk | `/lib/apk/db/installed` | Go solver over the base's repositories; base packages are pinned too | apk fetches by exact version from the locked repositories; the build then checks each installed package's APKINDEX checksum against the lock | APKINDEX signed by a key in the base's `/etc/apk/keys` |
| apt | os-release `debian`/`ubuntu` | `apt-get` in the base; Debian sources point at snapshot.debian.org | Debian: snapshot.debian.org. Ubuntu: Launchpad, which keeps every published file | apt verifies the signed indexes |
| dnf | os-release `fedora`/`rhel`/`amzn`/… | `dnf --downloadonly` in the base | Fedora: Koji's signed copy of the build (byte-identical to the repository's). Amazon Linux: its content-addressed CDN. Others: the repository (mirror it) | `rpm -K` against the distribution's keys |

**Moving one package.** `clearcutt-factory lock --update-package NAME[,NAME…]`
(repeatable) re-resolves only the named packages and whatever their new
versions need, and keeps every other package at its pin, so the pull request
for a CVE fix changes what the fix needs and nothing else. A kept package that
nothing needs any more is dropped. If the new versions need a kept package at
another version, or a kept version is gone from the repositories, `lock`
fails and names the packages that would have to move; name them too. To
release a hold, drop the version from its `packages:` entry
(`libcrypto3=3.6.3-r4` → `libcrypto3`) and name it. apt and dnf packages built
from one source usually need each other's exact version, so name them
together (`curl,libcurl4t64`). Plain `lock` after an edit to `packages:`
re-resolves every package, and `update-locks.yml` still updates everything
weekly.

Override detection with `spec.packageManager`. Each manager's leftovers that
differ between runs (logs, caches, ldconfig's aux-cache, apt's binary caches,
SQLite's shared-memory file) are removed in the install layer. Amazon Linux's
rpm records the wall-clock install time, so `clearcutt-factory` rewrites those header
fields to `SOURCE_DATE_EPOCH`, as newer rpm does natively.

## Apps and stacks

A **stack** is a platform team's recipe for building one kind of app. It is
the "buildpack", written in YAML and owned by you:

```yaml
apiVersion: factory.clearcutt.dev/v1alpha1
kind: Stack
metadata: {name: go}
spec:
  build: golang:1                          # toolchain the steps run in
  run: ../go-runtime/image.yaml            # what apps ship on: an image ref, or a factory manifest
  platforms: [linux/amd64, linux/arm64]
  crossCompile: true                       # run steps on the build machine with TARGETOS/TARGETARCH
  buildEnv: {CGO_ENABLED: "0", MAIN: .}    # apps may override
  caches: [/root/.cache/go-build, /go/pkg/mod]
  steps:                                   # run in the app's source (/src); write the app to /out
    - run: go mod download
    - run: GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w -buildid=" -o "/out/$APP_NAME" "$MAIN"
  appDir: /app                             # where /out lands (default /app)
  user: "65532"                            # defaults for apps; {{name}} is the app's name
  entrypoint: ["/app/{{name}}"]
```

An **app** names a stack and adds little else:

```yaml
apiVersion: factory.clearcutt.dev/v1alpha1
kind: App
metadata: {name: hello-app}
spec:
  stack: ../stacks/go.yaml
  source: .                 # default: the manifest's directory
  exclude: [docs/]          # .gitignore-style; .git, /out, factory's own files, and what git doesn't track are always left out
  buildEnv: {MAIN: ./cmd/server}
  env: {PORT: "8080"}       # env, labels, user, workdir, entrypoint, cmd override the stack's
```

`lock`, `render`, `build`, and `verify` work on apps exactly as on images
(`-f app.yaml`, which is also the default when there is no `image.yaml`). The
lock pins the build and run images and records the stack's digest, so a stack
change makes every app's lock stale. The generated `app.Containerfile` runs
the steps in the pinned build image and copies only `/out` onto the pinned run
image with `COPY --link`. The steps run as root whatever user the build image
names (so a build image that meets `policy.requireNonRoot` works): that stage
never ships, and the app runs as the stack's or app's `user`. The source the
steps see leaves out `.git`, `/out`, and factory's own files when they are in
it (the app's lock and Containerfile, and the org profile), so a pull request
that only pins a new base doesn't change it. It also leaves out what isn't
part of the source: in a git work tree, every file git doesn't track (a
stray `.env`, build output, an editor's backup; `build` names what it left
out, so commit what the build needs), elsewhere what `.gitignore` files
ignore, and in both what a `.dockerignore` at the source's root excludes, as
Docker reads it. The same goes for directories in an image's `files:`. The
recipe embeds this source, so nothing else can reach a signed recipe. The app's layer therefore never touches the run
image's files, and the image records its base in the standard
`org.opencontainers.image.base.name`/`.base.digest` annotations. Those two
properties are what make it safe to rebase.

**Stacks in a registry.** A platform team publishes a stack once
(`clearcutt-factory stack push -f stacks/go.yaml --ref ghcr.io/acme/stacks/go:1`,
which resolves manifest paths to image references and signs it), and apps in
any repository name it: `stack: ghcr.io/acme/stacks/go:1`. A build image
given as a manifest is pinned by the digest its tag holds when the stack is
pushed (`ghcr.io/acme/build-go:1@sha256:…`, the tag kept for readers), so a
rebuilt build image changes the stack's content: pushing the stack again
publishes a new one, and `notify.yml` announces it. The run image stays a
tag: apps follow it by rebasing. The app's lock pins
the stack's digest until `lock --update` moves it, and
`policy.requireSignedStacks` accepts only stacks signed by the org's stack
signer (`signing.stacks`). Every command that uses the stack checks the
version the lock pins, so editing the lock can't bring in an unsigned one.
Pushing an unchanged stack again only moves its tag once the stack signer
has signed it, and in key mode stacks are signed with `signing.stackKey`
(or `stack push --key`) when the platform's stacks have a key of their own.

Apps can't declare packages, tools, or files: anything an app needs from the
OS belongs in the stack's run image, which is itself a factory image. Quote
flow-style values that contain `{{name}}` (`["/app/{{name}}"]`).

## Rebasing

`clearcutt-factory rebase --image repo:tag` swaps the base layers under an image's own
layers for a newer build of its base, without rebuilding the image. By default
it follows the base the image names in its annotations (the stack's run image
tag), so after the platform team pushes a patched run image, rebasing every
app takes seconds and needs no source. `--onto` picks another base; `--from`
names the old one for images without annotations (built with plain
Dockerfiles, say). With a tag, `--push` moves that tag to the result, unless
another publish took the tag while the rebase ran: then the result is pushed
by digest only, the tag stays on the newer image, and a warning says so
(`--tag` tags likewise move only if they still hold what they did when the
rebase started). Where the registry supports conditional requests, the tag
is written with an ETag precondition, so a publish between that check and
the write is caught too.

For apps, `clearcutt-factory rebase -f app.yaml` rebases the app's published image
(`metadata.ref` and its first tag) onto its stack's run image and runs the
app's smoke test on the result before pushing. `--update-lock` then pins
`app.lock.yaml` to that base (`clearcutt-factory lock --update-base`), so the next build
from source doesn't quietly go back to the unpatched one. The build image
stays pinned: the app's layer was built with it, and the lock says how the
image was built. If the rebase is refused, the command fails and the lock
moves anyway, for the rebuild that is the fix: to the new run image, and to
the stack's newest build image (a registry stack to its newest version), so
the app links against the libraries the new run image has.
`clearcutt-factory lock --update-stack` moves the lock the same way on
demand, keeping every other pin: what `update-locks.yml` proposes when the
platform publishes a build image.

Before rebasing, `clearcutt-factory` checks each platform (`--check` stops
there and changes nothing, so it doesn't take `--update-lock`):

* **The image's own layers only add files.** If they replace, delete, or hide
  a base file, write through a base symlink, or change package-manager state
  (an `apt-get install` in a Dockerfile), the image's copies would win over
  the new base's, so a patched library could stay unpatched. These images are
  refused; rebuild them.
* **The bases are compatible.** The distribution release (`os-release`) must
  match, every shared library and ELF interpreter the image's own programs
  load must still be there, and so must the entrypoint. Otherwise rebuild, or
  pass `--force`.

How the image runs never changes: user, entrypoint, command, working
directory, ports, and volumes stay as built, and `clearcutt-factory` notes where the new
base would differ. Environment variables and labels the image inherited
unchanged from the old base follow the new one (a changed `PATH`, say).

**The rebase record** (predicate type
`https://github.com/northcutted/clearcutt-factory/rebase/v1`, on the
rebased index) holds `image`, the image that was rebased (`repo@digest`);
`from`, each platform's old base; `onto`, the new base's `name` and the
`ref` it resolved to; `config`, per platform, the configuration that
followed the base; `result`, the new digests; and `test` when the rebase ran
the app's smoke test (`rebase -f` without `--no-test`): the app's
`spec.test` as declared (`command`, `http`, `timeout`) and `platforms`,
each platform's result. A failing test stops the rebase before anything is
published, so a published record says `passed`; `rebase --image` (which has
no test) and `--no-test` record no `test`.

A rebase is a pure function of its inputs. The result carries a signed
**rebase record** (above) instead of a recipe,
so `clearcutt-factory verify --image` repeats the rebase and compares digests in seconds.
SBOM and vulnerability attestations are made for the result as for builds.

A rebased app is also the image a build from source on the new base gives,
bit for bit: `clearcutt-factory` writes the manifests as BuildKit does and
describes the new base's layers as a BuildKit build on it would. So
building the app from the lock `--update-lock` pinned (merging the fleet's
pull request) finds the rebased image already published and only moves its
tags. The exception is a new base that changes an environment variable or
label the app inherited: the rebase then writes the image config in another
order than a build does, so that build publishes once more.

## Running a fleet

The intended split, and the automation that keeps it current:

| Who | Owns | Changes it when |
|---|---|---|
| Platform team, with security | The org profile: signers, vulnerability gate, policy, mirrors, pinned BuildKit; published once with `profile push` and extended by every repository ([below](#one-profile-for-every-repository)) | Rarely; each repository's weekly job proposes the new version |
| Platform team | Run and base images (`kind: Image`) and their locks | Weekly updates, CVE fixes |
| Platform team, one owner per language | Stacks | Toolchain bumps; every app on the stack rebuilds |
| App teams | `app.yaml`, the source, `app.lock.yaml`; their `factory.org.yaml`, which extends the shared profile and may only tighten it | Their own releases |
| Security | VEX statements (in the shared profile, so they apply to every scan); fleet-wide audit (e.g. [clearcutt-verify](https://github.com/northcutted/clearcutt-verify)) | When triaged |

* **Weekly updates** ([`update-locks.yml`](.github/workflows/update-locks.yml)).
  `clearcutt-factory lock --update` on every manifest, one pull request each, listing
  exactly what moved (image digests, package and tool versions). CI on the
  pull request builds, smoke-tests, scans, and gates; merging publishes.
  Auto-merging these when the gates pass is reasonable.
* **Base patches reach apps without app teams** ([`fleet.yml`](.github/workflows/fleet.yml)).
  Daily and after every successful run of the images workflow for a push to
  `main`, `clearcutt-factory rebase -f <app> --push --update-lock` for each
  app: rebase if safe, smoke-test, scan, push, sign, repeat from the signed
  record (and attest the match), add SLSA provenance, then a pull request
  pinning the app's lock to the same base. If the repeat fails, the pull
  request is still opened (the image is published either way), marked as not
  independently reproduced, and the job fails. An app that can't be rebased
  gets a pull request titled "Rebuild …" that also moves its stack's build
  image (merging rebuilds it on both) and a failed job. A push that publishes while the
  fleet rebases keeps the tag; the next run rebases it.
* **CVE response** is the same path on demand: fix the run image
  (`lock --update-package` the fixed packages, so the pull request moves only
  them; merge), and the fleet job moves every app onto it in minutes.
* **Apps in other repositories hear about it** ([`notify.yml`](.github/workflows/notify.yml)).
  As soon as the platform repository publishes (before the second-runner
  reproduction finishes), its `notify` job sends
  `repository_dispatch` to the owner's repositories with the topic
  `clearcutt-app`: `clearcutt.run-image-published` for each new run image
  (or image no stack names), `clearcutt.build-image-published` for each new
  build image (what the stacks in the platform repository make of it:
  `clearcutt-factory roles`), `clearcutt.stack-published` for each new
  stack, and `clearcutt.profile-published` for a new shared profile, with
  `{image, digest, roles, …}`. `init`'s workflow answers the first with the
  fleet job and the others with the lock-update job, so a patched run image
  reaches every app in minutes, not at its next daily run. The payload is
  only a hint: the receivers re-resolve tags from the registry and verify
  signatures, as they do on their schedules
  ([adopting](docs/adopting.md#waking-the-apps-when-the-platform-publishes)).
* **Toolchain and stack changes** rebuild rather than rebase (the app's own
  layer changes). `update-locks.yml` with `update: stack` runs
  `clearcutt-factory lock --update-stack` on each app, which moves its lock
  to the stack's newest version and build and run images and nothing else,
  and opens a pull request titled "Rebuild … on the newest build image" (or
  stack), tested by the app's CI. `init`'s workflow runs it when the
  platform announces a build image or stack, and daily, so a toolchain fix
  (a CVE in Go's standard library, say) reaches the apps in minutes, or a
  day without the dispatch, not at the weekly update, whose pull request
  carries everything else too.
* **Distribution upgrades** (Debian 13 to 14, say) are refused by rebase on
  purpose. Publish a new run image and stack version beside the old ones;
  apps move with a one-line change and a rebuild.

Pull requests opened with the default `GITHUB_TOKEN` are
`github-actions[bot]`'s, and GitHub holds the CI runs they trigger until a
maintainer approves them on the pull request (the runs show as
`action_required`), so nothing gates the change on its own. Give the jobs an
identity of their own and CI starts by itself: a **GitHub App**
(a `CLEARCUTT_APP_ID` variable and a `CLEARCUTT_APP_PRIVATE_KEY` secret), from
which each job mints a token that expires within the hour and reaches only
its repository's contents and pull requests; or a `CLEARCUTT_BOT_TOKEN` secret
(a fine-grained token with contents and pull-requests write). The App wins
when both are set ([adopting](docs/adopting.md#a-github-app-for-the-automation)).

**Merging by itself.** The `auto-merge` input of `fleet.yml` (`pin`,
`rebuild`) and `update-locks.yml` (`update`, `rebuild`; or `all`) turns on
GitHub auto-merge, as a merge commit, for the pull requests of those kinds,
so each merges once the base branch's required checks pass and the fleet
runs without a person: a patched run image reaches every app, a rebuilt
build image rebuilds every app. It needs **Allow auto-merge** in the
repository settings, branch protection (or a ruleset) with required status
checks on the base branch (without them nothing gates the change: a pull
request is mergeable at once, and auto-merge is refused), and pull requests
from the App or token above, since `GITHUB_TOKEN`'s get no CI. When it
can't be turned on, the pull request stays open with a warning
([adopting](docs/adopting.md#4-turn-on-the-automation)).

Deploy by digest and let GitOps follow the tags; keep old run images (a
rebase needs the old base's manifest) and old app digests (rollback).

**Tags only move forward.** Until an app's pin pull request merges, a build
from unchanged source uses the old lock and reproduces the image the fleet
rebased. Publishing moves the tags to the image, new or one the registry
already has, except a tag that holds a newer image: this image rebased onto a newer build
of its base (its own layers on another base, while its base's tag has moved
on), or an image created later (built from a newer lock: a build's created
time is its lock's `SOURCE_DATE_EPOCH`). That tag stays, with a warning.
`--force-tags` (on `build` and `rebase`) moves it anyway, for a deliberate
rollback. So a run of an older job (re-run after a newer one published)
publishes its image without taking a tag back to it.

A build from changed source before the pin pull request merges is a new
image, on the old base. When a tag of an app holds an image on a newer build
of that base (by its `org.opencontainers.image.base.*` annotations: the
build the base's tag points at now, or one created later),
`clearcutt-factory build --push` pushes the new image by digest only,
rebases it onto the base's newest build as the fleet would (the same checks,
smoke test, scan, gate, and signed rebase record, which the images workflow
repeats), and moves the tags to the result. If the rebase is refused or
fails, the tags stay and the build fails: merge the pin pull request (or run
`clearcutt-factory lock --update-base`) and build again. `--force-tags` tags
the new image as built. Merge pin pull requests promptly all the same: each
app build until then also rebases.

## The org profile

Everything that differs between organizations lives in `factory.org.yaml`,
found by walking up from the manifest (or `--org`). See
[`examples/factory.org.yaml`](examples/factory.org.yaml).

| Section | Controls |
|---|---|
| `registry`, `tags` | Where images go and how they are tagged |
| `defaults` | Base image, platforms, and labels for every manifest |
| `builder` | Pinned BuildKit, Dockerfile frontend, toolbox, Go and Nix images, default nixpkgs branch; `runtime: docker\|podman`; `addr:` for a remote buildkitd (e.g. in Kubernetes); `config:` (a `buildkitd.toml`: mirrors, plain-HTTP or insecure registries, CA certificates) and `network:` for the BuildKit container ([a registry on this machine](docs/adopting.md#a-registry-on-this-machine)) |
| `signing` | `keyless` (Sigstore OIDC), `key` (file or any cosign KMS URI; `stackKey` signs stacks with a key of their own), or `none`; extra cosign args (a signing config for a private Sigstore, or for signing [without a transparency log](docs/adopting.md#who-signs-and-binding-signatures-to-your-repository)); who signs this repository's images (`verify`, bound to the workflow run's repository with `sourceRepository`) and its stacks (`stacks`), or a shared ClearCutt `trustPolicy` file ([adopting](docs/adopting.md#who-signs-and-binding-signatures-to-your-repository)) |
| `sbom` | Whether to add a syft scan to the declared SBOM |
| `extends` | A shared org profile to build on, and who may sign it ([below](#one-profile-for-every-repository)) |
| `vulnerabilities` | Scanner and the `failOn` severity gate, optionally `onlyFixed`; `vex` documents applied to every scan: a statement whose product is an image (`pkg:oci/…` by digest or `repository_url`, or a reference) applies to that image only, one whose product is a package wherever the package is ([below](#what-gets-attached-to-a-pushed-image)) |
| `policy` | Non-root, required labels, TOFU, allowed download hosts (tools, package files, and apk repositories) and registries (each entry covers itself and the paths below it, by whole segment: `ghcr.io/acme` covers `ghcr.io/acme/app`, not `ghcr.io/acme-evil/app`), signed stacks, and `requireOfflineBuildTools` (`from: build` scripts run with no network) |
| `mirrors` | URL prefix rewrites for every download (`from: https://snapshot.debian.org/`, `to: https://artifactory.acme/debian-snapshot/`); checksums still pin the content |

### One profile for every repository

A platform team publishes its profile once, signed, with the trust policy,
public keys, and VEX documents it names:

```sh
clearcutt-factory profile push -f org/profile.yaml --ref ghcr.io/acme/factory/org:1
```

Each app repository's `factory.org.yaml` extends it, naming who may sign it,
and adds what the shared profile leaves to each repository:

```yaml
extends:
  ref: ghcr.io/acme/factory/org:1   # each lock pins its digest; lock --update moves it
  signer:                           # who may sign the shared profile
    certificateIdentity: https://github.com/acme/platform/.github/workflows/profile.yml@refs/heads/main
    certificateOIDCIssuer: https://token.actions.githubusercontent.com
registry: ghcr.io/acme/checkout
vulnerabilities: {failOn: high}     # tighter than the shared profile: allowed
```

What the shared profile sets is fixed; a repository may only add what it
leaves unset and tighten its gate and policy (a stricter `failOn`, more
required labels, narrower allow lists, `requireX` on, `allowTOFU` and
`onlyFixed` off). Anything that would loosen or change it is an error naming
the field. VEX statements from the repository are refused unless the shared
profile allows them. The shared profile is checked against
`extends.signer` whenever it is loaded, at the digest the lock pins, so an
unsigned, tampered, or otherwise signed version never applies. (Outside
CI, a check counts on that machine for a day, per digest and signer;
`--reverify` checks again.)
`extends.signers` lists several signers instead, any one of which may sign
it, so the platform can rotate its signer without every repository changing
at that moment.
[docs/adopting.md](docs/adopting.md#6-one-org-profile-for-every-repository)
has the full rules and why the signer is stated in the app repository.
`clearcutt-factory init --extends REF --extends-identity ID` sets a
repository up this way. The platform repository extends the profile it
publishes by path (`extends: {path: org/profile.yaml}`), under the same
rules and with no signer, since it is its own file; its locks pin the digest
`profile push` publishes it at.

## What makes it reproducible

* **Every input is content-addressed in the lock**: base, BuildKit, frontend,
  and helper images by digest; every package *including transitive
  dependencies* by exact version and checksum (apk: the APKINDEX checksum,
  checked against apk's database after install; apt/dnf: the file's sha256,
  checked before); every download
  by sha256; Go modules by version (sumdb-checked); Nix store paths by their
  signed hashes. The lock also records which release wrote it (`generator`)
  and a digest of its own content (`contentDigest`): a lock edited by hand
  is refused wherever it is read (`lock --update` resolves it again), and a
  lock a newer release wrote says so instead of failing to decode.
  This digest detects accidental edits, not deliberate tampering: removing
  both fields makes a lock appear legacy. Review locks like code. Every
  legacy read warns that its pins are taken as written; review them before
  running `clearcutt-factory lock` to stamp the digest.
* **Pinned BuildKit**: builds run `moby/buildkit@sha256:…` in a container, so
  every machine uses the same builder.
* **Clamped timestamps**: `SOURCE_DATE_EPOCH` comes from the lock (midnight
  UTC the day before the pins last changed, so files created during any build
  are newer and get clamped even on a builder whose clock lags) and
  `rewrite-timestamp=true` clamps them. Every stage that runs commands declares
  the epoch, so layers cached under a different epoch are never reused.
  Downloads and local files are copied through a toolbox stage so upstream
  mtimes never reach the image.
* **Known nondeterminism removed**: glibc's ldconfig `aux-cache` (which records
  inode numbers) is deleted in the same layer it is created.
* **One layer per tool** (`COPY --link`), so a change to one tool doesn't
  disturb the others.

`clearcutt-factory verify` rebuilds without any cache and compares digests. On a mismatch
it names the first differing layer and the files that differ.

## What gets attached to a pushed image

| Attestation | Subject | Content |
|---|---|---|
| Signature | index and each platform image | cosign (`sign --recursive`) |
| Recipe (`…/recipe/v1`) | index | Containerfile, effective manifest, lock, staged context files, BuildKit digest, epoch, platforms, digests |
| SBOM (CycloneDX) | each platform image | syft scan merged with components declared by the lock (purls, hashes, download URLs, verification method) |
| Vulnerabilities (`cosign …/vuln/v1`) | each platform image | grype results with VEX applied; `metadata.vex` lists every statement the scan was given |
| Rebase record (`…/rebase/v1`) | index of a rebased image (instead of a recipe) | the image that was rebased, each platform's old base, the new base; enough to repeat the rebase |
| Reproduction (`…/reproduction/v1`) | index, once reproduced (`verify --image --attest`) | how (`recipe-rebuild` or `rebase-repeat`), the digest it gave, the recipe or rebase record it started from, factory and BuildKit versions, the run and machine, when |
| SLSA provenance | index | from the CI platform (see [`images.yml`](.github/workflows/images.yml), and [`fleet.yml`](.github/workflows/fleet.yml) for rebased images) |

Unsigned copies of all of these are written to `out/<name>/attestations/`, and
`out/<name>/result.json` summarizes the build for CI.

**VEX statements are applied per image.** grype, scanning an SBOM, applies
only statements whose product is a package, and applies them to every
image; a statement whose product is an image it ignores. So before each
scan (at build, rebase, and `reattest`), factory selects the statements
that name the image being scanned, by the rule clearcutt-verify applies to
its rescans:

* a product that is an image purl (`pkg:oci/…` or `pkg:docker/…`) names the
  image by its version, when that (percent-decoded) is the index's or the
  platform image's digest, or, with no version, by its `repository_url`
  qualifier (the image's repository; and its `tag` qualifier, if any, one
  of the image's tags). A bare `pkg:oci/NAME` names no image: it would name
  every repository called NAME;
* a product that isn't a purl names the image when it is the image's
  repository, `repository:tag`, `repository@digest`, or one of its digests;
* any other purl is a package, passed as a product containing only its `@id`; it
  applies wherever the package is, in every image.

A statement about the image is rewritten as one about the packages its
`subcomponents` name (by `@id` or `identifiers.purl`; an OpenVEX 0.0.1
document's statement-level `subcomponents` count), or every package in the
SBOM when it names none; subcomponents none of which can be read leave the
statement out, never widened to every package. A statement about another
image never reaches the scan. The vulnerability attestation's
`metadata.vex.statements` lists every statement passed (`document`,
`vulnerability`, `status`, `justification`, `product` as written, `scope`:
`image` or `package`, and `packages`), `metadata.vex.suppressed` each
finding grype left out for a VEX statement (`vulnerability`, `package`,
`version`, `purl`, and the statement's `document`, `product`, `status`, and
`justification`, empty when it matches none passed), so a suppression is
visible there. Vulnerability publication uses the full predicate URI so
Cosign retains VEX metadata and the source SBOM identity. Non-OpenVEX documents and malformed fields are refused before
scanning. OpenVEX 0.0.1 is converted: string vulnerabilities become `name`,
string products/subcomponents become `@id`, and statement-level
subcomponents move to products that have none. Package products retain
only `@id`, so alternate identifiers cannot broaden their scope.

**Tags move last.** `build --push` and `rebase --push` push the image by
digest, sign it, and attach every attestation above before any tag moves, so
a tag only ever names a signed, attested image. An image the registry
already has counts as published only when the org's image signers verify
its signature (on the index and every platform image), its recipe or
rebase record, and each platform's SBOM and vulnerability report; whatever
is missing is added, and nothing else is signed again. So a run that failed
partway (cosign or the transparency log down) is completed by the next one,
and `rebase --push` does the same for an image it finds already on the
newest base (one with neither a recipe nor a rebase record from the org's
signer is refused: rebuild it). Without a signer to check against
(`signing.verify` or a trust policy), every publish signs and attests
again. `result.json` is written before the push and again once the image
is published, before its tags move; its `published` is true when the run
pushed the image or added anything to it.

**Reproductions.** `clearcutt-factory verify --image IMAGE --attest` rebuilds
the image from its signed recipe without cache (or repeats its signed rebase
record) and, when the digest matches, signs a statement saying so onto the
image with the org's `signing` settings, as builds sign their recipes. The
reusable workflows do it on a second runner after each publish (`images.yml`)
and after each rebase (`fleet.yml`), so a verifier can see that an image was
reproduced, how, where, and when, without rebuilding it. The predicate
(`https://github.com/northcutted/clearcutt-factory/reproduction/v1`):

```json
{
  "method": "recipe-rebuild",
  "image": "ghcr.io/acme/platform-tools@sha256:4f…",
  "digest": "sha256:4f…",
  "from": {
    "predicateType": "https://github.com/northcutted/clearcutt-factory/recipe/v1",
    "digest": {"sha256": "9a…"}
  },
  "factory": {"version": "v0.2.0"},
  "buildkit": "moby/buildkit:v0.33.1@sha256:…",
  "builder": {
    "id": "https://github.com/acme/platform/actions/runs/123/attempts/1",
    "workflow": "acme/platform/.github/workflows/clearcutt-factory.yml@refs/heads/main",
    "job": "reproduce",
    "runner": "github-hosted",
    "os": "linux",
    "arch": "amd64"
  },
  "reproducedAt": "2026-10-13T06:41:09Z"
}
```

`digest` is what the reproduction gave, always the subject's digest (only
matches are attested). `from` names the recipe or rebase record by the
sha256 of its in-toto statement (the signed DSSE payload). A verifier should
check that the attestation is signed by a signer it trusts for the image,
that `digest` is the subject's, and that `from` is a recipe or rebase record
on the same image that it verified too. `builder` comes from the
environment of the job that reproduced it, and the certificate binds the
attestation to that run's workflow and repository; it shows the image
rebuilt on a fresh machine, not who else could rebuild it. For that,
rebuild it yourself with `verify --image`.

### Renewing the evidence

A vulnerability report says what grype found the day it ran, and the next
CVE comes out after it. `clearcutt-factory reattest [-f image.yaml | --image
REF] [--older-than 7d]` renews it without rebuilding: for each platform
image, it reads the SBOM attestation the org's image signer made (never an
SBOM nobody vouched for), updates grype's database, scans the SBOM, and
attaches the new vulnerability report to the same digest, signed with the
org's `signing` settings, beside the reports already there. The report's
`metadata.rescan.sbom` names the SBOM attestation it scanned (its predicate
type and statement digest), and `metadata.scanFinishedOn` says when;
clearcutt-verify reads the newest verified report. With `--older-than`, a
platform whose newest verified report is younger is left alone. The gate
doesn't fail a re-attestation (the image is out; the report says what it
holds, and `reattest` lists what the gate would block); `update-locks.yml`
proposes the fix. It also reports whether the image carries a verified
reproduction attestation (`reproduced=` in `$GITHUB_OUTPUT`), and writes
what it did to `out/<name>-reattest/reattest.json`. No tag moves.

[`.github/workflows/reattest.yml`](.github/workflows/reattest.yml) runs it
for every manifest on a schedule, on the default branch only, and
reproduces, on its own runner, each image without a verified reproduction
attestation (`verify --image … --attest`): one whose second-runner
reproduction failed, or ran before reproductions were attested. `init`'s
workflow calls it daily with `older-than: 6d`, so each image's report is
renewed about weekly and a missed run costs a day; for a tighter
`maxScanAgeDays` in clearcutt-verify, lower `older-than`. Its signatures name
`reattest.yml`, so the image signer must accept it beside `images.yml` and
`fleet.yml` (`init` writes `(images|fleet|reattest)`); a report signed by an
identity the signer doesn't accept makes re-attestation fail with a trust
configuration message. The command checks that the exact newly attached
predicate verifies, so an older trusted report cannot satisfy this check.
Existing adopters must add `reattest` to the image signer's regexp before
enabling the schedule.

## CI

[`.github/workflows/images.yml`](.github/workflows/images.yml) is a complete
pipeline. On pull requests it builds, scans, and gates; with `changed-only:
true` (as `init`'s workflow sets it), only the manifests the pull request
affects, so one image's lock update isn't failed by another image's old
lock ([adopting](docs/adopting.md#pull-requests-build-what-they-change)).
On the default branch
(and the ref its `publish-ref` input names, if any) it also pushes, signs
keylessly, adds SLSA provenance, and then rebuilds on a second runner from
the signed recipe alone and attests the match; runs on any other ref, such
as a `workflow_dispatch` from a branch, publish nothing. `fleet.yml` and
`update-locks.yml` push and open pull requests only there too. Its `published` output lists
what the run newly published (a JSON array of `{manifest, kind, image,
repository, digest, tags, roles}`; `roles` is what the stacks make of an
image: `build`, `run`, both, or none). A calling job gets it only when the whole
workflow is done, reproduction included, so `init`'s workflow calls it with
`reproduce: false`, then again with that call's `published` output, which
only reproduces (signed by `images.yml`, as before). `notify` and `fleet`
start as soon as the images are published, beside the reproduction, and a
failed reproduction still fails the run. `clearcutt-factory build`, `rebase`,
`stack push`, and `profile push` emit `image`, `repository`, and `digest` to
`$GITHUB_OUTPUT`.
[`update-locks.yml`](.github/workflows/update-locks.yml),
[`fleet.yml`](.github/workflows/fleet.yml), and
[`notify.yml`](.github/workflows/notify.yml) keep the fleet current (see
[Running a fleet](#running-a-fleet)), and
[`reattest.yml`](.github/workflows/reattest.yml) its evidence
([Renewing the evidence](#renewing-the-evidence)).
[`app.yml`](.github/workflows/app.yml) calls all of them for an app
repository, choosing from the event, so an app repository's workflow is one
job ([adopting](docs/adopting.md#an-app-repository-is-its-appyaml-and-one-call)).
The workflows that push log in with `REGISTRY_USERNAME`/`REGISTRY_PASSWORD`,
or by OIDC federation to Amazon ECR, Google Artifact Registry, or Azure
Container Registry ([adopting](docs/adopting.md#registries-in-a-cloud-without-a-stored-secret)).
Other CI systems call the same commands; nothing is GitHub-specific.

## Limitations

* Repositories that drop old versions break old locks: Alpine (apk) and
  RHEL/UBI, Rocky, Alma, and CentOS (dnf). Wolfi, Chainguard, Debian (snapshot),
  Ubuntu (Launchpad), Fedora (Koji), and Amazon Linux keep history (Ubuntu has
  no snapshot for arm64, so it resolves against the live archive at lock time;
  the pinned files still never change). For the
  others, set `mirrors:` to a caching proxy (Artifactory, Nexus, Pulp).
* dnf locking needs `dnf` in the base; microdnf-only images (`ubi-minimal`)
  can't be locked yet.
* Nix packages must be in the binary cache; anything that would need building
  from source is rejected at lock time. They bring their own libraries (larger
  images), and scanners cover Nix less thoroughly than distro packages.
* `from: build` steps are only as reproducible as the script; `verify` will tell you.
* SLSA provenance must come from the build platform, not from `clearcutt-factory`.
* Vulnerability reports describe the day they were made. `reattest.yml`
  renews them on a schedule ([Renewing the evidence](#renewing-the-evidence));
  between its runs, the newest report is as old as the last one.
* The local BuildKit cache volume is shared, so run one build at a time per machine.
* Rebase checks are file-level: they catch replaced files, missing libraries
  and interpreters, and a changed distribution release, not every behavior
  change in the new base (a different default config file, say). Within one
  distribution release, as the stack's run image is rebuilt, that is the
  usual contract; test rebased images like any other.
* Rebasing needs the old base's manifest, so keep old run images in the
  registry.
* The fleet workflow rebases the apps whose manifests are in its own
  repository. Apps elsewhere run it themselves, on their schedule or when
  `notify.yml` wakes them; `notify.yml` finds them by a topic, or, with
  its `estate-report` input, by what the estate's clearcutt-verify report
  proves (by layer digest) is built on a run image: only for apps whose
  images the estate verifies, with the topic as the fallback.
* Smoke tests run images on the build machine, other architectures through
  emulation (QEMU in CI); `--no-test` skips them. A command test's container
  has no network unless the test sets `network: true`; an HTTP test's has the
  runtime's default network, which publishing its port needs.

## Versions

Releases are signed and reproducible; until 1.0, formats may change between
minor releases with migration notes. See [docs/stability.md](docs/stability.md)
and [CHANGELOG.md](CHANGELOG.md).

## Development

```sh
go test ./...
go test ./internal/render -update   # refresh the golden Containerfiles
go test ./internal/schema -update   # regenerate schemas/ after changing manifest types
CLEARCUTT_FACTORY_E2E=1 go test ./internal/factory   # real lock + build + no-cache rebuild per package manager,
                                                     # an app built on a stack, then rebased, and an image pushed
                                                     # and signed with cosign (needs docker or podman, and cosign)
CLEARCUTT_FACTORY_COSIGN_E2E=1 go test ./internal/factory -run TestEndToEndCosign   # publish with the real cosign
                                                     # and check every signature and attestation with it
scripts/release.sh v0.2.0           # after adding a CHANGELOG section: re-pin refs, commit, tag
```

## License

Apache-2.0; see [LICENSE](LICENSE).
