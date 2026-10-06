<img src="assets/icon.svg" width="64" height="64" alt="">

# ClearCutt Factory

`clearcutt-factory` turns a short YAML manifest into a purpose-built OCI image
that is **reproducible bit-for-bit**, **signed**, and shipped with **SBOMs**,
**vulnerability reports**, and a **signed recipe** (the exact Containerfile,
lockfile, and build settings) that anyone can use to rebuild it and get the
same digest.

It is the build side of [ClearCutt](https://github.com/northcutted/clearcutt),
a family of tools for the OCI images you run: ClearCutt Factory builds and
maintains them, and ClearCutt governs estates whatever built them (which
images are built on which, how stale they are, and what can be proven about
them).

Distro packages come from the base image's own package manager — **apk**
(Wolfi, Chainguard, Alpine), **apt** (Debian, Ubuntu), or **dnf** (Fedora,
RHEL/UBI, Amazon Linux, Rocky, Alma) — with every package pinned by version and
hash. Everything else — release binaries, **Nix** packages, tools inside other
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

Requirements: Go, and Docker or Podman (BuildKit runs inside a container, pinned
by digest). `syft`, `grype`, and `cosign` on `PATH` for scanning and signing.

```sh
go install github.com/northcutted/clearcutt-factory/cmd/clearcutt-factory@latest

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
  vex: [vex/triaged.openvex.json] # OpenVEX statements applied to scans
  test:                          # smoke test, run in every platform image before pushing
    command: [/usr/local/bin/kubectl, version, --client]   # must exit 0
    # http: {port: 8080, path: /healthz}   # or: start the image, expect a non-error answer
    # timeout: 60s
```

| Tool source | Pinned by | Verified against |
|---|---|---|
| `url` | sha256 per platform | `sha256:` in the manifest, or a `checksum:` file URL |
| `github-release` | sha256 per platform | `checksums:` asset, else the digest GitHub reports for the asset |
| `oci` | image digest | content addressing |
| `go` | module version + toolchain image digest | the Go checksum database |
| `nix` | nixpkgs commit + store path and closure per platform | cache.nixos.org's ed25519 signature on every store path, checked at lock and again by `nix copy` at build |
| `build` | builder image digest | nothing — the lock marks it `unverified` |

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
installed — for apt and dnf, each file's URL and sha256 — and the build
downloads exactly those files with `ADD --checksum` and installs them offline.
The build never asks a repository what is current.

| Manager | Detected from | Resolution | Pinned download URL | Signatures checked at lock |
|---|---|---|---|---|
| apk | `/lib/apk/db/installed` | Go solver over the base's repositories; base packages are pinned too | apk fetches by exact version | APKINDEX signed by a key in the base's `/etc/apk/keys` |
| apt | os-release `debian`/`ubuntu` | `apt-get` in the base; Debian sources point at snapshot.debian.org | Debian: snapshot.debian.org. Ubuntu: Launchpad, which keeps every published file | apt verifies the signed indexes |
| dnf | os-release `fedora`/`rhel`/`amzn`/… | `dnf --downloadonly` in the base | Fedora: Koji's signed copy of the build (byte-identical to the repository's). Amazon Linux: its content-addressed CDN. Others: the repository (mirror it) | `rpm -K` against the distribution's keys |

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
  exclude: [docs/]          # .gitignore-style; .git and /out are always left out
  buildEnv: {MAIN: ./cmd/server}
  env: {PORT: "8080"}       # env, labels, user, workdir, entrypoint, cmd override the stack's
```

`lock`, `render`, `build`, and `verify` work on apps exactly as on images
(`-f app.yaml`, which is also the default when there is no `image.yaml`). The
lock pins the build and run images and records the stack's digest, so a stack
change makes every app's lock stale. The generated `app.Containerfile` runs
the steps in the pinned build image and copies only `/out` onto the pinned run
image with `COPY --link`. The app's layer therefore never touches the run
image's files, and the image records its base in the standard
`org.opencontainers.image.base.name`/`.base.digest` annotations. Those two
properties are what make it safe to rebase.

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
Dockerfiles, say). With a tag, `--push` moves that tag to the result.

For apps, `clearcutt-factory rebase -f app.yaml` rebases the app's published image
(`metadata.ref` and its first tag) onto its stack's run image and runs the
app's smoke test on the result before pushing. `--update-lock` then pins
`app.lock.yaml` to that base (`clearcutt-factory lock --update-base`), so the next build
from source doesn't quietly go back to the unpatched one. If the rebase is
refused, the lock still moves and the command fails: rebuilding is the fix.

Before rebasing, `clearcutt-factory` checks each platform (`--check` stops there):

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

A rebase is a pure function of its inputs. The result carries a signed
**rebase record** (the image, old and new base digests) instead of a recipe,
so `clearcutt-factory verify --image` repeats the rebase and compares digests in seconds.
SBOM and vulnerability attestations are made for the result as for builds.

## Running a fleet

The intended split, and the automation that keeps it current:

| Who | Owns | Changes it when |
|---|---|---|
| Platform team, with security | `factory.org.yaml`: registry, signer identity, vulnerability gate, policy, mirrors, pinned BuildKit | Rarely; every lock goes stale |
| Platform team | Run and base images (`kind: Image`) and their locks | Weekly updates, CVE fixes |
| Platform team, one owner per language | Stacks | Toolchain bumps; every app on the stack rebuilds |
| App teams | `app.yaml`, the source, `app.lock.yaml` | Their own releases |
| Security | VEX statements; fleet-wide audit (e.g. [ClearCutt](https://github.com/northcutted/clearcutt)) | When triaged |

* **Weekly updates** ([`update-locks.yml`](.github/workflows/update-locks.yml)).
  `clearcutt-factory lock --update` on every manifest, one pull request each, listing
  exactly what moved (image digests, package and tool versions). CI on the
  pull request builds, smoke-tests, scans, and gates; merging publishes.
  Auto-merging these when the gates pass is reasonable.
* **Base patches reach apps without app teams** ([`fleet.yml`](.github/workflows/fleet.yml)).
  Daily and after every publish on `main`, `clearcutt-factory rebase -f <app> --push
  --update-lock` for each app: rebase if safe, smoke-test, scan, push, sign,
  repeat from the signed record, then a pull request pinning the app's lock
  to the same base. An app that can't be rebased gets the same pull request
  (merging rebuilds it) and a failed job.
* **CVE response** is the same path on demand: fix the run image (re-lock,
  merge), and the fleet job moves every app onto it in minutes.
* **Toolchain and stack changes** rebuild rather than rebase (the app's own
  layer changes): the weekly job's pull request per app does it, tested by
  each app's CI.
* **Distribution upgrades** (Debian 13 to 14, say) are refused by rebase on
  purpose. Publish a new run image and stack version beside the old ones;
  apps move with a one-line change and a rebuild.

Pull requests opened with the default `GITHUB_TOKEN` don't start other
workflows, so set a `CLEARCUTT_BOT_TOKEN` secret (a GitHub App token, or a
fine-grained token with contents and pull-requests write) for CI to run on
them. Deploy by digest and let GitOps follow the tags; keep old run images
(a rebase needs the old base's manifest) and old app digests (rollback).

## The org profile

Everything that differs between organizations lives in `factory.org.yaml`,
found by walking up from the manifest (or `--org`). See
[`examples/factory.org.yaml`](examples/factory.org.yaml).

| Section | Controls |
|---|---|
| `registry`, `tags` | Where images go and how they are tagged |
| `defaults` | Base image, platforms, and labels for every manifest |
| `builder` | Pinned BuildKit, Dockerfile frontend, toolbox, Go and Nix images, default nixpkgs branch; `runtime: docker\|podman`; `addr:` for a remote buildkitd (e.g. in Kubernetes) |
| `signing` | `keyless` (Sigstore OIDC), `key` (file or any cosign KMS URI), or `none`; extra cosign args (private Sigstore, no tlog); the identity verifiers expect |
| `sbom` | Whether to add a syft scan to the declared SBOM |
| `vulnerabilities` | Scanner and the `failOn` severity gate, optionally `onlyFixed` |
| `policy` | Non-root, required labels, TOFU, allowed download hosts (tools and packages) and registries |
| `mirrors` | URL prefix rewrites for every download (`from: https://snapshot.debian.org/`, `to: https://artifactory.acme/debian-snapshot/`); checksums still pin the content |

## What makes it reproducible

* **Every input is content-addressed in the lock**: base, BuildKit, frontend,
  and helper images by digest; every package *including transitive
  dependencies* by exact version, and for apt/dnf by file sha256; every download
  by sha256; Go modules by version (sumdb-checked); Nix store paths by their
  signed hashes.
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
| Vulnerabilities (`cosign …/vuln/v1`) | each platform image | grype results with VEX applied |
| Rebase record (`…/rebase/v1`) | index of a rebased image (instead of a recipe) | the image that was rebased, each platform's old base, the new base; enough to repeat the rebase |
| SLSA provenance | index | from the CI platform (see [`images.yml`](.github/workflows/images.yml)) |

Unsigned copies of all of these are written to `out/<name>/attestations/`, and
`out/<name>/result.json` summarizes the build for CI.

## CI

[`.github/workflows/images.yml`](.github/workflows/images.yml) is a complete
pipeline. On pull requests it builds, scans, and gates. On `main` it also pushes,
signs keylessly, adds SLSA provenance, and then rebuilds on a second runner from
the signed recipe alone. `clearcutt-factory` emits `image`, `repository`, and `digest` to
`$GITHUB_OUTPUT`. [`update-locks.yml`](.github/workflows/update-locks.yml)
and [`fleet.yml`](.github/workflows/fleet.yml) keep the fleet current (see
[Running a fleet](#running-a-fleet)). Other CI systems call the same commands;
nothing is GitHub-specific.

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
* Vulnerability reports describe the day they were made. Rescanning and
  re-attesting on a schedule is not built in yet.
* The local BuildKit cache volume is shared, so run one build at a time per machine.
* Stacks are referenced by path, so apps in other repositories vendor them
  (a git submodule, say); fetching stacks from a registry is not built in yet.
* Rebase checks are file-level: they catch replaced files, missing libraries
  and interpreters, and a changed distribution release, not every behavior
  change in the new base (a different default config file, say). Within one
  distribution release, as the stack's run image is rebuilt, that is the
  usual contract; test rebased images like any other.
* Rebasing needs the old base's manifest, so keep old run images in the
  registry.
* The fleet workflow finds apps by their manifests in this repository. Apps
  in other repositories run the same job on their own, or a registry-wide
  inventory (ClearCutt's base graph) drives `clearcutt-factory rebase --image`.
* Smoke tests run images on the build machine, other architectures through
  emulation (QEMU in CI); `--no-test` skips them.

## Development

```sh
go test ./...
go test ./internal/render -update   # refresh the golden Containerfiles
CLEARCUTT_FACTORY_E2E=1 go test ./internal/factory   # real lock + build + no-cache rebuild per package manager,
                                           # and an app built on a stack, then rebased (needs docker or podman)
```

## License

Apache-2.0; see [LICENSE](LICENSE).
