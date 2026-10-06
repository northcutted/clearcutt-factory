# Versions and stability

ClearCutt Factory is pre-1.0. This page says what you can rely on meanwhile.

## Releases

Releases are tagged `vMAJOR.MINOR.PATCH` and published by
[`release.yml`](../.github/workflows/release.yml): binaries for Linux and macOS
on amd64 and arm64, each signed by that workflow at that tag (a Sigstore
bundle beside it), SLSA provenance, and `SHA256SUMS`. Binaries are built with
`-trimpath` and fixed flags, so rebuilding a tag with the same Go version gives
the same bytes. Notes come from [CHANGELOG.md](../CHANGELOG.md).

Pin the action and the reusable workflows to a release tag (or its commit),
never to `main`.

## What may change before 1.0

| Surface | Promise |
|---|---|
| Manifest, stack, and org profile formats (`factory.clearcutt.dev/v1alpha1`) | Fields may change in a minor release. A breaking change gets a new `apiVersion` and changelog notes on moving to it. |
| Lockfile format | Same, and `clearcutt-factory lock` rewrites old locks it can still read. A change that alters how images are built makes locks stale, so `lock` runs once more. |
| Generated Containerfiles | May change between minor releases. A changed Containerfile builds a different digest from the same lock, so after upgrading, re-render (`render`) and let CI publish once. |
| Attestation predicates (`…/recipe/v1`, `…/rebase/v1`) | Versioned by URI. `verify --image` keeps accepting old versions. |
| CLI commands and flags | Removals and renames are announced a minor release ahead where possible. |
| Reusable workflow inputs | Same as the CLI. |

Patch releases fix bugs without changing formats or digests.

## Reproducibility across versions

A recipe records the BuildKit digest, the Containerfile, and the lock, so an
image published by any version can be rebuilt and compared with
`verify --image` by any later version. A *new* build of the same manifest by a
newer version may differ when its Containerfile changes; the changelog says
when that happens.

## Supported platforms

| | Supported |
|---|---|
| CLI | Linux and macOS, amd64 and arm64 |
| Container runtimes | Docker, Podman (including Podman machine on macOS), or a remote BuildKit |
| Image platforms | Any BuildKit builds; other architectures run under emulation for package resolution and smoke tests |
| Package managers | apk (Wolfi, Chainguard, Alpine), apt (Debian, Ubuntu), dnf (Fedora, RHEL/UBI, Amazon Linux, Rocky, Alma) |
