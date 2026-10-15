# Changelog

ClearCutt Factory is pre-1.0; see [docs/stability.md](docs/stability.md) for
what may change between releases.

## Unreleased

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

**SLSA provenance for every published image.** `images.yml` skipped
provenance on this repository's own push builds (its `provenance` input is
empty outside `workflow_call`, and the condition read empty as false). It now
attests any published digest that lacks provenance, so an image pushed without
it (the step failed, or was skipped) gets it on the next run, and unchanged
images that have it get no new attestation.

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
