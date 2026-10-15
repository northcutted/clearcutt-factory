# Changelog

ClearCutt Factory is pre-1.0; see [docs/stability.md](docs/stability.md) for
what may change between releases.

## Unreleased

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
