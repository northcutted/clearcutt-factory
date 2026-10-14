# Changelog

ClearCutt Factory is pre-1.0; see [docs/stability.md](docs/stability.md) for
what may change between releases.

## Unreleased

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
