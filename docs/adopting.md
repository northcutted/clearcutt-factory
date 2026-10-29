# Adopting ClearCutt Factory

This guide takes a repository from nothing to signed, reproducible images that
keep themselves current. It assumes GitHub Actions and a GitHub container
registry; [Other CI systems](#other-ci-systems) covers the rest.

## 1. Install

Download a release binary for Linux or macOS from
[Releases](https://github.com/northcutted/clearcutt-factory/releases) and
check its signature, made by the release workflow at that tag:

```sh
v=v0.4.1 asset=clearcutt-factory-darwin-arm64
curl -fsSLO https://github.com/northcutted/clearcutt-factory/releases/download/$v/$asset
curl -fsSLO https://github.com/northcutted/clearcutt-factory/releases/download/$v/$asset.sigstore.json
cosign verify-blob --bundle $asset.sigstore.json \
  --certificate-identity https://github.com/northcutted/clearcutt-factory/.github/workflows/release.yml@refs/tags/$v \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com $asset
install -m 0755 $asset /usr/local/bin/clearcutt-factory
```

Or build it: `go install github.com/northcutted/clearcutt-factory/cmd/clearcutt-factory@v0.4.1`.

Building needs Docker or Podman (BuildKit runs in a container). Scanning and
signing need `syft`, `grype`, and `cosign` on `PATH`.

On macOS and Windows the runtime runs in a VM (a Podman machine, Docker
Desktop) that sees only the host directories shared with it: by default a
Podman machine shares your home directory, `/private`, and `/var/folders`.
`build` mounts the repository's staged context and the `--out` directory into
the BuildKit container by their real paths (so `/tmp`, which is
`/private/tmp`, works), and when the runtime can't see one it says which path
and how to share it. Keep the repository and `--out` under your home directory
and a local build matches CI's: an app the showcase publishes rebuilds locally,
on a Podman machine, to the same digest in about 30 seconds.

`clearcutt-factory doctor` checks all of this before a build does, and
prints a fix for each failure (exit 1 when any check fails; `--json` for a
machine):

```
$ clearcutt-factory doctor -f checkout/app.yaml
clearcutt-factory doctor (v0.4.1)
OK    manifest           checkout/app.yaml loads with its org profile, and app.lock.yaml is current (written by v0.4.1)
FAIL  container runtime  podman version 6.1.4, but its server doesn't answer: Cannot connect to Podman. …
                         fix: start the Podman machine (podman machine start); if it runs, check that the default connection points at it (podman system connection list)
…
```

| Check | What it looks at |
|---|---|
| `manifest` | `-f` loads with its org profile (a shared profile's signature checked) and its lock is current; a lock a newer release wrote names the release to install |
| `container runtime` | docker or podman (`builder.runtime`, `CLEARCUTT_FACTORY_RUNTIME`) is on `PATH` and its server answers |
| `file sharing` | a container sees the repository and `--out` (default `out`) by their real paths: a Podman machine or Docker Desktop shares only some directories |
| `buildkit`, `platforms` | the pinned BuildKit starts (privileged, or at `builder.addr`), and builds every platform the manifest does, natively or with QEMU (binfmt) |
| `syft`, `grype`, `cosign` | on `PATH`, with their versions; cosign 3 |
| `registry push` | the credentials here may push to the manifest's repository, checked without pushing (a failure is a warning outside Actions) |
| `github app` | in Actions, or wherever `CLEARCUTT_APP_ID` and `CLEARCUTT_APP_PRIVATE_KEY` (or `CLEARCUTT_BOT_TOKEN`) are set: the App's key signs a token GitHub accepts, and the App is installed on the repository with contents and pull-requests write |
| `factory version` | this binary is the release the repository's workflows pin (their `uses:` ref, a commit mapped to its release tag, or `factory-version`), so a lock written here matches CI's |

In a workflow, pass the App's credentials to the step to check them:

```yaml
- uses: northcutted/clearcutt-factory@v0.4.1
- run: clearcutt-factory doctor -f checkout/app.yaml
  env:
    CLEARCUTT_APP_ID: ${{ vars.CLEARCUTT_APP_ID }}
    CLEARCUTT_APP_PRIVATE_KEY: ${{ secrets.CLEARCUTT_APP_PRIVATE_KEY }}
```

## 2. Scaffold

In your repository:

```sh
clearcutt-factory init
```

It writes four files and keeps any that exist (`--force` overwrites):

| File | What it is |
|---|---|
| `factory.org.yaml` | Your registry (default `ghcr.io/<owner>`), signer identity (keyless: ClearCutt Factory's reusable workflows, at a release tag or a commit, bound to runs in this repository; see [Who signs](#who-signs-and-binding-signatures-to-your-repository)), vulnerability gate, and policy |
| `images/example/image.yaml` | An example image to replace |
| `.github/workflows/clearcutt-factory.yml` | Calls the reusable workflows: build, test, and scan on pull requests; publish on the default branch; weekly lock updates; daily app rebases; across repositories, notify dependents of what it published and answer such notices ([below](#waking-the-apps-when-the-platform-publishes)) |
| `.github/dependabot.yml` | Keeps the actions and ClearCutt workflows the workflow pins current, the ClearCutt pins grouped, each version a week old ([below](#dependabot)) |

`--repo owner/name`, `--registry`, and `--default-branch` override what it
reads from the `origin` remote (the branch is the one the signer identity
requires, as `sourceRef`). In an app repository of an organization that publishes a shared org
profile, `--extends REF --extends-identity ID` (or `--extends-key K`) checks
that profile's signature and writes a `factory.org.yaml` that extends it
([section 6](#6-one-org-profile-for-every-repository)). Every file names its JSON Schema, so editors with the YAML language
server complete and check fields as you type.

An organization with a platform team, app teams, and an estate report sets
up each kind of repository with its own flag instead
([below](#init-for-a-platform-its-apps-and-its-estate)): `init --platform`,
`init --app`, and `init --estate`.

### Dependabot

Every repository `init` sets up gets a `.github/dependabot.yml`: the
actions and ClearCutt reusable workflows its workflows pin (one group for
`northcutted/clearcutt-*`, so factory, verify, and portal move together),
and, for an app, its own dependencies, for each manifest `init` finds
beside `app.yaml` (`go.mod`, `package.json`, `requirements.txt` or
`pyproject.toml`, `Cargo.toml`, `pom.xml`, `build.gradle`, `Gemfile`,
`composer.json`): factory's lock updates move the OS packages and
toolchains, not the app's own dependencies, so a CVE in those reaches the
app through Dependabot (turn on its security updates, which don't wait for
the schedule). A version is proposed once it is seven days old
(`cooldown`). The signer identity `init` writes accepts any factory release
tag, so a factory bump keeps images verifiable.

### init for a platform, its apps, and its estate

Three flags write the three shapes of repository a ClearCutt organization
runs, each consistent with the others' (the registry layout under
`--registry`, default `ghcr.io/<owner>`: `platform/`, `stacks/`,
`factory/org:1`, `apps/`, `estate:latest`):

```sh
clearcutt-factory init --platform --repo acme/platform --estate-repo acme/estate
clearcutt-factory init --app --repo acme/checkout --platform-repo acme/platform \
  --stack ghcr.io/acme/stacks/go:1 --estate-repo acme/estate
clearcutt-factory init --estate --repo acme/estate --platform-repo acme/platform
```

| Flag | Files | What they do |
|---|---|---|
| `--platform` | `factory.org.yaml` (extends `org/profile.yaml` by path), `org/profile.yaml` (the shared profile: builder, keyless signing, `signing.trustPolicy`, the gate, policy requiring signed stacks and a source label), `org/trust.yaml`, `images/run-go/`, `images/build-go/`, `stacks/go.yaml`, `.github/workflows/` `platform.yml`, `stacks.yml`, `profile.yml`, `update-locks.yml`, `reattest.yml`, `.github/dependabot.yml`, `.gitignore` | `platform.yml` publishes the images, then the stacks (`stacks.yml`) and the shared profile (`profile.yml`), each signed by its own workflow, wakes the app repositories (`notify.yml`), reproduces, and with `--estate-repo` refreshes the estate. The trust policy's image signer is **owner-scoped**: `sourceRepositoryOwner: https://github.com/<owner>` with `sourceMatchesImage: true` and `sourceRef`, so an image is trusted when it was signed by factory's workflows in a run of the owner's repository it names as its source, on the default branch; a new app repository needs no change to it. Its stack signer is `stacks.yml`; with `--estate-repo`, its estate signer is that repository's `estate.yml`, and `notify.yml` wakes only the apps the estate's report proves are built on a run image ([above](#only-the-apps-built-on-it)) |
| `--app` | `app.yaml` (with `--stack`), `factory.org.yaml`, `.github/workflows/factory.yml`, `.github/dependabot.yml`, `.gitignore` | With `--platform-repo`, the org profile extends `<registry>/factory/org:1`, signed by that repository's `profile.yml` (checked now), and images go to `<registry>/apps`; the workflow is a caller of [`app.yml`](#an-app-repository-is-its-appyaml-and-one-call), with `estate:` from `--estate-repo`. `--name` (default the repository's) names the app |
| `--estate` | `.github/workflows/estate.yml`, `estate/policy.yaml`, `estate/refs.txt`, `.github/dependabot.yml` | clearcutt-verify (by release tag) over `estate/refs.txt`, daily, on `clearcutt.estate-changed`, and by hand, with `--rescan` (a checksum-pinned grype) and `--reproduce`, the trust policy read from the platform's signed profile (`--platform-repo`'s `profile.yml` must have signed it), the last report bundle pulled only if this workflow signed it, the new one pushed and signed; then clearcutt-portal (by release tag) publishes it to Pages. `--name` (default the owner) names the estate |

Each takes `--repo`, `--registry`, `--default-branch`, and `--force` as
before (and all but `--estate` take `--allow-commit-pins`: [Who
signs](#who-signs-and-binding-signatures-to-your-repository)); a flag that
doesn't apply to the kind is refused. The workflows
call factory's at the release `init` is, and the other tools at the
releases it was tested with; Dependabot moves them all. Owner-scoped trust
accepts any of the owner's repositories that build on factory's workflows,
so it suits an organization where every repository is the owner's; to trust
only some, give each a signer of its own with `sourceRepository`, as the
default `init` does for its one repository.

## 3. Write manifests and lock them

Describe each image in an `image.yaml` (see the [README](../README.md#the-manifest)),
then pin every input:

```sh
clearcutt-factory lock  -f images/example/image.yaml
clearcutt-factory build -f images/example/image.yaml   # build, smoke-test, SBOM, scan, gate
```

Commit the manifest, `image.lock.yaml`, and `image.Containerfile`. The lock is
what reviewers read: every version and hash that changed. To move only some
distro packages (a CVE fix, a released hold), name them:
`clearcutt-factory lock --update-package openssl,libssl3` keeps every other
package where it is, or says which would have to move too.

## 4. Turn on the automation

Push, then in the repository (or organization) settings:

1. **An identity for the bot's pull requests.** The weekly and daily jobs
   open pull requests, and CI starts on them by itself only when they come
   from an identity of their own:
   * a **GitHub App** (recommended; [below](#a-github-app-for-the-automation)):
     a `CLEARCUTT_APP_ID` variable and a `CLEARCUTT_APP_PRIVATE_KEY` secret;
   * or a `CLEARCUTT_BOT_TOKEN` secret: a fine-grained token with contents
     and pull-requests write, which belongs to a person and lives until it
     expires.

   The jobs use the App when it is set, then the token. With neither, they
   use the workflow's `GITHUB_TOKEN`: allow it under **Actions → General →
   Workflow permissions** to create pull requests. Its pull requests are
   `github-actions[bot]`'s, and GitHub holds the CI runs they trigger until a
   maintainer approves them on each pull request (the runs show as
   `action_required`).
2. For a registry other than `ghcr.io`: set the reusable workflows' `registry`
   input and add `REGISTRY_USERNAME` and `REGISTRY_PASSWORD` secrets, or log
   in by OIDC federation instead ([below](#registries-in-a-cloud-without-a-stored-secret)).
3. **To merge the bot's pull requests by themselves** once CI passes, pass
   the `auto-merge` input to `fleet.yml` (`pin`, `rebuild`) and
   `update-locks.yml` (`update`, `rebuild`), or `all`, naming the kinds to
   merge; each such pull request gets GitHub auto-merge (a merge commit).
   For that, under **General**, allow auto-merge; under **Branches** (or
   **Rules**), protect the default branch with required status checks
   (`images / result`, the check `images.yml` reports for the whole build:
   [below](#pull-requests-build-what-they-change)), since without required checks
   a pull request is mergeable at once and GitHub refuses to auto-merge it;
   and use the App or token from step 1, since `GITHUB_TOKEN`'s pull
   requests get no CI and would never merge. When auto-merge can't be
   turned on, the job warns and leaves the pull request open; it never
   fails for that. A pull request the job updates into a kind not listed
   (the fleet's pin, refused at its next run, becomes a rebuild on the same
   branch) has auto-merge turned off. A reasonable start: `pin` and
   `rebuild` on the fleet, `update` and `rebuild` on the weekly job once
   you trust its gate.

On `main`, each changed image is pushed, signed keylessly, attested (SBOM,
vulnerabilities, recipe, SLSA provenance), and rebuilt on a second runner from
its signed recipe, which attests the match (a reproduction attestation).
Unchanged images aren't republished. The rebuild is the workflow's `reproduce`
job (`images.yml` again, given what `images` published), beside `fleet` and
`notify` rather than before them, so they start as soon as the images are
published; a failed reproduction still fails the run.

**Only the default branch publishes.** `images.yml` and `fleet.yml` push,
sign, and attest, and `fleet.yml` and `update-locks.yml` open pull requests,
only in runs on the repository's default branch (`schedule`,
`repository_dispatch`, and `workflow_run` always run there). A
`workflow_dispatch` from another branch builds and checks, and publishes
nothing: otherwise anyone who can push a branch could publish an image the
signer identity trusts. To publish from another ref too (release branches,
say), set the `publish-ref` input of each of them to it, or to a bash glob
(`refs/heads/release/*`), and add a signer for it (the `sourceRef` below
names one ref).

### Pull requests build what they change

With `changed-only: true`, as `init`'s workflow passes it, `images.yml`
builds on a pull request only the manifests the pull request affects
(`clearcutt-factory affected`, given the diff between GitHub's merge commit
and the base branch). A manifest is affected when the pull request changes
a file it owns: anything under its directory (its lock and Containerfile
among them), a file it `extends`, its `vex:` documents, its `files:`
sources and an app's `source` wherever they are, a `factory.org.yaml`
above it, and, for an app, its stack file and the manifests of the stack's
build and run images (and what they extend), which give the app's lock its
build image and base. A build image's lock is not among them: the app's
lock pins the build image that is published, not the one in the pull
request. So the weekly job's pull request for one image builds that image
only, and goes green on its own even when another image fails the gate on
its old lock (a CVE in a package every image ships gets one pull request
per image, each of which can merge).

Every manifest builds when the pull request changes a file no manifest
owns, since nothing says it can't matter: a shared profile, the trust
policy or VEX documents a profile names, a workflow, a README at the root.
Deleting an unowned file also builds every surviving manifest, since the
previous configuration may have read it. Root manifests do not hide shared
changes. Local shared-profile inputs belong to every manifest using them. Every manifest builds, too, when the
affected set can't be told (no merge commit, or a `factory-version`
before `affected`, with a warning), and on every other event: a push to
the default branch, a schedule, a dispatch, or a merge queue's
`merge_group`.

The per-manifest checks (`images / build (images/a/image.yaml)`) then
differ from one pull request to the next, and branch protection that
requires one waits forever on a pull request that doesn't build it.
Require `images / result` (the job name in your workflow, then `result`):
it passes when every manifest the run built passed, including when there
was nothing to build, and fails otherwise.

### Registries in a cloud, without a stored secret

`images.yml`, `fleet.yml`, `reattest.yml`, and `app.yml` can log in to
Amazon ECR, Google Artifact Registry, or Azure Container Registry with the
job's GitHub OIDC token, exchanged for short-lived registry credentials, so
no registry password is stored in GitHub. Set the `registry` input to the
registry host and one cloud's inputs:

| Registry | Inputs | The cloud side |
|---|---|---|
| Amazon ECR (`ACCOUNT.dkr.ecr.REGION.amazonaws.com`) | `aws-role-arn` (and `aws-region`, default the registry's) | An IAM role whose trust policy accepts `token.actions.githubusercontent.com` for `repo:OWNER/REPO:ref:refs/heads/main`, allowed to push to the repositories |
| Google Artifact Registry (`REGION-docker.pkg.dev`) | `gcp-workload-identity-provider`, `gcp-service-account` | A workload identity pool and provider for GitHub, and a service account with Artifact Registry Writer that the repository may impersonate |
| Azure Container Registry (`NAME.azurecr.io`) | `azure-client-id`, `azure-tenant-id`, `azure-subscription-id` | An app registration or user-assigned managed identity with a federated credential for the repository and branch, and `AcrPush` on the registry |

```yaml
  images:
    uses: northcutted/clearcutt-factory/.github/workflows/images.yml@v0.4.1
    permissions: {contents: read, packages: write, id-token: write, attestations: write}
    with:
      registry: 123456789012.dkr.ecr.eu-west-1.amazonaws.com
      aws-role-arn: arn:aws:iam::123456789012:role/clearcutt-publish
```

The jobs log in with
[`registry-login`](../registry-login/action.yml), this repository's action
(of the `factory-version` release), which runs the cloud's own actions,
pinned by commit (`aws-actions/configure-aws-credentials` and
`amazon-ecr-login`, `google-github-actions/auth`, `azure/login`), and fails
when inputs of more than one cloud are set, or one cloud's are incomplete,
or the registry isn't that cloud's. Workflows of your own can use it too
(`uses: northcutted/clearcutt-factory/registry-login@v0.4.1`). Scope the
cloud's trust to the default branch, as the signer's `sourceRef` is: only
the default branch publishes. Without these inputs, the jobs log in with
`REGISTRY_USERNAME` and `REGISTRY_PASSWORD`, or as `github.actor` with the
workflow's token for `ghcr.io`, as before. `update-locks.yml` doesn't log in:
it reads what it locks anonymously.

### A GitHub App for the automation

An App's installation tokens expire within the hour, carry only the
permissions a job asks for, and belong to no person. One App can serve every
repository in the organization.

1. **Create it:** organization settings → **Developer settings → GitHub Apps
   → New GitHub App** (your account's developer settings, for repositories
   you own). Any name and homepage URL; clear **Webhook → Active**; install
   **only on this account**.
2. **Repository permissions** (nothing else: no organization or account
   permissions, no events):

   | Permission | Access | Why |
   |---|---|---|
   | Contents | Read and write | Push the branches of the lock-update and pin pull requests; send `repository_dispatch` to dependents (`notify.yml`) |
   | Pull requests | Read and write | Open, update, and close those pull requests |
   | Metadata | Read-only | Required for every App; find dependents by topic (`notify.yml`) |

3. **Keys:** note the App's **Client ID**, and **Generate a private key** (a
   `.pem` file).
4. **Install it** on the repositories that run the workflows, including
   the app repositories a platform repository notifies.
5. **Hand it to the workflows:** a variable `CLEARCUTT_APP_ID` holding the
   Client ID (the numeric App ID works too; the reusable workflows also take
   it as their `app-id` input), and a secret `CLEARCUTT_APP_PRIVATE_KEY`
   holding the whole `.pem` file.

Each job of `update-locks.yml` and `fleet.yml` mints its own token with
[`actions/create-github-app-token`](https://github.com/actions/create-github-app-token),
limited to the repository it runs in and to contents and pull-requests
write. `notify.yml` mints one with metadata read on the owner's repositories
the App is installed on, to find dependents, then one with contents write on
only those, to dispatch. Tokens are revoked when the job ends. Setting only
one of the two fails the job instead of quietly falling back to another
identity.

## 5. Apps and stacks across repositories

### An app repository is its app.yaml and one call

An app repository needs everything factory does for an app (publish on
merge, reproduce, rebase onto new run images, propose lock updates and
rebuilds, renew its evidence, and refresh the estate's report) but none of
it varies between apps. `app.yml` does all of it in one call, choosing what
to run from the event, so the repository holds its `app.yaml`, its org
profile, and a short caller (`clearcutt-factory init --app` writes all
three, [below](#init-for-a-platform-its-apps-and-its-estate)):

```yaml
name: factory
on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: "23 6 * * 1" # weekly: every input (app.yml's weekly input)
    - cron: "41 5 * * *" # daily: rebase, rebuild on new build images, rescan
  workflow_dispatch:
  repository_dispatch:
    types: [clearcutt.run-image-published, clearcutt.build-image-published, clearcutt.stack-published, clearcutt.profile-published]
permissions:
  contents: read
jobs:
  app:
    uses: northcutted/clearcutt-factory/.github/workflows/app.yml@v0.4.1
    permissions: {contents: write, pull-requests: write, packages: write, id-token: write, attestations: write}
    with:
      estate: estate # the estate repository to refresh; omit for none
    secrets:
      CLEARCUTT_APP_PRIVATE_KEY: ${{ secrets.CLEARCUTT_APP_PRIVATE_KEY }}
      CLEARCUTT_BOT_TOKEN: ${{ secrets.CLEARCUTT_BOT_TOKEN }}
```

| Event | What runs |
|---|---|
| pull request, merge queue | `images.yml`: build, smoke-test, scan, gate (only the manifests it affects) |
| push to the default branch | `images.yml` publishes; then `fleet.yml`, while `images.yml` reproduces on a second runner |
| the weekly schedule (the `weekly` input's cron) | `update-locks.yml`, every input |
| any other schedule (daily) | `fleet.yml`, `update-locks.yml` with `update: stack`, and `reattest.yml` |
| `clearcutt.run-image-published` | `fleet.yml` |
| `clearcutt.build-image-published`, `clearcutt.stack-published` | `update-locks.yml` with `update: stack` |
| `clearcutt.profile-published` | `update-locks.yml`, every input |
| `workflow_dispatch` | what the `run` input names (or the dispatch's own `run` input, when the caller declares one): `images`, `fleet`, `update-locks`, `reattest`, or `all` (images, fleet, and update-locks; the default) |

With `estate`, it then sends `clearcutt.estate-changed` to the estate
repository once the app was published and reproduced, or rebased (not on
pull requests or schedules: the estate's daily run follows those). Its
other inputs are those of the workflows it calls: `manifests` (default
`**/app.yaml`), `registry`, `changed-only` (default `true`), `publish-ref`,
`auto-merge` (`pin`, `rebuild`, `update`, or `all`, handed to each workflow
in its own kinds), `reattest` and `older-than`, `provenance`, `app-id`,
`factory-version`, and the OIDC login inputs; its secrets, the four the
others take. Branch protection requires `app / images / result` (the
caller's job name, then `images / result`). Images are signed by
`images.yml`, `fleet.yml`, and `reattest.yml` as when they are called
directly, so the signer identity needn't change.

### Platform stacks

A platform team publishes stacks once:

```sh
clearcutt-factory stack push -f stacks/go.yaml --ref ghcr.io/acme/stacks/go:1
```

Build and run images given as factory manifests (`run: ../go-runtime/image.yaml`)
are resolved to their published references before pushing, and the stack is
signed. The build image is pinned by the digest its tag holds at that
moment (`ghcr.io/acme/build-go:1@sha256:…`), so push stacks after the
images workflow has published, and a rebuilt build image (a Go or npm
fix, say) makes the next `stack push` publish a new stack; the run image
is named by tag, since apps follow it by rebasing. A stack is published
by its content, so pushing an unchanged one
again only moves the tag, once the org's stack signer (`signing.stacks`,
below) has signed it: a workflow can run `stack push` on every change
without piling up signatures. App repositories name it by reference:

```yaml
kind: App
metadata: {name: billing}
spec:
  stack: ghcr.io/acme/stacks/go:1
```

The app's lock pins the stack's digest, so a moved tag changes nothing until
`clearcutt-factory lock --update` (the weekly job) proposes it. Set
`policy.requireSignedStacks: true` to accept only stacks signed by
`signing.stacks` (the platform repository's identity; `signing.verify` when
unset). Every command that uses the stack (`lock`, `render`, `build`,
`verify`, `rebase`) checks the version the lock pins, so a pull request that
edits the lock to an unsigned version fails CI too.

### Waking the apps when the platform publishes

Each app repository's daily fleet job picks up a new run image on its own.
To have it happen minutes after the platform publishes:

```
platform: images.yml ─┬▶ notify.yml ─repository_dispatch─▶ each repository with the topic clearcutt-app
                      └▶ images.yml with published: reproduce on a second runner, meanwhile
  clearcutt.run-image-published   ─▶ fleet.yml: rebase onto the new run image, then the pin pull request
  clearcutt.build-image-published ─▶ update-locks.yml (update: stack): a pull request rebuilding the app
  clearcutt.stack-published       ─▶   on the stack's newest build (and run) image, "Rebuild … on the newest build image"
  clearcutt.profile-published     ─▶ update-locks.yml (update: all): a pull request moving the lock to the new profile
```

A published image is a build image or a run image by what the platform
repository's stacks make of it (`spec.build` or `spec.run` naming its
manifest; `clearcutt-factory roles -f image.yaml` prints it, and
`images.yml` records it as `roles` in its `published` output); an image no
stack names is announced as a run image, and one that is both gets both
events.

Which event moves an app to a rebuilt build image depends on how its stack
names it. A stack published with `stack push` pins its build image by
digest, so an app on it moves when the stack does: the
`clearcutt.stack-published` that follows the platform's next `stack push`
(push stacks after the images, as below), not the
`clearcutt.build-image-published` before it, which finds the app's stack
unchanged and proposes nothing. An app whose own stack file names the
build image by reference (`build: ghcr.io/acme/build-go:1`) moves on
`clearcutt.build-image-published` itself.

1. **Tag the app repositories** with the topic `clearcutt-app` (the
   repository's About settings). `notify.yml`'s `topic` and `owner` inputs
   change the search, and `repositories` names dependents outright (topic
   search can lag a change by a few minutes).
2. **Give the platform repository an identity that can write to them:** the
   GitHub App installed on them too ([above](#a-github-app-for-the-automation)),
   or a `CLEARCUTT_BOT_TOKEN` with Contents read and write on each.
   `GITHUB_TOKEN` can't dispatch to other repositories.
3. **That's all for images and apps:** `init`'s workflow has the `notify`
   job (sending, for the images `images.yml` reports in its `published`
   output) and answers every event (receiving). The payload,
   `{image, repository, digest, tags, roles, source}` (`roles` for images:
   `build` and/or `run`), is advisory: the jobs it
   starts re-resolve tags from the registry and verify signatures as they do
   on their schedules, so a stale or forged dispatch starts a run that
   changes nothing. That is also why `notify` needn't wait for the
   second-runner reproduction. A job that uses `images.yml` ends only when
   every job in it has, so a workflow of your own calls it with
   `reproduce: false`, and again, beside `notify`, with the first call's
   `published` output, which only reproduces, as `init`'s does. Jobs that
   read the reproduction attestations (an estate report, say) need
   `reproduce` too:

```yaml
  images:
    uses: northcutted/clearcutt-factory/.github/workflows/images.yml@v0.4.1
    permissions: {contents: read, packages: write, id-token: write, attestations: write}
    with:
      reproduce: false
      changed-only: true # a pull request builds only the images it affects

  reproduce:
    needs: images
    if: ${{ !cancelled() && needs.images.outputs.published != '[]' && needs.images.outputs.published != '' }}
    uses: northcutted/clearcutt-factory/.github/workflows/images.yml@v0.4.1
    permissions: {contents: read, packages: write, id-token: write, attestations: write}
    with:
      published: ${{ needs.images.outputs.published }} # only reproduce what images published

  notify-images:
    needs: images # not reproduce: the apps verify what they are sent
    if: ${{ !cancelled() && github.event_name == 'push' && needs.images.outputs.published != '[]' && needs.images.outputs.published != '' }}
    uses: northcutted/clearcutt-factory/.github/workflows/notify.yml@v0.4.1
    permissions: {contents: read}
    with:
      published: ${{ needs.images.outputs.published }}
    secrets:
      CLEARCUTT_APP_PRIVATE_KEY: ${{ secrets.CLEARCUTT_APP_PRIVATE_KEY }}
      CLEARCUTT_BOT_TOKEN: ${{ secrets.CLEARCUTT_BOT_TOKEN }}
```

   On the receiving side, a workflow of your own answers
   `clearcutt.build-image-published` and `clearcutt.stack-published` with
   `update-locks.yml`'s stack update, which proposes the rebuild and nothing
   else, and runs it daily too, so a dispatch that was missed costs a day
   rather than a week (the weekly `update: all` pull request carries the
   same images with everything else; merging either lets the other close at
   its next run):

```yaml
on:
  schedule:
    - cron: "23 6 * * 1" # weekly: every input
    - cron: "41 5 * * *" # daily: the stack and its images, in case a dispatch was missed
  workflow_dispatch:
  repository_dispatch:
    types: [clearcutt.run-image-published, clearcutt.build-image-published, clearcutt.stack-published, clearcutt.profile-published]
jobs:
  update-locks:
    if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch' || github.event.action == 'clearcutt.build-image-published' || github.event.action == 'clearcutt.stack-published' || github.event.action == 'clearcutt.profile-published'
    uses: northcutted/clearcutt-factory/.github/workflows/update-locks.yml@v0.4.1
    permissions: {contents: write, pull-requests: write}
    with:
      update: ${{ (github.event.schedule == '41 5 * * *' || github.event.action == 'clearcutt.build-image-published' || github.event.action == 'clearcutt.stack-published') && 'stack' || 'all' }}
    secrets:
      CLEARCUTT_APP_PRIVATE_KEY: ${{ secrets.CLEARCUTT_APP_PRIVATE_KEY }}
      CLEARCUTT_BOT_TOKEN: ${{ secrets.CLEARCUTT_BOT_TOKEN }}
```

4. **Stacks** are pushed by a job of your own, after the images (a stack
   pins its build image by the digest the tag holds when it is pushed, so
   before the images job has published it would pin the old one), so hand
   `notify.yml` what it pushed (`stack push` writes `image`, `repository`,
   `digest`, and `published` to `$GITHUB_OUTPUT`; `published` is `false`
   when the stack was unchanged and only its tag moved):

```yaml
  stacks:
    needs: images # the build images it pins are published
    if: ${{ !cancelled() && needs.images.result != 'skipped' && github.event_name == 'push' }}
    runs-on: ubuntu-latest
    permissions: {contents: read, packages: write, id-token: write}
    outputs:
      published: ${{ steps.push.outputs.published == 'true' && format('[{{"kind":"stack","image":"{0}","digest":"{1}"}}]', steps.push.outputs.image, steps.push.outputs.digest) || '[]' }}
    steps:
      - uses: actions/checkout@v7
      - uses: northcutted/clearcutt-factory@v0.4.1
        with: {tools: "false"}
      - uses: docker/login-action@v4
        with: {registry: ghcr.io, username: "${{ github.actor }}", password: "${{ github.token }}"}
      - id: push
        run: clearcutt-factory stack push -f stacks/go.yaml --ref ghcr.io/acme/stacks/go:1

  notify-stacks:
    needs: stacks
    if: needs.stacks.outputs.published != '[]'
    uses: northcutted/clearcutt-factory/.github/workflows/notify.yml@v0.4.1
    permissions: {contents: read}
    with:
      published: ${{ needs.stacks.outputs.published }}
    secrets:
      CLEARCUTT_APP_PRIVATE_KEY: ${{ secrets.CLEARCUTT_APP_PRIVATE_KEY }}
      CLEARCUTT_BOT_TOKEN: ${{ secrets.CLEARCUTT_BOT_TOKEN }}
```

Dispatches queue behind any fleet or lock-update run already going in the
app repository, so a burst of them costs at most one more run.

### Only the apps built on it

The topic wakes every app repository for every publish. When the
organization runs [clearcutt-verify](https://github.com/northcutted/clearcutt-verify)
over its estate (as `init --estate` sets up), `notify.yml` can ask the
estate's report instead which images are built on a run image, proven by
layer digest (`clearcutt-verify estate dependents`), and wake only the
repositories they come from:

```yaml
  notify-images:
    needs: images
    if: ${{ !cancelled() && github.event_name == 'push' && needs.images.outputs.published != '[]' && needs.images.outputs.published != '' }}
    uses: northcutted/clearcutt-factory/.github/workflows/notify.yml@v0.4.1
    permissions: {contents: read}
    with:
      published: ${{ needs.images.outputs.published }}
      estate-report: ghcr.io/acme/estate:latest # the bundle the estate workflow pushes
      estate-report-signer: https://github.com/acme/estate/.github/workflows/estate.yml@refs/heads/main
    secrets:
      CLEARCUTT_APP_PRIVATE_KEY: ${{ secrets.CLEARCUTT_APP_PRIVATE_KEY }}
      CLEARCUTT_BOT_TOKEN: ${{ secrets.CLEARCUTT_BOT_TOKEN }}
```

The bundle is pulled anonymously (a public package) and read only once its
signature verifies against `estate-report-signer`. A dependent's repository
is its image's source (verified provenance where there is any, else its
`org.opencontainers.image.source` label), and must be one of the owner's.
The topic search stays for what has no layer relation to an app (build
images, stacks, profiles), and for a run image the report can't answer for,
with a warning naming the image and why: the bundle can't be pulled or
verified; no image in the report is built on the run image, or none by
layer digest; or a dependent names no repository of the owner. An empty
answer never wakes nothing: `estate dependents` lists nothing, and
succeeds, for a base the report doesn't know, as when the estate's
`refs.txt` lists the platform's images but not the apps' (as `init
--estate` writes it). So add each app's image to the estate's `refs.txt`
as it starts publishing (`init --app` says which). An app the report
doesn't list yet, while it lists others built on the same run image (it
joined after the estate's last run), isn't woken; its daily fleet run
catches up.

`estate: NAME` (or `OWNER/NAME`) also sends `clearcutt.estate-changed`
(`{source, sha}`) to the estate repository when `published` lists anything,
apps included, or `changed: true` says something else changed (a rebase),
so its report and portal refresh now rather than at the next scheduled run.
`app.yml` does this for an app repository with its `estate` input.

## 6. One org profile for every repository

Without this, each app repository carries its own copy of the platform
team's `factory.org.yaml`. Copies drift, and an app repository can weaken its
copy (drop `failOn:`, turn off `requireSignedStacks`) in the same pull
request as its code. Instead, the platform team publishes one signed profile,
and app repositories extend it.

| Who | Owns | What it says |
|---|---|---|
| Platform team, with security | The shared profile, published with `profile push` | The builder, how images are signed and whom to trust, the vulnerability gate, policy, mirrors, VEX statements for every repository, and whatever else should be the same everywhere |
| Each app repository | Its `factory.org.yaml`, which `extends` the shared one | Who may sign the shared profile, plus what the shared profile leaves to each repository (usually the registry and who signs this repository's images), and any tightening of the gate and policy |

**Publish it** from the platform repository. Keep the shared profile in a
file of its own: it leaves out what differs per repository, which the
platform repository's own `factory.org.yaml` sets (it extends the shared
profile by path; [below](#the-platform-repository-extends-it-by-path)).

```yaml
# org/profile.yaml: what every repository shares
apiVersion: factory.clearcutt.dev/v1alpha1
kind: OrgProfile
builder:
  buildkit: moby/buildkit:v0.33.1
signing:
  mode: keyless
  trustPolicy: trust.yaml            # image and stack signers, shared with clearcutt-verify
  profile:                           # who signs this profile (profile push checks it)
    certificateIdentity: https://github.com/acme/platform/.github/workflows/profile.yml@refs/heads/main
    certificateOIDCIssuer: https://token.actions.githubusercontent.com
vulnerabilities:
  failOn: critical
  onlyFixed: true
  vex: [../vex/2026-10.openvex.json] # applied to every repository's scans (image products apply to their image only)
policy:
  requireNonRoot: true
  requireSignedStacks: true
  requiredLabels: [org.opencontainers.image.source]
  allowedRegistries: [cgr.dev/chainguard/, ghcr.io/acme/]
```

```sh
clearcutt-factory profile push -f org/profile.yaml --ref ghcr.io/acme/factory/org:1
```

The artifact (type `application/vnd.clearcutt.factory.org-profile.v1`)
holds the profile and the files it names, renamed inside it: the trust
policy, public keys, and VEX documents. It is signed as stacks are
(`--key`, else `signing.stackKey` in key mode, else as images are signed).
Like `stack push`, it is published by its content: pushing an unchanged
profile that `signing.profile` has signed only moves the tag, and it writes
`image`, `repository`, `digest`, and `published` to `$GITHUB_OUTPUT`. Hand
`notify.yml` `[{"kind":"profile", "image": …, "digest": …}]` to send
`clearcutt.profile-published`, which `init`'s workflow answers with a
lock-update pull request.

A shared profile can't extend another, set `builder.runtime`, `addr`,
`config`, or `network` (they describe the machine that builds; each
repository sets its own), or name a private key file in `signing.key` or
`stackKey` (a KMS key is fine). With `policy.requireSignedStacks` it must
name the stack signer itself.

**Extend it** in each app repository (`clearcutt-factory init --extends
ghcr.io/acme/factory/org:1 --extends-identity …` writes this, after checking
the signature):

```yaml
apiVersion: factory.clearcutt.dev/v1alpha1
kind: OrgProfile
extends:
  ref: ghcr.io/acme/factory/org:1
  signer:              # who may sign the shared profile
    certificateIdentity: https://github.com/acme/platform/.github/workflows/profile.yml@refs/heads/main
    certificateOIDCIssuer: https://token.actions.githubusercontent.com
registry: ghcr.io/acme/checkout       # what the shared profile leaves to each repository
signing:
  verify:
    certificateIdentityRegexp: ^https://github\.com/northcutted/clearcutt-factory/\.github/workflows/(images|fleet|reattest)\.yml@refs/tags/v\d+\.\d+\.\d+$
    certificateOIDCIssuer: https://token.actions.githubusercontent.com
    sourceRepository: https://github.com/acme/checkout
    sourceRef: refs/heads/main
vulnerabilities:
  failOn: high         # stricter than the shared critical: allowed
```

**Who may sign it is stated here, never in the shared profile.** The shared
profile names every other signer (of images and stacks) and sets the gate,
so whoever can publish it controls what the repository accepts. A profile
that named its own signer would vouch for itself: anyone who can push to the
tag could publish one naming themselves. `extends.signer` is a signer like
`signing.verify` (a key, or a certificate identity and issuer), reviewed in
the app repository like any other change; protect `factory.org.yaml` with
CODEOWNERS. It isn't a role in a local trust policy: the trust policy is
part of what the shared profile provides, and its roles (`image`, `stack`,
and `estate`, clearcutt-verify's report signers, which factory reads past)
are shared with clearcutt-verify.

**Rotating the shared profile's signer.** `extends.signers` lists several
signers, any one of which may sign the shared profile (`signer` is the
same with one entry; set one or the other). To move to a new key, or to a
workflow that was moved or renamed, without changing every repository at
the moment of the switch:

1. Each repository lists the new signer beside the old one:

   ```yaml
   extends:
     ref: ghcr.io/acme/factory/org:1
     signers:
       - certificateIdentity: https://github.com/acme/platform/.github/workflows/profile.yml@refs/heads/main
         certificateOIDCIssuer: https://token.actions.githubusercontent.com
       - certificateIdentity: https://github.com/acme/platform/.github/workflows/publish-profile.yml@refs/heads/main
         certificateOIDCIssuer: https://token.actions.githubusercontent.com
   ```

2. The platform publishes with the new signer (and changes `signing.profile`
   to it). Locks pinning an older version still load, since the old signer
   signed it; `lock --update` moves them to a version the new one signed.
3. Once every lock pins a version the new signer signed, each repository
   drops the old signer. A version only the old signer signed then fails to
   load, so a leaked old key stops counting.

**Pinned, and checked on every load.** Each manifest's lock records the
digest the shared profile resolved to (`profile: {ref, digest}`), as it
does for a registry stack. Every command that loads the manifest (`lock`,
`render`, `build`, `verify`, `rebase`) uses that digest and checks its
signature against `extends.signer` (or `signers`), so an unsigned or
tampered profile, or one signed by someone else, fails closed, including in
a pull request that edits the lock. `lock` keeps the pin; `lock --update`
(the weekly job, or a `clearcutt.profile-published` notice) moves it, in a
pull request whose description names the new digest. Moving the pin alone
doesn't change the build timestamp, so images change only if what the
profile sets shapes them (the builder, labels). A lock that doesn't pin the
profile its org profile extends is stale. Commands without a manifest
(`verify --image`, `rebase --image`, `stack push`) follow the tag, checked
the same way.

**On your machine, a check counts for a day.** Outside CI, a successful
signature check is remembered for 24 hours in the user cache directory
(`clearcutt-factory/verified/`), per pinned digest and signer, so commands
don't run `cosign` (and reach the registry and the transparency log) on
every load, and a pinned profile loads offline. CI always checks: with
`CI=true` or `GITHUB_ACTIONS=true`, every load runs `cosign`, as do
`--reverify` and `CLEARCUTT_FACTORY_REVERIFY=1` anywhere
(`CLEARCUTT_FACTORY_REVERIFY=0` lets a CI job reuse checks). `init
--extends` always checks. Failures are never remembered. What is skipped
is only `cosign`:

* The profile itself is still read at the pinned digest, from the
  registry or from the cache (`clearcutt-factory/profiles/`), which keeps
  the artifact's manifest beside its files. A cached copy is used only
  after its manifest is checked against the digest and every file against
  the manifest; one that doesn't match is fetched again. A record can't
  make other content load: the digest names the content, and the record
  only says that a signer's signature was found on that digest.
* A record is the signer's, as written in `extends`, with a key file
  identified by its content. Changing or removing a signer, or replacing
  a key file in place, means checking again; a version only a removed
  signer signed fails at once.
* What a record can't notice for up to a day: a signature deleted from the
  registry, a KMS alias moved to another key, or a Sigstore trust root
  update. That is why CI, where images are published, checks every time.
* Someone who can write your cache directory can forge a record, but not
  change what loads at a pinned digest; and they can usually also change
  the programs you run.

Loading needs the registry and `cosign`, except for a pinned profile this
machine has cached and checked within the day.

**What a repository can and can't change.** A repository's profile may add
what the shared profile leaves unset and tighten its gate and policy.
Anything that would change or loosen the shared profile is an error naming
the field, not a silent override, so what the file says is what applies:

| Setting | Rule |
|---|---|
| `registry`, `tags`, `defaults.base`, `defaults.platforms`, `mirrors`, `signing.key`, `signing.stackKey`, `signing.args` | The shared profile's when it sets them (a repository may restate the same value), else the repository's |
| `defaults.labels` | Per label: as above; repositories add labels |
| `builder.buildkit`, `frontend`, `toolbox`, `go`, `nix`, `nixpkgs`; `signing.mode`; `vulnerabilities.scanner` | The shared profile's, or factory's default when it leaves them unset; never the repository's |
| `builder.runtime`, `addr`, `config`, `network` | The repository's only (the machine that builds) |
| `signing.trustPolicy` | The shared profile's only |
| `signing.verify` | The shared profile's if it sets it; else the repository's. Refused when the shared profile has a trust policy |
| `signing.stacks` | The shared profile's stack signer when it names one (`signing.stacks`, `signing.verify`, or its trust policy's stack signers); else the repository's |
| `signing.profile` | Only in a profile you publish |
| `vulnerabilities.failOn` | The repository may set a stricter (lower) severity, not a looser one |
| `vulnerabilities.onlyFixed`, `vulnerabilities.allowLocalVEX`, `policy.allowTOFU` | Can only turn off |
| `policy.requireNonRoot`, `policy.requireSignedStacks`, `policy.requireOfflineBuildTools`, `sbom.scan` | Can only turn on |
| `policy.requiredLabels` | Union |
| `policy.allowedHosts`, `policy.allowedRegistries` | The repository's list, when it sets one, must lie within the shared one (a host or `.suffix` the shared list allows; a registry or repository path at or below a shared one, by whole path segments) |
| `vulnerabilities.vex` | The shared profile's statements apply to every scan (a statement whose product is an image, `pkg:oci/…` by digest or `repository_url`, to that image only; see the README's [VEX statements are applied per image](../README.md#what-gets-attached-to-a-pushed-image)). The repository's (its profile's `vex` and its manifests' `spec.vex`) are refused unless the shared profile sets `vulnerabilities.allowLocalVEX: true`: a statement that a vulnerability doesn't apply lets an image past the gate |

Under a shared profile, `build --push` and `rebase --push` refuse
`--no-scan`, which would publish past its vulnerability gate; `--no-scan`
still works for builds that aren't pushed.

### The platform repository extends it by path

The platform repository builds images too (its stacks, its tools), under
the profile it publishes. Its own `factory.org.yaml` extends that file by
path, so it can't drift from what it publishes and works before the first
publish:

```yaml
# factory.org.yaml in the platform repository
apiVersion: factory.clearcutt.dev/v1alpha1
kind: OrgProfile
extends:
  path: org/profile.yaml             # relative to this file
registry: ghcr.io/acme/platform
```

The same merge rules apply as for a published profile. There is no signer
(`signer` or `signers` with `path` is an error, as is `path` with `ref`):
it is the repository's own file, reviewed with the rest of the
repository, so nothing is verified. The path, and every file the shared
profile names (trust policy, keys, VEX), must be inside the repository: the
directory holding `.git` above `factory.org.yaml`, or `factory.org.yaml`'s
own directory outside a git checkout.

Each manifest's lock pins it as `profile: {path, digest}`. The digest is
the one `profile push` publishes the profile at, computed the same way
(the profile and the files it names, packed as one artifact), so it covers
the files the profile names as well as the profile, and once published it
equals the published digest. When the profile or one of its files changes,
the lock is stale until `lock` pins the new digest; `lock` (unlike for a
published profile, whose pin only `lock --update` moves) always pins the
file as it is.

## Who signs, and binding signatures to your repository

The reusable workflows sign inside ClearCutt Factory's workflows, so the
certificate's identity is the called workflow
(`https://github.com/northcutted/clearcutt-factory/.github/workflows/images.yml@refs/tags/v0.4.1`),
not your repository. Anyone can call those workflows and get the same
identity, so an identity alone would accept images built in any repository.
The certificate also records the repository whose run signed (Fulcio's GitHub
workflow repository extension), and `sourceRepository` makes cosign require
it; and the ref the run was on, which `sourceRef` requires (so a run on
another branch can't sign a trusted image, should one ever publish). `init`
writes all three, with the origin remote's default branch (or
`--default-branch`):

```yaml
signing:
  mode: keyless
  verify:          # this repository's images
    certificateIdentityRegexp: ^https://github\.com/northcutted/clearcutt-factory/\.github/workflows/(images|fleet|reattest)\.yml@refs/tags/v\d+\.\d+\.\d+$
    certificateOIDCIssuer: https://token.actions.githubusercontent.com
    sourceRepository: https://github.com/acme/checkout
    sourceRef: refs/heads/main
  stacks:          # who may sign the stacks apps here build on
    certificateIdentity: https://github.com/acme/platform/.github/workflows/stacks.yml@refs/heads/main
    certificateOIDCIssuer: https://token.actions.githubusercontent.com
```

`sourceMatchesImage: true` instead requires the run to be in the repository
the image names as its source (`org.opencontainers.image.source`), and
`sourceRepositoryOwner` limits that to one owner's repositories. These
bind images only: a stack names no source, so a stack
signer names its repository with `sourceRepository` (or is a workflow in it,
as above), and with `policy.requireSignedStacks` a stack signer with
`sourceMatchesImage` is an error.

**Pinning factory's workflows by commit.** The regexp `init` writes accepts
the signing workflows at a release tag only (`@refs/tags/v\d+\.\d+\.\d+$`).
Calling `images.yml`, `fleet.yml`, or `reattest.yml` by commit SHA changes
the identity's `@…` suffix to that commit. (`app.yml` at a release, by its
tag or its commit, calls them at the release's tag, so pinning `app.yml`
by SHA needs nothing here.) `init --allow-commit-pins` writes
`@(refs/tags/v\d+\.\d+\.\d+|[0-9a-f]{40})$` instead, but a pattern that
accepts any commit accepts commits nobody reviewed: GitHub resolves
`northcutted/clearcutt-factory/…@<sha>` for a commit anywhere in the
repository's fork network (an *impostor commit*), so anyone can push a
modified workflow to a fork and sign as "factory's `images.yml`" at that
commit. The source constraints still require the run to be in one of your
repositories on the publishing branch, so it takes a change merged there to
call one; but the workflow's identity then proves nothing about the code
that signed. Name the exact commits you pin instead of the pattern:
`…\.yml@(refs/tags/v\d+\.\d+\.\d+|1a2b3c…40 hex…)$`, one alternative per
pinned commit, added in the same pull request that moves the pin.

`sourceRepositoryOwner` is read as clearcutt-verify reads it: exactly
`https://github.com/OWNER`, and the repository it resolves to (the image's
source, with `sourceMatchesImage`) must be one of the owner's, which cosign
is then held to. clearcutt-verify also accepts it alone, reading the
repository from each certificate; factory, which hands cosign the signer as
written, needs `sourceMatchesImage` (or `sourceRepository`) with it and
skips a signer that has neither.

**With keys.** In key mode, `signing.key` signs images and
`signing.stackKey` signs stacks (default: `signing.key`), so a platform's
stacks can have a signer of their own; `signing.verify.key` and
`signing.stacks.key` are the public halves. `stack push --key` signs with
another key (a file or KMS URI) whatever `signing.mode` says:

```yaml
signing:
  mode: key
  key: awskms:///alias/images         # signs images
  stackKey: awskms:///alias/stacks    # signs stacks (stack push)
  verify: {key: keys/images.pub}
  stacks: {key: keys/stacks.pub}
```

**Without a transparency log.** A key that signs without a transparency
log (a private or offline setup) gets a cosign signing config that names
no log, instead of cosign 2's `--tlog-upload=false`, which cosign 3
deprecates. Verifiers then accept that key's evidence without a log entry
when its signer says `tlog: false`:

```sh
cosign signing-config create --out cosign/no-tlog.json   # no services: no Rekor, no timestamp authority
```

```yaml
signing:
  mode: key
  key: awskms:///alias/images
  args: [--signing-config, cosign/no-tlog.json]   # passed to cosign as is: relative to the working directory
  verify: {key: keys/images.pub, tlog: false}      # cosign --insecure-ignore-tlog, for this key only
```

`tlog: false` means the same in a trust policy's signers (clearcutt-verify
reads it too), and `verify --image --key K --insecure-ignore-tlog` passes it
on the command line. Keyless signers can't set it: a certificate is only
valid with a log entry that shows it was used in time. Nothing shows when
key-signed evidence without one was made, so set it only for keys that
never log. A private Sigstore with its own services gets a signing config
naming them (`cosign signing-config create --fulcio … --rekor …`).

**One trust policy for the organization.** Instead of `verify` and `stacks`,
`signing.trustPolicy` can name a ClearCutt trust policy, the same file
[clearcutt-verify](https://github.com/northcutted/clearcutt-verify) reads to
check the estate
([schema](https://github.com/northcutted/clearcutt-verify/blob/main/contract/trust-policy.v1.schema.json)):

```yaml
apiVersion: clearcutt.dev/v1
kind: TrustPolicy
signers:
  - name: factory-builds              # images (the default role)
    identityRegexp: ^https://github\.com/northcutted/clearcutt-factory/\.github/workflows/(images|fleet|reattest)\.yml@refs/tags/v\d+\.\d+\.\d+$
    issuer: https://token.actions.githubusercontent.com
    sourceRepositoryOwner: https://github.com/acme   # a run in one of acme's repositories,
    sourceMatchesImage: true                         # the one the image names as its source,
    sourceRef: refs/heads/main                       # on main
  - name: platform-stacks
    roles: [stack]
    identity: https://github.com/acme/platform/.github/workflows/stacks.yml@refs/heads/main
    issuer: https://token.actions.githubusercontent.com
```

A signer's `key:` file is relative to the trust policy, as keys in `signing`
are relative to the org profile.

## The reusable workflows

Call them from your own workflow, pinned to a release. `images.yml`,
`update-locks.yml`, and `fleet.yml` take a `factory-version` input (default:
their own release). Pass the optional secrets above by name, as `init`'s
workflow does: `secrets: inherit` reaches only workflows in your own
organization or enterprise. Variables (`CLEARCUTT_APP_ID`) are read from the
calling repository. `images.yml`'s output `published` is what the run newly
published: a JSON array of `{manifest, kind (image or app), image
(repository@digest), repository, digest, tags, roles}` (`roles`: `build`
and/or `run` for an image, as the stacks name it; `[]` for none), `[]` on
pull requests.
It arrives when the whole workflow is done. With `reproduce: false` the run
publishes without reproducing, and a second call given its `published` builds
nothing and only reproduces what that lists, so jobs that need only the
output start right after the images are published
([above](#waking-the-apps-when-the-platform-publishes)).

| Workflow | Inputs | Secrets | Caller permissions |
|---|---|---|---|
| `images.yml` | `manifests` (globs, default `**/image.yaml **/app.yaml`), `registry`, `provenance`, `reproduce` (default `true`), `published` (only reproduce this), `changed-only` (default `false`: on a pull request, only the manifests it affects; [above](#pull-requests-build-what-they-change)), `publish-ref`, the OIDC login inputs ([above](#registries-in-a-cloud-without-a-stored-secret)) | `REGISTRY_USERNAME`, `REGISTRY_PASSWORD` | `contents: read`, `packages: write`, `id-token: write`, `attestations: write` |
| `update-locks.yml` | `manifests`, `update` (`all`, default, or `stack`: apps only, the stack and its build and run images, as a rebuild pull request), `app-id`, `auto-merge` (`update`, `rebuild`, or `all`) | `CLEARCUTT_APP_PRIVATE_KEY`, `CLEARCUTT_BOT_TOKEN` | `contents: write`, `pull-requests: write` |
| `fleet.yml` | `apps` (default `**/app.yaml`), `registry`, `provenance`, `app-id`, `auto-merge` (`pin`, `rebuild`, or `all`), the OIDC login inputs | `CLEARCUTT_APP_PRIVATE_KEY`, `CLEARCUTT_BOT_TOKEN`, `REGISTRY_USERNAME`, `REGISTRY_PASSWORD` | `contents: write`, `pull-requests: write`, `packages: write`, `id-token: write`, `attestations: write` |
| `reattest.yml` | `manifests`, `registry`, `older-than` (default `6d`), `reproduce` (default `true`), `publish-ref`, the OIDC login inputs | `REGISTRY_USERNAME`, `REGISTRY_PASSWORD` | `contents: read`, `packages: write`, `id-token: write` |
| `app.yml` | `manifests` (default `**/app.yaml`), `estate`, `registry`, `changed-only` (default `true`), `publish-ref`, `auto-merge` (`pin`, `rebuild`, `update`, `all`), `weekly` (default `23 6 * * 1`), `run`, `reattest` (default `true`), `older-than`, `provenance`, `app-id`, the OIDC login inputs ([above](#an-app-repository-is-its-appyaml-and-one-call)) | all four | `contents: write`, `pull-requests: write`, `packages: write`, `id-token: write`, `attestations: write` |
| `notify.yml` | `published` (required), `topic` (default `clearcutt-app`), `owner`, `repositories`, `app-id`, `estate-report` and `estate-report-signer` (a run image's dependents by layer digest, [above](#only-the-apps-built-on-it)), `estate` and `changed` (send `clearcutt.estate-changed`) | `CLEARCUTT_APP_PRIVATE_KEY`, `CLEARCUTT_BOT_TOKEN` | `contents: read` |

`reattest.yml` renews published images' evidence on a schedule: each
platform image's signed SBOM is scanned again with grype's newest database
and the new vulnerability report attached to the same digest, and an image
without a verified reproduction attestation is reproduced and the match
attested; nothing is rebuilt or retagged
([README](../README.md#renewing-the-evidence)). `init`'s workflow runs it
daily with `older-than: 6d`, which renews each report about weekly; a
caller of your own:

```yaml
on:
  schedule:
    - cron: "41 5 * * *"
jobs:
  reattest:
    uses: northcutted/clearcutt-factory/.github/workflows/reattest.yml@v0.4.1
    permissions: {contents: read, packages: write, id-token: write}
```

Its signatures name `reattest.yml`, so the org profile's image signer (or
the trust policy's `image` signers) must match it:
`certificateIdentityRegexp` with `(images|fleet|reattest)`, as `init` writes
it. clearcutt-verify reads the newest verified report, so the estate's scan
age follows.

For workflows of your own, the action installs a signature-verified binary
plus cosign, syft, and grype:

```yaml
- uses: northcutted/clearcutt-factory@v0.4.1
- run: clearcutt-factory build -f images/example/image.yaml
```

Pinned by commit (`uses: northcutted/clearcutt-factory@<40-hex SHA>`), it
installs the release whose tag points at exactly that commit, and its
signature must come from the release workflow running at that commit
(`cosign verify-blob --certificate-github-workflow-sha`), so a tag moved or
added later can't hand it another commit's binary. A commit no release tag
points at is built from source at that commit (Go, from the action's own
checkout), with a notice in the run's log saying so: pin a release's commit
to get its signed binary. If the repository's tags can't be listed, the step
fails rather than building from source.

## Other CI systems

Nothing is GitHub-specific except the workflows. The same commands run anywhere
Docker or Podman does:

```sh
clearcutt-factory render -f $M --check           # lock and Containerfile are current
clearcutt-factory build  -f $M --push            # build, test, scan, gate, push, sign, attest
clearcutt-factory verify --image $IMAGE          # second machine: rebuild from the signed recipe
clearcutt-factory lock   -f $M --update          # scheduled: propose updates
clearcutt-factory rebase -f $APP --push --update-lock   # scheduled: keep apps on the newest base
```

For keyless signing elsewhere, set `signing.verify` to your CI's OIDC
identity (the `source…` fields are GitHub Actions only); or sign with a key (`signing.mode: key`, a file or any cosign KMS
URI). `builder.addr` points builds at an existing BuildKit (in Kubernetes,
say) instead of starting a container.

### A registry on this machine

BuildKit runs in a container, where `localhost` is the container itself, so
a base in a registry on your machine (`localhost:5000/platform/run-go`, say)
can't be pulled in a build, though `lock`, cosign, and the scanners reach
it. Two settings in the org profile give the BuildKit container what it
needs:

```yaml
builder:
  network: host               # Linux: share the host's network, so localhost is the host
  config: buildkitd.toml      # relative to this profile; mounted as /etc/buildkit/buildkitd.toml
```

BuildKit already talks plain HTTP to `localhost` and `127.0.0.1`. With
Docker Desktop or a Podman machine (macOS, Windows), containers run in a VM
whose host network isn't your machine's, so instead mirror the registry to
the address the VM gives your machine, over HTTP:

```toml
# buildkitd.toml
[registry."localhost:5000"]
  mirrors = ["host.containers.internal:5000"]   # Docker Desktop: host.docker.internal
[registry."host.containers.internal:5000"]
  http = true
```

The same file takes other registry settings (`insecure`, `ca`, pull-through
mirrors); see BuildKit's
[buildkitd.toml reference](https://docs.docker.com/build/buildkit/toml-configuration/).
Neither setting changes what is built: every input is pinned by digest. With
`builder.addr`, configure that buildkitd instead.

## Governing what you built

[clearcutt-verify](https://github.com/northcutted/clearcutt-verify) reads
the images back: which images are built on which, how stale each one is, and
what can be proven about them. It verifies factory's signatures, SBOM,
vulnerability, recipe, and rebase attestations against the same trust policy,
can rebuild each image with `clearcutt-factory verify --image`, and lists the
images built on a base (`estate dependents`) so a platform repository can wake
exactly the apps a new run image affects.
[clearcutt-portal](https://github.com/northcutted/clearcutt-portal) publishes
its report as a website.

Re-attestation checks its newly attached report against the image signers.
An existing adopter must trust `reattest.yml` before enabling its schedule;
otherwise the command fails with the regexp change to make. A previous
trusted scan cannot satisfy that check. The lock `contentDigest` catches
accidental edits; it is not a signature. Review legacy pins before stamping
them, and review all lock changes like code.
