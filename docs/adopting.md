# Adopting ClearCutt Factory

This guide takes a repository from nothing to signed, reproducible images that
keep themselves current. It assumes GitHub Actions and a GitHub container
registry; [Other CI systems](#other-ci-systems) covers the rest.

## 1. Install

Download a release binary for Linux or macOS from
[Releases](https://github.com/northcutted/clearcutt-factory/releases) and
check its signature, made by the release workflow at that tag:

```sh
v=v0.3.0 asset=clearcutt-factory-darwin-arm64
curl -fsSLO https://github.com/northcutted/clearcutt-factory/releases/download/$v/$asset
curl -fsSLO https://github.com/northcutted/clearcutt-factory/releases/download/$v/$asset.sigstore.json
cosign verify-blob --bundle $asset.sigstore.json \
  --certificate-identity https://github.com/northcutted/clearcutt-factory/.github/workflows/release.yml@refs/tags/$v \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com $asset
install -m 0755 $asset /usr/local/bin/clearcutt-factory
```

Or build it: `go install github.com/northcutted/clearcutt-factory/cmd/clearcutt-factory@v0.3.0`.

Building needs Docker or Podman (BuildKit runs in a container). Scanning and
signing need `syft`, `grype`, and `cosign` on `PATH`.

## 2. Scaffold

In your repository:

```sh
clearcutt-factory init
```

It writes three files and keeps any that exist (`--force` overwrites):

| File | What it is |
|---|---|
| `factory.org.yaml` | Your registry (default `ghcr.io/<owner>`), signer identity (keyless: ClearCutt Factory's reusable workflows, bound to runs in this repository; see [Who signs](#who-signs-and-binding-signatures-to-your-repository)), vulnerability gate, and policy |
| `images/example/image.yaml` | An example image to replace |
| `.github/workflows/clearcutt-factory.yml` | Calls the reusable workflows: build, test, and scan on pull requests; publish on the default branch; weekly lock updates; daily app rebases; across repositories, notify dependents of what it published and answer such notices ([below](#waking-the-apps-when-the-platform-publishes)) |

`--repo owner/name`, `--registry`, and `--default-branch` override what it
reads from the `origin` remote (the branch is the one the signer identity
requires, as `sourceRef`). In an app repository of an organization that publishes a shared org
profile, `--extends REF --extends-identity ID` (or `--extends-key K`) checks
that profile's signature and writes a `factory.org.yaml` that extends it
([section 6](#6-one-org-profile-for-every-repository)). Every file names its JSON Schema, so editors with the YAML language
server complete and check fields as you type.

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
   input and add `REGISTRY_USERNAME` and `REGISTRY_PASSWORD` secrets.

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
  clearcutt.run-image-published ─▶ fleet.yml: rebase onto the new run image, then the pin pull request
  clearcutt.stack-published     ─▶ update-locks.yml: a pull request moving the lock to the new stack
```

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
   output) and answers both events (receiving). The payload,
   `{image, repository, digest, tags, source}`, is advisory: the jobs it
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
    uses: northcutted/clearcutt-factory/.github/workflows/images.yml@v0.3.0
    permissions: {contents: read, packages: write, id-token: write, attestations: write}
    with:
      reproduce: false

  reproduce:
    needs: images
    if: ${{ !cancelled() && needs.images.outputs.published != '[]' && needs.images.outputs.published != '' }}
    uses: northcutted/clearcutt-factory/.github/workflows/images.yml@v0.3.0
    permissions: {contents: read, packages: write, id-token: write, attestations: write}
    with:
      published: ${{ needs.images.outputs.published }} # only reproduce what images published

  notify-images:
    needs: images # not reproduce: the apps verify what they are sent
    if: ${{ !cancelled() && github.event_name == 'push' && needs.images.outputs.published != '[]' && needs.images.outputs.published != '' }}
    uses: northcutted/clearcutt-factory/.github/workflows/notify.yml@v0.3.0
    permissions: {contents: read}
    with:
      published: ${{ needs.images.outputs.published }}
    secrets:
      CLEARCUTT_APP_PRIVATE_KEY: ${{ secrets.CLEARCUTT_APP_PRIVATE_KEY }}
      CLEARCUTT_BOT_TOKEN: ${{ secrets.CLEARCUTT_BOT_TOKEN }}
```

4. **Stacks** are pushed by a job of your own, so hand `notify.yml` what it
   pushed (`stack push` writes `image`, `repository`, `digest`, and
   `published` to `$GITHUB_OUTPUT`; `published` is `false` when the stack was
   unchanged and only its tag moved):

```yaml
  stacks:
    if: github.event_name == 'push'
    runs-on: ubuntu-latest
    permissions: {contents: read, packages: write, id-token: write}
    outputs:
      published: ${{ steps.push.outputs.published == 'true' && format('[{{"kind":"stack","image":"{0}","digest":"{1}"}}]', steps.push.outputs.image, steps.push.outputs.digest) || '[]' }}
    steps:
      - uses: actions/checkout@v7
      - uses: northcutted/clearcutt-factory@v0.3.0
        with: {tools: "false"}
      - uses: docker/login-action@v4
        with: {registry: ghcr.io, username: "${{ github.actor }}", password: "${{ github.token }}"}
      - id: push
        run: clearcutt-factory stack push -f stacks/go.yaml --ref ghcr.io/acme/stacks/go:1

  notify-stacks:
    needs: stacks
    if: needs.stacks.outputs.published != '[]'
    uses: northcutted/clearcutt-factory/.github/workflows/notify.yml@v0.3.0
    permissions: {contents: read}
    with:
      published: ${{ needs.stacks.outputs.published }}
    secrets:
      CLEARCUTT_APP_PRIVATE_KEY: ${{ secrets.CLEARCUTT_APP_PRIVATE_KEY }}
      CLEARCUTT_BOT_TOKEN: ${{ secrets.CLEARCUTT_BOT_TOKEN }}
```

Dispatches queue behind any fleet or lock-update run already going in the
app repository, so a burst of them costs at most one more run.

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
  vex: [../vex/2026-10.openvex.json] # applied to every repository's scans
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
    certificateIdentityRegexp: ^https://github\.com/northcutted/clearcutt-factory/\.github/workflows/(images|fleet)\.yml@refs/tags/v\d+\.\d+\.\d+$
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
| `vulnerabilities.vex` | The shared profile's statements apply to every scan. The repository's (its profile's `vex` and its manifests' `spec.vex`) are refused unless the shared profile sets `vulnerabilities.allowLocalVEX: true`: a statement that a vulnerability doesn't apply lets an image past the gate |

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
(`https://github.com/northcutted/clearcutt-factory/.github/workflows/images.yml@refs/tags/v0.3.0`),
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
    certificateIdentityRegexp: ^https://github\.com/northcutted/clearcutt-factory/\.github/workflows/(images|fleet)\.yml@refs/tags/v\d+\.\d+\.\d+$
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
`sourceMatchesImage` is an error. Pinning the workflows by commit SHA changes
the identity's `@…` suffix: adjust the regexp to match.

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
    identityRegexp: ^https://github\.com/northcutted/clearcutt-factory/\.github/workflows/(images|fleet)\.yml@refs/tags/v\d+\.\d+\.\d+$
    issuer: https://token.actions.githubusercontent.com
    sourceRepositoryOwner: https://github.com/acme
    sourceMatchesImage: true
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
(repository@digest), repository, digest, tags}`, `[]` on pull requests.
It arrives when the whole workflow is done. With `reproduce: false` the run
publishes without reproducing, and a second call given its `published` builds
nothing and only reproduces what that lists, so jobs that need only the
output start right after the images are published
([above](#waking-the-apps-when-the-platform-publishes)).

| Workflow | Inputs | Secrets | Caller permissions |
|---|---|---|---|
| `images.yml` | `manifests` (globs, default `**/image.yaml **/app.yaml`), `registry`, `provenance`, `reproduce` (default `true`), `published` (only reproduce this) | `REGISTRY_USERNAME`, `REGISTRY_PASSWORD` | `contents: read`, `packages: write`, `id-token: write`, `attestations: write` |
| `update-locks.yml` | `manifests`, `app-id` | `CLEARCUTT_APP_PRIVATE_KEY`, `CLEARCUTT_BOT_TOKEN` | `contents: write`, `pull-requests: write` |
| `fleet.yml` | `apps` (default `**/app.yaml`), `registry`, `provenance`, `app-id` | `CLEARCUTT_APP_PRIVATE_KEY`, `CLEARCUTT_BOT_TOKEN`, `REGISTRY_USERNAME`, `REGISTRY_PASSWORD` | `contents: write`, `pull-requests: write`, `packages: write`, `id-token: write`, `attestations: write` |
| `notify.yml` | `published` (required), `topic` (default `clearcutt-app`), `owner`, `repositories`, `app-id` | `CLEARCUTT_APP_PRIVATE_KEY`, `CLEARCUTT_BOT_TOKEN` | `contents: read` |

For workflows of your own, the action installs a signature-verified binary
plus cosign, syft, and grype:

```yaml
- uses: northcutted/clearcutt-factory@v0.3.0
- run: clearcutt-factory build -f images/example/image.yaml
```

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
