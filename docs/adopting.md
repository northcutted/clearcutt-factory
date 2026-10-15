# Adopting ClearCutt Factory

This guide takes a repository from nothing to signed, reproducible images that
keep themselves current. It assumes GitHub Actions and a GitHub container
registry; [Other CI systems](#other-ci-systems) covers the rest.

## 1. Install

Download a release binary for Linux or macOS from
[Releases](https://github.com/northcutted/clearcutt-factory/releases) and
check its signature, made by the release workflow at that tag:

```sh
v=v0.1.0 asset=clearcutt-factory-darwin-arm64
curl -fsSLO https://github.com/northcutted/clearcutt-factory/releases/download/$v/$asset
curl -fsSLO https://github.com/northcutted/clearcutt-factory/releases/download/$v/$asset.sigstore.json
cosign verify-blob --bundle $asset.sigstore.json \
  --certificate-identity https://github.com/northcutted/clearcutt-factory/.github/workflows/release.yml@refs/tags/$v \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com $asset
install -m 0755 $asset /usr/local/bin/clearcutt-factory
```

Or build it: `go install github.com/northcutted/clearcutt-factory/cmd/clearcutt-factory@v0.1.0`.

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
| `factory.org.yaml` | Your registry (default `ghcr.io/<owner>`), signer identity (this repository's workflows, keyless), vulnerability gate, and policy |
| `images/example/image.yaml` | An example image to replace |
| `.github/workflows/clearcutt-factory.yml` | Calls the reusable workflows: build, test, and scan on pull requests; publish on `main`; weekly lock updates; daily app rebases |

`--repo owner/name` and `--registry` override what it reads from the `origin`
remote. Every file names its JSON Schema, so editors with the YAML language
server complete and check fields as you type.

## 3. Write manifests and lock them

Describe each image in an `image.yaml` (see the [README](../README.md#the-manifest)),
then pin every input:

```sh
clearcutt-factory lock  -f images/example/image.yaml
clearcutt-factory build -f images/example/image.yaml   # build, smoke-test, SBOM, scan, gate
```

Commit the manifest, `image.lock.yaml`, and `image.Containerfile`. The lock is
what reviewers read: every version and hash that changed.

## 4. Turn on the automation

Push, then in the repository settings:

1. **Actions → General → Workflow permissions:** allow GitHub Actions to
   create and approve pull requests (the weekly and daily jobs open them).
2. **Secrets → `CLEARCUTT_BOT_TOKEN`:** a GitHub App token, or a fine-grained
   token with contents and pull-requests write. Pull requests opened with the
   default `GITHUB_TOKEN` don't start workflows, so without it CI won't run on
   the bot's pull requests. (Closing and reopening one as yourself starts it.)
3. For a registry other than `ghcr.io`: set the reusable workflows' `registry`
   input and add `REGISTRY_USERNAME` and `REGISTRY_PASSWORD` secrets.

On `main`, each changed image is pushed, signed keylessly, attested (SBOM,
vulnerabilities, recipe, SLSA provenance), and rebuilt on a second runner from
its signed recipe. Unchanged images aren't republished.

## 5. Apps and stacks across repositories

A platform team publishes stacks once:

```sh
clearcutt-factory stack push -f stacks/go.yaml --ref ghcr.io/acme/stacks/go:1
```

Build and run images given as factory manifests (`run: ../go-runtime/image.yaml`)
are resolved to their published references before pushing, and the stack is
signed. A stack is published by its content, so pushing an unchanged one
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

## Who signs, and binding signatures to your repository

The reusable workflows sign inside ClearCutt Factory's workflows, so the
certificate's identity is the called workflow
(`https://github.com/northcutted/clearcutt-factory/.github/workflows/images.yml@refs/tags/v0.1.1`),
not your repository. Anyone can call those workflows and get the same
identity, so an identity alone would accept images built in any repository.
The certificate also records the repository whose run signed (Fulcio's GitHub
workflow repository extension), and `sourceRepository` makes cosign require
it. `init` writes both:

```yaml
signing:
  mode: keyless
  verify:          # this repository's images
    certificateIdentityRegexp: ^https://github\.com/northcutted/clearcutt-factory/\.github/workflows/(images|fleet)\.yml@refs/tags/v\d+\.\d+\.\d+$
    certificateOIDCIssuer: https://token.actions.githubusercontent.com
    sourceRepository: https://github.com/acme/checkout
  stacks:          # who may sign the stacks apps here build on
    certificateIdentity: https://github.com/acme/platform/.github/workflows/stacks.yml@refs/heads/main
    certificateOIDCIssuer: https://token.actions.githubusercontent.com
```

`sourceMatchesImage: true` instead requires the run to be in the repository
the image names as its source (`org.opencontainers.image.source`), and
`sourceRepositoryOwner` limits that to one owner's repositories; `sourceRef`
requires a ref. It binds images only: a stack names no source, so a stack
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

Call them from your own workflow, pinned to a release. All three take a
`factory-version` input (default: their own release) and need
`secrets: inherit` for the optional secrets above.

| Workflow | Inputs | Caller permissions |
|---|---|---|
| `images.yml` | `manifests` (globs, default `**/image.yaml **/app.yaml`), `registry`, `provenance` | `contents: read`, `packages: write`, `id-token: write`, `attestations: write` |
| `update-locks.yml` | `manifests` | `contents: write`, `pull-requests: write` |
| `fleet.yml` | `apps` (default `**/app.yaml`), `registry` | `contents: write`, `pull-requests: write`, `packages: write`, `id-token: write` |

For workflows of your own, the action installs a signature-verified binary
plus cosign, syft, and grype:

```yaml
- uses: northcutted/clearcutt-factory@v0.1.1
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
