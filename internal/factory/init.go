package factory

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/northcutted/clearcutt-factory/internal/manifest"
)

type InitOptions struct {
	// Dir is the repository to set up (default ".").
	Dir string
	// Repo is owner/name on GitHub, for the signer identity and image
	// labels. Default: the origin remote.
	Repo string
	// Registry receives the images (default ghcr.io/<owner>).
	Registry string
	// Branch is the branch that publishes, which the signer identity
	// requires (sourceRef). Default: the origin remote's default branch,
	// else main.
	Branch string
	// Force overwrites existing files.
	Force bool
	// Extends makes the org profile extend this shared profile (published
	// with profile push), signed by ExtendsIdentity (a certificate
	// identity, with ExtendsIssuer, default GitHub Actions) or ExtendsKey.
	// Init checks the signature, and writes only what the shared profile
	// leaves to each repository.
	Extends, ExtendsIdentity, ExtendsIssuer, ExtendsKey string
}

var releaseRE = regexp.MustCompile(`^v\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$`)

// Init scaffolds a repository: an org profile, an example image manifest,
// and a GitHub Actions workflow that calls ClearCutt Factory's reusable
// workflows to publish, update, and rebase.
func Init(ctx context.Context, opts Options, io InitOptions) error {
	dir := io.Dir
	if dir == "" {
		dir = "."
	}
	repo := io.Repo
	if repo == "" {
		repo = githubRepo(ctx, dir)
	}
	if repo != "" && !regexp.MustCompile(`^[\w.-]+/[\w.-]+$`).MatchString(repo) {
		return fmt.Errorf("--repo %q must look like owner/name", repo)
	}
	owner, _, _ := strings.Cut(repo, "/")
	registry := io.Registry
	if registry == "" && owner != "" {
		registry = "ghcr.io/" + strings.ToLower(owner)
	}
	if repo == "" {
		opts.logf("warning: no GitHub origin remote found; fill in OWNER/REPO (or pass --repo)")
		repo, registry = "OWNER/REPO", firstNonEmpty(registry, "ghcr.io/OWNER")
	}
	org := orgTemplate
	if io.Extends != "" || io.ExtendsIdentity != "" || io.ExtendsIssuer != "" || io.ExtendsKey != "" {
		var err error
		if org, err = extendingOrg(ctx, opts, dir, io); err != nil {
			return err
		}
	}
	branch := io.Branch
	if branch == "" {
		branch = defaultBranch(ctx, dir)
	}
	if !regexp.MustCompile(`^[\w./-]+$`).MatchString(branch) || strings.HasPrefix(branch, "refs/") {
		return fmt.Errorf("--default-branch %q must be a branch name, like main", branch)
	}
	// Release builds pin what they are; development builds follow main.
	ref := "main"
	if releaseRE.MatchString(opts.Version) {
		ref = opts.Version
	}
	r := strings.NewReplacer("{{ref}}", ref, "{{repo}}", repo, "{{identityRegexp}}", workflowIdentityRegexp(ref), "{{registry}}", registry, "{{branch}}", branch)

	var wrote []string
	for _, f := range []struct{ path, body string }{
		{"factory.org.yaml", org},
		{"images/example/image.yaml", imageTemplate},
		{".github/workflows/clearcutt-factory.yml", workflowTemplate},
	} {
		p := filepath.Join(dir, filepath.FromSlash(f.path))
		if _, err := os.Stat(p); err == nil && !io.Force {
			opts.printf("kept %s (exists; --force overwrites)", f.path)
			continue
		} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, []byte(r.Replace(f.body)), 0o644); err != nil {
			return err
		}
		wrote = append(wrote, f.path)
	}
	for _, p := range wrote {
		opts.printf("wrote %s", p)
	}
	opts.printf(`
Next:
  clearcutt-factory lock  -f images/example/image.yaml   # pin every input
  clearcutt-factory build -f images/example/image.yaml   # build, test, scan locally
  Commit and push. On GitHub, so that CI runs on the pull requests the weekly
  and daily jobs open: install a GitHub App with contents and pull-requests
  write, and set a CLEARCUTT_APP_ID variable (its Client ID) and a
  CLEARCUTT_APP_PRIVATE_KEY secret; or add a CLEARCUTT_BOT_TOKEN secret (a
  fine-grained token with the same permissions). Without either, allow GitHub
  Actions to create pull requests (Settings → Actions → General) and approve
  their CI runs by hand. See docs/adopting.md.`)
	return nil
}

// extendingOrg checks the shared profile io.Extends names against its
// signer and returns an org profile template that extends it, adding only
// what it leaves to each repository: the registry, and who signs this
// repository's images.
func extendingOrg(ctx context.Context, opts Options, dir string, io InitOptions) (string, error) {
	if io.Extends == "" {
		return "", errors.New("--extends-identity, --extends-issuer, and --extends-key name who signs the shared profile --extends names")
	}
	e := manifest.Extends{Ref: io.Extends}
	var signer string
	switch {
	case (io.ExtendsIdentity == "") == (io.ExtendsKey == ""):
		return "", errors.New("--extends needs who signs the shared profile: --extends-identity (a certificate identity) or --extends-key")
	case io.ExtendsKey != "":
		if io.ExtendsIssuer != "" {
			return "", errors.New("--extends-issuer goes with --extends-identity, not --extends-key")
		}
		e.Signer.Key, signer = io.ExtendsKey, io.ExtendsKey
		if !strings.Contains(io.ExtendsKey, "://") {
			abs, err := filepath.Abs(io.ExtendsKey)
			if err != nil {
				return "", err
			}
			e.Signer.Key = abs
			if absDir, err := filepath.Abs(dir); err == nil {
				if r, err := filepath.Rel(absDir, abs); err == nil {
					signer = filepath.ToSlash(r)
				}
			}
		}
		signer = "    key: " + signer + "\n"
	default:
		e.Signer.CertificateIdentity = io.ExtendsIdentity
		e.Signer.CertificateOIDCIssuer = firstNonEmpty(io.ExtendsIssuer, "https://token.actions.githubusercontent.com")
		signer = "    certificateIdentity: " + e.Signer.CertificateIdentity + "\n    certificateOIDCIssuer: " + e.Signer.CertificateOIDCIssuer + "\n"
	}
	// Check the signature now, whatever this machine checked before: this
	// is where the repository starts trusting the profile.
	vopts := opts
	vopts.Reverify = true
	path, digest, err := fetchProfile(ctx, vopts, e, "")
	if err != nil {
		return "", fmt.Errorf("--extends %s: %w", io.Extends, err)
	}
	shared, err := manifest.ReadShared(path)
	if err != nil {
		return "", fmt.Errorf("--extends %s: %w", io.Extends, err)
	}
	opts.printf("%s (%s) is signed by the signer given", io.Extends, digest)

	var b strings.Builder
	b.WriteString(orgExtendsHeader)
	b.WriteString("extends:\n  ref: " + io.Extends + " # each manifest's lock pins its digest; lock --update moves it\n")
	b.WriteString("  signer: # who may sign the shared profile; checked whenever it is loaded\n" + signer)
	if shared.Registry == "" {
		b.WriteString("\nregistry: {{registry}} # images go to <registry>/<metadata.name>\n")
	} else if io.Registry != "" && io.Registry != shared.Registry {
		opts.logf("warning: the shared profile sets the registry (%s), so --registry %s isn't written", shared.Registry, io.Registry)
	}
	if shared.Trust == nil && shared.Signing.Verify.IsZero() {
		if shared.Signing.Mode == "" || shared.Signing.Mode == "keyless" {
			b.WriteString(orgVerifyBlock)
		} else {
			b.WriteString("\n# The shared profile signs with keys; name this repository's public key:\n# signing:\n#   verify: {key: keys/images.pub}\n")
		}
	}
	return b.String(), nil
}

// workflowIdentityRegexp matches the certificate identity of ClearCutt
// Factory's signing reusable workflows (images.yml and fleet.yml) at the
// ref the generated workflow calls them by: any release tag, or main.
func workflowIdentityRegexp(ref string) string {
	at := `refs/tags/v\d+\.\d+\.\d+$`
	if !releaseRE.MatchString(ref) {
		at = `refs/heads/` + regexp.QuoteMeta(ref) + `$`
	}
	return `^https://github\.com/northcutted/clearcutt-factory/\.github/workflows/(images|fleet)\.yml@` + at
}

// defaultBranch is the origin remote's default branch (its HEAD), else
// main.
func defaultBranch(ctx context.Context, dir string) string {
	out, err := exec.CommandContext(ctx, "git", "-C", dir, "symbolic-ref", "--quiet", "refs/remotes/origin/HEAD").Output()
	if b, ok := strings.CutPrefix(strings.TrimSpace(string(out)), "refs/remotes/origin/"); err == nil && ok && b != "" {
		return b
	}
	return "main"
}

// githubRepo reads owner/name from the origin remote, if it is on GitHub.
func githubRepo(ctx context.Context, dir string) string {
	out, err := exec.CommandContext(ctx, "git", "-C", dir, "config", "--get", "remote.origin.url").Output()
	if err != nil {
		return ""
	}
	m := regexp.MustCompile(`github\.com[:/]([\w.-]+/[\w.-]+?)(?:\.git)?/?$`).FindStringSubmatch(strings.TrimSpace(string(out)))
	if m == nil {
		return ""
	}
	return m[1]
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

const orgTemplate = `# yaml-language-server: $schema=https://raw.githubusercontent.com/northcutted/clearcutt-factory/{{ref}}/schemas/org.schema.json
# Org profile: every manifest below this directory inherits these choices.
apiVersion: factory.clearcutt.dev/v1alpha1
kind: OrgProfile

registry: {{registry}} # images go to <registry>/<metadata.name>
tags: [latest]

defaults:
  base: cgr.dev/chainguard/wolfi-base:latest
  platforms: [linux/amd64, linux/arm64]

signing:
  mode: keyless # Sigstore, with the CI workflow's OIDC identity
  verify:
    # Images are signed inside ClearCutt Factory's reusable workflows, so the
    # certificate names those workflows. Any repository can call them, so
    # sourceRepository binds signatures to runs in this repository, and
    # sourceRef to runs on the branch that publishes (the reusable workflows
    # publish only from the default branch, or their publish-ref input).
    certificateIdentityRegexp: {{identityRegexp}}
    certificateOIDCIssuer: https://token.actions.githubusercontent.com
    sourceRepository: https://github.com/{{repo}}
    sourceRef: refs/heads/{{branch}}
  # Stacks from a platform repository have their own signer, for
  # policy.requireSignedStacks:
  # stacks:
  #   certificateIdentity: https://github.com/OWNER/platform/.github/workflows/stacks.yml@refs/heads/main
  #   certificateOIDCIssuer: https://token.actions.githubusercontent.com

vulnerabilities:
  scanner: grype
  failOn: critical
  onlyFixed: true # don't block on CVEs nobody can fix yet

policy:
  requireNonRoot: true
  # allowedRegistries: [cgr.dev/chainguard/, ghcr.io/]
  # allowedHosts: [github.com, dl.k8s.io]
`

const orgExtendsHeader = `# yaml-language-server: $schema=https://raw.githubusercontent.com/northcutted/clearcutt-factory/{{ref}}/schemas/org.schema.json
# Org profile. It extends the platform team's shared profile, which sets the
# builder, signing, vulnerability gate, and policy: this file adds what the
# shared profile leaves to each repository, and may tighten (never loosen)
# the gate and policy.
apiVersion: factory.clearcutt.dev/v1alpha1
kind: OrgProfile

`

const orgVerifyBlock = `
signing:
  verify:
    # Images are signed inside ClearCutt Factory's reusable workflows, so the
    # certificate names those workflows. Any repository can call them, so
    # sourceRepository binds signatures to runs in this repository, and
    # sourceRef to runs on the branch that publishes (the reusable workflows
    # publish only from the default branch, or their publish-ref input).
    certificateIdentityRegexp: {{identityRegexp}}
    certificateOIDCIssuer: https://token.actions.githubusercontent.com
    sourceRepository: https://github.com/{{repo}}
    sourceRef: refs/heads/{{branch}}
`

const imageTemplate = `# yaml-language-server: $schema=https://raw.githubusercontent.com/northcutted/clearcutt-factory/{{ref}}/schemas/manifest.schema.json
# An example image to replace with your own. Packages come from the base's
# package manager; anything else is a tool (see the ClearCutt Factory README).
apiVersion: factory.clearcutt.dev/v1alpha1
kind: Image
metadata:
  name: example
spec:
  packages: [ca-certificates-bundle, jq]
  labels:
    org.opencontainers.image.source: https://github.com/{{repo}}
  user: "65532"
  entrypoint: [/usr/bin/jq]
  test:
    command: [/usr/bin/jq, --version]
`

const workflowTemplate = `# Builds, publishes, and maintains this repository's images and apps with
# ClearCutt Factory: https://github.com/northcutted/clearcutt-factory
#
# CI starts on the pull requests the weekly and daily jobs open only when they
# come from a GitHub App (a CLEARCUTT_APP_ID variable holding its Client ID,
# and a CLEARCUTT_APP_PRIVATE_KEY secret) or a CLEARCUTT_BOT_TOKEN secret:
# https://github.com/northcutted/clearcutt-factory/blob/{{ref}}/docs/adopting.md#a-github-app-for-the-automation
# Secrets are passed by name because secrets: inherit reaches only workflows
# in this repository's own organization or enterprise.
#
# Across repositories: a platform repository's notify job wakes the
# repositories with the topic clearcutt-app when it publishes run images,
# build images, stacks, or a shared org profile; theirs then rebase onto the
# new run image, propose a rebuild on the new build image or stack, or
# propose the new profile.
name: clearcutt-factory
on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: "23 6 * * 1" # weekly: re-resolve every input, one pull request per manifest
    - cron: "41 5 * * *" # daily: rebase apps onto the newest build of their run image, and propose a rebuild on their stack's newest build image
  workflow_dispatch:
  # From a platform repository's notify job. The payload is only a hint: the
  # jobs re-resolve everything from the registry and verify it.
  repository_dispatch:
    types: [clearcutt.run-image-published, clearcutt.build-image-published, clearcutt.stack-published, clearcutt.profile-published]
permissions:
  contents: read
jobs:
  images:
    if: github.event_name != 'schedule' && github.event_name != 'repository_dispatch'
    uses: northcutted/clearcutt-factory/.github/workflows/images.yml@{{ref}}
    permissions: {contents: read, packages: write, id-token: write, attestations: write}
    with:
      reproduce: false # the reproduce job does it, so fleet and notify start without waiting
      # A pull request builds only the manifests it affects, so one image's
      # lock update isn't failed by another image's. Require images / result.
      changed-only: true
    secrets:
      REGISTRY_USERNAME: ${{ secrets.REGISTRY_USERNAME }} # only for a registry other than ghcr.io
      REGISTRY_PASSWORD: ${{ secrets.REGISTRY_PASSWORD }}

  # images.yml again, given what images published: it rebuilds each image on
  # a second runner from its signed recipe alone and attests the match. A
  # failed reproduction fails the run.
  reproduce:
    needs: images
    if: ${{ !cancelled() && needs.images.outputs.published != '[]' && needs.images.outputs.published != '' }}
    uses: northcutted/clearcutt-factory/.github/workflows/images.yml@{{ref}}
    permissions: {contents: read, packages: write, id-token: write, attestations: write}
    with:
      published: ${{ needs.images.outputs.published }}
    secrets:
      REGISTRY_USERNAME: ${{ secrets.REGISTRY_USERNAME }}
      REGISTRY_PASSWORD: ${{ secrets.REGISTRY_PASSWORD }}

  # Weekly, on a new shared profile, and by hand: every input, one pull
  # request per manifest. Daily, and when the platform publishes a build
  # image or a stack: only each app's stack and its build and run images, as
  # a pull request to rebuild the app on them, so a toolchain fix reaches
  # the apps in minutes (the daily run catches a dispatch that was missed).
  update-locks:
    if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch' || github.event.action == 'clearcutt.build-image-published' || github.event.action == 'clearcutt.stack-published' || github.event.action == 'clearcutt.profile-published'
    uses: northcutted/clearcutt-factory/.github/workflows/update-locks.yml@{{ref}}
    permissions: {contents: write, pull-requests: write}
    with:
      update: ${{ (github.event.schedule == '41 5 * * *' || github.event.action == 'clearcutt.build-image-published' || github.event.action == 'clearcutt.stack-published') && 'stack' || 'all' }}
      # auto-merge: rebuild update # merge by itself once required checks pass; needs "Allow auto-merge", branch protection, and the App (docs/adopting.md#4-turn-on-the-automation)
    secrets:
      CLEARCUTT_APP_PRIVATE_KEY: ${{ secrets.CLEARCUTT_APP_PRIVATE_KEY }}
      CLEARCUTT_BOT_TOKEN: ${{ secrets.CLEARCUTT_BOT_TOKEN }}

  fleet:
    needs: images
    if: always() && (github.event.schedule == '41 5 * * *' || github.event.action == 'clearcutt.run-image-published' || (github.event_name == 'push' && needs.images.result == 'success'))
    uses: northcutted/clearcutt-factory/.github/workflows/fleet.yml@{{ref}}
    permissions: {contents: write, pull-requests: write, packages: write, id-token: write, attestations: write}
    # with:
    #   auto-merge: pin rebuild # merge by itself once required checks pass (see update-locks above)
    secrets:
      CLEARCUTT_APP_PRIVATE_KEY: ${{ secrets.CLEARCUTT_APP_PRIVATE_KEY }}
      CLEARCUTT_BOT_TOKEN: ${{ secrets.CLEARCUTT_BOT_TOKEN }}
      REGISTRY_USERNAME: ${{ secrets.REGISTRY_USERNAME }}
      REGISTRY_PASSWORD: ${{ secrets.REGISTRY_PASSWORD }}

  # Wakes the repositories with the topic clearcutt-app when this one
  # publishes images (run images, typically), as soon as they are published:
  # it needs images, not reproduce. Needs a GitHub App installed on them, or
  # a CLEARCUTT_BOT_TOKEN that can write to them.
  notify:
    needs: images
    if: ${{ !cancelled() && github.event_name == 'push' && needs.images.outputs.published != '[]' && needs.images.outputs.published != '' }}
    uses: northcutted/clearcutt-factory/.github/workflows/notify.yml@{{ref}}
    permissions: {contents: read}
    with:
      published: ${{ needs.images.outputs.published }}
    secrets:
      CLEARCUTT_APP_PRIVATE_KEY: ${{ secrets.CLEARCUTT_APP_PRIVATE_KEY }}
      CLEARCUTT_BOT_TOKEN: ${{ secrets.CLEARCUTT_BOT_TOKEN }}
`
