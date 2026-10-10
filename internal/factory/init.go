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
)

type InitOptions struct {
	// Dir is the repository to set up (default ".").
	Dir string
	// Repo is owner/name on GitHub, for the signer identity and image
	// labels. Default: the origin remote.
	Repo string
	// Registry receives the images (default ghcr.io/<owner>).
	Registry string
	// Force overwrites existing files.
	Force bool
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
	// Release builds pin what they are; development builds follow main.
	ref := "main"
	if releaseRE.MatchString(opts.Version) {
		ref = opts.Version
	}
	r := strings.NewReplacer("{{ref}}", ref, "{{repo}}", repo, "{{identityRegexp}}", workflowIdentityRegexp(ref), "{{registry}}", registry)

	var wrote []string
	for _, f := range []struct{ path, body string }{
		{"factory.org.yaml", orgTemplate},
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
  Commit and push. On GitHub: Settings → Actions → General → allow GitHub
  Actions to create pull requests, and add a CLEARCUTT_BOT_TOKEN secret (a
  GitHub App or fine-grained token with contents and pull-requests write) so
  CI runs on the pull requests the weekly and daily jobs open.`)
	return nil
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
    # sourceRepository binds signatures to runs in this repository.
    certificateIdentityRegexp: {{identityRegexp}}
    certificateOIDCIssuer: https://token.actions.githubusercontent.com
    sourceRepository: https://github.com/{{repo}}
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
name: clearcutt-factory
on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: "23 6 * * 1" # weekly: re-resolve every input, one pull request per manifest
    - cron: "41 5 * * *" # daily: rebase apps onto the newest build of their run image
  workflow_dispatch:
permissions:
  contents: read
jobs:
  images:
    if: github.event_name != 'schedule'
    uses: northcutted/clearcutt-factory/.github/workflows/images.yml@{{ref}}
    permissions: {contents: read, packages: write, id-token: write, attestations: write}
    secrets: inherit

  update-locks:
    if: github.event.schedule == '23 6 * * 1' || github.event_name == 'workflow_dispatch'
    uses: northcutted/clearcutt-factory/.github/workflows/update-locks.yml@{{ref}}
    permissions: {contents: write, pull-requests: write}
    secrets: inherit

  fleet:
    needs: images
    if: always() && (github.event.schedule == '41 5 * * *' || (github.event_name == 'push' && needs.images.result == 'success'))
    uses: northcutted/clearcutt-factory/.github/workflows/fleet.yml@{{ref}}
    permissions: {contents: write, pull-requests: write, packages: write, id-token: write}
    secrets: inherit
`
