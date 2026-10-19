package policy

import (
	"strings"
	"testing"

	"github.com/northcutted/clearcutt-factory/internal/lock"
	"github.com/northcutted/clearcutt-factory/internal/manifest"
)

func TestCheck(t *testing.T) {
	o := manifest.DefaultOrg()
	o.Policy = manifest.Policy{
		RequireNonRoot:    true,
		RequiredLabels:    []string{"org.opencontainers.image.source"},
		AllowedHosts:      []string{"github.com", ".k8s.io"},
		AllowedRegistries: []string{"cgr.dev/chainguard/", "docker.io/library/"},
	}
	m := &manifest.Manifest{Spec: manifest.Spec{User: "root"}}
	img := func(ref string) lock.Image { return lock.Image{Ref: ref, Digest: "sha256:x"} }
	l := &lock.Lock{
		Base:    img("cgr.dev/chainguard/wolfi-base:latest"),
		Builder: lock.Builder{BuildKit: img("moby/buildkit:v0.33.1"), Frontend: img("docker/dockerfile:1"), Toolbox: img("golang:1")},
		Tools: []lock.Tool{
			{Name: "ok", Verification: lock.VerifiedChecksumFile, Artifacts: map[string]lock.Artifact{"linux/amd64": {URL: "https://dl.k8s.io/x"}}},
			{Name: "tofu", Verification: lock.VerifiedTOFU, Artifacts: map[string]lock.Artifact{"linux/amd64": {URL: "https://evil.example/x"}}},
		},
	}
	err := Check(m, o, l)
	if err == nil {
		t.Fatal("expected violations")
	}
	msg := err.Error()
	for _, want := range []string{"non-root", "org.opencontainers.image.source", "tool tofu has no checksum", "evil.example", "moby/buildkit", "docker/dockerfile"} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q in:\n%s", want, msg)
		}
	}
	for _, unwanted := range []string{"dl.k8s.io", "golang:1", "wolfi-base"} {
		if strings.Contains(msg, unwanted) {
			t.Errorf("unexpected %q in:\n%s", unwanted, msg)
		}
	}

	m.Spec.User = "65532:65532"
	m.Spec.Labels = map[string]string{"org.opencontainers.image.source": "x"}
	o.Policy.AllowTOFU = true
	o.Policy.AllowedHosts = append(o.Policy.AllowedHosts, "evil.example")
	o.Policy.AllowedRegistries = nil
	if err := Check(m, o, l); err != nil {
		t.Fatalf("expected no violations, got %v", err)
	}
}

// TestRequireNonRoot: the user is judged as the Containerfile's USER will
// hold it, so a value that smuggles in a second USER (or spells root's ID
// another way) doesn't pass.
func TestRequireNonRoot(t *testing.T) {
	o := manifest.DefaultOrg()
	o.Policy.RequireNonRoot = true
	l := &lock.Lock{}
	for _, c := range []struct {
		user string
		ok   bool
	}{
		{"65532", true},
		{"65532:65532", true},
		{"nonroot", true},
		{"app-user.1", true},
		{"65532\nUSER 0", false},
		{"65532 \\\n0", false},
		{"65532\rUSER 0", false},
		{"65532 0", false},
		{"$UID", false},
		{"", false},
		{"0", false},
		{"00", false},
		{"0:65532", false},
		{"root", false},
		{"root:nonroot", false},
	} {
		m := &manifest.Manifest{Spec: manifest.Spec{User: c.user}}
		err := Check(m, o, l)
		if (err == nil) != c.ok {
			t.Errorf("user %q: %v, want ok=%v", c.user, err, c.ok)
		}
		if err != nil && !strings.Contains(err.Error(), "requireNonRoot") {
			t.Errorf("user %q: %v", c.user, err)
		}
	}
}

// TestAllowedHostsCoverAPKRepositories: apk packages have no URL of their
// own, so the repositories they install from are what allowedHosts checks.
func TestAllowedHostsCoverAPKRepositories(t *testing.T) {
	o := manifest.DefaultOrg()
	o.Policy.AllowedHosts = []string{"apk.cgr.dev"}
	m := &manifest.Manifest{}
	l := &lock.Lock{Packages: lock.Packages{
		Manager:      lock.ManagerAPK,
		Repositories: []string{"https://apk.cgr.dev/chainguard", "https://packages.evil.example/wolfi"},
		Platforms:    map[string][]lock.Package{"linux/amd64": {{Name: "jq", Version: "1.8.2-r3", Checksum: "Q1x="}}},
	}}
	err := Check(m, o, l)
	if err == nil || !strings.Contains(err.Error(), "repository not in allowedHosts: https://packages.evil.example/wolfi") || strings.Contains(err.Error(), "apk.cgr.dev") {
		t.Errorf("got %v", err)
	}
	l.Packages.Repositories = l.Packages.Repositories[:1]
	if err := Check(m, o, l); err != nil {
		t.Errorf("allowed repository: %v", err)
	}
}

// TestAllowedRegistriesWholeSegments: an entry covers itself and what is
// below it, never a longer name that starts the same way.
func TestAllowedRegistriesWholeSegments(t *testing.T) {
	for _, c := range []struct {
		entry, ref string
		ok         bool
	}{
		{"ghcr.io/acme", "ghcr.io/acme/app:1", true},
		{"ghcr.io/acme", "ghcr.io/acme/team/app@sha256:" + strings.Repeat("a", 64), true},
		{"ghcr.io/acme/", "ghcr.io/acme/app", true},
		{"ghcr.io/acme/app", "ghcr.io/acme/app:1", true},
		{"ghcr.io/acme/app", "ghcr.io/acme/app@sha256:" + strings.Repeat("a", 64), true},
		{"ghcr.io", "ghcr.io/acme/app", true},
		{"ghcr.io/acme", "ghcr.io/acme-evil/app:1", false},
		{"ghcr.io/acme/app", "ghcr.io/acme/app-evil:1", false},
		{"ghcr.io", "ghcr.io.evil.example/app", false},
		{"cgr.dev/chainguard/", "cgr.dev/chainguard-evil/x", false},
		{"docker.io/library/golang", "golang:1", true},
		{"docker.io/library/golang", "golangci/golangci-lint:1", false},
	} {
		o := manifest.DefaultOrg()
		o.Policy.AllowedRegistries = []string{c.entry}
		if err := CheckImages(o, c.ref); (err == nil) != c.ok {
			t.Errorf("%s under %s: %v, want ok=%v", c.ref, c.entry, err, c.ok)
		}
	}
}
