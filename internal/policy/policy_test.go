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
