package factory

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/northcutted/clearcutt-factory/internal/attest"
	"github.com/northcutted/clearcutt-factory/internal/manifest"
	"github.com/northcutted/clearcutt-factory/internal/rebase"
	"github.com/northcutted/clearcutt-factory/internal/registry"
)

// TestPublishKeepsRebasedTag: until an app's lock pins the base it was
// rebased onto, a build from source reproduces the original image; publishing
// it again must not take latest back off the patched base (#15).
func TestPublishKeepsRebasedTag(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0))))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	ctx := context.Background()

	osRel := map[string]string{"etc/": "", "etc/os-release": "ID=wolfi\nVERSION_ID=20230201\n"}
	oldBase := testIndex(t, nil, func(arch string) []v1.Layer {
		return []v1.Layer{testLayer(t, osRel), testLayer(t, map[string]string{"usr/lib/libssl.so.3": "old " + arch})}
	}, nil)
	newBase := testIndex(t, nil, func(arch string) []v1.Layer {
		return []v1.Layer{testLayer(t, osRel), testLayer(t, map[string]string{"usr/lib/libssl.so.3": "patched " + arch})}
	}, nil)
	push(t, host+"/run:latest", oldBase)
	baseImage := func(arch string) v1.Image {
		im, _ := oldBase.IndexManifest()
		for _, d := range im.Manifests {
			if d.Platform.Architecture == arch {
				img, _ := oldBase.Image(d.Digest)
				return img
			}
		}
		return nil
	}
	// The app as built from source on the old run image. No created
	// times differ here, so only the layers tell the rebase apart.
	built := testIndex(t, baseImage, func(arch string) []v1.Layer {
		return []v1.Layer{testLayer(t, map[string]string{"app/": "", "app/hello": "hello " + arch})}
	}, func(arch string) map[string]string {
		d, _ := baseImage(arch).Digest()
		return map[string]string{rebase.AnnotationBaseName: host + "/run:latest", rebase.AnnotationBaseDigest: d.String()}
	})
	d, _ := built.Digest()
	art := &registry.Artifact{Digest: d.String(), Index: built}
	org := manifest.DefaultOrg()
	org.Signing.Mode = "none"
	var out bytes.Buffer
	opts := Options{Stdout: &out, Stderr: &out}
	repo := host + "/hello"
	latest := func() string {
		t.Helper()
		got, err := registry.Digest(ctx, repo+":latest")
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	publishBuilt := func(force bool) {
		t.Helper()
		if _, _, _, err := publish(ctx, opts, org, art, repo, []string{"latest"}, attest.RecipePredicateType, "", nil, false, force); err != nil {
			t.Fatalf("%v\n%s", err, out.String())
		}
	}
	publishBuilt(false)

	// The run image is patched and the fleet rebases the app onto it.
	push(t, host+"/run:latest", newBase)
	dir := t.TempDir()
	orgPath := filepath.Join(dir, "factory.org.yaml")
	if err := os.WriteFile(orgPath, []byte("apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\nsigning: {mode: none}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ro := RebaseOptions{Image: repo + ":latest", OutDir: filepath.Join(dir, "out"), NoScan: true, Push: true}
	if err := Rebase(ctx, Options{OrgPath: orgPath, Version: "test", Stdout: &out, Stderr: &out}, ro); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	rebased := latest()
	if rebased == art.Digest {
		t.Fatal("the rebase did not move latest")
	}

	// A push to main rebuilds the original from the old lock: latest stays
	// on the rebased image.
	out.Reset()
	publishBuilt(false)
	if got := latest(); got != rebased {
		t.Fatalf("latest moved back to %s\n%s", got, out.String())
	}
	if !strings.Contains(out.String(), "warning: left "+repo+":latest where it is") || !strings.Contains(out.String(), "this image rebased onto a newer build of "+host+"/run:latest") {
		t.Errorf("output:\n%s", out.String())
	}

	// A rebase of the rebase descends from it too.
	newer := testIndex(t, nil, func(arch string) []v1.Layer {
		return []v1.Layer{testLayer(t, osRel), testLayer(t, map[string]string{"usr/lib/libssl.so.3": "patched again " + arch})}
	}, nil)
	push(t, host+"/run:latest", newer)
	if err := Rebase(ctx, Options{OrgPath: orgPath, Version: "test", Stdout: &out, Stderr: &out}, ro); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	twice := latest()
	publishBuilt(false)
	if got := latest(); got != twice || twice == rebased {
		t.Fatalf("latest is %s, want the second rebase %s\n%s", got, twice, out.String())
	}

	// A deliberate rollback.
	out.Reset()
	publishBuilt(true)
	if got := latest(); got != art.Digest {
		t.Fatalf("--force-tags: latest is %s\n%s", got, out.String())
	}

	// Moving forward is fine: republishing the rebase onto the current run
	// image (as the fleet does the next day) moves latest back to it.
	out.Reset()
	twiceArt, err := registry.Fetch(ctx, repo+"@"+twice)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := publish(ctx, opts, org, twiceArt, repo, []string{"latest"}, attest.RebasePredicateType, "", nil, false, false); err != nil {
		t.Fatal(err)
	}
	if got := latest(); got != twice {
		t.Fatalf("republishing the newest rebase left latest at %s\n%s", got, out.String())
	}

	// When the platform team takes the run image back, the original is on
	// the current base again, and the tag may follow it.
	push(t, host+"/run:latest", oldBase)
	out.Reset()
	publishBuilt(false)
	if got := latest(); got != art.Digest {
		t.Fatalf("after the run image went back, latest is %s\n%s", got, out.String())
	}
}

// TestPublishKeepsNewerTag: a tag holding an image created later (built
// from a newer lock) isn't moved back to one published before; new tags
// are still added, and --force-tags moves them anyway.
func TestPublishKeepsNewerTag(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0))))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	ctx := context.Background()
	at := func(day int, content string) *registry.Artifact {
		created := time.Date(2026, 10, day, 0, 0, 0, 0, time.UTC)
		idx := testIndex(t, func(string) v1.Image {
			img, err := mutate.CreatedAt(mutate.ConfigMediaType(mutate.MediaType(empty.Image, types.OCIManifestSchema1), types.OCIConfigJSON), v1.Time{Time: created})
			if err != nil {
				t.Fatal(err)
			}
			return img
		}, func(arch string) []v1.Layer {
			return []v1.Layer{testLayer(t, map[string]string{"usr/bin/tool": content + arch})}
		}, nil)
		d, _ := idx.Digest()
		return &registry.Artifact{Digest: d.String(), Index: idx}
	}
	older, newer := at(1, "v1 "), at(8, "v2 ")
	org := manifest.DefaultOrg()
	org.Signing.Mode = "none"
	var out bytes.Buffer
	opts := Options{Stdout: &out, Stderr: &out}
	repo := host + "/tools"
	pub := func(a *registry.Artifact, force bool, tags ...string) {
		t.Helper()
		if _, _, _, err := publish(ctx, opts, org, a, repo, tags, attest.RecipePredicateType, "", nil, false, force); err != nil {
			t.Fatalf("%v\n%s", err, out.String())
		}
	}
	tagged := func(tag string) string {
		got, _ := registry.Digest(ctx, repo+":"+tag)
		return got
	}

	pub(older, false, "latest")
	pub(newer, false, "latest")
	out.Reset()
	pub(older, false, "latest", "v1")
	if tagged("latest") != newer.Digest || tagged("v1") != older.Digest {
		t.Fatalf("latest %s (want %s), v1 %s (want %s)\n%s", tagged("latest"), newer.Digest, tagged("v1"), older.Digest, out.String())
	}
	if !strings.Contains(out.String(), "created 2026-10-08T00:00:00Z, after this image (2026-10-01T00:00:00Z)") || !strings.Contains(out.String(), "moved its tags (v1)") {
		t.Errorf("output:\n%s", out.String())
	}

	// Forward is fine, and so is a rollback with --force-tags.
	pub(older, true, "latest")
	if tagged("latest") != older.Digest {
		t.Fatalf("--force-tags left latest at %s", tagged("latest"))
	}
	pub(newer, false, "latest")
	if tagged("latest") != newer.Digest {
		t.Fatalf("latest did not move forward: %s", tagged("latest"))
	}
}
