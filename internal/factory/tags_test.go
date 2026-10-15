package factory

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
		if _, _, _, err := publish(ctx, opts, org, art, repo, []string{"latest"}, attest.RecipePredicateType, "", nil, false, force, nil); err != nil {
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
	if _, _, _, err := publish(ctx, opts, org, twiceArt, repo, []string{"latest"}, attest.RebasePredicateType, "", nil, false, false, nil); err != nil {
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
		if _, _, _, err := publish(ctx, opts, org, a, repo, tags, attest.RecipePredicateType, "", nil, false, force, nil); err != nil {
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

// hookRegistry is a test registry that runs a hook once, before the next
// push of a manifest by digest to a repository: a publish that happens
// while another one is under way.
type hookRegistry struct {
	h    http.Handler
	mu   sync.Mutex
	repo string
	hook func()
}

func newHookRegistry(t *testing.T) (*hookRegistry, string) {
	r := &hookRegistry{h: ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)))}
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return r, strings.TrimPrefix(srv.URL, "http://")
}

func (r *hookRegistry) arm(repo string, hook func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.repo, r.hook = repo, hook
}

func (r *hookRegistry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodPut {
		r.mu.Lock()
		f := r.hook
		if f != nil && strings.HasPrefix(req.URL.Path, "/v2/"+r.repo+"/manifests/sha256:") {
			r.hook = nil
		} else {
			f = nil
		}
		r.mu.Unlock()
		if f != nil {
			f()
		}
	}
	r.h.ServeHTTP(w, req)
}

// runImage is a run image created on the given day of October 2026.
func runImage(t *testing.T, libssl string, day int) v1.ImageIndex {
	t.Helper()
	created := time.Date(2026, 10, day, 0, 0, 0, 0, time.UTC)
	osRel := map[string]string{"etc/": "", "etc/os-release": "ID=wolfi\nVERSION_ID=20230201\n"}
	return testIndex(t, func(string) v1.Image {
		img, err := mutate.CreatedAt(mutate.ConfigMediaType(mutate.MediaType(empty.Image, types.OCIManifestSchema1), types.OCIConfigJSON), v1.Time{Time: created})
		if err != nil {
			t.Fatal(err)
		}
		return img
	}, func(arch string) []v1.Layer {
		return []v1.Layer{testLayer(t, osRel), testLayer(t, map[string]string{"usr/lib/libssl.so.3": libssl + " " + arch})}
	}, nil)
}

func platformImage(t *testing.T, idx v1.ImageIndex, arch string) v1.Image {
	t.Helper()
	im, err := idx.IndexManifest()
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range im.Manifests {
		if d.Platform.Architecture == arch {
			img, err := idx.Image(d.Digest)
			if err != nil {
				t.Fatal(err)
			}
			return img
		}
	}
	t.Fatalf("no %s image", arch)
	return nil
}

// appOn is an app built on base, named baseName, adding files.
func appOn(t *testing.T, base v1.ImageIndex, baseName string, files map[string]string) *registry.Artifact {
	t.Helper()
	idx := testIndex(t, func(arch string) v1.Image { return platformImage(t, base, arch) },
		func(string) []v1.Layer { return []v1.Layer{testLayer(t, files)} },
		func(arch string) map[string]string {
			d, _ := platformImage(t, base, arch).Digest()
			return map[string]string{rebase.AnnotationBaseName: baseName, rebase.AnnotationBaseDigest: d.String()}
		})
	d, err := idx.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return &registry.Artifact{Digest: d.String(), Index: idx}
}

func hello(version string) map[string]string {
	return map[string]string{"app/": "", "app/hello": "hello " + version}
}

func unsignedOrg(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "factory.org.yaml")
	if err := os.WriteFile(p, []byte("apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\nsigning: {mode: none}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestRebaseLeavesMovedTag: a rebase that a newer publish overtakes pushes
// its result by digest only and leaves the tag to the newer image, which
// the next rebase picks up (#37).
func TestRebaseLeavesMovedTag(t *testing.T) {
	reg, host := newHookRegistry(t)
	ctx := context.Background()
	run := host + "/run:latest"
	oldBase, newBase := runImage(t, "old", 1), runImage(t, "patched", 2)
	push(t, run, oldBase)
	repo := host + "/hello"
	v1App, v2App := appOn(t, oldBase, run, hello("v1")), appOn(t, oldBase, run, hello("v2"))
	push(t, repo+":latest", v1App.Index)
	push(t, run, newBase)

	// While the fleet rebases v1, a push to main publishes v2.
	reg.arm("hello", func() { push(t, repo+":latest", v2App.Index) })
	dir := t.TempDir()
	var out bytes.Buffer
	opts := Options{OrgPath: unsignedOrg(t), Version: "test", Stdout: &out, Stderr: &out}
	ro := RebaseOptions{Image: repo + ":latest", OutDir: filepath.Join(dir, "out"), NoScan: true, Push: true}
	if err := Rebase(ctx, opts, ro); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	var res Result
	b, _ := os.ReadFile(filepath.Join(dir, "out", "hello-rebase", "result.json"))
	if err := json.Unmarshal(b, &res); err != nil {
		t.Fatal(err)
	}
	if got, _ := registry.Digest(ctx, repo+":latest"); got != v2App.Digest {
		t.Fatalf("latest is %s, want the newer publish %s\n%s", got, v2App.Digest, out.String())
	}
	if ok, err := registry.Exists(ctx, res.Image); !ok || !res.Published || err != nil {
		t.Fatalf("rebased image %s not published by digest (%v)", res.Image, err)
	}
	if want := "warning: " + repo + ":latest moved from " + v1App.Digest + " to " + v2App.Digest + " during the rebase, so it stays there; pushed " + res.Image + " by digest only"; !strings.Contains(out.String(), want) {
		t.Errorf("output lacks %q:\n%s", want, out.String())
	}

	// The next run rebases what latest holds now.
	out.Reset()
	if err := Rebase(ctx, opts, ro); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	got, _ := registry.Digest(ctx, repo+":latest")
	files, err := registry.ReadFiles(ctx, repo+"@"+got, "linux/amd64", "app/hello", "usr/lib/libssl.so.3")
	if err != nil {
		t.Fatal(err)
	}
	if string(files["app/hello"]) != "hello v2" || string(files["usr/lib/libssl.so.3"]) != "patched amd64" {
		t.Errorf("latest after the next rebase: %q\n%s", files, out.String())
	}
}

// TestBuildRebasesOntoNewerBase: until the pin pull request merges, a build
// from changed source is on the old base. When latest is on a newer build
// of it, the build is rebased onto the newest build before it takes latest,
// and if it can't be, latest stays (#35).
func TestBuildRebasesOntoNewerBase(t *testing.T) {
	reg, host := newHookRegistry(t)
	ctx := context.Background()
	run := host + "/run:latest"
	b1, b2, b3 := runImage(t, "old", 1), runImage(t, "patched", 2), runImage(t, "patched again", 3)
	push(t, run, b1)
	repo := host + "/hello"
	dir := t.TempDir()
	org := manifest.DefaultOrg()
	org.Signing.Mode = "none"
	m := &manifest.Manifest{Kind: manifest.KindApp, Path: filepath.Join(dir, "app.yaml"),
		Metadata: manifest.Metadata{Name: "hello", Ref: repo, Tags: []string{"latest"}}}
	var out bytes.Buffer
	opts := Options{OrgPath: unsignedOrg(t), Version: "test", Stdout: &out, Stderr: &out}
	bo := BuildOptions{Push: true, NoScan: true, OutDir: filepath.Join(dir, "out")}
	ghOut := filepath.Join(dir, "github-output")
	t.Setenv("GITHUB_OUTPUT", ghOut)
	build := func(art *registry.Artifact, bo BuildOptions) (Result, error) {
		t.Helper()
		out.Reset()
		_ = os.Remove(ghOut)
		res := Result{Repository: repo, Digest: art.Digest, Tags: m.Metadata.Tags}
		return res, publishBuild(ctx, opts, org, m, art, bo, "", nil, &res)
	}
	latest := func() string {
		t.Helper()
		got, err := registry.Digest(ctx, repo+":latest")
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	baseOf := func(ref string) string {
		t.Helper()
		a, err := registry.Fetch(ctx, ref)
		if err != nil {
			t.Fatal(err)
		}
		m, _ := platformImage(t, a.Index, "amd64").Manifest()
		return m.Annotations[rebase.AnnotationBaseDigest]
	}
	digestOn := func(base v1.ImageIndex) string {
		d, _ := platformImage(t, base, "amd64").Digest()
		return d.String()
	}

	v1App := appOn(t, b1, run, hello("v1"))
	if res, err := build(v1App, bo); err != nil || latest() != v1App.Digest || res.Rebased != "" {
		t.Fatalf("first build: %v, %+v\n%s", err, res, out.String())
	}
	// The run image is patched, and the fleet rebases the app onto it.
	push(t, run, b2)
	if err := Rebase(ctx, opts, RebaseOptions{Image: repo + ":latest", OutDir: filepath.Join(dir, "out"), NoScan: true, Push: true}); err != nil {
		t.Fatal(err)
	}

	// Before the pin pull request merges, v2 is built on the old base.
	v2App := appOn(t, b1, run, hello("v2"))
	res, err := build(v2App, bo)
	if err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if res.Image != repo+"@"+v2App.Digest || res.Rebased != repo+"@"+latest() || res.Tags != nil {
		t.Fatalf("result %+v, latest %s\n%s", res, latest(), out.String())
	}
	files, err := registry.ReadFiles(ctx, res.Rebased, "linux/arm64", "app/hello", "usr/lib/libssl.so.3")
	if err != nil {
		t.Fatal(err)
	}
	if string(files["app/hello"]) != "hello v2" || string(files["usr/lib/libssl.so.3"]) != "patched arm64" {
		t.Errorf("latest: %q\n%s", files, out.String())
	}
	if !strings.Contains(out.String(), repo+":latest holds sha256:") || !strings.Contains(out.String(), "on a newer build of "+run) {
		t.Errorf("output:\n%s", out.String())
	}
	// The rebase is recorded like the fleet's, and repeats.
	var rec attest.Rebase
	b, _ := os.ReadFile(filepath.Join(dir, "out", "hello-rebase", "attestations", "rebase.predicate.json"))
	if err := json.Unmarshal(b, &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Image != res.Image {
		t.Errorf("rebase record of %s, want %s", rec.Image, res.Image)
	}
	if err := verifyRebase(ctx, opts, &rec, digestOf(res.Rebased)); err != nil {
		t.Fatal(err)
	}
	// The workflow's outputs describe the build, once.
	gh, _ := os.ReadFile(ghOut)
	if strings.Count(string(gh), "digest=") != 1 || !strings.Contains(string(gh), "digest="+v2App.Digest) {
		t.Errorf("GITHUB_OUTPUT:\n%s", gh)
	}

	// An image that can't be rebased leaves latest where it is.
	tagged := latest()
	vendored := appOn(t, b1, run, map[string]string{"usr/lib/libssl.so.3": "vendored"})
	if _, err = build(vendored, bo); err == nil || !strings.Contains(err.Error(), "could not be rebased onto that base, so the tags stay where they are") || !strings.Contains(err.Error(), "lock --update-base") {
		t.Fatalf("unrebaseable build: %v\n%s", err, out.String())
	}
	if latest() != tagged {
		t.Fatal("an unrebaseable build moved latest")
	}
	// --force-tags tags it anyway.
	force := bo
	force.ForceTags = true
	if _, err := build(vendored, force); err != nil || latest() != vendored.Digest {
		t.Fatalf("--force-tags: %v, latest %s\n%s", err, latest(), out.String())
	}

	// A build on the newest base is tagged as it is.
	v3App := appOn(t, b2, run, hello("v3"))
	if res, err := build(v3App, bo); err != nil || res.Rebased != "" || latest() != v3App.Digest {
		t.Fatalf("build on the newest base: %v, %+v\n%s", err, res, out.String())
	}

	// The run image moves on again before the fleet rebases latest: latest
	// is on a build created after the old base, and the new build is
	// rebased onto the newest one.
	push(t, run, b3)
	v4App := appOn(t, b1, run, hello("v4"))
	if res, err = build(v4App, bo); err != nil || res.Rebased == "" || baseOf(repo+":latest") != digestOn(b3) {
		t.Fatalf("build behind two run images: %v, %+v\n%s", err, res, out.String())
	}
	// A build on a newer base than latest's is tagged as it is, though the
	// base moved on since.
	push(t, repo+":latest", v3App.Index)
	push(t, run, runImage(t, "patched once more", 4))
	v5App := appOn(t, b3, run, hello("v5"))
	if res, err := build(v5App, bo); err != nil || res.Rebased != "" || latest() != v5App.Digest {
		t.Fatalf("build on a newer base than latest's: %v, %+v\n%s", err, res, out.String())
	}

	// latest moves while the build rebases: it stays, and the build fails.
	push(t, repo+":latest", appOn(t, b3, run, hello("v5")).Index)
	push(t, run, b3)
	other := appOn(t, b2, run, hello("other"))
	reg.arm("hello", func() { push(t, repo+":latest", other.Index) })
	v6App := appOn(t, b1, run, hello("v6"))
	if _, err := build(v6App, bo); err == nil || !strings.Contains(err.Error(), "while this build was rebasing") || latest() != other.Digest {
		t.Fatalf("latest moved during the rebase: %v, latest %s\n%s", err, latest(), out.String())
	}
}
