package factory

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"maps"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/northcutted/clearcutt-factory/internal/attest"
	"github.com/northcutted/clearcutt-factory/internal/lock"
	"github.com/northcutted/clearcutt-factory/internal/manifest"
	"github.com/northcutted/clearcutt-factory/internal/rebase"
	"github.com/northcutted/clearcutt-factory/internal/registry"
)

func testLayer(t *testing.T, files map[string]string) v1.Layer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, n := range slices.Sorted(maps.Keys(files)) {
		h := &tar.Header{Name: n, Mode: 0o644, Size: int64(len(files[n])), Typeflag: tar.TypeReg, ModTime: time.Unix(1700000000, 0)}
		if strings.HasSuffix(n, "/") {
			h.Typeflag, h.Mode, h.Size = tar.TypeDir, 0o755, 0
		}
		_ = tw.WriteHeader(h)
		_, _ = tw.Write([]byte(files[n]))
	}
	_ = tw.Close()
	b := buf.Bytes()
	l, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil },
		tarball.WithMediaType(types.OCILayer))
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// testIndex builds an amd64+arm64 index; layers(arch) gives each image's
// layers on top of base(arch) (nil for none).
func testIndex(t *testing.T, base func(arch string) v1.Image, layers func(arch string) []v1.Layer, anns func(arch string) map[string]string) v1.ImageIndex {
	t.Helper()
	var adds []mutate.IndexAddendum
	for _, arch := range []string{"amd64", "arm64"} {
		img := mutate.ConfigMediaType(mutate.MediaType(empty.Image, types.OCIManifestSchema1), types.OCIConfigJSON)
		if base != nil {
			img = base(arch)
		}
		img, err := mutate.AppendLayers(img, layers(arch)...)
		if err != nil {
			t.Fatal(err)
		}
		cf, _ := img.ConfigFile()
		cf = cf.DeepCopy()
		cf.OS, cf.Architecture = "linux", arch
		cf.Config.Entrypoint = []string{"/app/hello"}
		if img, err = mutate.ConfigFile(img, cf); err != nil {
			t.Fatal(err)
		}
		if anns != nil {
			img = mutate.Annotations(img, anns(arch)).(v1.Image)
		}
		adds = append(adds, mutate.IndexAddendum{Add: img, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: arch}}})
	}
	return mutate.IndexMediaType(mutate.AppendManifests(empty.Index, adds...), types.OCIImageIndex)
}

func push(t *testing.T, ref string, idx v1.ImageIndex) {
	t.Helper()
	r, err := name.ParseReference(ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.WriteIndex(r, idx); err != nil {
		t.Fatal(err)
	}
}

func TestRebaseCommand(t *testing.T) {
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
	push(t, host+"/base:v1", oldBase)
	push(t, host+"/base:latest", oldBase)

	baseImage := func(arch string) v1.Image {
		im, _ := oldBase.IndexManifest()
		for _, d := range im.Manifests {
			if d.Platform.Architecture == arch {
				img, _ := oldBase.Image(d.Digest)
				return img
			}
		}
		t.Fatal("no base for " + arch)
		return nil
	}
	app := testIndex(t, baseImage, func(arch string) []v1.Layer {
		return []v1.Layer{testLayer(t, map[string]string{"app/": "", "app/hello": "hello " + arch})}
	}, func(arch string) map[string]string {
		d, _ := baseImage(arch).Digest()
		return map[string]string{rebase.AnnotationBaseName: host + "/base:latest", rebase.AnnotationBaseDigest: d.String()}
	})
	push(t, host+"/hello:1", app)

	dir := t.TempDir()
	org := filepath.Join(dir, "factory.org.yaml")
	if err := os.WriteFile(org, []byte("apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\nsigning: {mode: none}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	opts := Options{OrgPath: org, Version: "test", Stdout: &out, Stderr: &out}
	ro := RebaseOptions{Image: host + "/hello:1", OutDir: filepath.Join(dir, "out"), NoScan: true, Push: true}

	// The base tag hasn't moved: nothing to do.
	if err := Rebase(ctx, opts, ro); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "nothing to do") {
		t.Fatalf("expected nothing to do:\n%s", out.String())
	}

	// The base is rebuilt: the app follows the tag.
	push(t, host+"/base:latest", newBase)
	out.Reset()
	check := ro
	check.Check = true
	if err := Rebase(ctx, opts, check); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "linux/amd64: safe to rebase") {
		t.Fatalf("check output:\n%s", out.String())
	}
	out.Reset()
	if err := Rebase(ctx, opts, ro); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}

	b, err := os.ReadFile(filepath.Join(dir, "out", "hello-rebase", "result.json"))
	if err != nil {
		t.Fatal(err)
	}
	var res Result
	if err := json.Unmarshal(b, &res); err != nil {
		t.Fatal(err)
	}
	pushed, err := registry.Fetch(ctx, host+"/hello:1")
	if err != nil {
		t.Fatal(err)
	}
	if pushed.Digest != res.Digest || res.Image != host+"/hello@"+res.Digest {
		t.Fatalf("tag 1 points at %s; result %+v", pushed.Digest, res)
	}
	files, err := registry.ReadFiles(ctx, res.Image, "linux/arm64", "usr/lib/libssl.so.3", "app/hello")
	if err != nil {
		t.Fatal(err)
	}
	if string(files["usr/lib/libssl.so.3"]) != "patched arm64" || string(files["app/hello"]) != "hello arm64" {
		t.Errorf("rebased arm64 files: %q", files)
	}

	// The record repeats to the same digest.
	var rec attest.Rebase
	b, _ = os.ReadFile(filepath.Join(dir, "out", "hello-rebase", "attestations", "rebase.predicate.json"))
	if err := json.Unmarshal(b, &rec); err != nil {
		t.Fatal(err)
	}
	if err := verifyRebase(ctx, opts, &rec, res.Digest); err != nil {
		t.Fatal(err)
	}

	// Rebasing the rebased image again is a no-op: it names the new base.
	out.Reset()
	if err := Rebase(ctx, opts, ro); err != nil || !strings.Contains(out.String(), "nothing to do") {
		t.Fatalf("second rebase: %v\n%s", err, out.String())
	}

	// An image whose layers patch a base file is refused.
	bad := testIndex(t, baseImage, func(arch string) []v1.Layer {
		return []v1.Layer{testLayer(t, map[string]string{"usr/lib/libssl.so.3": "vendored"})}
	}, func(arch string) map[string]string {
		d, _ := baseImage(arch).Digest()
		return map[string]string{rebase.AnnotationBaseName: host + "/base:latest", rebase.AnnotationBaseDigest: d.String()}
	})
	push(t, host+"/bad:1", bad)
	out.Reset()
	badOpts := ro
	badOpts.Image = host + "/bad:1"
	err = Rebase(ctx, opts, badOpts)
	if err == nil || !strings.Contains(out.String(), "replace files of the old base: /usr/lib/libssl.so.3") {
		t.Fatalf("bad rebase: %v\n%s", err, out.String())
	}
}

// TestRebaseApp rebases apps by manifest and keeps their locks on the base
// the published image is on, also when the rebase is refused.
func TestRebaseApp(t *testing.T) {
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
	ann := func(arch string) map[string]string {
		d, _ := baseImage(arch).Digest()
		return map[string]string{rebase.AnnotationBaseName: host + "/run:latest", rebase.AnnotationBaseDigest: d.String()}
	}
	push(t, host+"/apps/hello:latest", testIndex(t, baseImage, func(string) []v1.Layer {
		return []v1.Layer{testLayer(t, map[string]string{"app/": "", "app/hello": "hi"})}
	}, ann))
	push(t, host+"/apps/bad:latest", testIndex(t, baseImage, func(string) []v1.Layer {
		return []v1.Layer{testLayer(t, map[string]string{"usr/lib/libssl.so.3": "vendored"})}
	}, ann))

	dir := t.TempDir()
	files := map[string]string{
		"factory.org.yaml": "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\nregistry: " + host + "/apps\nsigning: {mode: none}\n",
		"stack.yaml":       "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: Stack\nmetadata: {name: s}\nspec:\n  build: golang:1\n  run: " + host + "/run:latest\n  platforms: [linux/amd64, linux/arm64]\n  steps: [{run: make}]\n",
		"hello/app.yaml":   "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: App\nmetadata: {name: hello}\nspec: {stack: ../stack.yaml}\n",
		"bad/app.yaml":     "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: App\nmetadata: {name: bad}\nspec: {stack: ../stack.yaml}\n",
	}
	for n, body := range files {
		p := filepath.Join(dir, n)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	oldIdx, _ := oldBase.Digest()
	newIdx, _ := newBase.Digest()
	var out bytes.Buffer
	for _, app := range []string{"hello", "bad"} {
		opts := Options{ManifestPath: filepath.Join(dir, app, "app.yaml"), Version: "test", Stdout: &out, Stderr: &out}
		// The app's lock pins the run image it was built on.
		m, org, err := load(ctx, opts, false)
		if err != nil {
			t.Fatal(err)
		}
		fake := func(c string) lock.Image { return lock.Image{Ref: c, Digest: "sha256:" + strings.Repeat("f", 64)} }
		amd, _ := baseImage("amd64").Digest()
		arm, _ := baseImage("arm64").Digest()
		l := &lock.Lock{
			APIVersion: manifest.APIVersion, Kind: lock.Kind, InputsDigest: lock.InputsOf(m, org).Digest(), SourceDateEpoch: 1700000000,
			Builder: lock.Builder{BuildKit: fake(org.Builder.BuildKit), Frontend: fake(org.Builder.Frontend), Toolbox: fake(org.Builder.Toolbox)},
			Base:    lock.Image{Ref: m.Spec.Base, Digest: oldIdx.String()},
			App: &lock.App{Stack: "s", StackDigest: lock.StackDigest(m.Stack), Build: fake("golang:1"),
				RunPlatforms: map[string]string{"linux/amd64": amd.String(), "linux/arm64": arm.String()}},
		}
		if err := l.Write(m.LockPath()); err != nil {
			t.Fatal(err)
		}
	}
	push(t, host+"/run:latest", newBase)

	opts := Options{ManifestPath: filepath.Join(dir, "hello", "app.yaml"), Version: "test", Stdout: &out, Stderr: &out}
	ro := RebaseOptions{OutDir: filepath.Join(dir, "out"), Push: true, NoScan: true, UpdateLock: true}
	if err := Rebase(ctx, opts, ro); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	l, err := lock.Read(filepath.Join(dir, "hello", "app.lock.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if l.Base.Digest != newIdx.String() || l.App.Build.Digest != "sha256:"+strings.Repeat("f", 64) {
		t.Errorf("lock: base %s (want %s), build %s\n%s", l.Base.Digest, newIdx, l.App.Build.Digest, out.String())
	}
	cf, _ := os.ReadFile(filepath.Join(dir, "hello", "app.Containerfile"))
	if !strings.Contains(string(cf), "FROM "+host+"/run:latest@"+newIdx.String()) {
		t.Errorf("Containerfile does not build on the new base:\n%s", cf)
	}
	if !strings.Contains(out.String(), "base "+host+"/run:latest: sha256:") {
		t.Errorf("no change summary:\n%s", out.String())
	}

	out.Reset()
	if err := Rebase(ctx, opts, ro); err != nil || !strings.Contains(out.String(), "nothing to do") || !strings.Contains(out.String(), "is up to date") {
		t.Errorf("second run: %v\n%s", err, out.String())
	}

	// A refused rebase still moves the lock, so the next build fixes it.
	out.Reset()
	opts.ManifestPath = filepath.Join(dir, "bad", "app.yaml")
	err = Rebase(ctx, opts, ro)
	if err == nil || !strings.Contains(err.Error(), "now pins the new base; build the app") {
		t.Fatalf("bad app: %v\n%s", err, out.String())
	}
	if l, _ := lock.Read(filepath.Join(dir, "bad", "app.lock.yaml")); l == nil || l.Base.Digest != newIdx.String() {
		t.Error("refused rebase did not move the lock")
	}

	if err := Rebase(ctx, Options{ManifestPath: filepath.Join(dir, "stack.yaml"), Stdout: &out, Stderr: &out}, ro); err == nil {
		t.Error("rebase -f accepted a stack")
	}
}

// TestPublishOnce: publishing an unchanged digest again only moves tags.
func TestPublishOnce(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0))))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	ctx := context.Background()
	idx := testIndex(t, nil, func(arch string) []v1.Layer { return []v1.Layer{testLayer(t, map[string]string{"a": arch})} }, nil)
	d, _ := idx.Digest()
	art := &registry.Artifact{Digest: d.String(), Index: idx}
	org := manifest.DefaultOrg()
	org.Signing.Mode = "none"
	var out bytes.Buffer
	opts := Options{Stdout: &out, Stderr: &out}

	ref, published, _, err := publish(ctx, opts, org, art, host+"/app", []string{"latest"}, attest.RecipePredicateType, "", nil, false)
	if err != nil || !published || ref != host+"/app@"+d.String() {
		t.Fatalf("first publish: %s %v %v", ref, published, err)
	}
	// The tag moves elsewhere, then the same digest is published again.
	other := testIndex(t, nil, func(arch string) []v1.Layer { return []v1.Layer{testLayer(t, map[string]string{"b": arch})} }, nil)
	push(t, host+"/app:latest", other)
	_, published, _, err = publish(ctx, opts, org, art, host+"/app", []string{"latest", "v1"}, attest.RecipePredicateType, "", nil, false)
	if err != nil || published {
		t.Fatalf("second publish: published=%v, %v", published, err)
	}
	for _, tag := range []string{"latest", "v1"} {
		if got, _ := registry.Digest(ctx, host+"/app:"+tag); got != d.String() {
			t.Errorf("%s points at %s, want %s", tag, got, d)
		}
	}
	if !strings.Contains(out.String(), "already published; moved its tags") {
		t.Errorf("output:\n%s", out.String())
	}
	if ok, err := registry.Exists(ctx, host+"/app@sha256:"+strings.Repeat("0", 64)); ok || err != nil {
		t.Errorf("missing digest: exists=%v, %v", ok, err)
	}
}

// TestRegistryStack publishes a stack and builds an app manifest on it.
func TestRegistryStack(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0))))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	ctx := context.Background()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))

	dir := t.TempDir()
	files := map[string]string{
		"platform/factory.org.yaml":   "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\nregistry: registry.example/platform\ntags: [stable]\nsigning: {mode: none}\n",
		"platform/runtime/image.yaml": "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: Image\nmetadata: {name: go-runtime}\nspec: {base: cgr.dev/chainguard/static:latest}\n",
		"platform/stacks/go.yaml":     "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: Stack\nmetadata: {name: go}\nspec:\n  build: golang:1\n  run: ../runtime/image.yaml\n  steps: [{run: go build -o /out/app .}]\n  entrypoint: [\"/app/{{name}}\"]\n",
		"team/factory.org.yaml":       "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\nregistry: registry.example/team\nsigning: {mode: none}\n",
		"team/svc/app.yaml":           "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: App\nmetadata: {name: svc}\nspec: {stack: " + host + "/stacks/go:1}\n",
	}
	for n, body := range files {
		p := filepath.Join(dir, n)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	opts := Options{Stdout: &out, Stderr: &out}
	if err := StackPush(ctx, opts, filepath.Join(dir, "platform/stacks/go.yaml"), host+"/stacks/go:1", false); err != nil {
		t.Fatal(err)
	}

	// Another repository's app names the published stack; its run image was
	// a factory manifest path, published as that image's reference.
	opts.ManifestPath = filepath.Join(dir, "team/svc/app.yaml")
	m, _, err := load(ctx, opts, false)
	if err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if m.Spec.Base != "registry.example/platform/go-runtime:stable" || m.Stack.BuildRef != "golang:1" || m.StackFrom == nil || !strings.HasPrefix(m.StackFrom.Digest, "sha256:") {
		t.Fatalf("app on registry stack: base %q build %q from %+v", m.Spec.Base, m.Stack.BuildRef, m.StackFrom)
	}
	if strings.Join(m.Spec.Entrypoint, " ") != "/app/svc" {
		t.Errorf("entrypoint = %v", m.Spec.Entrypoint)
	}

	// A lock pin wins over the tag, even after the tag moves.
	pinned := m.StackFrom.Digest
	l := &lock.Lock{APIVersion: manifest.APIVersion, Kind: lock.Kind, App: &lock.App{StackArtifact: &lock.Image{Ref: host + "/stacks/go:1", Digest: pinned}}}
	if err := l.Write(m.LockPath()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "platform/stacks/go.yaml"), []byte(strings.Replace(files["platform/stacks/go.yaml"], "golang:1", "golang:2", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := StackPush(ctx, opts, filepath.Join(dir, "platform/stacks/go.yaml"), host+"/stacks/go:1", false); err != nil {
		t.Fatal(err)
	}
	if m, _, err = load(ctx, opts, false); err != nil || m.StackFrom.Digest != pinned || m.Stack.BuildRef != "golang:1" {
		t.Errorf("pinned load: %v, %+v", err, m.StackFrom)
	}
	if m, _, err = load(ctx, opts, true); err != nil || m.StackFrom.Digest == pinned || m.Stack.BuildRef != "golang:2" {
		t.Errorf("fresh load: %v, %+v", err, m.StackFrom)
	}
}
