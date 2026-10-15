package factory

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"maps"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
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
	if got, err := verifyRebase(ctx, opts, &rec, res.Digest); err != nil || got != res.Digest {
		t.Fatalf("repeating the rebase gave %s, %v", got, err)
	}

	// verify --attest repeats it from the signed record and attests that.
	t.Run("attest", func(t *testing.T) { testAttestReproduction(t, dir, res.Image) })

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
// the published image is on. When the rebase is refused, the lock moves to
// the new base anyway, and to the stack's newest build image, so the
// rebuild uses the toolchain that matches the new run image.
func TestRebaseApp(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0))))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	ctx := context.Background()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))

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
	push(t, host+"/apps/badreg:latest", testIndex(t, baseImage, func(string) []v1.Layer {
		return []v1.Layer{testLayer(t, map[string]string{"usr/lib/libssl.so.3": "vendored too"})}
	}, ann))
	// The build image (toolchain) the platform team publishes with the run
	// image.
	toolchain := func(v string) v1.ImageIndex {
		return testIndex(t, nil, func(string) []v1.Layer { return []v1.Layer{testLayer(t, map[string]string{"usr/bin/cc": v})} }, nil)
	}
	oldBuild, newBuild := toolchain("old"), toolchain("new")
	push(t, host+"/build:1", oldBuild)
	oldBuildIdx, _ := oldBuild.Digest()
	newBuildIdx, _ := newBuild.Digest()

	dir := t.TempDir()
	stack := func(build string) string {
		return "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: Stack\nmetadata: {name: s}\nspec:\n  build: " + host + "/" + build + "\n  run: " + host + "/run:latest\n  platforms: [linux/amd64, linux/arm64]\n  steps: [{run: make}]\n"
	}
	files := map[string]string{
		"factory.org.yaml":    "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\nregistry: " + host + "/apps\nsigning: {mode: none}\n",
		"stack.yaml":          stack("build:1"),
		"hello/app.yaml":      "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: App\nmetadata: {name: hello}\nspec: {stack: ../stack.yaml}\n",
		"bad/app.yaml":        "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: App\nmetadata: {name: bad}\nspec: {stack: ../stack.yaml}\n",
		"badreg/app.yaml":     "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: App\nmetadata: {name: badreg}\nspec: {stack: " + host + "/stacks/s:1}\n",
		"platform/stack.yaml": stack("build:1"),
	}
	for n, body := range files {
		p := filepath.Join(dir, n)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	// badreg builds on a registry stack.
	stackPush := func(build string) string {
		if err := os.WriteFile(filepath.Join(dir, "platform/stack.yaml"), []byte(stack(build)), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := StackPush(ctx, Options{Stdout: &out, Stderr: &out}, filepath.Join(dir, "platform/stack.yaml"), host+"/stacks/s:1", true); err != nil {
			t.Fatal(err)
		}
		d, err := registry.Digest(ctx, host+"/stacks/s:1")
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	oldStack := stackPush("build:1")

	oldIdx, _ := oldBase.Digest()
	newIdx, _ := newBase.Digest()
	fake := func(c string) lock.Image { return lock.Image{Ref: c, Digest: "sha256:" + strings.Repeat("f", 64)} }
	for _, app := range []string{"hello", "bad", "badreg"} {
		opts := Options{ManifestPath: filepath.Join(dir, app, "app.yaml"), Version: "test", Stdout: &out, Stderr: &out}
		// The app's lock pins the run and build images it was built with.
		m, org, err := load(ctx, opts, false)
		if err != nil {
			t.Fatal(err)
		}
		amd, _ := baseImage("amd64").Digest()
		arm, _ := baseImage("arm64").Digest()
		l := &lock.Lock{
			APIVersion: manifest.APIVersion, Kind: lock.Kind, InputsDigest: lock.InputsOf(m, org).Digest(), SourceDateEpoch: 1700000000,
			Builder: lock.Builder{BuildKit: fake(org.Builder.BuildKit), Frontend: fake(org.Builder.Frontend), Toolbox: fake(org.Builder.Toolbox)},
			Base:    lock.Image{Ref: m.Spec.Base, Digest: oldIdx.String()},
			App: &lock.App{Stack: "s", StackDigest: lock.StackDigest(m.Stack), Build: lock.Image{Ref: m.Stack.BuildRef, Digest: oldBuildIdx.String()},
				RunPlatforms: map[string]string{"linux/amd64": amd.String(), "linux/arm64": arm.String()}},
		}
		if m.StackFrom != nil {
			l.App.StackArtifact = &lock.Image{Ref: m.StackFrom.Ref, Digest: m.StackFrom.Digest}
		}
		if err := l.Write(m.LockPath()); err != nil {
			t.Fatal(err)
		}
	}
	// The platform team publishes a new run image and, with it, a new build
	// of the toolchain; the registry stack's new version names it.
	push(t, host+"/run:latest", newBase)
	push(t, host+"/build:1", newBuild)
	push(t, host+"/build:2", newBuild)
	newStack := stackPush("build:2")

	opts := Options{ManifestPath: filepath.Join(dir, "hello", "app.yaml"), Version: "test", Stdout: &out, Stderr: &out}
	ro := RebaseOptions{OutDir: filepath.Join(dir, "out"), Push: true, NoScan: true, UpdateLock: true}
	if err := Rebase(ctx, opts, ro); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	l, err := lock.Read(filepath.Join(dir, "hello", "app.lock.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	// The rebased image's layer was built with the old build image, so the
	// lock, its recipe, keeps it.
	if l.Base.Digest != newIdx.String() || l.App.Build.Digest != oldBuildIdx.String() {
		t.Errorf("lock: base %s (want %s), build %s (want %s)\n%s", l.Base.Digest, newIdx, l.App.Build.Digest, oldBuildIdx, out.String())
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

	// A refused rebase still moves the lock, so the next build fixes it:
	// to the new run image and the build image made for it, keeping the
	// builder pins.
	out.Reset()
	opts.ManifestPath = filepath.Join(dir, "bad", "app.yaml")
	err = Rebase(ctx, opts, ro)
	if err == nil || !strings.Contains(err.Error(), "now pins the new base and the stack's newest build image; build the app") {
		t.Fatalf("bad app: %v\n%s", err, out.String())
	}
	l, err = lock.Read(filepath.Join(dir, "bad", "app.lock.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if l.Base.Digest != newIdx.String() || l.App.Build.Digest != newBuildIdx.String() || l.Builder.BuildKit != fake(l.Builder.BuildKit.Ref) {
		t.Errorf("refused rebase: base %s (want %s), build %s (want %s), buildkit %s\n%s", l.Base.Digest, newIdx, l.App.Build.Digest, newBuildIdx, l.Builder.BuildKit.Digest, out.String())
	}
	if !strings.Contains(out.String(), "build image "+host+"/build:1: sha256:") {
		t.Errorf("no build image change in the summary:\n%s", out.String())
	}
	cf, _ = os.ReadFile(filepath.Join(dir, "bad", "app.Containerfile"))
	if !strings.Contains(string(cf), host+"/build:1@"+newBuildIdx.String()) {
		t.Errorf("Containerfile does not build with the new build image:\n%s", cf)
	}

	// On a registry stack, the rebuild also takes the stack's newest
	// version (which may name another build image).
	out.Reset()
	opts.ManifestPath = filepath.Join(dir, "badreg", "app.yaml")
	if err := Rebase(ctx, opts, ro); err == nil || !strings.Contains(err.Error(), "build the app") {
		t.Fatalf("badreg app: %v\n%s", err, out.String())
	}
	l, err = lock.Read(filepath.Join(dir, "badreg", "app.lock.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if l.App.StackArtifact == nil || l.App.StackArtifact.Digest != newStack || newStack == oldStack {
		t.Errorf("registry stack pin %+v, want %s\n%s", l.App.StackArtifact, newStack, out.String())
	}
	if l.Base.Digest != newIdx.String() || l.App.Build != (lock.Image{Ref: host + "/build:2", Digest: newBuildIdx.String()}) {
		t.Errorf("refused rebase on a registry stack: base %s (want %s), build %+v\n%s", l.Base.Digest, newIdx, l.App.Build, out.String())
	}
	// The next build reads the new stack, and the lock is current for it.
	if m, _, _, err := loadLocked(ctx, opts); err != nil || m.StackFrom.Digest != newStack {
		t.Errorf("next build: %v", err)
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

	ref, published, _, err := publish(ctx, opts, org, art, host+"/app", []string{"latest"}, attest.RecipePredicateType, "", nil, false, false)
	if err != nil || !published || ref != host+"/app@"+d.String() {
		t.Fatalf("first publish: %s %v %v", ref, published, err)
	}
	// The tag moves elsewhere, then the same digest is published again.
	other := testIndex(t, nil, func(arch string) []v1.Layer { return []v1.Layer{testLayer(t, map[string]string{"b": arch})} }, nil)
	push(t, host+"/app:latest", other)
	_, published, _, err = publish(ctx, opts, org, art, host+"/app", []string{"latest", "v1"}, attest.RecipePredicateType, "", nil, false, false)
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
	ghOutput := filepath.Join(dir, "github-output")
	t.Setenv("GITHUB_OUTPUT", ghOutput)
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
	// The workflow learns what was pushed, for notify.yml.
	gho, _ := os.ReadFile(ghOutput)
	if want := "image=" + host + "/stacks/go@" + m.StackFrom.Digest + "\nrepository=" + host + "/stacks/go\ndigest=" + m.StackFrom.Digest + "\n"; !strings.HasPrefix(string(gho), want) {
		t.Errorf("GITHUB_OUTPUT:\n%s\nwant prefix\n%s", gho, want)
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

// testAttestReproduction runs verify --image --attest on a rebased image
// with a stand-in cosign that serves the image's rebase record and records
// what it is asked to attest.
func testAttestReproduction(t *testing.T, dir, image string) {
	ctx := context.Background()
	statement, err := os.ReadFile(filepath.Join(dir, "out", "hello-rebase", "attestations", "rebase.intoto.json"))
	if err != nil {
		t.Fatal(err)
	}
	bin, work := t.TempDir(), t.TempDir()
	envelope, _ := json.Marshal(map[string]string{"payloadType": "application/vnd.in-toto+json", "payload": base64.StdEncoding.EncodeToString(statement)})
	if err := os.WriteFile(filepath.Join(work, "envelope.json"), envelope, 0o644); err != nil {
		t.Fatal(err)
	}
	cosign := `#!/bin/sh
case "$1" in
verify-attestation)
  case "$*" in
  *` + attest.RebasePredicateType + `*) cat "$WORK/envelope.json"; echo ;;
  *) echo "no matching attestations" >&2; exit 1 ;;
  esac ;;
attest)
  printf '%s\n' "$@" > "$WORK/args"
  while [ $# -gt 0 ]; do [ "$1" = --predicate ] && cp "$2" "$WORK/predicate.json"; shift; done ;;
*) exit 1 ;;
esac
`
	if err := os.WriteFile(filepath.Join(bin, "cosign"), []byte(cosign), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("WORK", work)
	for k, v := range map[string]string{
		"GITHUB_ACTIONS": "true", "GITHUB_SERVER_URL": "https://github.com", "GITHUB_REPOSITORY": "acme/checkout",
		"GITHUB_RUN_ID": "42", "GITHUB_RUN_ATTEMPT": "2", "GITHUB_JOB": "reproduce", "RUNNER_ENVIRONMENT": "github-hosted",
		"GITHUB_WORKFLOW_REF": "acme/checkout/.github/workflows/clearcutt-factory.yml@refs/heads/main",
	} {
		t.Setenv(k, v)
	}
	org := filepath.Join(work, "factory.org.yaml")
	if err := os.WriteFile(org, []byte("apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\nsigning:\n  mode: keyless\n  verify: {certificateIdentity: https://example.test/wf, certificateOIDCIssuer: https://issuer.example.test}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	opts := Options{OrgPath: org, Version: "v9.9.9", Stdout: &out, Stderr: io.Discard}
	digest := digestOf(image)
	if err := Verify(ctx, opts, VerifyOptions{Image: image, OutDir: filepath.Join(work, "out"), Attest: true}); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	// clearcutt-verify reads the result from the last line.
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if last := lines[len(lines)-1]; last != "reproducible: rebase gives "+digest+" again" {
		t.Errorf("last line %q", last)
	}

	args, _ := os.ReadFile(filepath.Join(work, "args"))
	if want := "attest\n--type\n" + attest.ReproductionPredicateType + "\n--predicate\n"; !strings.HasPrefix(string(args), want) || !strings.Contains(string(args), "\n"+image+"\n--yes\n") {
		t.Errorf("cosign attest arguments:\n%s", args)
	}
	var r attest.Reproduction
	b, _ := os.ReadFile(filepath.Join(work, "predicate.json"))
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(statement)
	want := attest.Reproduction{
		Method: MethodRebaseRepeat, Image: image, Digest: digest,
		From:    attest.Evidence{PredicateType: attest.RebasePredicateType, Digest: map[string]string{"sha256": hex.EncodeToString(sum[:])}},
		Factory: attest.FactoryInfo{Version: "v9.9.9"},
		Builder: attest.Builder{
			ID: "https://github.com/acme/checkout/actions/runs/42/attempts/2", Job: "reproduce", Runner: "github-hosted",
			Workflow: "acme/checkout/.github/workflows/clearcutt-factory.yml@refs/heads/main", OS: runtime.GOOS, Arch: runtime.GOARCH,
		},
		ReproducedAt: r.ReproducedAt,
	}
	if !reflect.DeepEqual(r, want) {
		t.Errorf("reproduction\n got %+v\nwant %+v", r, want)
	}
	if _, err := time.Parse(time.RFC3339, r.ReproducedAt); err != nil {
		t.Errorf("reproducedAt %q: %v", r.ReproducedAt, err)
	}

	// Rebuilding from source attests nothing: the attestation is about the
	// signed recipe or record.
	if err := Verify(ctx, opts, VerifyOptions{Image: image, FromSource: true, Attest: true}); err == nil || !strings.Contains(err.Error(), "--attest needs --image without -f") {
		t.Errorf("verify -f --attest: %v", err)
	}
}
