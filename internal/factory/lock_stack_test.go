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

	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/northcutted/clearcutt-factory/internal/lock"
	"github.com/northcutted/clearcutt-factory/internal/manifest"
	"github.com/northcutted/clearcutt-factory/internal/registry"
)

// TestLockUpdateStack: lock --update-stack moves an app's lock to the
// stack's newest build and run images (a registry stack to its newest
// version), keeping every other pin, for the rebuild that follows a
// build-image publish; a plain lock keeps the old pins, and the flag is
// refused for images and with --update.
func TestLockUpdateStack(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0))))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	ctx := context.Background()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))

	osRel := map[string]string{"etc/": "", "etc/os-release": "ID=wolfi\nVERSION_ID=20230201\n"}
	run := func(v string) v1.ImageIndex {
		return testIndex(t, nil, func(arch string) []v1.Layer {
			return []v1.Layer{testLayer(t, osRel), testLayer(t, map[string]string{"usr/lib/libssl.so.3": v + " " + arch})}
		}, nil)
	}
	toolchain := func(v string) v1.ImageIndex {
		return testIndex(t, nil, func(string) []v1.Layer { return []v1.Layer{testLayer(t, map[string]string{"usr/bin/cc": v})} }, nil)
	}
	oldRun, newRun := run("old"), run("patched")
	oldBuild, newBuild := toolchain("old"), toolchain("new")
	push(t, host+"/run:latest", oldRun)
	push(t, host+"/build:1", oldBuild)
	digest := func(idx v1.ImageIndex) string { d, _ := idx.Digest(); return d.String() }

	dir := t.TempDir()
	stack := func(build string) string {
		return "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: Stack\nmetadata: {name: s}\nspec:\n  build: " + host + "/" + build + "\n  run: " + host + "/run:latest\n  platforms: [linux/amd64, linux/arm64]\n  steps: [{run: make}]\n"
	}
	files := map[string]string{
		"factory.org.yaml":    "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\nregistry: " + host + "/apps\nsigning: {mode: none}\n",
		"stack.yaml":          stack("build:1"),
		"platform/stack.yaml": stack("build:1"),
		"hello/app.yaml":      "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: App\nmetadata: {name: hello}\nspec: {stack: ../stack.yaml}\n",
		"reg/app.yaml":        "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: App\nmetadata: {name: reg}\nspec: {stack: " + host + "/stacks/s:1}\n",
		"tools/image.yaml":    "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: Image\nmetadata: {name: tools}\nspec: {base: " + host + "/run:latest}\n",
	}
	for n, body := range files {
		p := filepath.Join(dir, n)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
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

	// Each app's lock pins the run and build images it was built with; the
	// builder pins are made up, so nothing is fetched for them.
	fake := func(c string) lock.Image { return lock.Image{Ref: c, Digest: "sha256:" + strings.Repeat("f", 64)} }
	platforms := func(idx v1.ImageIndex) map[string]string {
		im, _ := idx.IndexManifest()
		m := map[string]string{}
		for _, d := range im.Manifests {
			m["linux/"+d.Platform.Architecture] = d.Digest.String()
		}
		return m
	}
	for _, app := range []string{"hello", "reg"} {
		opts := Options{ManifestPath: filepath.Join(dir, app, "app.yaml"), Version: "test", Stdout: &out, Stderr: &out}
		m, org, err := load(ctx, opts, false)
		if err != nil {
			t.Fatal(err)
		}
		l := &lock.Lock{
			APIVersion: manifest.APIVersion, Kind: lock.Kind, InputsDigest: lock.InputsOf(m, org).Digest(), SourceDateEpoch: 1700000000,
			Builder: lock.Builder{BuildKit: fake(org.Builder.BuildKit), Frontend: fake(org.Builder.Frontend), Toolbox: fake(org.Builder.Toolbox)},
			Base:    lock.Image{Ref: m.Spec.Base, Digest: digest(oldRun)},
			App: &lock.App{Stack: "s", StackDigest: lock.StackDigest(m.Stack), Build: lock.Image{Ref: m.Stack.BuildRef, Digest: digest(oldBuild)},
				RunPlatforms: platforms(oldRun)},
		}
		if m.StackFrom != nil {
			l.App.StackArtifact = &lock.Image{Ref: m.StackFrom.Ref, Digest: m.StackFrom.Digest}
		}
		if err := l.Write(m.LockPath()); err != nil {
			t.Fatal(err)
		}
	}

	// The platform team rebuilds the toolchain (same tag) and the run
	// image, and publishes a stack version naming a new build image tag.
	push(t, host+"/build:1", newBuild)
	push(t, host+"/run:latest", newRun)
	push(t, host+"/build:2", newBuild)
	newStack := stackPush("build:2")
	if newStack == oldStack {
		t.Fatal("the stack did not change")
	}

	hello := Options{ManifestPath: filepath.Join(dir, "hello", "app.yaml"), Version: "test", Stdout: &out, Stderr: &out}
	// A plain lock keeps the pins it has.
	out.Reset()
	if err := Lock(ctx, hello, LockOptions{}); err != nil || !strings.Contains(out.String(), "is up to date") {
		t.Fatalf("plain lock: %v\n%s", err, out.String())
	}
	l, err := lock.Read(filepath.Join(dir, "hello", "app.lock.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if l.App.Build.Digest != digest(oldBuild) || l.Base.Digest != digest(oldRun) {
		t.Errorf("plain lock moved: build %s, base %s", l.App.Build.Digest, l.Base.Digest)
	}

	// --update-stack moves the build image (and the run image, which moved
	// too), keeping the builder pins.
	out.Reset()
	if err := Lock(ctx, hello, LockOptions{UpdateStack: true}); err != nil {
		t.Fatalf("update-stack: %v\n%s", err, out.String())
	}
	if l, err = lock.Read(filepath.Join(dir, "hello", "app.lock.yaml")); err != nil {
		t.Fatal(err)
	}
	if l.App.Build != (lock.Image{Ref: host + "/build:1", Digest: digest(newBuild)}) || l.Base.Digest != digest(newRun) || l.Builder.BuildKit != fake(l.Builder.BuildKit.Ref) {
		t.Errorf("update-stack: build %+v (want %s), base %s (want %s), buildkit %s\n%s", l.App.Build, digest(newBuild), l.Base.Digest, digest(newRun), l.Builder.BuildKit.Digest, out.String())
	}
	if l.App.RunPlatforms["linux/amd64"] != platforms(newRun)["linux/amd64"] {
		t.Errorf("run platforms not moved: %v", l.App.RunPlatforms)
	}
	for _, want := range []string{"build image " + host + "/build:1: sha256:", "base " + host + "/run:latest: sha256:", "wrote "} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
	cf, _ := os.ReadFile(filepath.Join(dir, "hello", "app.Containerfile"))
	if !strings.Contains(string(cf), host+"/build:1@"+digest(newBuild)) || !strings.Contains(string(cf), host+"/run:latest@"+digest(newRun)) {
		t.Errorf("Containerfile does not build with the new images:\n%s", cf)
	}
	// Again: nothing moves.
	out.Reset()
	if err := Lock(ctx, hello, LockOptions{UpdateStack: true}); err != nil || !strings.Contains(out.String(), "is up to date") {
		t.Errorf("second update-stack: %v\n%s", err, out.String())
	}

	// On a registry stack, the stack moves to its newest version, and the
	// build image to the one that version names.
	reg := Options{ManifestPath: filepath.Join(dir, "reg", "app.yaml"), Version: "test", Stdout: &out, Stderr: &out}
	out.Reset()
	if err := Lock(ctx, reg, LockOptions{UpdateStack: true}); err != nil {
		t.Fatalf("update-stack on a registry stack: %v\n%s", err, out.String())
	}
	if l, err = lock.Read(filepath.Join(dir, "reg", "app.lock.yaml")); err != nil {
		t.Fatal(err)
	}
	if l.App.StackArtifact == nil || l.App.StackArtifact.Digest != newStack {
		t.Errorf("stack pin %+v, want %s\n%s", l.App.StackArtifact, newStack, out.String())
	}
	if l.App.Build != (lock.Image{Ref: host + "/build:2", Digest: digest(newBuild)}) || l.Base.Digest != digest(newRun) {
		t.Errorf("registry stack: build %+v, base %s\n%s", l.App.Build, l.Base.Digest, out.String())
	}
	if !strings.Contains(out.String(), "stack "+host+"/stacks/s:1: sha256:") {
		t.Errorf("no stack change in the summary:\n%s", out.String())
	}
	if m, _, _, err := loadLocked(ctx, reg); err != nil || m.StackFrom.Digest != newStack {
		t.Errorf("next build: %v", err)
	}

	// Refused for images, and with --update or --update-base.
	tools := Options{ManifestPath: filepath.Join(dir, "tools", "image.yaml"), Version: "test", Stdout: &out, Stderr: &out}
	if err := Lock(ctx, tools, LockOptions{UpdateStack: true}); err == nil || !strings.Contains(err.Error(), "is a Image: --update-stack") {
		t.Errorf("image: %v", err)
	}
	for _, lo := range []LockOptions{{UpdateStack: true, Update: true}, {UpdateStack: true, UpdateBase: true}} {
		if err := Lock(ctx, hello, lo); err == nil || !strings.Contains(err.Error(), "doesn't go with") {
			t.Errorf("%+v: %v", lo, err)
		}
	}
}
