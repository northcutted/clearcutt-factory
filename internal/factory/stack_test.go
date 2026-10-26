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

// TestStackPushSignsOnce: stack push signs with the stack key, and pushing
// an unchanged stack the org's stack signer signed only moves the tag.
func TestStackPushSignsOnce(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0))))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	ctx := context.Background()
	dir := t.TempDir()
	stack := "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: Stack\nmetadata: {name: go}\nspec:\n  build: golang:1\n  run: cgr.dev/chainguard/static:latest\n  steps: [{run: go build -o /out/app .}]\n"
	for n, body := range map[string]string{
		"factory.org.yaml": "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\nsigning:\n  mode: key\n  key: keys/images.key\n  stackKey: keys/stacks.key\n  stacks: {key: keys/stacks.pub}\n",
		"go.yaml":          stack,
	} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cosign := newFakeCosign(t, "--key "+filepath.Join(dir, "keys/stacks.pub"))
	var out bytes.Buffer
	opts := Options{Stdout: &out, Stderr: &out}
	file := filepath.Join(dir, "go.yaml")
	ref := host + "/stacks/go:1"
	digest := func() string {
		t.Helper()
		d, err := registry.Digest(ctx, ref)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}

	// The first push signs with signing.stackKey, not signing.key.
	if err := StackPushWith(ctx, opts, file, StackPushOptions{Ref: ref}); err != nil {
		t.Fatal(err)
	}
	pushed := host + "/stacks/go@" + digest()
	if c := cosign.calls(); len(c) != 1 || c[0] != "sign "+pushed+" --key "+filepath.Join(dir, "keys/stacks.key")+" --yes" {
		t.Fatalf("first push: cosign calls %q", c)
	}
	signed, err := os.OpenFile(cosign.path+".signed", os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = signed.WriteString(pushed + "\n")
	_ = signed.Close()

	// The tag moves elsewhere; pushing the same stack again moves it back,
	// checks the signature, and doesn't sign again (nor with --key).
	if _, err := registry.PushFile(ctx, ref, manifest.StackArtifactType, "stack.yaml", []byte("other")); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := StackPushWith(ctx, opts, file, StackPushOptions{Ref: ref, Key: "awskms:///alias/other"}); err != nil {
		t.Fatal(err)
	}
	if c := cosign.calls(); len(c) != 1 || !strings.HasPrefix(c[0], "verify ") || !strings.HasSuffix(c[0], " "+pushed) {
		t.Errorf("unchanged push: cosign calls %q", c)
	}
	if host+"/stacks/go@"+digest() != pushed || !strings.Contains(out.String(), "already published at "+pushed+"; moved 1") {
		t.Errorf("unchanged push didn't move the tag back:\n%s", out.String())
	}

	// A stack pushed unsigned is signed when pushed again with signing on.
	changed := strings.Replace(stack, "golang:1", "golang:2", 1)
	if err := os.WriteFile(file, []byte(changed), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := StackPushWith(ctx, opts, file, StackPushOptions{Ref: ref, NoSign: true}); err != nil {
		t.Fatal(err)
	}
	if c := cosign.calls(); len(c) != 0 {
		t.Errorf("--no-sign: cosign calls %q", c)
	}
	if err := StackPushWith(ctx, opts, file, StackPushOptions{Ref: ref, Key: "awskms:///alias/stacks"}); err != nil {
		t.Fatal(err)
	}
	pushed = host + "/stacks/go@" + digest()
	if c := cosign.calls(); len(c) != 2 || !strings.HasPrefix(c[0], "verify ") || c[1] != "sign "+pushed+" --key awskms:///alias/stacks --yes" {
		t.Errorf("unsigned, then --key: cosign calls %q", c)
	}

	if err := StackPushWith(ctx, opts, file, StackPushOptions{Ref: ref, Key: "k", NoSign: true}); err == nil {
		t.Error("--key with --no-sign was accepted")
	}
}

// TestStackSigner: who stack push signs as.
func TestStackSigner(t *testing.T) {
	key := &manifest.Org{Signing: manifest.Signing{Mode: "key", Key: "images.key", Args: []string{"--signing-config", "sc.json"}}}
	keyless := &manifest.Org{Signing: manifest.Signing{Mode: "keyless"}}
	none := &manifest.Org{Signing: manifest.Signing{Mode: "none"}}
	withStackKey := &manifest.Org{Signing: manifest.Signing{Mode: "key", Key: "images.key", StackKey: "stacks.key"}}
	for _, c := range []struct {
		name      string
		org       *manifest.Org
		so        StackPushOptions
		mode, key string // empty mode: no signature
	}{
		{"key mode", key, StackPushOptions{}, "key", "images.key"},
		{"stack key", withStackKey, StackPushOptions{}, "key", "stacks.key"},
		{"--key over the stack key", withStackKey, StackPushOptions{Key: "flag.key"}, "key", "flag.key"},
		{"keyless", keyless, StackPushOptions{}, "keyless", ""},
		{"--key in keyless mode", keyless, StackPushOptions{Key: "flag.key"}, "key", "flag.key"},
		{"signing off", none, StackPushOptions{}, "", ""},
		{"--key with signing off", none, StackPushOptions{Key: "flag.key"}, "key", "flag.key"},
		{"--no-sign", key, StackPushOptions{NoSign: true}, "", ""},
	} {
		s := stackSigner(Options{}, c.org, c.so)
		switch {
		case c.mode == "" && s != nil:
			t.Errorf("%s: signs (%+v)", c.name, s)
		case c.mode != "" && (s == nil || s.Mode != c.mode || (c.mode == "key" && s.Key != c.key) || strings.Join(s.Args, " ") != strings.Join(c.org.Signing.Args, " ")):
			t.Errorf("%s: %+v, want mode %s key %s", c.name, s, c.mode, c.key)
		}
	}
}

// TestStackPinsBuildImage: stack push pins a build image given as a factory
// manifest by the digest its tag holds (the tag kept for readers), so a
// rebuilt build image under the same tag changes the stack and publishes a
// new one, which an app's lock --update then takes, moving the build image
// with it. The run image stays a tag (apps follow it by rebasing). A stack
// published before, naming its build image by tag alone, still loads.
func TestStackPinsBuildImage(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0))))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	ctx := context.Background()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))
	image := func(content string) v1.ImageIndex {
		return testIndex(t, nil, func(arch string) []v1.Layer {
			return []v1.Layer{testLayer(t, map[string]string{"etc/x": content + arch})}
		}, nil)
	}
	for _, name := range []string{"platform/build-go", "platform/go-runtime", "bk", "fe", "tb"} {
		push(t, host+"/"+name+":1", image(name))
	}
	digestOf := func(ref string) string {
		t.Helper()
		d, err := registry.Digest(ctx, ref)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	buildOne := digestOf(host + "/platform/build-go:1")

	dir := t.TempDir()
	builder := "builder: {buildkit: " + host + "/bk:1, frontend: " + host + "/fe:1, toolbox: " + host + "/tb:1}\n"
	files := map[string]string{
		"platform/factory.org.yaml":           "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\nregistry: " + host + "/platform\ntags: [\"1\"]\nsigning: {mode: none}\n" + builder,
		"platform/images/build-go/image.yaml": "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: Image\nmetadata: {name: build-go}\nspec: {base: cgr.dev/chainguard/wolfi-base:latest}\n",
		"platform/runtime/image.yaml":         "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: Image\nmetadata: {name: go-runtime}\nspec: {base: cgr.dev/chainguard/static:latest}\n",
		"platform/stacks/go.yaml":             "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: Stack\nmetadata: {name: go}\nspec:\n  build: ../images/build-go/image.yaml\n  run: ../runtime/image.yaml\n  steps: [{run: go build -o /out/app .}]\n  entrypoint: [\"/app/{{name}}\"]\n",
		"team/factory.org.yaml":               "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\nregistry: " + host + "/team\nsigning: {mode: none}\n" + builder,
		"team/svc/app.yaml":                   "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: App\nmetadata: {name: svc}\nspec: {stack: " + host + "/stacks/go:1, platforms: [linux/amd64, linux/arm64]}\n",
		"team/svc/main.go":                    "package main\n",
	}
	for n, body := range files {
		p := filepath.Join(dir, n)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	opts := Options{Stdout: &out, Stderr: &out, Version: "v0.4.0"}
	ghOutput := filepath.Join(dir, "github-output")
	t.Setenv("GITHUB_OUTPUT", ghOutput)
	pushStack := func() (digest string, published bool) {
		t.Helper()
		_ = os.Remove(ghOutput)
		if err := StackPush(ctx, opts, filepath.Join(dir, "platform/stacks/go.yaml"), host+"/stacks/go:1", false); err != nil {
			t.Fatalf("%v\n%s", err, out.String())
		}
		gho, _ := os.ReadFile(ghOutput)
		for _, line := range strings.Split(string(gho), "\n") {
			if d, ok := strings.CutPrefix(line, "digest="); ok {
				digest = d
			}
			published = published || line == "published=true"
		}
		return digest, published
	}
	stackOne, published := pushStack()
	if !published {
		t.Fatal("first push: not published")
	}
	content, _, err := registry.FetchFile(ctx, host+"/stacks/go@"+stackOne, manifest.StackArtifactType)
	if err != nil {
		t.Fatal(err)
	}
	if want := "build: " + host + "/platform/build-go:1@" + buildOne + "\n"; !strings.Contains(string(content), want) || !strings.Contains(string(content), "run: "+host+"/platform/go-runtime:1\n") {
		t.Errorf("published stack:\n%s\nwant build %q and the run image by tag", content, want)
	}
	// Unchanged: the tag moves back, nothing is published.
	if d, published := pushStack(); d != stackOne || published {
		t.Errorf("unchanged push: digest %s published %v", d, published)
	}

	// An app in another repository locks the build image at the digest
	// the stack pins.
	opts.ManifestPath = filepath.Join(dir, "team/svc/app.yaml")
	if err := Lock(ctx, opts, LockOptions{}); err != nil {
		t.Fatalf("lock: %v\n%s", err, out.String())
	}
	l, err := lock.Read(filepath.Join(dir, "team/svc/app.lock.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if l.App.Build.Ref != host+"/platform/build-go:1@"+buildOne || l.App.Build.Digest != buildOne || l.App.StackArtifact.Digest != stackOne {
		t.Errorf("lock: build %+v, stack %+v", l.App.Build, l.App.StackArtifact)
	}
	if err := Render(ctx, opts, true, ""); err != nil {
		t.Errorf("render --check: %v", err)
	}
	cf, _ := os.ReadFile(filepath.Join(dir, "team/svc/app.Containerfile"))
	if !strings.Contains(string(cf), "FROM "+host+"/platform/build-go:1@"+buildOne+" AS build") {
		t.Errorf("Containerfile builds with the wrong image:\n%s", cf)
	}

	// The build image is rebuilt under the same tag: the stack changes and
	// a new one is published; the app's lock keeps its pin until --update.
	push(t, host+"/platform/build-go:1", image("patched"))
	buildTwo := digestOf(host + "/platform/build-go:1")
	stackTwo, published := pushStack()
	if !published || stackTwo == stackOne {
		t.Fatalf("after the build image was rebuilt: digest %s (was %s), published %v", stackTwo, stackOne, published)
	}
	out.Reset()
	if err := Lock(ctx, opts, LockOptions{}); err != nil {
		t.Fatal(err)
	}
	if l, _ = lock.Read(filepath.Join(dir, "team/svc/app.lock.yaml")); l.App.Build.Digest != buildOne || !strings.Contains(out.String(), "is up to date") {
		t.Errorf("lock without --update moved the pin: %+v\n%s", l.App.Build, out.String())
	}
	out.Reset()
	if err := Lock(ctx, opts, LockOptions{Update: true}); err != nil {
		t.Fatal(err)
	}
	if l, _ = lock.Read(filepath.Join(dir, "team/svc/app.lock.yaml")); l.App.Build.Digest != buildTwo || l.App.StackArtifact.Digest != stackTwo {
		t.Errorf("lock --update: build %+v, stack %+v", l.App.Build, l.App.StackArtifact)
	}
	if s := out.String(); !strings.Contains(s, "build image: "+host+"/platform/build-go:1@"+buildOne+" → "+host+"/platform/build-go:1@"+buildTwo) || !strings.Contains(s, "stack "+host+"/stacks/go:1: ") {
		t.Errorf("lock --update should list the build image and the stack:\n%s", s)
	}

	// A stack published by an earlier release names the build image by
	// tag alone: it loads, and the lock pins what the tag holds.
	old := strings.Replace(string(content), "build: "+host+"/platform/build-go:1@"+buildOne, "build: "+host+"/platform/build-go:1", 1)
	if _, err := registry.PushFile(ctx, host+"/stacks/go:1", manifest.StackArtifactType, "stack.yaml", []byte(old)); err != nil {
		t.Fatal(err)
	}
	if err := Lock(ctx, opts, LockOptions{Update: true}); err != nil {
		t.Fatalf("lock --update on a stack by tag: %v\n%s", err, out.String())
	}
	if l, _ = lock.Read(filepath.Join(dir, "team/svc/app.lock.yaml")); l.App.Build.Ref != host+"/platform/build-go:1" || l.App.Build.Digest != buildTwo {
		t.Errorf("old stack: build %+v", l.App.Build)
	}

	// A build image not published yet can't be pinned: the push says so.
	if err := os.WriteFile(filepath.Join(dir, "platform/images/build-go/image.yaml"), []byte("apiVersion: factory.clearcutt.dev/v1alpha1\nkind: Image\nmetadata: {name: build-rust}\nspec: {base: cgr.dev/chainguard/wolfi-base:latest}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := StackPush(ctx, opts, filepath.Join(dir, "platform/stacks/go.yaml"), host+"/stacks/go:1", false); err == nil || !strings.Contains(err.Error(), "the published image "+host+"/platform/build-rust:1 can't be resolved") {
		t.Errorf("unpublished build image: %v", err)
	}
}
