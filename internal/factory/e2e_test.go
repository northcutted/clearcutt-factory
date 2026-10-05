package factory

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/northcutted/declarative-image-factory/internal/rebase"
	"github.com/northcutted/declarative-image-factory/internal/registry"
)

// TestEndToEnd locks, builds, and rebuilds small real images, one per package
// manager, and requires the digests to match. It needs network access and
// docker or podman, so it only runs with FACTORY_E2E=1. The work directory
// must be visible to the container runtime (on macOS, somewhere under $HOME).
func TestEndToEnd(t *testing.T) {
	if os.Getenv("FACTORY_E2E") == "" {
		t.Skip("set FACTORY_E2E=1 to run (needs network and docker or podman)")
	}
	platform := "linux/" + runtime.GOARCH
	cases := []struct{ name, base, extra string }{
		{"apk", "cgr.dev/chainguard/wolfi-base:latest", `
  tools:
    - name: cosign
      from: github-release
      repo: sigstore/cosign
      version: 3.1.3
      asset: cosign-{{os}}-{{arch}}`},
		{"apt", "debian:trixie-slim", `
  tools:
    - name: ripgrep
      from: nix
      package: ripgrep`},
		{"dnf", "amazonlinux:2023", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			endToEnd(t, c.name, `apiVersion: factory.dev/v1alpha1
kind: Image
metadata: {name: e2e-`+c.name+`}
spec:
  base: `+c.base+`
  platforms: [`+platform+`]
  packages: [jq]`+c.extra+`
  files:
    - {src: conf/, dst: /etc/e2e/}
  user: "65532"
  test:
    command: [/usr/bin/jq, --version]
`)
		})
	}
}

func endToEnd(t *testing.T, name, manifest string) {
	home, _ := os.UserHomeDir()
	base := filepath.Join(home, ".cache", "factory-e2e-test", name)
	_ = os.RemoveAll(base)
	t.Cleanup(func() {
		if !t.Failed() {
			_ = os.RemoveAll(base)
		}
	})
	dir := filepath.Join(base, "src")
	if err := os.MkdirAll(filepath.Join(dir, "conf"), 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"factory.org.yaml": "apiVersion: factory.dev/v1alpha1\nkind: OrgProfile\nregistry: registry.example/e2e\nsigning: {mode: none}\npolicy: {requireNonRoot: true}\n",
		"conf/app.yaml":    "greeting: hello\n",
		"image.yaml":       manifest,
	}
	for n, body := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	opts := Options{ManifestPath: filepath.Join(dir, "image.yaml"), Version: "test", Stdout: io.Discard, Stderr: io.Discard}
	if testing.Verbose() {
		opts.Stdout, opts.Stderr = os.Stdout, os.Stderr
	}
	ctx := context.Background()
	if err := Lock(ctx, opts, LockOptions{}); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(base, "out")
	if err := Build(ctx, opts, BuildOptions{OutDir: out, NoScan: true}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(out, "e2e-"+name, "result.json"))
	if err != nil {
		t.Fatal(err)
	}
	var res Result
	if err := json.Unmarshal(b, &res); err != nil {
		t.Fatal(err)
	}
	if err := Verify(ctx, opts, VerifyOptions{Digest: res.Digest, FromSource: true, OutDir: out}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(out, "e2e-"+name, "attestations", "recipe.intoto.json")); err != nil {
		t.Error("recipe attestation not written")
	}
}

// TestEndToEndApp builds a Go app on a stack, rebuilds it to compare
// digests, then rebases it onto an updated run image in a local registry.
func TestEndToEndApp(t *testing.T) {
	if os.Getenv("FACTORY_E2E") == "" {
		t.Skip("set FACTORY_E2E=1 to run (needs network and docker or podman)")
	}
	home, _ := os.UserHomeDir()
	base := filepath.Join(home, ".cache", "factory-e2e-test", "app")
	_ = os.RemoveAll(base)
	t.Cleanup(func() {
		if !t.Failed() {
			_ = os.RemoveAll(base)
		}
	})
	dir := filepath.Join(base, "src")
	files := map[string]string{
		"factory.org.yaml": "apiVersion: factory.dev/v1alpha1\nkind: OrgProfile\nregistry: registry.example/e2e\nsigning: {mode: none}\npolicy: {requireNonRoot: true}\n",
		"stacks/go.yaml": `apiVersion: factory.dev/v1alpha1
kind: Stack
metadata: {name: go}
spec:
  build: golang:1
  run: cgr.dev/chainguard/static:latest
  crossCompile: true
  buildEnv: {CGO_ENABLED: "0"}
  caches: [/root/.cache/go-build, /go/pkg/mod]
  steps:
    - run: GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w -buildid=" -o "/out/$APP_NAME" .
  user: "65532"
  entrypoint: ["/app/{{name}}"]
`,
		"hello/app.yaml": "apiVersion: factory.dev/v1alpha1\nkind: App\nmetadata: {name: hello}\nspec:\n  stack: ../stacks/go.yaml\n  platforms: [linux/" + runtime.GOARCH + "]\n  test: {command: [/app/hello]}\n",
		"hello/go.mod":   "module example.com/hello\n\ngo 1.24\n",
		"hello/main.go":  "package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Println(\"hello\") }\n",
	}
	for n, body := range files {
		p := filepath.Join(dir, n)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	opts := Options{ManifestPath: filepath.Join(dir, "hello", "app.yaml"), Version: "test", Stdout: io.Discard, Stderr: io.Discard}
	if testing.Verbose() {
		opts.Stdout, opts.Stderr = os.Stdout, os.Stderr
	}
	ctx := context.Background()
	if err := Lock(ctx, opts, LockOptions{}); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(base, "out")
	if err := Build(ctx, opts, BuildOptions{OutDir: out, NoScan: true}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(out, "hello", "result.json"))
	if err != nil {
		t.Fatal(err)
	}
	var res Result
	if err := json.Unmarshal(b, &res); err != nil {
		t.Fatal(err)
	}
	if err := Verify(ctx, opts, VerifyOptions{Digest: res.Digest, FromSource: true, OutDir: out}); err != nil {
		t.Fatal(err)
	}

	// Publish the app to a local registry, along with a "rebuilt" run
	// image: the same image plus a layer.
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0))))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	built, err := registry.OpenLayout(res.Layout)
	if err != nil {
		t.Fatal(err)
	}
	plats, err := built.Platforms()
	if err != nil {
		t.Fatal(err)
	}
	m, err := plats[0].Image.Manifest()
	if err != nil {
		t.Fatal(err)
	}
	if m.Annotations[rebase.AnnotationBaseName] != "cgr.dev/chainguard/static:latest" || m.Annotations[rebase.AnnotationBaseDigest] == "" {
		t.Fatalf("app image does not record its base: %v", m.Annotations)
	}
	if _, err := registry.Push(ctx, built, host+"/hello", []string{"1"}); err != nil {
		t.Fatal(err)
	}
	oldRun, err := registry.Fetch(ctx, "cgr.dev/chainguard/static@"+m.Annotations[rebase.AnnotationBaseDigest])
	if err != nil {
		t.Fatal(err)
	}
	newRun, err := mutate.AppendLayers(oldRun.Image, testLayer(t, map[string]string{"etc/": "", "etc/patched": "yes"}))
	if err != nil {
		t.Fatal(err)
	}
	r, _ := name.ParseReference(host + "/static:latest")
	if err := remote.Write(r, newRun); err != nil {
		t.Fatal(err)
	}

	ro := RebaseOptions{Image: host + "/hello:1", Onto: host + "/static:latest", OutDir: out, NoScan: true, NoSign: true, Push: true}
	if err := Rebase(ctx, opts, ro); err != nil {
		t.Fatal(err)
	}
	rebased, err := registry.Fetch(ctx, host+"/hello:1")
	if err != nil {
		t.Fatal(err)
	}
	got, err := registry.ReadFiles(ctx, host+"/hello@"+rebased.Digest, "linux/"+runtime.GOARCH, "etc/patched", "app/hello")
	if err != nil {
		t.Fatal(err)
	}
	if string(got["etc/patched"]) != "yes" || len(got["app/hello"]) == 0 {
		t.Errorf("rebased image is missing the new base's file or the app: %v", len(got))
	}
}
