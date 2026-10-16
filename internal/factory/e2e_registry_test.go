package factory

import (
	"context"
	"io"
	"log"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/northcutted/clearcutt-factory/internal/container"
)

// TestEndToEndLocalRegistry builds an image on a base in a plain-HTTP
// registry on this machine's localhost. The BuildKit container reaches it
// through builder.network: host on Linux; elsewhere docker and podman run
// containers in a VM, so builder.config mirrors the registry to the host's
// address in that VM, over HTTP.
func TestEndToEndLocalRegistry(t *testing.T) {
	if os.Getenv("CLEARCUTT_FACTORY_E2E") == "" {
		t.Skip("set CLEARCUTT_FACTORY_E2E=1 to run (needs network and docker or podman)")
	}
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0))))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	busybox, err := remote.Image(name.MustParseReference("cgr.dev/chainguard/busybox:latest"), remote.WithPlatform(v1.Platform{OS: "linux", Architecture: runtime.GOARCH}))
	if err != nil {
		t.Fatal(err)
	}
	// A layer no earlier build has seen, so BuildKit can't take the base
	// from its cache and has to reach the registry.
	src, err := mutate.AppendLayers(busybox, testLayer(t, map[string]string{"etc/": "", "etc/e2e-base": time.Now().String()}))
	if err != nil {
		t.Fatal(err)
	}
	dst, err := name.ParseReference(host + "/e2e/busybox:latest")
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(dst, src); err != nil {
		t.Fatal(err)
	}

	builder := "  config: buildkitd.toml\n"
	config := "[registry.\"" + host + "\"]\n  http = true\n"
	if runtime.GOOS == "linux" {
		builder += "  network: host\n"
	} else {
		rt, err := container.Runtime("auto")
		if err != nil {
			t.Fatal(err)
		}
		hostname := "host.containers.internal"
		if filepath.Base(rt) == "docker" {
			hostname = "host.docker.internal"
		}
		_, port, _ := net.SplitHostPort(host)
		mirror := net.JoinHostPort(hostname, port)
		config = "[registry.\"" + host + "\"]\n  mirrors = [\"" + mirror + "\"]\n[registry.\"" + mirror + "\"]\n  http = true\n"
	}

	home, _ := os.UserHomeDir()
	base := filepath.Join(home, ".cache", "factory-e2e-test", "local-registry")
	_ = os.RemoveAll(base)
	t.Cleanup(func() {
		if !t.Failed() {
			_ = os.RemoveAll(base)
		}
	})
	dir := filepath.Join(base, "src")
	files := map[string]string{
		"factory.org.yaml": "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\nregistry: registry.example/e2e\nsigning: {mode: none}\npolicy: {requireNonRoot: true}\nbuilder:\n" + builder,
		"buildkitd.toml":   config,
		"conf/app.yaml":    "greeting: hello\n",
		"image.yaml": `apiVersion: factory.clearcutt.dev/v1alpha1
kind: Image
metadata: {name: e2e-local-registry}
spec:
  base: ` + host + `/e2e/busybox:latest
  platforms: [linux/` + runtime.GOARCH + `]
  files:
    - {src: conf/, dst: /etc/e2e/}
  user: "65532"
  test:
    command: [/bin/sh, -c, "test -f /etc/e2e/app.yaml"]
`,
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
	opts := Options{ManifestPath: filepath.Join(dir, "image.yaml"), Version: "test", Stdout: io.Discard, Stderr: io.Discard}
	if testing.Verbose() {
		opts.Stdout, opts.Stderr = os.Stdout, os.Stderr
	}
	ctx := context.Background()
	if err := Lock(ctx, opts, LockOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := Build(ctx, opts, BuildOptions{OutDir: filepath.Join(base, "out"), NoScan: true}); err != nil {
		t.Fatal(err)
	}
}
