package factory

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/northcutted/clearcutt-factory/internal/attest"
	"github.com/northcutted/clearcutt-factory/internal/manifest"
	"github.com/northcutted/clearcutt-factory/internal/rebase"
)

// TestRebaseRecordsTest: the rebase record names the smoke test that ran on
// the result, with each platform's result, and only when one ran.
func TestRebaseRecordsTest(t *testing.T) {
	// A container runtime that passes every test and logs its calls.
	bin := t.TempDir()
	fake := filepath.Join(bin, "docker")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$0.log\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("CLEARCUTT_FACTORY_RUNTIME", "docker")

	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0))))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	osRel := map[string]string{"etc/": "", "etc/os-release": "ID=wolfi\nVERSION_ID=20230201\n"}
	oldBase := testIndex(t, nil, func(arch string) []v1.Layer {
		return []v1.Layer{testLayer(t, osRel), testLayer(t, map[string]string{"usr/lib/libssl.so.3": "old " + arch})}
	}, nil)
	newBase := testIndex(t, nil, func(arch string) []v1.Layer {
		return []v1.Layer{testLayer(t, osRel), testLayer(t, map[string]string{"usr/lib/libssl.so.3": "patched " + arch})}
	}, nil)
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
	push(t, host+"/run:latest", oldBase)
	push(t, host+"/apps/hello:latest", testIndex(t, baseImage, func(string) []v1.Layer {
		return []v1.Layer{testLayer(t, map[string]string{"app/": "", "app/hello": "hi"})}
	}, ann))
	push(t, host+"/run:latest", newBase)

	ctx := context.Background()
	var out bytes.Buffer
	opts := Options{Version: "test", Stdout: &out, Stderr: &out}
	org := manifest.DefaultOrg()
	org.Signing.Mode = "none"
	outDir := t.TempDir()
	record := func() map[string]any {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(outDir, "hello-rebase", "attestations", "rebase.predicate.json"))
		if err != nil {
			t.Fatal(err)
		}
		var r map[string]any
		if err := json.Unmarshal(b, &r); err != nil {
			t.Fatal(err)
		}
		return r
	}

	// rebase -f: the app's test runs, and the record says so. (The fake
	// runtime answers no HTTP, so the test is a command here.)
	test := &manifest.Test{Command: []string{"/app/hello", "--check"}, Timeout: "30s"}
	ro := RebaseOptions{Image: host + "/apps/hello:latest", OutDir: outDir, NoScan: true}
	if _, _, err := rebaseImage(ctx, opts, org, ro, test, "hello"); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	b, _ := json.Marshal(record()["test"])
	if want := `{"command":["/app/hello","--check"],"platforms":{"linux/amd64":"passed","linux/arm64":"passed"},"timeout":"30s"}`; string(b) != want {
		t.Errorf("record test = %s, want %s", b, want)
	}
	if calls, _ := os.ReadFile(fake + ".log"); strings.Count(string(calls), "run --name") != 2 {
		t.Errorf("the smoke test didn't run on both platforms:\n%s", calls)
	}

	// --no-test, and rebase --image (no test): nothing ran, nothing recorded.
	for name, c := range map[string]struct {
		test   *manifest.Test
		noTest bool
	}{"--no-test": {test, true}, "--image": {nil, false}} {
		ro.NoTest = c.noTest
		if _, _, err := rebaseImage(ctx, opts, org, ro, c.test, ""); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if r := record(); r["test"] != nil {
			t.Errorf("%s: record has a test: %v", name, r["test"])
		}
	}

	// The record type reads back with the declared test's fields.
	var rec attest.Rebase
	if err := json.Unmarshal([]byte(`{"test":{"http":{"port":8080,"path":"/healthz"},"platforms":{"linux/amd64":"passed"}}}`), &rec); err != nil ||
		rec.Test == nil || rec.Test.HTTP == nil || rec.Test.HTTP.Path != "/healthz" || rec.Test.Platforms["linux/amd64"] != attest.TestPassed {
		t.Errorf("record test: %+v, %v", rec.Test, err)
	}
}
