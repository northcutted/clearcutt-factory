package factory

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInit(t *testing.T) {
	dir := t.TempDir()
	for _, args := range [][]string{{"init", "-q"}, {"remote", "add", "origin", "git@github.com:Acme/platform-images.git"}} {
		if out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	var out bytes.Buffer
	opts := Options{Version: "v1.2.3", Stdout: &out, Stderr: &out}
	if err := Init(context.Background(), opts, InitOptions{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	org, _ := os.ReadFile(filepath.Join(dir, "factory.org.yaml"))
	wf, _ := os.ReadFile(filepath.Join(dir, ".github/workflows/clearcutt-factory.yml"))
	for _, want := range []string{"registry: ghcr.io/acme ", `^https://github\.com/Acme/platform-images/`, "clearcutt-factory/v1.2.3/schemas/org.schema.json"} {
		if !strings.Contains(string(org), want) {
			t.Errorf("org profile lacks %q:\n%s", want, org)
		}
	}
	if !strings.Contains(string(wf), "northcutted/clearcutt-factory/.github/workflows/images.yml@v1.2.3") {
		t.Errorf("workflow:\n%s", wf)
	}

	// The scaffold is a working setup: the example loads under the org.
	opts.ManifestPath = filepath.Join(dir, "images/example/image.yaml")
	m, _, err := load(context.Background(), opts, false)
	if err != nil {
		t.Fatal(err)
	}
	if m.Metadata.Ref != "ghcr.io/acme/example" || m.Spec.Test == nil {
		t.Errorf("example: ref %q, test %+v", m.Metadata.Ref, m.Spec.Test)
	}

	// Running again keeps what is there.
	out.Reset()
	if err := Init(context.Background(), Options{Version: "dev", Stdout: &out, Stderr: &out}, InitOptions{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	if strings.Count(out.String(), "kept ") != 3 {
		t.Errorf("second run:\n%s", out.String())
	}
}
