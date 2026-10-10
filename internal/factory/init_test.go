package factory

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt-factory/internal/manifest"
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
	for _, want := range []string{"registry: ghcr.io/acme ", "sourceRepository: https://github.com/Acme/platform-images", "clearcutt-factory/v1.2.3/schemas/org.schema.json"} {
		if !strings.Contains(string(org), want) {
			t.Errorf("org profile lacks %q:\n%s", want, org)
		}
	}
	// The identity is that of factory's signing reusable workflows, at the
	// release tags the workflow calls them by (#11).
	o, err := manifest.LoadOrg(filepath.Join(dir, "factory.org.yaml"), "")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(o.Signing.Verify.CertificateIdentityRegexp)
	for san, want := range map[string]bool{
		"https://github.com/northcutted/clearcutt-factory/.github/workflows/images.yml@refs/tags/v1.2.3":       true,
		"https://github.com/northcutted/clearcutt-factory/.github/workflows/fleet.yml@refs/tags/v1.3.0":        true,
		"https://github.com/northcutted/clearcutt-factory/.github/workflows/update-locks.yml@refs/tags/v1.2.3": false,
		"https://github.com/Acme/platform-images/.github/workflows/clearcutt-factory.yml@refs/heads/main":      false,
	} {
		if re.MatchString(san) != want {
			t.Errorf("identity regexp %s on %s: want %v", re, san, want)
		}
	}
	args, err := signerArgs(o, manifest.RoleImage, "")
	if err != nil || len(args) != 1 || !strings.Contains(strings.Join(args[0], " "), "--certificate-github-workflow-repository Acme/platform-images") {
		t.Errorf("signer args %q, %v", args, err)
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
