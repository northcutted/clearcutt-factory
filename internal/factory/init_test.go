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

	"go.yaml.in/yaml/v3"

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
	for _, want := range []string{
		"northcutted/clearcutt-factory/.github/workflows/images.yml@v1.2.3",
		"northcutted/clearcutt-factory/.github/workflows/notify.yml@v1.2.3",
		// Dependents of a platform repository are woken by its notify job.
		"types: [clearcutt.run-image-published, clearcutt.stack-published]",
		"github.event.action == 'clearcutt.run-image-published'",
		"github.event.action == 'clearcutt.stack-published'",
	} {
		if !strings.Contains(string(wf), want) {
			t.Errorf("workflow lacks %q:\n%s", want, wf)
		}
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

// The generated workflow passes only the inputs and secrets factory's
// reusable workflows declare (GitHub rejects others), by name: secrets:
// inherit doesn't reach workflows in another organization.
func TestInitWorkflowMatchesReusableWorkflows(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	if err := Init(context.Background(), Options{Version: "v1.2.3", Stdout: &out, Stderr: &out}, InitOptions{Dir: dir, Repo: "acme/platform"}); err != nil {
		t.Fatal(err)
	}
	var wf struct {
		Jobs map[string]struct {
			Uses    string         `yaml:"uses"`
			With    map[string]any `yaml:"with"`
			Secrets any            `yaml:"secrets"`
		} `yaml:"jobs"`
	}
	b, err := os.ReadFile(filepath.Join(dir, ".github/workflows/clearcutt-factory.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(b, &wf); err != nil {
		t.Fatal(err)
	}
	called := 0
	for name, job := range wf.Jobs {
		path, ok := strings.CutPrefix(job.Uses, "northcutted/clearcutt-factory/")
		if !ok {
			continue
		}
		called++
		path, _, _ = strings.Cut(path, "@")
		var reusable struct {
			On struct {
				WorkflowCall struct {
					Inputs  map[string]any `yaml:"inputs"`
					Secrets map[string]any `yaml:"secrets"`
				} `yaml:"workflow_call"`
			} `yaml:"on"`
		}
		rb, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(path)))
		if err != nil {
			t.Fatal(err)
		}
		if err := yaml.Unmarshal(rb, &reusable); err != nil {
			t.Fatal(err)
		}
		for k := range job.With {
			if _, ok := reusable.On.WorkflowCall.Inputs[k]; !ok {
				t.Errorf("job %s passes input %s, which %s doesn't declare", name, k, path)
			}
		}
		secrets, ok := job.Secrets.(map[string]any)
		if job.Secrets != nil && !ok {
			t.Errorf("job %s passes secrets %v; name them", name, job.Secrets)
		}
		for k := range secrets {
			if _, ok := reusable.On.WorkflowCall.Secrets[k]; !ok {
				t.Errorf("job %s passes secret %s, which %s doesn't declare", name, k, path)
			}
		}
	}
	if called == 0 {
		t.Errorf("no job calls factory's reusable workflows:\n%s", b)
	}
}
