package factory

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
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
	// release tags the workflow calls them by (#11); at a commit only with
	// --allow-commit-pins, since a commit can be any in the fork network.
	o, err := manifest.LoadOrg(filepath.Join(dir, "factory.org.yaml"), "")
	if err != nil {
		t.Fatal(err)
	}
	pinned := t.TempDir()
	if err := Init(context.Background(), Options{Version: "v1.2.3", Stdout: &out, Stderr: &out}, InitOptions{Dir: pinned, Repo: "Acme/platform-images", AllowCommitPins: true}); err != nil {
		t.Fatal(err)
	}
	op, err := manifest.LoadOrg(filepath.Join(pinned, "factory.org.yaml"), "")
	if err != nil {
		t.Fatal(err)
	}
	re, reCommits := regexp.MustCompile(o.Signing.Verify.CertificateIdentityRegexp), regexp.MustCompile(op.Signing.Verify.CertificateIdentityRegexp)
	for _, c := range []struct {
		san                 string
		byDefault, withPins bool
	}{
		{"https://github.com/northcutted/clearcutt-factory/.github/workflows/images.yml@refs/tags/v1.2.3", true, true},
		{"https://github.com/northcutted/clearcutt-factory/.github/workflows/fleet.yml@refs/tags/v1.3.0", true, true},
		{"https://github.com/northcutted/clearcutt-factory/.github/workflows/reattest.yml@refs/tags/v1.2.3", true, true},
		{"https://github.com/northcutted/clearcutt-factory/.github/workflows/update-locks.yml@refs/tags/v1.2.3", false, false},
		{"https://github.com/Acme/platform-images/.github/workflows/clearcutt-factory.yml@refs/heads/main", false, false},
		// A caller that pins the workflows by commit: any commit, a fork's
		// included, so only with --allow-commit-pins.
		{"https://github.com/northcutted/clearcutt-factory/.github/workflows/images.yml@0123456789abcdef0123456789abcdef01234567", false, true},
		{"https://github.com/northcutted/clearcutt-factory/.github/workflows/fleet.yml@0123456789abcdef0123456789abcdef01234567", false, true},
		{"https://github.com/northcutted/clearcutt-factory/.github/workflows/images.yml@0123456", false, false},
		{"https://github.com/northcutted/clearcutt-factory/.github/workflows/images.yml@0123456789ABCDEF0123456789ABCDEF01234567", false, false},
		{"https://github.com/northcutted/clearcutt-factory/.github/workflows/images.yml@0123456789abcdef0123456789abcdef012345678", false, false},
		{"https://github.com/northcutted/clearcutt-factory/.github/workflows/images.yml@refs/heads/main", false, false},
		{"https://github.com/northcutted/clearcutt-factory/.github/workflows/images.yml@refs/tags/v1.2.3-rc.1", false, false},
		{"https://github.com/northcutted/clearcutt-factory/.github/workflows/images.yml@refs/tags/v1.2.3x", false, false},
		{"https://github.com/northcutted/clearcutt-factory-evil/.github/workflows/images.yml@0123456789abcdef0123456789abcdef01234567", false, false},
		{"https://github.com/northcutted/clearcutt-factory-evil/.github/workflows/images.yml@refs/tags/v1.2.3", false, false},
	} {
		if re.MatchString(c.san) != c.byDefault {
			t.Errorf("identity regexp %s on %s: want %v", re, c.san, c.byDefault)
		}
		if reCommits.MatchString(c.san) != c.withPins {
			t.Errorf("--allow-commit-pins identity regexp %s on %s: want %v", reCommits, c.san, c.withPins)
		}
	}
	args, err := signerArgs(o, manifest.RoleImage, "")
	if err != nil || len(args) != 1 || !strings.Contains(strings.Join(args[0], " "), "--certificate-github-workflow-repository Acme/platform-images") {
		t.Errorf("signer args %q, %v", args, err)
	}
	for _, want := range []string{
		"northcutted/clearcutt-factory/.github/workflows/images.yml@v1.2.3",
		"northcutted/clearcutt-factory/.github/workflows/notify.yml@v1.2.3",
		// Reproduction runs beside notify, not inside images (#60).
		"reproduce: false",
		// A pull request builds only the manifests it affects.
		"changed-only: true",
		// Published images are rescanned and re-attested daily.
		"northcutted/clearcutt-factory/.github/workflows/reattest.yml@v1.2.3",
		"if: github.event.schedule == '41 5 * * *'\n    uses: northcutted/clearcutt-factory/.github/workflows/reattest.yml",
		"published: ${{ needs.images.outputs.published }}",
		// Dependents of a platform repository are woken by its notify job.
		"types: [clearcutt.run-image-published, clearcutt.build-image-published, clearcutt.stack-published, clearcutt.profile-published]",
		"github.event.action == 'clearcutt.profile-published'",
		"github.event.action == 'clearcutt.run-image-published'",
		"github.event.action == 'clearcutt.build-image-published'",
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
	if strings.Count(out.String(), "kept ") != 4 {
		t.Errorf("second run:\n%s", out.String())
	}
}

// notify and fleet start once images.yml has published, without waiting for
// the second-runner reproduction, which runs beside them (#60).
func TestInitNotifiesBeforeReproducing(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	if err := Init(context.Background(), Options{Version: "v1.2.3", Stdout: &out, Stderr: &out}, InitOptions{Dir: dir, Repo: "acme/platform"}); err != nil {
		t.Fatal(err)
	}
	var wf struct {
		Jobs map[string]struct {
			Needs any            `yaml:"needs"`
			Uses  string         `yaml:"uses"`
			With  map[string]any `yaml:"with"`
		} `yaml:"jobs"`
	}
	b, err := os.ReadFile(filepath.Join(dir, ".github/workflows/clearcutt-factory.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(b, &wf); err != nil {
		t.Fatal(err)
	}
	if r := wf.Jobs["images"].With["reproduce"]; r != false {
		t.Errorf("images reproduces itself (reproduce: %v), so its dependents wait for it", r)
	}
	// images.yml reproduces, so the reproduction attestation is signed by
	// the identity org profiles and trust policies accept for images.
	if r := wf.Jobs["reproduce"]; r.Uses != wf.Jobs["images"].Uses || r.With["published"] != "${{ needs.images.outputs.published }}" {
		t.Errorf("reproduce: uses %s with %v", r.Uses, r.With)
	}
	for _, job := range []string{"reproduce", "notify", "fleet"} {
		if needs := wf.Jobs[job].Needs; needs != "images" {
			t.Errorf("%s needs %v, want images alone", job, needs)
		}
	}
}

// TestInitAnswersBuildImagePublished: the workflow answers a platform's
// clearcutt.build-image-published (and stack-published, and the daily
// run) with update-locks.yml's stack update, the rebuild pull request,
// and everything else with the full update.
func TestInitAnswersBuildImagePublished(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	if err := Init(context.Background(), Options{Version: "v1.2.3", Stdout: &out, Stderr: &out}, InitOptions{Dir: dir, Repo: "acme/platform"}); err != nil {
		t.Fatal(err)
	}
	var wf struct {
		On struct {
			RepositoryDispatch struct {
				Types []string `yaml:"types"`
			} `yaml:"repository_dispatch"`
			Schedule []struct {
				Cron string `yaml:"cron"`
			} `yaml:"schedule"`
		} `yaml:"on"`
		Jobs map[string]struct {
			If   string            `yaml:"if"`
			With map[string]string `yaml:"with"`
		} `yaml:"jobs"`
	}
	b, err := os.ReadFile(filepath.Join(dir, ".github/workflows/clearcutt-factory.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(b, &wf); err != nil {
		t.Fatal(err)
	}
	const build, stack = "clearcutt.build-image-published", "clearcutt.stack-published"
	if !slices.Contains(wf.On.RepositoryDispatch.Types, build) {
		t.Errorf("repository_dispatch types %v lack %s", wf.On.RepositoryDispatch.Types, build)
	}
	daily := ""
	for _, s := range wf.On.Schedule {
		if strings.HasPrefix(s.Cron, "41 ") {
			daily = s.Cron
		}
	}
	if daily == "" {
		t.Fatalf("no daily schedule in %v", wf.On.Schedule)
	}
	job := wf.Jobs["update-locks"]
	for _, want := range []string{build, stack, "github.event_name == 'schedule'"} {
		if !strings.Contains(job.If, want) {
			t.Errorf("update-locks runs on %q, which lacks %s", job.If, want)
		}
	}
	update := job.With["update"]
	for _, want := range []string{build, stack, daily, "'stack'", "'all'"} {
		if !strings.Contains(update, want) {
			t.Errorf("update-locks passes update: %q, which lacks %s", update, want)
		}
	}
	if fleet := wf.Jobs["fleet"].If; strings.Contains(fleet, build) {
		t.Errorf("fleet runs on %s too (%q); update-locks proposes the rebuild", build, fleet)
	}
}
