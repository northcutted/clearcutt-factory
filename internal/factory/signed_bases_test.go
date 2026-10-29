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
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"

	"github.com/northcutted/clearcutt-factory/internal/attest"
	"github.com/northcutted/clearcutt-factory/internal/lock"
	"github.com/northcutted/clearcutt-factory/internal/manifest"
	"github.com/northcutted/clearcutt-factory/internal/rebase"
	"github.com/northcutted/clearcutt-factory/internal/registry"
)

// The trust policy init --platform writes, in short: the platform's own
// image signer (repository-scoped) and the apps' (owner-scoped).
const (
	platformImages = "  - {name: platform-images, roles: [image], identityRegexp: '" + reusable + "', issuer: " + ghIssuer +
		", sourceRepository: https://github.com/acme/platform, sourceMatchesImage: true}\n"
	appImages = "  - {name: app-images, roles: [image], identityRegexp: '" + reusable + "', issuer: " + ghIssuer +
		", sourceRepositoryOwner: https://github.com/acme, sourceMatchesImage: true}\n"
	byPlatform = "--certificate-github-workflow-repository acme/platform"
	byCheckout = "--certificate-github-workflow-repository acme/checkout"
)

// basesOrg writes an org profile requiring signed bases (or not) with a
// trust policy of the signers given, and loads it.
func basesOrg(t *testing.T, require bool, signers string) (path string, org *manifest.Org) {
	t.Helper()
	dir := t.TempDir()
	policy := ""
	if require {
		policy = "policy: {requireSignedBases: true}\n"
	}
	files := map[string]string{
		"trust.yaml":       "apiVersion: clearcutt.dev/v1\nkind: TrustPolicy\nsigners:\n" + signers,
		"factory.org.yaml": "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\nsigning: {mode: none, trustPolicy: trust.yaml}\n" + policy,
	}
	for n, body := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	path = filepath.Join(dir, "factory.org.yaml")
	org, err := manifest.LoadOrg(path, "")
	if err != nil {
		t.Fatal(err)
	}
	return path, org
}

// pushBase pushes a two-platform image naming source as its source
// repository to ref, and returns it by digest.
func pushBase(t *testing.T, ref, source, content string) (pinned string, idx v1.ImageIndex) {
	t.Helper()
	osRel := map[string]string{"etc/": "", "etc/os-release": "ID=wolfi\nVERSION_ID=20230201\n"}
	idx = testIndex(t, nil, func(arch string) []v1.Layer {
		return []v1.Layer{testLayer(t, osRel), testLayer(t, map[string]string{"usr/lib/libssl.so.3": content + " " + arch})}
	}, nil)
	idx = mutate.Annotations(idx, map[string]string{registry.SourceLabel: source}).(v1.ImageIndex)
	push(t, ref, idx)
	d, err := idx.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return lock.RepoOf(ref) + "@" + d.String(), idx
}

// TestSignedBases: under policy.requireSignedBases, a base is checked only
// against image signers that name one repository. A run image signed in
// an app repository, which the owner-scoped signer accepts as an image,
// is refused as a base; the same image signed by the platform's signer is
// accepted.
func TestSignedBases(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0))))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	ctx := context.Background()

	// The platform's run image, and one an app repository built and pushed
	// to the same repository (it had write access to the registry).
	platformRun, _ := pushBase(t, host+"/platform/run-go:1", "https://github.com/acme/platform", "platform")
	checkoutRun, _ := pushBase(t, host+"/platform/run-go:evil", "https://github.com/acme/checkout", "evil")

	_, both := basesOrg(t, true, platformImages+appImages)
	_, ownerOnly := basesOrg(t, true, appImages)
	_, notRequired := basesOrg(t, false, appImages)

	for _, c := range []struct {
		name     string
		org      *manifest.Org
		ref      string
		signedBy string // the repository whose run signed ref
		want     string // "" accepted, else part of the error
		calls    int    // cosign verify runs
	}{
		{"the platform's signer signed it", both, platformRun, byPlatform, "", 1},
		{"by tag, checked at its digest", both, host + "/platform/run-go:1", byPlatform, "", 1},
		{"an app repository signed it", both, checkoutRun, byCheckout, "names https://github.com/acme/checkout as its source, not https://github.com/acme/platform", 0},
		{"names the platform, signed elsewhere", both, platformRun, byCheckout, "is not signed by a repository-scoped image signer", 1},
		{"only an owner-scoped signer", ownerOnly, platformRun, byPlatform, "no image signer can vouch for the run image", 0},
		{"not required", notRequired, checkoutRun, byCheckout, "", 0},
	} {
		cosign := newFakeCosign(t, c.signedBy, platformRun, checkoutRun)
		err := verifyBase(ctx, c.org, "run image", c.ref)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: got %v, want %q", c.name, err, c.want)
		}
		calls := cosign.calls()
		if len(calls) != c.calls {
			t.Errorf("%s: cosign calls %q", c.name, calls)
		}
		for _, call := range calls {
			if !strings.Contains(call, byPlatform) || !strings.HasSuffix(call, " "+platformRun) {
				t.Errorf("%s: checked against another signer or image: %q", c.name, call)
			}
		}
	}

	// As an image (an app's own), the owner-scoped signer accepts the one
	// an app repository signed: what it must never vouch for is a base.
	cosign := newFakeCosign(t, byCheckout, checkoutRun)
	args, err := signerArgs(both, manifest.RoleImage, "https://github.com/acme/checkout")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := firstVerified(args, func(a []string) (struct{}, error) {
		return struct{}{}, attest.VerifySignature(ctx, checkoutRun, a)
	}); err != nil {
		t.Errorf("the owner-scoped signer doesn't accept the app repository's image: %v %q", err, cosign.calls())
	}

	// The bases a lock pins: its build image and its run image.
	newFakeCosign(t, byPlatform, platformRun)
	l := &lock.Lock{Base: lock.Image{Ref: host + "/platform/run-go:1", Digest: digestOf(platformRun)},
		App: &lock.App{Build: lock.Image{Ref: host + "/platform/run-go:evil", Digest: digestOf(checkoutRun)}}}
	if err := verifyLockedBases(ctx, both, l); err == nil || !strings.Contains(err.Error(), "the build image "+checkoutRun) {
		t.Errorf("a lock pinning an app repository's image as its build image: %v", err)
	}
	l.App.Build = l.Base
	if err := verifyLockedBases(ctx, both, l); err != nil {
		t.Errorf("a lock pinning the platform's images: %v", err)
	}
}

// TestSignedBasesEnforced: rebase won't move an app onto a run image, nor
// stack push publish a stack naming one, that the platform's signer didn't
// sign.
func TestSignedBasesEnforced(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0))))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	ctx := context.Background()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))

	oldRun, oldIdx := pushBase(t, host+"/platform/run-go:1", "https://github.com/acme/platform", "old")
	build, _ := pushBase(t, host+"/platform/build-go:1", "https://github.com/acme/platform", "toolchain")
	baseImage := func(arch string) v1.Image {
		im, _ := oldIdx.IndexManifest()
		for _, d := range im.Manifests {
			if d.Platform.Architecture == arch {
				img, _ := oldIdx.Image(d.Digest)
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
		return map[string]string{rebase.AnnotationBaseName: host + "/platform/run-go:1", rebase.AnnotationBaseDigest: d.String()}
	})
	push(t, host+"/apps/hello:1", app)
	// A new run image, pushed by an app repository.
	evilRun, _ := pushBase(t, host+"/platform/run-go:1", "https://github.com/acme/checkout", "evil")

	orgPath, _ := basesOrg(t, true, platformImages+appImages)
	var out bytes.Buffer
	opts := Options{OrgPath: orgPath, Version: "test", Stdout: &out, Stderr: &out}
	ro := RebaseOptions{Image: host + "/apps/hello:1", OutDir: filepath.Join(t.TempDir(), "out"), NoScan: true, Check: true}

	newFakeCosign(t, byCheckout, evilRun, oldRun, build)
	if err := Rebase(ctx, opts, ro); err == nil || !strings.Contains(err.Error(), "policy.requireSignedBases") {
		t.Errorf("rebase onto an app repository's run image: %v\n%s", err, out.String())
	}

	// The platform publishes a new run image: the rebase goes ahead.
	newRun, _ := pushBase(t, host+"/platform/run-go:1", "https://github.com/acme/platform", "patched")
	newFakeCosign(t, byPlatform, newRun, oldRun, build)
	out.Reset()
	if err := Rebase(ctx, opts, ro); err != nil || !strings.Contains(out.String(), "safe to rebase") {
		t.Errorf("rebase onto the platform's run image: %v\n%s", err, out.String())
	}

	// stack push, from a directory under the same org profile.
	dir := filepath.Dir(orgPath)
	stackFile := filepath.Join(dir, "go.yaml")
	writeStack := func(run string) {
		t.Helper()
		body := "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: Stack\nmetadata: {name: go}\nspec:\n  build: " + host + "/platform/build-go:1\n  run: " + run + "\n  steps: [{run: go build -o /out/app .}]\n"
		if err := os.WriteFile(stackFile, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	push(t, host+"/platform/run-go:evil", mustIndex(t, ctx, evilRun))
	writeStack(host + "/platform/run-go:evil")
	if err := StackPush(ctx, opts, stackFile, host+"/stacks/go:1", true); err == nil || !strings.Contains(err.Error(), "the run image "+host+"/platform/run-go@") {
		t.Errorf("stack push naming an app repository's run image: %v", err)
	}
	if _, err := registry.Digest(ctx, host+"/stacks/go:1"); err == nil {
		t.Error("stack push published a stack naming an unsigned run image")
	}
	writeStack(host + "/platform/run-go:1")
	if err := StackPush(ctx, opts, stackFile, host+"/stacks/go:1", true); err != nil {
		t.Errorf("stack push naming the platform's images: %v", err)
	}
}

func mustIndex(t *testing.T, ctx context.Context, ref string) v1.ImageIndex {
	t.Helper()
	a, err := registry.Fetch(ctx, ref)
	if err != nil || a.Index == nil {
		t.Fatalf("%s: %v", ref, err)
	}
	return a.Index
}
