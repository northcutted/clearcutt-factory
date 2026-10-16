package factory

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/northcutted/clearcutt-factory/internal/lock"
	"github.com/northcutted/clearcutt-factory/internal/manifest"
	"github.com/northcutted/clearcutt-factory/internal/registry"
)

const profileIdentity = "https://github.com/acme/platform/.github/workflows/profile.yml@refs/heads/main"

// profileWorld is a registry, a cache, and a directory of files for the
// shared profile tests.
type profileWorld struct {
	t    *testing.T
	ctx  context.Context
	host string
	dir  string
	out  bytes.Buffer
}

func newProfileWorld(t *testing.T, files map[string]string) *profileWorld {
	t.Helper()
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(srv.Close)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))
	w := &profileWorld{t: t, ctx: context.Background(), host: strings.TrimPrefix(srv.URL, "http://"), dir: t.TempDir()}
	for n, body := range files {
		w.write(n, strings.ReplaceAll(body, "HOST", w.host))
	}
	return w
}

func (w *profileWorld) write(n, body string) {
	w.t.Helper()
	p := filepath.Join(w.dir, n)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		w.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		w.t.Fatal(err)
	}
}

func (w *profileWorld) opts() Options { return Options{Stdout: &w.out, Stderr: &w.out} }

// push publishes the profile file n (unsigned) to HOST/factory/org:1 and
// returns its digest.
func (w *profileWorld) push(n string) string {
	w.t.Helper()
	if err := ProfilePush(w.ctx, w.opts(), filepath.Join(w.dir, n), ProfilePushOptions{Ref: w.host + "/factory/org:1", NoSign: true}); err != nil {
		w.t.Fatal(err)
	}
	return w.digest(w.host + "/factory/org:1")
}

func (w *profileWorld) digest(ref string) string {
	w.t.Helper()
	d, err := registry.Digest(w.ctx, ref)
	if err != nil {
		w.t.Fatal(err)
	}
	return d
}

// image pushes a random image to HOST/<repo>:1, for a lock to pin.
func (w *profileWorld) image(repo string) {
	w.t.Helper()
	img, err := random.Image(64, 1)
	if err != nil {
		w.t.Fatal(err)
	}
	r, err := name.ParseReference(w.host + "/" + repo + ":1")
	if err != nil {
		w.t.Fatal(err)
	}
	if err := remote.Write(r, img); err != nil {
		w.t.Fatal(err)
	}
}

const sharedOrg = `apiVersion: factory.clearcutt.dev/v1alpha1
kind: OrgProfile
signing:
  mode: key
  stackKey: awskms:///alias/platform
  profile: {key: keys/profile.pub}
  trustPolicy: trust.yaml
vulnerabilities:
  failOn: high
  vex: [vex/triage.openvex.json]
policy:
  requireSignedStacks: true
`

// TestProfilePush: profile push publishes the profile with the files it
// names, signs it as stacks are signed, and pushing it unchanged only
// moves the tag once signing.profile has signed it.
func TestProfilePush(t *testing.T) {
	w := newProfileWorld(t, map[string]string{
		"platform/factory.org.yaml":        sharedOrg,
		"platform/trust.yaml":              "apiVersion: clearcutt.dev/v1\nkind: TrustPolicy\nsigners:\n  - {name: stacks, roles: [stack], key: keys/stacks.pub}\n",
		"platform/keys/profile.pub":        "-----BEGIN PUBLIC KEY-----\nprofile\n-----END PUBLIC KEY-----\n",
		"platform/keys/stacks.pub":         "-----BEGIN PUBLIC KEY-----\nstacks\n-----END PUBLIC KEY-----\n",
		"platform/vex/triage.openvex.json": `{"@context": "https://openvex.dev/ns/v0.2.0"}`,
	})
	cosign := newFakeCosign(t, "--key "+filepath.Join(w.dir, "platform/keys/profile.pub"))
	output := filepath.Join(t.TempDir(), "github-output")
	t.Setenv("GITHUB_OUTPUT", output)
	file := filepath.Join(w.dir, "platform/factory.org.yaml")
	ref := w.host + "/factory/org:1"

	// The first push signs as stacks are signed (signing.stackKey).
	if err := ProfilePush(w.ctx, w.opts(), file, ProfilePushOptions{Ref: ref}); err != nil {
		t.Fatal(err)
	}
	pushed := w.host + "/factory/org@" + w.digest(ref)
	if c := cosign.calls(); len(c) != 1 || c[0] != "sign "+pushed+" --key awskms:///alias/platform --yes" {
		t.Fatalf("first push: cosign calls %q", c)
	}
	files, d, err := registry.FetchFiles(w.ctx, pushed, manifest.ProfileArtifactType)
	if err != nil || d != w.digest(ref) {
		t.Fatalf("fetch: %v", err)
	}
	var names []string
	for _, f := range files {
		names = append(names, f.Name+" "+f.MediaType)
	}
	if want := []string{
		"factory.org.yaml " + manifest.ProfileMediaType,
		"keys/profile.pub " + manifest.PublicKeyMediaType,
		"keys/stacks.pub " + manifest.PublicKeyMediaType,
		"trust-policy.yaml " + manifest.TrustPolicyMediaType,
		"vex/triage.openvex.json " + manifest.VEXMediaType,
	}; !slices.Equal(names, want) {
		t.Errorf("artifact files %q, want %q", names, want)
	}

	// Signed now. The tag moves elsewhere; pushing the same profile again
	// checks the signature, doesn't sign again, and moves the tag back.
	signed, err := os.OpenFile(cosign.path+".signed", os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = signed.WriteString(pushed + "\n")
	_ = signed.Close()
	if _, err := registry.PushFile(w.ctx, ref, manifest.StackArtifactType, "stack.yaml", []byte("other")); err != nil {
		t.Fatal(err)
	}
	w.out.Reset()
	if err := ProfilePush(w.ctx, w.opts(), file, ProfilePushOptions{Ref: ref}); err != nil {
		t.Fatal(err)
	}
	if c := cosign.calls(); len(c) != 1 || !strings.HasPrefix(c[0], "verify ") || !strings.HasSuffix(c[0], " "+pushed) {
		t.Errorf("unchanged push: cosign calls %q", c)
	}
	if w.host+"/factory/org@"+w.digest(ref) != pushed || !strings.Contains(w.out.String(), "already published at "+pushed+"; moved 1") {
		t.Errorf("unchanged push didn't move the tag back:\n%s", w.out.String())
	}
	if b, _ := os.ReadFile(output); !strings.Contains(string(b), "published=true\n") || !strings.HasSuffix(string(b), "image="+pushed+"\nrepository="+w.host+"/factory/org\ndigest="+w.digest(ref)+"\npublished=false\n") {
		t.Errorf("GITHUB_OUTPUT:\n%s", b)
	}

	// A changed profile is published and signed again, with --key.
	w.write("platform/factory.org.yaml", strings.Replace(sharedOrg, "failOn: high", "failOn: medium", 1))
	if err := ProfilePush(w.ctx, w.opts(), file, ProfilePushOptions{Ref: ref, Key: "awskms:///alias/profile"}); err != nil {
		t.Fatal(err)
	}
	if c := cosign.calls(); len(c) != 1 || c[0] != "sign "+w.host+"/factory/org@"+w.digest(ref)+" --key awskms:///alias/profile --yes" {
		t.Errorf("changed: cosign calls %q", c)
	}

	if err := ProfilePush(w.ctx, w.opts(), file, ProfilePushOptions{Ref: ref, Key: "k", NoSign: true}); err == nil {
		t.Error("--key with --no-sign was accepted")
	}
	// Key mode without a key to sign with fails before pushing.
	w.write("platform/factory.org.yaml", strings.Replace(sharedOrg, "  stackKey: awskms:///alias/platform\n", "", 1))
	if err := ProfilePush(w.ctx, w.opts(), file, ProfilePushOptions{Ref: w.host + "/factory/other:1"}); err == nil || !strings.Contains(err.Error(), "pass --key") {
		t.Errorf("key mode without a key: %v", err)
	}
	if ok, _ := registry.Exists(w.ctx, w.host+"/factory/other:1"); ok {
		t.Error("pushed without a key to sign with")
	}
}

// sharedFiles is a platform's shared profile and an app repository's
// profile and image that extend it.
func sharedFiles(signer string) map[string]string {
	return map[string]string{
		"platform/factory.org.yaml": "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\n" +
			"builder: {buildkit: HOST/buildkit:1, frontend: HOST/frontend:1, toolbox: HOST/toolbox:1}\nvulnerabilities: {failOn: high}\n",
		"team/factory.org.yaml": "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\n" +
			"extends:\n  ref: HOST/factory/org:1\n  signer: {certificateIdentity: " + signer + ", certificateOIDCIssuer: " + ghIssuer + "}\nregistry: HOST/team\n",
		"team/img/image.yaml": "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: Image\nmetadata: {name: img}\nspec:\n  base: HOST/base:1\n  platforms: [linux/amd64]\n",
	}
}

// TestSharedProfileEnforced: the shared profile is verified against
// extends.signer whenever a command loads it, at the digest the lock pins,
// so a lock edited to pin an unsigned (or tampered) version, or a profile
// signed by someone else, fails everywhere, before anything is built or
// written.
func TestSharedProfileEnforced(t *testing.T) {
	w := newProfileWorld(t, sharedFiles(profileIdentity))
	signedDigest := w.push("platform/factory.org.yaml")
	w.write("platform/factory.org.yaml", strings.Replace(strings.ReplaceAll(sharedFiles("")["platform/factory.org.yaml"], "HOST", w.host), "vulnerabilities: {failOn: high}\n", "", 1))
	unsignedDigest := w.push("platform/factory.org.yaml")
	repo := w.host + "/factory/org"
	cosign := newFakeCosign(t, "--certificate-identity "+profileIdentity, repo+"@"+signedDigest)

	opts := w.opts()
	opts.ManifestPath = filepath.Join(w.dir, "team/img/image.yaml")
	lockPath := filepath.Join(w.dir, "team/img/image.lock.yaml")
	pin := func(digest string) []byte {
		t.Helper()
		l := &lock.Lock{APIVersion: manifest.APIVersion, Kind: lock.Kind, Profile: &lock.Image{Ref: w.host + "/factory/org:1", Digest: digest}}
		if err := l.Write(lockPath); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(lockPath)
		return b
	}

	// The lock pins the signed version, which loads although the tag has
	// moved on to an unsigned one.
	pin(signedDigest)
	_, org, err := load(w.ctx, opts, false)
	if err != nil || org.Shared.Digest != signedDigest || org.Vulnerabilities.FailOn != "high" || org.Registry != w.host+"/team" {
		t.Fatalf("signed pin: %v", err)
	}
	if c := cosign.calls(); len(c) != 1 || !strings.HasPrefix(c[0], "verify ") || !strings.Contains(c[0], "--certificate-identity "+profileIdentity+" --certificate-oidc-issuer "+ghIssuer) || !strings.HasSuffix(c[0], " "+repo+"@"+signedDigest) {
		t.Errorf("cosign calls: %q", c)
	}
	// Loading it again verifies again (the cached copy isn't trusted on
	// its own).
	if _, _, err := load(w.ctx, opts, false); err != nil || len(cosign.calls()) != 1 {
		t.Errorf("second load: %v", err)
	}

	// A lock edited to pin the unsigned version fails everywhere.
	edited := pin(unsignedDigest)
	outDir := filepath.Join(w.dir, "out")
	imageOpts := opts
	imageOpts.ManifestPath, imageOpts.OrgPath = "", filepath.Join(w.dir, "team/factory.org.yaml")
	for _, c := range []struct {
		name string
		run  func() error
	}{
		{"lock", func() error { return Lock(w.ctx, opts, LockOptions{}) }},
		{"lock --update-base", func() error { return Lock(w.ctx, opts, LockOptions{UpdateBase: true}) }},
		{"render", func() error { return Render(w.ctx, opts, true, "") }},
		{"build", func() error { return Build(w.ctx, opts, BuildOptions{OutDir: outDir}) }},
		{"verify", func() error {
			return Verify(w.ctx, opts, VerifyOptions{FromSource: true, Digest: unsignedDigest, OutDir: outDir})
		}},
		{"rebase", func() error { return Rebase(w.ctx, opts, RebaseOptions{OutDir: outDir, Push: true, UpdateLock: true}) }},
		// Without a manifest, the tag is followed: it is unsigned too.
		{"verify --image", func() error {
			return Verify(w.ctx, imageOpts, VerifyOptions{Image: w.host + "/team/img@" + unsignedDigest, OutDir: outDir})
		}},
		{"rebase --image", func() error {
			return Rebase(w.ctx, imageOpts, RebaseOptions{Image: w.host + "/team/img:1", OutDir: outDir})
		}},
	} {
		err := c.run()
		if err == nil || !strings.Contains(err.Error(), "is not signed by extends.signer") {
			t.Errorf("%s on an unsigned profile: %v", c.name, err)
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

	// Signed, but not by the signer the repository names.
	pin(signedDigest)
	w.write("team/factory.org.yaml", strings.ReplaceAll(sharedFiles("https://github.com/mallory/platform/.github/workflows/profile.yml@refs/heads/main")["team/factory.org.yaml"], "HOST", w.host))
	if _, _, err := load(w.ctx, opts, false); err == nil || !strings.Contains(err.Error(), "is not signed by extends.signer") {
		t.Errorf("another signer: %v", err)
	}
}

// TestSharedProfileLock: each manifest's lock pins the shared profile;
// lock keeps the pin, lock --update moves it (without moving the build
// timestamp), and a lock that doesn't pin it is stale.
func TestSharedProfileLock(t *testing.T) {
	w := newProfileWorld(t, sharedFiles(profileIdentity))
	for _, r := range []string{"base", "buildkit", "frontend", "toolbox"} {
		w.image(r)
	}
	v1 := w.push("platform/factory.org.yaml")
	repo := w.host + "/factory/org"
	signedList := repo + "@" + v1
	cosign := newFakeCosign(t, "--certificate-identity "+profileIdentity, signedList)

	opts := w.opts()
	opts.ManifestPath = filepath.Join(w.dir, "team/img/image.yaml")
	lockPath := filepath.Join(w.dir, "team/img/image.lock.yaml")
	read := func() *lock.Lock {
		t.Helper()
		l, err := lock.Read(lockPath)
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	if err := Lock(w.ctx, opts, LockOptions{}); err != nil {
		t.Fatalf("lock: %v\n%s", err, w.out.String())
	}
	first := read()
	if first.Profile == nil || first.Profile.Ref != w.host+"/factory/org:1" || first.Profile.Digest != v1 || first.Builder.BuildKit.Ref != w.host+"/buildkit:1" {
		t.Fatalf("lock pins %+v, builder %+v", first.Profile, first.Builder)
	}
	if !strings.Contains(w.out.String(), "shared profile "+w.host+"/factory/org:1: pinned at") {
		t.Errorf("lock output:\n%s", w.out.String())
	}

	// A new version, signed too. lock keeps the pin; render accepts it.
	w.write("platform/factory.org.yaml", strings.ReplaceAll(strings.Replace(sharedFiles("")["platform/factory.org.yaml"], "failOn: high", "failOn: medium", 1), "HOST", w.host))
	v2 := w.push("platform/factory.org.yaml")
	_ = os.WriteFile(cosign.path+".signed", []byte(signedList+"\n"+repo+"@"+v2+"\n"), 0o644)
	w.out.Reset()
	if err := Lock(w.ctx, opts, LockOptions{}); err != nil || read().Profile.Digest != v1 || !strings.Contains(w.out.String(), "is up to date") {
		t.Errorf("lock moved the pin: %v\n%s", err, w.out.String())
	}
	if err := Render(w.ctx, opts, true, ""); err != nil {
		t.Errorf("render --check on the pinned profile: %v", err)
	}

	// lock --update moves it, and nothing else: the build timestamp stays
	// (an old one, so that a new one would show).
	first.SourceDateEpoch = 86400 * 1000
	if err := first.Write(lockPath); err != nil {
		t.Fatal(err)
	}
	w.out.Reset()
	if err := Lock(w.ctx, opts, LockOptions{Update: true}); err != nil {
		t.Fatal(err)
	}
	moved := read()
	if moved.Profile.Digest != v2 || moved.SourceDateEpoch != first.SourceDateEpoch || moved.Base != first.Base {
		t.Errorf("after --update: profile %s, epoch %d (was %d)", moved.Profile.Digest, moved.SourceDateEpoch, first.SourceDateEpoch)
	}
	if want := "shared profile " + w.host + "/factory/org:1: " + "sha256:" + v1[7:19] + " → sha256:" + v2[7:19]; !strings.Contains(w.out.String(), want) {
		t.Errorf("lock --update output lacks %q:\n%s", want, w.out.String())
	}
	_, org, err := load(w.ctx, opts, false)
	if err != nil || org.Vulnerabilities.FailOn != "medium" {
		t.Errorf("after --update, the new profile isn't loaded: %v", err)
	}

	// A lock that doesn't pin the shared profile is stale.
	unpinned := *moved
	unpinned.Profile = nil
	if err := unpinned.Write(lockPath); err != nil {
		t.Fatal(err)
	}
	if err := Render(w.ctx, opts, true, ""); err == nil || !strings.Contains(err.Error(), "doesn't pin the shared profile") {
		t.Errorf("unpinned lock: %v", err)
	}
	// And one that pins a profile no longer extended.
	if err := moved.Write(lockPath); err != nil {
		t.Fatal(err)
	}
	w.write("team/factory.org.yaml", "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\nregistry: "+w.host+"/team\nbuilder: {buildkit: "+w.host+"/buildkit:1, frontend: "+w.host+"/frontend:1, toolbox: "+w.host+"/toolbox:1}\n")
	if err := Render(w.ctx, opts, true, ""); err == nil || !strings.Contains(err.Error(), "no longer extends") {
		t.Errorf("pin without extends: %v", err)
	}
}

// TestInitExtends: init --extends checks the shared profile's signature
// and writes only what the shared profile leaves to the repository.
func TestInitExtends(t *testing.T) {
	w := newProfileWorld(t, map[string]string{
		"open.org.yaml":   "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\nvulnerabilities: {failOn: high}\n",
		"closed.org.yaml": "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\nregistry: ghcr.io/acme/apps\nsigning:\n  verify: {certificateIdentityRegexp: x, certificateOIDCIssuer: " + ghIssuer + ", sourceMatchesImage: true}\n",
	})
	open := w.push("open.org.yaml")
	repo := w.host + "/factory/org"
	cosign := newFakeCosign(t, "--certificate-identity "+profileIdentity, repo+"@"+open)
	ref := w.host + "/factory/org:1"

	dir := t.TempDir()
	iopts := InitOptions{Dir: dir, Repo: "acme/checkout", Extends: ref, ExtendsIdentity: profileIdentity}
	if err := Init(w.ctx, Options{Version: "v1.2.3", Stdout: &w.out, Stderr: &w.out}, iopts); err != nil {
		t.Fatal(err)
	}
	org, _ := os.ReadFile(filepath.Join(dir, "factory.org.yaml"))
	for _, want := range []string{"extends:\n  ref: " + ref + " ", "certificateIdentity: " + profileIdentity + "\n", "certificateOIDCIssuer: " + ghIssuer + "\n", "registry: ghcr.io/acme ", "sourceRepository: https://github.com/acme/checkout"} {
		if !strings.Contains(string(org), want) {
			t.Errorf("org profile lacks %q:\n%s", want, org)
		}
	}
	o, err := loadOrg(w.ctx, Options{}, dir, nil)
	if err != nil || o.Vulnerabilities.FailOn != "high" || o.Registry != "ghcr.io/acme" {
		t.Errorf("the profile init wrote doesn't load: %v\n%s", err, org)
	}
	_ = cosign.calls()

	// A shared profile that sets the registry and image signer leaves
	// nothing to add.
	closed := w.push("closed.org.yaml")
	_ = os.WriteFile(cosign.path+".signed", []byte(repo+"@"+closed+"\n"), 0o644)
	iopts.Force = true
	if err := Init(w.ctx, Options{Version: "v1.2.3", Stdout: &w.out, Stderr: &w.out}, iopts); err != nil {
		t.Fatal(err)
	}
	org, _ = os.ReadFile(filepath.Join(dir, "factory.org.yaml"))
	if strings.Contains(string(org), "registry:") || strings.Contains(string(org), "verify:") {
		t.Errorf("wrote what the shared profile sets:\n%s", org)
	}
	if _, err := loadOrg(w.ctx, Options{}, dir, nil); err != nil {
		t.Errorf("the profile init wrote doesn't load: %v\n%s", err, org)
	}

	// Unsigned (by that signer): nothing is written.
	_ = os.WriteFile(cosign.path+".signed", nil, 0o644)
	empty := t.TempDir()
	iopts.Dir = empty
	if err := Init(w.ctx, Options{Version: "v1.2.3", Stdout: &w.out, Stderr: &w.out}, iopts); err == nil || !strings.Contains(err.Error(), "is not signed by extends.signer") {
		t.Errorf("unsigned: %v", err)
	}
	if entries, _ := os.ReadDir(empty); len(entries) != 0 {
		t.Errorf("wrote %v", entries)
	}
	for _, bad := range []InitOptions{
		{Dir: empty, Extends: ref},
		{Dir: empty, Extends: ref, ExtendsIdentity: "x", ExtendsKey: "k.pub"},
		{Dir: empty, Extends: ref, ExtendsKey: "k.pub", ExtendsIssuer: ghIssuer},
		{Dir: empty, ExtendsIdentity: "x"},
	} {
		if err := Init(w.ctx, Options{Stdout: &w.out, Stderr: &w.out}, bad); err == nil {
			t.Errorf("init %+v: accepted", bad)
		}
	}
}
