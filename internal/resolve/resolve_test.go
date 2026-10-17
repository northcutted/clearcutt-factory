package resolve

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/northcutted/clearcutt-factory/internal/apk"
	"github.com/northcutted/clearcutt-factory/internal/lock"
	"github.com/northcutted/clearcutt-factory/internal/manifest"
)

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func TestParseChecksum(t *testing.T) {
	h := sum("x")
	cases := map[string]string{
		h + "\n":                                     "tool",
		h + "  tool\n" + sum("y") + "  other\n":      "tool",
		sum("y") + " *other\n" + h + " *dist/tool\n": "tool",
		"SHA256 (tool) = " + h:                       "tool",
	}
	for body, name := range cases {
		got, err := parseChecksum([]byte(body), name)
		if err != nil || got != h {
			t.Errorf("parseChecksum(%q) = %q, %v", body, got, err)
		}
	}
	if _, err := parseChecksum([]byte(sum("y")+"  other\n"+sum("z")+"  another"), "tool"); err == nil {
		t.Error("expected error when the file is not listed")
	}
}

func TestExpand(t *testing.T) {
	got, err := expand("v{{version}}/{{ os }}-{{arch}}", map[string]string{"version": "1.2", "os": "linux", "arch": "arm64"})
	if err != nil || got != "v1.2/linux-arm64" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := expand("{{versoin}}", map[string]string{"version": "1"}); err == nil || !strings.Contains(err.Error(), "versoin") {
		t.Fatalf("expected unknown placeholder error, got %v", err)
	}
}

const apkIndex = `P:jq
V:1.8.2-r2
A:aarch64
C:Q1jq=
D:so:libonig.so.5

P:oniguruma
V:6.9.10-r5
A:aarch64
C:Q1on=
p:so:libonig.so.5=5

P:busybox
V:1.38.0-r2
A:aarch64
C:Q1bb=
`

// fakeUpstream serves release artifacts, checksum files, the GitHub API, and
// the Go module proxy.
func fakeUpstream(t *testing.T) (*httptest.Server, *int) {
	t.Helper()
	downloads := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/dl/tool-linux-amd64", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "amd64 bin") })
	mux.HandleFunc("/dl/tool-linux-arm64", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "arm64 bin") })
	mux.HandleFunc("/dl/tool-linux-amd64.sha256", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, sum("amd64 bin")) })
	mux.HandleFunc("/dl/tool-linux-arm64.sha256", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, sum("arm64 bin")) })
	mux.HandleFunc("/dl/plain", func(w http.ResponseWriter, r *http.Request) {
		downloads++
		_, _ = io.WriteString(w, "plain")
	})
	mux.HandleFunc("/gh/acme/tool/releases/download/v2.0.0/checksums.txt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "%s  tool_amd64.tar.gz\n%s  tool_aarch64.tar.gz\n", sum("gh amd64"), sum("gh arm64"))
	})
	mux.HandleFunc("/api/repos/acme/nosums/releases/tags/v1.0.0", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `{"assets":[{"name":"nosums-amd64","digest":"sha256:%s"},{"name":"nosums-arm64","digest":"sha256:%s"}]}`, sum("a"), sum("b"))
	})
	mux.HandleFunc("/proxy/example.com/!acme/tool/@latest", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"Version":"v1.4.0"}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &downloads
}

func testResolver(t *testing.T, srv *httptest.Server) *Resolver {
	r := New()
	r.Log = io.Discard
	r.GitHubAPI = srv.URL + "/api"
	r.GitHubDownload = srv.URL + "/gh"
	r.GoProxy = srv.URL + "/proxy"
	r.ImageDigest = func(_ context.Context, ref string) (string, error) { return "sha256:" + sum(ref), nil }
	r.ReadImageFiles = func(_ context.Context, ref, platform string, paths ...string) (map[string][]byte, error) {
		return map[string][]byte{
			apkReposPath: []byte("# comment\nhttps://repo.example\n"),
			apkDBPath:    []byte("P:busybox\nV:1.37.0-r0\nA:aarch64\n\nP:not-in-repo\nV:1\n"),
		}, nil
	}
	r.FetchAPKIndex = func(_ context.Context, repos []string, arch string, _ map[string][]byte) (*apk.Index, error) {
		pkgs, err := apk.ParseIndex(strings.NewReader(strings.ReplaceAll(apkIndex, "aarch64", arch)))
		for _, p := range pkgs {
			p.Repo = repos[0]
		}
		return apk.NewIndex(arch, pkgs), err
	}
	r.Now = func() time.Time { return time.Unix(1700000000, 0) }
	return r
}

func testManifest(srv *httptest.Server) (*manifest.Manifest, *manifest.Org) {
	m := &manifest.Manifest{
		APIVersion: manifest.APIVersion, Kind: manifest.KindImage,
		Metadata: manifest.Metadata{Name: "t", Ref: "registry.example/t"},
		Spec: manifest.Spec{
			Base:      "registry.example/base:latest",
			Platforms: []string{"linux/amd64", "linux/arm64"},
			Packages:  []string{"jq"},
			Tools: []manifest.Tool{
				{Name: "tool", From: "url", Version: "1", URL: srv.URL + "/dl/tool-{{os}}-{{arch}}", Checksum: "{{url}}.sha256"},
				{Name: "plain", From: "url", URL: srv.URL + "/dl/plain"},
				{Name: "ghtool", From: "github-release", Repo: "acme/tool", Version: "2.0.0", Asset: "tool_{{arch}}.tar.gz",
					Checksums: "checksums.txt", Extract: "tool-{{arch}}/tool", ArchMap: map[string]string{"arm64": "aarch64"}},
				{Name: "nosums", From: "github-release", Repo: "acme/nosums", Version: "1.0.0", Asset: "nosums-{{arch}}"},
				{Name: "gotool", From: "go", Package: "example.com/Acme/tool/cmd/tool", Image: "golang:1"},
				{Name: "pinned", From: "url", URL: srv.URL + "/dl/never-fetched", SHA256: manifest.ArchMap{"*": strings.ToUpper(sum("p"))}},
			},
		},
	}
	return m, manifest.DefaultOrg()
}

func TestLock(t *testing.T) {
	srv, downloads := fakeUpstream(t)
	r := testResolver(t, srv)
	m, o := testManifest(srv)

	l, err := r.Lock(context.Background(), m, o, nil, false)
	if err != nil {
		t.Fatal(err)
	}

	if l.Base.Digest != "sha256:"+sum("registry.example/base:latest") {
		t.Errorf("base not pinned: %+v", l.Base)
	}
	arm := l.Packages.Platforms["linux/arm64"]
	var pins []string
	for _, p := range arm {
		pins = append(pins, p.Name+"="+p.Version)
	}
	// jq + its provider, plus busybox from the base pinned to the repo's newest.
	if got := strings.Join(pins, " "); got != "busybox=1.38.0-r2 jq=1.8.2-r2 oniguruma=6.9.10-r5" {
		t.Errorf("packages: %s", got)
	}
	if l.Packages.Repositories[0] != "https://repo.example" {
		t.Errorf("repositories: %v", l.Packages.Repositories)
	}

	check := func(name, plat, want, how string) {
		t.Helper()
		tl := l.Tool(name)
		if tl == nil {
			t.Fatalf("%s not locked", name)
		}
		if tl.Verification != how {
			t.Errorf("%s verification = %s, want %s", name, tl.Verification, how)
		}
		if plat != "" && tl.Artifacts[plat].SHA256 != want {
			t.Errorf("%s %s sha256 = %s, want %s", name, plat, tl.Artifacts[plat].SHA256, want)
		}
	}
	check("tool", "linux/arm64", sum("arm64 bin"), lock.VerifiedChecksumFile)
	check("plain", "linux/amd64", sum("plain"), lock.VerifiedTOFU)
	check("ghtool", "linux/arm64", sum("gh arm64"), lock.VerifiedChecksumFile)
	check("nosums", "linux/amd64", sum("a"), lock.VerifiedGitHubDigest)
	check("pinned", "linux/arm64", sum("p"), lock.VerifiedPinned)
	check("gotool", "", "", lock.VerifiedGoSumDB)

	if a := l.Tool("ghtool").Artifacts["linux/arm64"]; a.Extract != "tool-aarch64/tool" || !strings.HasSuffix(a.URL, "/v2.0.0/tool_aarch64.tar.gz") {
		t.Errorf("ghtool artifact: %+v", a)
	}
	if v := l.Tool("gotool").Version; v != "v1.4.0" {
		t.Errorf("go latest = %s", v)
	}
	if l.SourceDateEpoch != 1699833600 { // midnight UTC the day before Now (2023-11-14T22:13:20Z)
		t.Errorf("epoch = %d", l.SourceDateEpoch)
	}

	// Re-locking an unchanged manifest reuses every pin and keeps the epoch.
	before := *downloads
	r2 := testResolver(t, srv)
	r2.Now = func() time.Time { return time.Unix(1800000000, 0) }
	r2.FetchAPKIndex = nil // must not be called
	l2, err := r2.Lock(context.Background(), m, o, l, false)
	if err != nil {
		t.Fatal(err)
	}
	if string(l2.Marshal()) != string(l.Marshal()) || *downloads != before {
		t.Error("unchanged manifest should produce an identical lock without network work")
	}

	// Changing one tool re-resolves only that tool and bumps the epoch.
	m.Spec.Tools[1].URL += "?v=2"
	r3 := testResolver(t, srv)
	r3.Now = func() time.Time { return time.Unix(1800000000, 0) }
	l3, err := r3.Lock(context.Background(), m, o, l, false)
	if err != nil {
		t.Fatal(err)
	}
	if l3.SourceDateEpoch != epochFor(time.Unix(1800000000, 0)) || l3.Tool("tool").SpecDigest != l.Tool("tool").SpecDigest {
		t.Error("expected new epoch and untouched tool entry")
	}
}

func TestLockApp(t *testing.T) {
	r := New()
	r.Log = io.Discard
	r.ImageDigest = func(_ context.Context, ref string) (string, error) { return "sha256:" + sum(ref), nil }
	calls := 0
	r.PlatformDigests = func(_ context.Context, ref string) (map[string]string, error) {
		calls++
		return map[string]string{"linux/amd64": "sha256:" + sum("amd64"), "linux/arm64": "sha256:" + sum("arm64"), "linux/s390x": "sha256:" + sum("s390x")}, nil
	}
	r.Now = func() time.Time { return time.Unix(1700000000, 0) }
	st := &manifest.Stack{Metadata: manifest.StackMetadata{Name: "go"}, BuildRef: "golang:1", RunRef: "registry.example/run:latest",
		Spec: manifest.StackSpec{Build: "golang:1", Run: "registry.example/run:latest", Steps: []manifest.Step{{Run: "go build"}}}}
	m := &manifest.Manifest{
		APIVersion: manifest.APIVersion, Kind: manifest.KindApp, Stack: st,
		Metadata: manifest.Metadata{Name: "hello", Ref: "registry.example/hello"},
		Spec:     manifest.Spec{Base: st.RunRef, Platforms: []string{"linux/amd64", "linux/arm64"}},
	}
	l, err := r.Lock(context.Background(), m, manifest.DefaultOrg(), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if l.App == nil || l.App.Stack != "go" || l.App.Build.Ref != "golang:1" || l.App.StackDigest != lock.StackDigest(st) {
		t.Fatalf("app lock: %+v", l.App)
	}
	if len(l.App.RunPlatforms) != 2 || l.App.RunPlatforms["linux/arm64"] != "sha256:"+sum("arm64") {
		t.Errorf("run platforms: %v", l.App.RunPlatforms)
	}
	if len(l.Packages.Platforms) != 0 || len(l.Tools) != 0 {
		t.Errorf("apps lock no packages or tools: %+v", l)
	}
	if in := lock.InputsOf(m, manifest.DefaultOrg()); in.Build != "golang:1" || in.Stack == "" {
		t.Errorf("inputs: %+v", in)
	}

	again, err := r.Lock(context.Background(), m, manifest.DefaultOrg(), l, false)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || string(again.Marshal()) != string(l.Marshal()) {
		t.Errorf("relock changed the lock or refetched the run image (%d calls)", calls)
	}

	// Both tags move upstream. A plain relock keeps both pins; dropping
	// only the base pin (clearcutt-factory lock --update-base) moves only the base.
	r.ImageDigest = func(_ context.Context, ref string) (string, error) { return "sha256:" + sum(ref+"-v2"), nil }
	r.digests = nil // a new run of clearcutt-factory lock
	same, err := r.Lock(context.Background(), m, manifest.DefaultOrg(), l, false)
	if err != nil || same.Base.Digest != l.Base.Digest {
		t.Fatalf("plain relock moved the base: %v", err)
	}
	reuse := *l
	reuse.Base = lock.Image{Ref: m.Spec.Base}
	app := *l.App
	app.RunPlatforms = nil
	reuse.App = &app
	moved, err := r.LockFrom(context.Background(), m, manifest.DefaultOrg(), &reuse, l, false)
	if err != nil {
		t.Fatal(err)
	}
	if moved.Base.Digest != "sha256:"+sum(st.RunRef+"-v2") || moved.App.Build.Digest != l.App.Build.Digest || calls != 2 {
		t.Errorf("update-base: base %s, build %s, run platform fetches %d", moved.Base.Digest, moved.App.Build.Digest, calls)
	}
	if moved.SourceDateEpoch != l.SourceDateEpoch {
		// Same day in this test, so the epoch is unchanged; it is recomputed.
		t.Logf("epoch moved to %d", moved.SourceDateEpoch)
	}
	if c := strings.Join(lock.Changes(l, moved), "\n"); !strings.Contains(c, "base registry.example/run:latest: ") || strings.Contains(c, "build image") {
		t.Errorf("changes: %s", c)
	}

	m.Spec.Platforms = []string{"linux/riscv64"}
	if _, err := r.Lock(context.Background(), m, manifest.DefaultOrg(), l, false); err == nil || !strings.Contains(err.Error(), "no linux/riscv64 image") {
		t.Errorf("expected missing platform error, got %v", err)
	}
}

// TestUpdateKeepsSameContent: lock --update that resolves the same files
// (through a moved snapshot, say) leaves the lock and its timestamp alone.
func TestUpdateKeepsSameContent(t *testing.T) {
	srv, _ := fakeUpstream(t)
	r := testResolver(t, srv)
	m, o := testManifest(srv)
	first, err := r.Lock(context.Background(), m, o, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	// As if the first lock had resolved through another snapshot.
	first.Packages.Snapshot = "20261003T000000Z"
	r.Now = func() time.Time { return time.Unix(1800000000, 0) }
	again, err := r.Lock(context.Background(), m, o, first, true)
	if err != nil {
		t.Fatal(err)
	}
	if string(again.Marshal()) != string(first.Marshal()) {
		t.Errorf("an update that changed nothing moved the lock:\n%s", strings.Join(lock.Changes(first, again), "\n"))
	}
}

// The drill's run image: libcrypto3 held at a version with a CVE, and an
// unrelated openssl-4.0 that has an update of its own.
const oldAPKIndex = `P:libcrypto3
V:3.6.3-r4
A:aarch64
C:Q1lc-old=
D:openssl-config>=3.6

P:openssl-config
V:3.6.3-r4
A:aarch64
C:Q1oc-old=

P:openssl-4.0-libcrypto
V:4.0.3-r6
A:aarch64
C:Q1o4-old=

P:busybox
V:1.38.0-r2
A:aarch64
C:Q1bb=
`

// The fix: libcrypto3 3.6.5 needs a newer openssl-config and zlib.
const newAPKIndex = oldAPKIndex + `
P:libcrypto3
V:3.6.5-r2
A:aarch64
C:Q1lc-new=
D:openssl-config>=3.6.5 so:libz.so.1

P:openssl-config
V:3.6.5-r2
A:aarch64
C:Q1oc-new=

P:zlib
V:1.3.1-r0
A:aarch64
C:Q1z=
p:so:libz.so.1=1

P:openssl-4.0-libcrypto
V:4.0.3-r7
A:aarch64
C:Q1o4-new=
`

func serveAPKIndex(r *Resolver, index *string) {
	r.FetchAPKIndex = func(_ context.Context, repos []string, arch string, _ map[string][]byte) (*apk.Index, error) {
		pkgs, err := apk.ParseIndex(strings.NewReader(strings.ReplaceAll(*index, "aarch64", arch)))
		for _, p := range pkgs {
			p.Repo = repos[0]
		}
		return apk.NewIndex(arch, pkgs), err
	}
}

func versionsOn(l *lock.Lock, plat string) string {
	var s []string
	for _, p := range l.Packages.Platforms[plat] {
		s = append(s, p.Name+"="+p.Version)
	}
	return strings.Join(s, " ")
}

func TestUpdatePackageAPK(t *testing.T) {
	srv, _ := fakeUpstream(t)
	index := oldAPKIndex
	r := testResolver(t, srv)
	serveAPKIndex(r, &index)
	m, o := testManifest(srv)
	m.Spec.Tools = nil
	m.Spec.Packages = []string{"libcrypto3", "openssl-4.0-libcrypto"}
	old, err := r.Lock(context.Background(), m, o, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := versionsOn(old, "linux/arm64"); got != "busybox=1.38.0-r2 libcrypto3=3.6.3-r4 openssl-4.0-libcrypto=4.0.3-r6 openssl-config=3.6.3-r4" {
		t.Fatalf("old lock: %s", got)
	}

	// The fix is published. Updating libcrypto3 alone would move
	// openssl-config: the error says so, and how to move it too.
	index = newAPKIndex
	update := func(names ...string) (*lock.Lock, error) {
		r := testResolver(t, srv)
		serveAPKIndex(r, &index)
		r.Now = func() time.Time { return time.Unix(1800000000, 0) }
		r.UpdatePackages = names
		return r.Lock(context.Background(), m, o, old, false)
	}
	_, err = update("libcrypto3")
	if err == nil || !strings.Contains(err.Error(), "libcrypto3-3.6.5-r2 needs openssl-config>=3.6.5, but openssl-config is pinned at 3.6.3-r4") ||
		!strings.Contains(err.Error(), "openssl-config would have to move too; to update them as well: --update-package libcrypto3,openssl-config") {
		t.Fatalf("expected openssl-config to block, got %v", err)
	}
	if strings.Contains(err.Error(), "(on linux/") || strings.Contains(err.Error(), "would move") {
		t.Errorf("a problem on every platform needn't name them, nor be repeated: %v", err)
	}

	// Named both: they move, zlib comes in for the new libcrypto3, and the
	// unrelated openssl-4.0 stays where it was.
	l, err := update("libcrypto3", "openssl-config")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"package libcrypto3: 3.6.3-r4 → 3.6.5-r2",
		"package openssl-config: 3.6.3-r4 → 3.6.5-r2",
		"package zlib: added 1.3.1-r0",
	}
	if got := lock.Changes(old, l); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("changes:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if l.SourceDateEpoch == old.SourceDateEpoch {
		t.Error("an update that moved packages should move the epoch")
	}

	// Nothing newer: the lock stays as it is.
	same, err := update("busybox")
	if err != nil || string(same.Marshal()) != string(old.Marshal()) {
		t.Errorf("updating a current package changed the lock: %v\n%s", err, strings.Join(lock.Changes(old, same), "\n"))
	}

	// A plain --update moves everything, as before.
	r2 := testResolver(t, srv)
	serveAPKIndex(r2, &index)
	all, err := r2.Lock(context.Background(), m, o, old, true)
	if err != nil {
		t.Fatal(err)
	}
	if got := versionsOn(all, "linux/amd64"); !strings.Contains(got, "openssl-4.0-libcrypto=4.0.3-r7") {
		t.Errorf("--update: %s", got)
	}

	if _, err := update("libssl3", "nope"); err == nil || !strings.Contains(err.Error(), "libssl3, nope is neither in spec.packages nor in the lock") {
		t.Errorf("expected unknown package error, got %v", err)
	}
}

// Releasing a hold in the manifest, the drill's way: the held entry loses
// its version and is named, and nothing else moves.
func TestUpdatePackageReleasesHold(t *testing.T) {
	srv, _ := fakeUpstream(t)
	index := newAPKIndex
	r := testResolver(t, srv)
	serveAPKIndex(r, &index)
	m, o := testManifest(srv)
	m.Spec.Tools = nil
	m.Spec.Packages = []string{"libcrypto3=3.6.3-r4", "openssl-config=3.6.3-r4", "openssl-4.0-libcrypto=4.0.3-r6"}
	held, err := r.Lock(context.Background(), m, o, nil, false)
	if err != nil {
		t.Fatal(err)
	}

	m.Spec.Packages = []string{"libcrypto3", "openssl-config", "openssl-4.0-libcrypto=4.0.3-r6"}
	r.UpdatePackages = []string{"libcrypto3", "openssl-config"}
	l, err := r.Lock(context.Background(), m, o, held, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := versionsOn(l, "linux/arm64"); got != "busybox=1.38.0-r2 libcrypto3=3.6.5-r2 openssl-4.0-libcrypto=4.0.3-r6 openssl-config=3.6.5-r2 zlib=1.3.1-r0" {
		t.Errorf("released: %s", got)
	}
	if l.Packages.InputsDigest == held.Packages.InputsDigest {
		t.Error("the package inputs changed with the manifest")
	}
}

// aptOutput is what aptScript prints for packages (name, version, sha256)
// resolved through snapshot.
func aptOutput(snapshot string, pkgs ...[3]string) string {
	var sim, uris, recs strings.Builder
	for _, p := range pkgs {
		file := p[0] + "_" + p[1] + "_arm64.deb"
		fmt.Fprintf(&sim, "Inst %s (%s Debian:13.7/stable [arm64])\n", p[0], p[1])
		fmt.Fprintf(&uris, "'http://snapshot.debian.org/archive/debian/%s/pool/main/x/%s/%s' %s 1 MD5Sum:00\n", snapshot, p[0], file, file)
		fmt.Fprintf(&recs, "Package: %s\nVersion: %s\nArchitecture: arm64\nFilename: pool/main/x/%s/%s\nSHA256: %s\n\n", p[0], p[1], p[0], file, p[2])
	}
	return "### os\ndebian 13\n### sources\nhttp://snapshot.debian.org/archive/debian/" + snapshot + "/\n### simulate\n" + sim.String() +
		"### uris\n" + uris.String() + "### records\n" + recs.String()
}

func TestUpdatePackageAPT(t *testing.T) {
	srv, _ := fakeUpstream(t)
	r := testResolver(t, srv)
	m, o := testManifest(srv)
	m.Spec.Tools = nil
	m.Spec.PackageManager = lock.ManagerAPT
	m.Spec.Platforms = []string{"linux/arm64"}
	m.Spec.Packages = []string{"curl"}
	r.Run = func(_ context.Context, _, _, _ string, args ...string) ([]byte, error) {
		return []byte(aptOutput(args[0], [3]string{"curl", "8.14.1-2", "c1"}, [3]string{"libc6", "2.41-12", "l1"})), nil
	}
	old, err := r.Lock(context.Background(), m, o, nil, false)
	if err != nil {
		t.Fatal(err)
	}

	// A fixed curl two weeks later, beside a newer libc6 that isn't needed.
	var gotArgs []string
	libc6 := "2.41-12"
	r = testResolver(t, srv)
	r.Now = func() time.Time { return time.Unix(1700000000+14*86400, 0) }
	r.UpdatePackages = []string{"curl"}
	r.Run = func(_ context.Context, _, _, _ string, args ...string) ([]byte, error) {
		gotArgs = args
		return []byte(aptOutput(args[0], [3]string{"curl", "8.14.1-2+deb13u1", "c2"}, [3]string{"libc6", libc6, "l1"})), nil
	}
	l, err := r.Lock(context.Background(), m, o, old, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(gotArgs, " "); got != "20231128T221320Z --keep-snapshot=20231114T221320Z --pin=libc6=2.41-12 curl" {
		t.Errorf("apt args: %s", got)
	}
	if got := strings.Join(lock.Changes(old, l), "\n"); got != "package curl: 8.14.1-2 → 8.14.1-2+deb13u1" {
		t.Errorf("changes: %s", got)
	}
	kept := l.Packages.Platforms["linux/arm64"][1]
	if kept != old.Packages.Platforms["linux/arm64"][1] || !strings.Contains(kept.URL, "/20231114T221320Z/") {
		t.Errorf("the kept libc6 should be the locked entry, from its own snapshot: %+v", kept)
	}

	// apt moved the pin (its version gone from the archive, say): fail,
	// naming it.
	libc6 = "2.41-13"
	if _, err := r.Lock(context.Background(), m, o, old, false); err == nil ||
		!strings.Contains(err.Error(), "libc6 would move from 2.41-12 to 2.41-13") ||
		!strings.Contains(err.Error(), "--update-package curl,libc6") {
		t.Errorf("expected libc6 to block, got %v", err)
	}

	// apt can't resolve with the pins: its error, and what to do.
	r.Run = func(context.Context, string, string, string, ...string) ([]byte, error) {
		return nil, errors.New("curl : Depends: libc6 (>= 2.41-13) but 2.41-12 is to be installed")
	}
	if _, err := r.Lock(context.Background(), m, o, old, false); err == nil ||
		!strings.Contains(err.Error(), "keeping every package but curl at its locked version: curl : Depends: libc6") ||
		!strings.Contains(err.Error(), "name that package in --update-package too") {
		t.Errorf("expected apt's error with a hint, got %v", err)
	}
}

// dnfOutput is what dnfScript prints for packages (name, version-release,
// sha256) on Amazon Linux.
func dnfOutput(pkgs ...[3]string) string {
	var rpms, sigs, urls strings.Builder
	for _, p := range pkgs {
		file := p[0] + "-" + p[1] + ".aarch64.rpm"
		ver, rel, _ := strings.Cut(p[1], "-")
		fmt.Fprintf(&rpms, "%s\t%s\t0\t%s\t%s\taarch64\t%s-%s.src.rpm\tMIT\n", p[2], p[0], ver, rel, p[0], p[1])
		fmt.Fprintf(&sigs, "/var/cache/dnf/amazonlinux-1/packages/%s: digests signatures OK\n", file)
		fmt.Fprintf(&urls, "https://cdn.amazonlinux.com/al2023/core/guids/abc/aarch64/../../../../blobstore/%s/%s\n", p[2], file)
	}
	return "### os\namzn 2023\n### rpms\n" + rpms.String() + "### signatures\n" + sigs.String() + "### urls\n" + urls.String()
}

func TestUpdatePackageDNF(t *testing.T) {
	srv, _ := fakeUpstream(t)
	r := testResolver(t, srv)
	m, o := testManifest(srv)
	m.Spec.Tools = nil
	m.Spec.PackageManager = lock.ManagerDNF
	m.Spec.Platforms = []string{"linux/arm64"}
	m.Spec.Packages = []string{"jq", "openssl"}
	r.Run = func(context.Context, string, string, string, ...string) ([]byte, error) {
		return []byte(dnfOutput([3]string{"jq", "1.7.1-49.amzn2023", "j1"}, [3]string{"oniguruma", "6.9.7-1.amzn2023", "o1"}, [3]string{"openssl", "3.0.8-1.amzn2023", "s1"})), nil
	}
	old, err := r.Lock(context.Background(), m, o, nil, false)
	if err != nil {
		t.Fatal(err)
	}

	var gotArgs []string
	r.UpdatePackages = []string{"jq"}
	r.Run = func(_ context.Context, _, _, _ string, args ...string) ([]byte, error) {
		gotArgs = args
		return []byte(dnfOutput([3]string{"jq", "1.7.1-50.amzn2023", "j2"}, [3]string{"oniguruma", "6.9.7-1.amzn2023", "o1"}, [3]string{"openssl", "3.0.8-1.amzn2023", "s1"})), nil
	}
	l, err := r.Lock(context.Background(), m, o, old, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(gotArgs, " "); got != "--pin=oniguruma=oniguruma-0:6.9.7-1.amzn2023.aarch64 --pin=openssl=openssl-0:3.0.8-1.amzn2023.aarch64 jq openssl" {
		t.Errorf("dnf args: %s", got)
	}
	if got := strings.Join(lock.Changes(old, l), "\n"); got != "package jq: 1.7.1-49.amzn2023 → 1.7.1-50.amzn2023" {
		t.Errorf("changes: %s", got)
	}

	// The new jq needs a newer oniguruma, which dnf took: fail, naming it.
	r.Run = func(context.Context, string, string, string, ...string) ([]byte, error) {
		return []byte(dnfOutput([3]string{"jq", "1.7.1-50.amzn2023", "j2"}, [3]string{"oniguruma", "6.9.7-2.amzn2023", "o2"}, [3]string{"openssl", "3.0.8-1.amzn2023", "s1"})), nil
	}
	if _, err := r.Lock(context.Background(), m, o, old, false); err == nil ||
		!strings.Contains(err.Error(), "oniguruma would move from 6.9.7-1.amzn2023 to 6.9.7-2.amzn2023") ||
		!strings.Contains(err.Error(), "--update-package jq,oniguruma") {
		t.Errorf("expected oniguruma to block, got %v", err)
	}
}

func TestMentions(t *testing.T) {
	for _, c := range []struct {
		entry, name, mgr string
		want             bool
	}{
		{"libcrypto3", "libcrypto3", lock.ManagerAPK, true},
		{"libcrypto3=3.6.3-r4", "libcrypto3", lock.ManagerAPK, true},
		{"libcrypto3>=3.6", "libcrypto3", lock.ManagerAPK, true},
		{"libcrypto3-doc", "libcrypto3", lock.ManagerAPK, false},
		{"curl=8.14.1-2", "curl", lock.ManagerAPT, true},
		{"curl/trixie-backports", "curl", lock.ManagerAPT, true},
		{"curlie", "curl", lock.ManagerAPT, false},
		{"openssl-libs-3.0.8-1.amzn2023", "openssl-libs", lock.ManagerDNF, true},
		{"openssl-libs.aarch64", "openssl-libs", lock.ManagerDNF, true},
		{"openssl-libs", "openssl", lock.ManagerDNF, false},
		{"python3.14", "python3", lock.ManagerDNF, false},
	} {
		if got := mentions(c.entry, c.name, c.mgr); got != c.want {
			t.Errorf("mentions(%q, %q, %s) = %v", c.entry, c.name, c.mgr, got)
		}
	}
}
