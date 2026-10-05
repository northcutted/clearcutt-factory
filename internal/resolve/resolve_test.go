package resolve

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/northcutted/declarative-image-factory/internal/apk"
	"github.com/northcutted/declarative-image-factory/internal/lock"
	"github.com/northcutted/declarative-image-factory/internal/manifest"
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
	// only the base pin (factory lock --update-base) moves only the base.
	r.ImageDigest = func(_ context.Context, ref string) (string, error) { return "sha256:" + sum(ref+"-v2"), nil }
	r.digests = nil // a new run of factory lock
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
