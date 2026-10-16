package registry

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

func TestQualify(t *testing.T) {
	for in, want := range map[string]string{
		"amazonlinux:2023": "docker.io/library/amazonlinux:2023",
		"amazonlinux:2023@sha256:5b29412077a463b4a3a8fbc99a8cdf4b929f38a3ecc8dac10328d8f36b0099b8": "docker.io/library/amazonlinux:2023@sha256:5b29412077a463b4a3a8fbc99a8cdf4b929f38a3ecc8dac10328d8f36b0099b8",
		"moby/buildkit@sha256:cec9f139f45e93c5c69c60f8b07cfad9f43f4ef6b6a6cd917527fea5ff2e3dea":    "docker.io/moby/buildkit@sha256:cec9f139f45e93c5c69c60f8b07cfad9f43f4ef6b6a6cd917527fea5ff2e3dea",
		"cgr.dev/chainguard/wolfi-base:latest":                                                     "cgr.dev/chainguard/wolfi-base:latest",
		"localhost:5555/e2e/x:latest":                                                              "localhost:5555/e2e/x:latest",
	} {
		if got := Qualify(in); got != want {
			t.Errorf("Qualify(%s) = %s, want %s", in, got, want)
		}
	}
}

func TestPlatformRef(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0))))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	var adds []mutate.IndexAddendum
	for _, arch := range []string{"amd64", "arm64"} {
		img, err := random.Image(32, 1)
		if err != nil {
			t.Fatal(err)
		}
		adds = append(adds, mutate.IndexAddendum{Add: img, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: arch}}})
	}
	idx := mutate.AppendManifests(empty.Index, adds...)
	ref, _ := name.ParseReference(host + "/base:latest")
	if err := remote.WriteIndex(ref, idx); err != nil {
		t.Fatal(err)
	}
	d, _ := idx.Digest()
	im, _ := idx.IndexManifest()
	got, err := PlatformRef(context.Background(), host+"/base:latest@"+d.String(), "linux/arm64")
	if err != nil {
		t.Fatal(err)
	}
	if want := host + "/base@" + im.Manifests[1].Digest.String(); got != want {
		t.Errorf("PlatformRef = %s, want %s", got, want)
	}
	single := host + "/base@" + im.Manifests[0].Digest.String()
	if got, err := PlatformRef(context.Background(), single, "linux/amd64"); err != nil || got != single {
		t.Errorf("single image: %s, %v", got, err)
	}
	if _, err := PlatformRef(context.Background(), host+"/base:latest", "linux/s390x"); err == nil {
		t.Error("expected an error for a missing platform")
	}
}

// TestExistsWithoutHead: a registry that rejects HEAD is asked with GET, as
// Digest does, and a HEAD 404 needs no second request.
func TestExistsWithoutHead(t *testing.T) {
	reg := ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)))
	var rejectHead, failGet bool
	var gets int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/manifests/") {
			switch {
			case r.Method == http.MethodHead && rejectHead:
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			case r.Method == http.MethodGet:
				gets++
				if failGet {
					w.WriteHeader(http.StatusForbidden)
					return
				}
			}
		}
		reg.ServeHTTP(w, r)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	ctx := context.Background()
	img, err := random.Image(32, 1)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := img.Digest()
	pushed := host + "/app@" + d.String()
	ref, _ := name.ParseReference(pushed)
	if err := remote.Write(ref, img); err != nil {
		t.Fatal(err)
	}
	missing := host + "/app@sha256:" + strings.Repeat("0", 64)

	gets = 0
	if ok, err := Exists(ctx, missing); ok || err != nil || gets != 0 {
		t.Errorf("HEAD 404: exists=%v, %v, %d GETs", ok, err, gets)
	}

	rejectHead = true
	if ok, err := Exists(ctx, pushed); !ok || err != nil {
		t.Errorf("HEAD rejected, pushed: exists=%v, %v", ok, err)
	}
	if ok, err := Exists(ctx, missing); ok || err != nil {
		t.Errorf("HEAD rejected, missing: exists=%v, %v", ok, err)
	}
	if got, err := Digest(ctx, pushed); err != nil || got != d.String() {
		t.Errorf("Digest with HEAD rejected: %s, %v", got, err)
	}

	failGet = true
	if ok, err := Exists(ctx, pushed); ok || err == nil || !strings.Contains(err.Error(), "with GET") {
		t.Errorf("HEAD and GET failing: exists=%v, %v", ok, err)
	}
}

// conditionalRegistry is a test registry that, like registries supporting
// conditional requests, returns ETags for manifests and refuses tag writes
// whose If-Match or If-None-Match doesn't hold.
type conditionalRegistry struct {
	h  http.Handler
	mu sync.Mutex
	// beforeWrite runs once, before the next tag write is checked (a
	// concurrent publish, say).
	beforeWrite func()
	// bogus fails every If-Match, like a registry whose ETags aren't the
	// ones it compares.
	bogus      bool
	conditions int
}

func (c *conditionalRegistry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_, ref, ok := strings.Cut(r.URL.Path, "/manifests/")
	if !ok || strings.HasPrefix(ref, "sha256:") {
		c.h.ServeHTTP(w, r)
		return
	}
	if r.Method == http.MethodPut {
		c.mu.Lock()
		f := c.beforeWrite
		c.beforeWrite = nil
		c.mu.Unlock()
		if f != nil {
			f()
		}
		rec := httptest.NewRecorder()
		c.h.ServeHTTP(rec, httptest.NewRequest(http.MethodHead, r.URL.Path, nil))
		etag := ""
		if rec.Code == http.StatusOK {
			etag = `"` + rec.Header().Get("Docker-Content-Digest") + `"`
		}
		match, none := r.Header.Get("If-Match"), r.Header.Get("If-None-Match") == "*"
		c.mu.Lock()
		bogus := c.bogus
		if match != "" || none {
			c.conditions++
		}
		c.mu.Unlock()
		if (match != "" && (bogus || match != etag)) || (none && etag != "") {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}
	}
	c.h.ServeHTTP(etagWriter{w}, r)
}

// etagWriter sets a manifest's digest as its ETag, as Distribution does.
type etagWriter struct{ http.ResponseWriter }

func (w etagWriter) WriteHeader(code int) {
	if d := w.Header().Get("Docker-Content-Digest"); d != "" {
		w.Header().Set("Etag", `"`+d+`"`)
	}
	w.ResponseWriter.WriteHeader(code)
}

func TestTagIf(t *testing.T) {
	reg := &conditionalRegistry{h: ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)))}
	srv := httptest.NewServer(reg)
	defer srv.Close()
	ctx := context.Background()
	repo := strings.TrimPrefix(srv.URL, "http://") + "/app"
	var a, b, c string
	for _, d := range []*string{&a, &b, &c} {
		img, err := random.Image(32, 1)
		if err != nil {
			t.Fatal(err)
		}
		h, _ := img.Digest()
		*d = repo + "@" + h.String()
		r, _ := name.NewDigest(*d)
		if err := remote.Write(r, img); err != nil {
			t.Fatal(err)
		}
	}
	digest := func(ref string) string { _, d, _ := strings.Cut(ref, "@"); return d }
	holds := func() string {
		t.Helper()
		got, err := Lookup(ctx, repo+":v1")
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	moved := func(err error, want, holds string) {
		t.Helper()
		var m *MovedError
		if !errors.As(err, &m) || m.Want != want || m.Holds != holds || m.Tag != repo+":v1" {
			t.Fatalf("want a move from %s to %s, got %v", want, holds, err)
		}
	}

	if got := holds(); got != "" {
		t.Fatalf("Lookup of a missing tag: %q", got)
	}
	// A new tag, then a move from what it holds: both conditional.
	if err := TagIf(ctx, a, "v1", ""); err != nil || holds() != digest(a) {
		t.Fatalf("new tag: %v, holds %s", err, holds())
	}
	if err := TagIf(ctx, b, "v1", digest(a)); err != nil || holds() != digest(b) {
		t.Fatalf("move: %v, holds %s", err, holds())
	}
	reg.mu.Lock()
	if reg.conditions != 2 {
		t.Errorf("%d conditional writes, want 2", reg.conditions)
	}
	reg.mu.Unlock()
	// The tag moved before the call.
	moved(TagIf(ctx, c, "v1", digest(a)), digest(a), digest(b))
	moved(TagIf(ctx, c, "v1", ""), "", digest(b))
	if holds() != digest(b) {
		t.Fatalf("a refused move changed the tag to %s", holds())
	}
	// The tag moves between the read and the write: the registry refuses it.
	reg.mu.Lock()
	reg.beforeWrite = func() {
		if err := Tag(ctx, c, []string{"v1"}); err != nil {
			t.Error(err)
		}
	}
	reg.mu.Unlock()
	moved(TagIf(ctx, a, "v1", digest(b)), digest(b), digest(c))
	if holds() != digest(c) {
		t.Fatalf("the write went through: v1 holds %s", holds())
	}
	// A registry whose ETags don't work as conditions still gets the write.
	reg.mu.Lock()
	reg.bogus = true
	reg.mu.Unlock()
	if err := TagIf(ctx, a, "v1", digest(c)); err != nil || holds() != digest(a) {
		t.Fatalf("bogus ETags: %v, holds %s", err, holds())
	}
}
