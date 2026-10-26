package factory

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/northcutted/clearcutt-factory/internal/lock"
)

// lockWorld is a registry holding a base and the builder images, and a
// repository with an org profile naming them, so lock resolves offline.
type lockWorld struct {
	t    *testing.T
	host string
	dir  string
	out  bytes.Buffer
	opts Options
}

func newLockWorld(t *testing.T, org, manifest string) *lockWorld {
	t.Helper()
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(srv.Close)
	w := &lockWorld{t: t, host: strings.TrimPrefix(srv.URL, "http://"), dir: t.TempDir()}
	for _, name := range []string{"base", "bk", "fe", "tb"} {
		push(t, w.host+"/"+name+":latest", testIndex(t, nil, func(arch string) []v1.Layer { return []v1.Layer{testLayer(t, map[string]string{"etc/" + name: arch})} }, nil))
	}
	w.write("factory.org.yaml", "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\nregistry: "+w.host+"/images\nsigning: {mode: none}\n"+
		"builder: {buildkit: "+w.host+"/bk:latest, frontend: "+w.host+"/fe:latest, toolbox: "+w.host+"/tb:latest}\n"+org)
	w.write("image.yaml", "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: Image\nmetadata: {name: t}\nspec:\n  base: "+w.host+"/base:latest\n  platforms: [linux/amd64]\n"+manifest)
	w.opts = Options{ManifestPath: filepath.Join(w.dir, "image.yaml"), Version: "v0.4.0", Stdout: &w.out, Stderr: &w.out}
	return w
}

func (w *lockWorld) write(name, body string) {
	w.t.Helper()
	if err := os.WriteFile(filepath.Join(w.dir, name), []byte(body), 0o644); err != nil {
		w.t.Fatal(err)
	}
}

func (w *lockWorld) read(name string) string {
	w.t.Helper()
	b, err := os.ReadFile(filepath.Join(w.dir, name))
	if err != nil {
		w.t.Fatal(err)
	}
	return string(b)
}

func (w *lockWorld) exists(name string) bool {
	_, err := os.Stat(filepath.Join(w.dir, name))
	return err == nil
}

// TestEditedLockRefused: a lock edited by hand (a digest changed) is
// refused by every command that reads it, and by lock itself unless
// --update resolves everything again; a lock without a content digest (an
// older release's) is refused by the commands that build from it, and
// lock rewrites it keeping its pins; a lock a newer release wrote is
// refused with a message that says which.
func TestEditedLockRefused(t *testing.T) {
	w := newLockWorld(t, "", "")
	ctx := context.Background()
	if err := Lock(ctx, w.opts, LockOptions{}); err != nil {
		t.Fatalf("%v\n%s", err, w.out.String())
	}
	good := w.read("image.lock.yaml")
	base, err := lock.Read(filepath.Join(w.dir, "image.lock.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(good, "generator: clearcutt-factory v0.4.0\n") {
		t.Errorf("no generator in:\n%s", good)
	}

	// A digest edited by hand.
	w.write("image.lock.yaml", strings.Replace(good, base.Base.Digest, "sha256:"+strings.Repeat("e", 64), 1))
	for name, run := range map[string]func() error{
		"render":             func() error { return Render(ctx, w.opts, true, "") },
		"build":              func() error { return Build(ctx, w.opts, BuildOptions{}) },
		"lock":               func() error { return Lock(ctx, w.opts, LockOptions{}) },
		"lock --update-base": func() error { return Lock(ctx, w.opts, LockOptions{UpdateBase: true}) },
	} {
		if err := run(); err == nil || !strings.Contains(err.Error(), "image.lock.yaml was edited by hand") {
			t.Errorf("%s on an edited lock: %v", name, err)
		}
	}
	if w.read("image.lock.yaml") == good {
		t.Fatal("the edited lock was rewritten by a refusing command")
	}
	w.out.Reset()
	if err := Lock(ctx, w.opts, LockOptions{Update: true}); err != nil {
		t.Fatalf("lock --update: %v\n%s", err, w.out.String())
	}
	if got, err := lock.Read(filepath.Join(w.dir, "image.lock.yaml")); err != nil || got.Base.Digest != base.Base.Digest {
		t.Errorf("lock --update of an edited lock: %v, base %s", err, got.Base.Digest)
	}
	if !strings.Contains(w.out.String(), "base "+w.host+"/base:latest: sha256:eeeeeeeeeeee → ") {
		t.Errorf("--update should show the edit undone:\n%s", w.out.String())
	}

	// No content digest: an older lock.
	var kept []string
	for _, ln := range strings.Split(good, "\n") {
		if !strings.HasPrefix(ln, "contentDigest:") {
			kept = append(kept, ln)
		}
	}
	w.write("image.lock.yaml", strings.Join(kept, "\n"))
	if err := Render(ctx, w.opts, true, ""); err == nil || !strings.Contains(err.Error(), "image.lock.yaml has no contentDigest") {
		t.Errorf("render on an undigested lock: %v", err)
	}
	w.out.Reset()
	if err := Lock(ctx, w.opts, LockOptions{}); err != nil {
		t.Fatalf("lock on an undigested lock: %v", err)
	}
	if got := w.read("image.lock.yaml"); got != good {
		t.Errorf("lock should have written the digest and kept the pins:\n%s\nwant\n%s", got, good)
	}
	if err := Render(ctx, w.opts, true, ""); err != nil {
		t.Errorf("render after re-locking: %v", err)
	}

	// A newer release's lock.
	w.write("image.lock.yaml", strings.Replace(good, "clearcutt-factory v0.4.0", "clearcutt-factory v0.5.0", 1))
	var ne *lock.NewerError
	if err := Render(ctx, w.opts, true, ""); !errors.As(err, &ne) || !strings.Contains(err.Error(), "written by clearcutt-factory v0.5.0, newer than this clearcutt-factory (v0.4.0)") {
		t.Errorf("render on a newer lock: %v", err)
	}
	if err := Lock(ctx, w.opts, LockOptions{}); !errors.As(err, &ne) {
		t.Errorf("lock on a newer lock: %v", err)
	}
}

// TestLockWritesNothingUnlessItRenders: the lock is written only once the
// Containerfile renders from it, so a resolution the Containerfile can't
// hold (here, a mirror that turns a download URL into one with a space)
// leaves no lock, or the previous one untouched.
func TestLockWritesNothingUnlessItRenders(t *testing.T) {
	tool := "  tools:\n    - {name: kubectl, from: url, version: \"1.37.1\", url: \"https://dl.example/{{version}}/kubectl\", sha256: " + strings.Repeat("ab", 32) + ", dest: /usr/bin/kubectl}\n"
	w := newLockWorld(t, "mirrors: [{from: https://dl.example/, to: \"https://mirror example/\"}]\n", tool)
	ctx := context.Background()
	err := Lock(ctx, w.opts, LockOptions{})
	if err == nil || !strings.Contains(err.Error(), "mirrors turn https://dl.example/1.37.1/kubectl into") {
		t.Fatalf("lock with a broken mirror: %v", err)
	}
	if w.exists("image.lock.yaml") || w.exists("image.Containerfile") {
		t.Fatal("the lock or Containerfile was written although the Containerfile can't be rendered")
	}
	org := w.read("factory.org.yaml")
	w.write("factory.org.yaml", strings.Replace(org, "mirrors: [{from: https://dl.example/, to: \"https://mirror example/\"}]\n", "", 1))
	if err := Lock(ctx, w.opts, LockOptions{}); err != nil {
		t.Fatalf("%v\n%s", err, w.out.String())
	}
	good, cf := w.read("image.lock.yaml"), w.read("image.Containerfile")
	if !strings.Contains(cf, "https://dl.example/1.37.1/kubectl") {
		t.Errorf("Containerfile:\n%s", cf)
	}
	// The same failure with a lock on disk leaves it as it was.
	w.write("factory.org.yaml", org)
	if err := Lock(ctx, w.opts, LockOptions{Update: true}); err == nil || !strings.Contains(err.Error(), "mirrors turn") {
		t.Fatalf("lock --update with a broken mirror: %v", err)
	}
	if w.read("image.lock.yaml") != good || w.read("image.Containerfile") != cf {
		t.Error("a failed lock changed the lock or Containerfile on disk")
	}
	entries, _ := os.ReadDir(w.dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".image") {
			t.Errorf("temporary file left behind: %s", e.Name())
		}
	}
}
