package factory

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExcluded(t *testing.T) {
	// The last two are how render leaves out an app's lock and
	// Containerfile: anchored, with pattern characters escaped.
	pats := []string{".git", "/out", "docs/", "*.log", "web/node_modules", "/app.lock.yaml", `/\[v1]/a\*.Containerfile`}
	for rel, want := range map[string]bool{
		".git":                     true,
		"sub/.git/config":          true,
		"out":                      true,
		"out/hello/context":        true,
		"cmd/out/main.go":          false, // /out is anchored to the source root
		"docs":                     true,
		"docs/a.md":                true,
		"pkg/docs/a.md":            true, // a trailing slash does not anchor (as in .gitignore)
		"build.log":                true,
		"sub/x.log":                true,
		"web/node_modules/a/b.js":  true,
		"other/web/node_modules/a": false,
		"main.go":                  false,
		"app.lock.yaml":            true,
		"sub/app.lock.yaml":        false,
		"[v1]/a*.Containerfile":    true,
		"[v1]/ab.Containerfile":    false,
		"v/a*.Containerfile":       false,
	} {
		if got := excluded(rel, pats); got != want {
			t.Errorf("excluded(%q) = %v, want %v", rel, got, want)
		}
	}
}

// lock --update-package keeps every other pin, so it needs a lock to keep
// them from, and doesn't combine with the options that move other pins.
func TestLockUpdatePackageNeeds(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"factory.org.yaml": "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\nregistry: registry.example\nsigning: {mode: none}\n",
		"image.yaml":       "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: Image\nmetadata: {name: t}\nspec:\n  base: cgr.dev/chainguard/wolfi-base:latest\n  packages: [jq]\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	opts := Options{ManifestPath: filepath.Join(dir, "image.yaml"), Stdout: io.Discard, Stderr: io.Discard}
	for _, c := range []struct {
		lo   LockOptions
		want string
	}{
		{LockOptions{UpdatePackages: []string{"jq"}}, "image.lock.yaml does not exist; run clearcutt-factory lock"},
		{LockOptions{UpdatePackages: []string{"jq"}, Update: true}, "doesn't go with --update or --update-base"},
		{LockOptions{UpdatePackages: []string{"jq"}, UpdateBase: true}, "doesn't go with --update or --update-base"},
	} {
		if err := Lock(context.Background(), opts, c.lo); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: got %v, want %q", c.lo, err, c.want)
		}
	}
}
