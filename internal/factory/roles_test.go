package factory

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRoles: the stacks in a repository say which images are build images
// (spec.build names their manifest) and which run images (spec.run); an
// image no stack names has no role, and stacks under hidden or output
// directories, or naming images by reference, don't count.
func TestRoles(t *testing.T) {
	dir := t.TempDir()
	image := func(name string) string {
		return "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: Image\nmetadata: {name: " + name + "}\nspec: {base: cgr.dev/chainguard/wolfi-base:latest}\n"
	}
	stack := func(name, build, run string) string {
		return "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: Stack\nmetadata: {name: " + name + "}\nspec:\n  build: " + build + "\n  run: " + run + "\n  steps: [{run: make}]\n"
	}
	files := map[string]string{
		"factory.org.yaml":                 "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\nregistry: r.example/p\nsigning: {mode: none}\n",
		"images/build-go/image.yaml":       image("build-go"),
		"images/run-go/image.yaml":         image("run-go"),
		"images/both/image.yaml":           image("both"),
		"images/tools/image.yaml":          image("tools"),
		"images/by-ref/image.yaml":         image("by-ref"),
		"stacks/go.yaml":                   stack("go", "../images/build-go/image.yaml", "../images/run-go/image.yaml"),
		"stacks/odd.yml":                   stack("odd", "./../images/both/image.yaml", "../images/both/image.yaml"),
		"stacks/node.yaml":                 stack("node", "r.example/p/by-ref:1", "../images/run-go/image.yaml"),
		"stacks/README.yaml":               "not: a stack\n",
		"out/stacks/stale.yaml":            stack("stale", "../../images/tools/image.yaml", "../../images/tools/image.yaml"),
		".hidden/stacks/hidden.yaml":       stack("hidden", "../../images/tools/image.yaml", "../../images/tools/image.yaml"),
		"apps/svc/app.yaml":                "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: App\nmetadata: {name: svc}\nspec: {stack: ../../stacks/go.yaml}\n",
		"vendor/node_modules/x/stack.yaml": stack("vendored", "../../../images/tools/image.yaml", "../../../images/tools/image.yaml"),
	}
	for n, body := range files {
		p := filepath.Join(dir, n)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for manifest, want := range map[string]string{
		"images/build-go/image.yaml": "build",
		"images/run-go/image.yaml":   "run",
		"images/both/image.yaml":     "build run",
		"images/tools/image.yaml":    "",
		"images/by-ref/image.yaml":   "",
	} {
		roles, err := imageRoles(filepath.Join(dir, manifest), dir)
		if err != nil {
			t.Fatalf("%s: %v", manifest, err)
		}
		if got := strings.Join(roles, " "); got != want {
			t.Errorf("%s: %q, want %q", manifest, got, want)
		}
	}
	if _, err := imageRoles(filepath.Join(dir, "apps/svc/app.yaml"), dir); err == nil || !strings.Contains(err.Error(), "is a App") {
		t.Errorf("an app: %v", err)
	}
	if _, err := imageRoles(filepath.Join(dir, "images/tools/image.yaml"), filepath.Join(dir, "nowhere")); err == nil || !strings.Contains(err.Error(), "no such directory") {
		t.Errorf("missing dir: %v", err)
	}

	// The command prints one role per line and writes roles= for the
	// workflow; a stack that doesn't load is an error.
	gho := filepath.Join(dir, "gho")
	t.Setenv("GITHUB_OUTPUT", gho)
	var out bytes.Buffer
	if err := Roles(context.Background(), Options{ManifestPath: filepath.Join(dir, "images/both/image.yaml"), Stdout: &out, Stderr: &out}, RolesOptions{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(gho); out.String() != "build\nrun\n" || string(b) != "roles=build run\n" {
		t.Errorf("stdout %q, GITHUB_OUTPUT %q", out.String(), b)
	}
	if err := os.WriteFile(filepath.Join(dir, "stacks/broken.yaml"), []byte("apiVersion: factory.clearcutt.dev/v1alpha1\nkind: Stack\nmetadata: {name: broken}\nspec: {build: x}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := imageRoles(filepath.Join(dir, "images/tools/image.yaml"), dir); err == nil || !strings.Contains(err.Error(), "broken.yaml") {
		t.Errorf("broken stack: %v", err)
	}
}
