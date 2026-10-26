package factory

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt-factory/internal/attest"
	"github.com/northcutted/clearcutt-factory/internal/render"
)

// TestContextLeavesOutStrayFiles: a stray .env next to the app's source
// never reaches the build context, so it can't be embedded in the signed
// recipe: in a git work tree only what git tracks goes in, elsewhere what
// .gitignore leaves, and .dockerignore applies on top (#6).
func TestContextLeavesOutStrayFiles(t *testing.T) {
	files := map[string]string{
		"main.go":        "package main\n",
		"go.mod":         "module hello\n",
		".gitignore":     "secret.key\n.env\n",
		".dockerignore":  "docs\n",
		"docs/guide.md":  "# guide\n",
		"cmd/tool.go":    "package main\n",
		"cmd/.gitignore": "*.out\n",
	}
	for _, git := range []bool{true, false} {
		t.Run(fmt.Sprintf("git=%v", git), func(t *testing.T) {
			stray := map[string]string{
				".env":         "DATABASE_PASSWORD=hunter2\n",
				"secret.key":   "-----BEGIN PRIVATE KEY-----\n",
				"cmd/dump.out": "core\n",
			}
			src := t.TempDir()
			write := func(m map[string]string) {
				for n, body := range m {
					p := filepath.Join(src, n)
					_ = os.MkdirAll(filepath.Dir(p), 0o755)
					if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
						t.Fatal(err)
					}
				}
			}
			write(files)
			if git {
				run := func(args ...string) {
					t.Helper()
					cmd := exec.Command("git", append([]string{"-C", src, "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)...)
					cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
					if out, err := cmd.CombinedOutput(); err != nil {
						t.Fatalf("git %v: %v\n%s", args, err, out)
					}
				}
				run("init", "-q")
				run("add", "-A")
				run("commit", "-q", "-m", "app")
				// In git, what git doesn't track is left out, ignored
				// or not.
				stray[".untracked-but-not-ignored"] = "x\n"
			}
			write(stray)

			ctxDir := filepath.Join(t.TempDir(), "context")
			out := &render.Output{Containerfile: []byte("FROM scratch\n"), Context: []render.ContextFile{{Src: src, Rel: "src", Exclude: render.DefaultExclude}}}
			var notes []string
			if err := stage(out, ctxDir, func(f string, a ...any) { notes = append(notes, fmt.Sprintf(f, a...)) }); err != nil {
				t.Fatal(err)
			}
			entries, err := attest.ContextEntries(ctxDir, render.ContainerfileName)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, e := range entries {
				got = append(got, e.Path)
				if strings.Contains(string(e.Content), "hunter2") || strings.Contains(string(e.Content), "PRIVATE KEY") {
					t.Errorf("the recipe embeds %s", e.Path)
				}
			}
			want := []string{"src/.dockerignore", "src/.gitignore", "src/cmd/.gitignore", "src/cmd/tool.go", "src/go.mod", "src/main.go"}
			if !slices.Equal(got, want) {
				t.Errorf("context:\n%q\nwant:\n%q", got, want)
			}
			if git && (len(notes) != 1 || !strings.Contains(notes[0], ".env") || !strings.Contains(notes[0], ".untracked-but-not-ignored") || !strings.Contains(notes[0], "commit it to build with it")) {
				t.Errorf("notes: %q", notes)
			}
			if !git && len(notes) != 0 {
				t.Errorf("notes outside git: %q", notes)
			}
		})
	}
}
