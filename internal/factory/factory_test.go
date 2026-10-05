package factory

import "testing"

func TestExcluded(t *testing.T) {
	pats := []string{".git", "/out", "docs/", "*.log", "web/node_modules"}
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
	} {
		if got := excluded(rel, pats); got != want {
			t.Errorf("excluded(%q) = %v, want %v", rel, got, want)
		}
	}
}
