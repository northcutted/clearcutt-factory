package ignore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGitignoreRules(t *testing.T) {
	rules := parseGitignore([]byte(`# secrets
.env
*.key
!public.key
/build
logs/
docs/**/draft.md
a/**/b
\#notes
` + "trailing\\ \n"))
	for _, c := range []struct {
		path  string
		dir   bool
		want  bool
		match bool
	}{
		{".env", false, true, true},
		{"config/.env", false, true, true},
		{"x.key", false, true, true},
		{"keys/public.key", false, false, true},
		{"build", true, true, true},
		{"cmd/build", true, false, false},
		{"logs", true, true, true},
		{"logs", false, false, false},
		{"docs/draft.md", false, true, true},
		{"docs/a/b/draft.md", false, true, true},
		{"a/b", false, true, true},
		{"a/x/y/b", false, true, true},
		{"#notes", false, true, true},
		{"trailing ", false, true, true},
		{"main.go", false, false, false},
		{".envrc", false, false, false},
	} {
		ignored, matched := lastMatch(rules, c.path, c.dir)
		if ignored != c.want || matched != c.match {
			t.Errorf("%s (dir %v): ignored %v matched %v, want %v %v", c.path, c.dir, ignored, matched, c.want, c.match)
		}
	}
}

func TestDockerignoreRules(t *testing.T) {
	rules := parseDockerignore([]byte(`# Docker anchors every pattern at the root
*.env
/secrets
**/*.pem
docs
!docs/README.md
`))
	for _, c := range []struct {
		path string
		want bool
	}{
		{"prod.env", true},
		{"config/prod.env", false}, // anchored, unlike .gitignore
		{"secrets", true},
		{"secrets/token", true}, // below an excluded directory
		{"a/b/c.pem", true},
		{"c.pem", true},
		{"docs/guide.md", true},
		{"docs/README.md", false},
		{"main.go", false},
	} {
		if got := dockerExcluded(rules, c.path); got != c.want {
			t.Errorf("%s: excluded %v, want %v", c.path, got, c.want)
		}
	}
}

// TestFilterOutsideGit: nested .gitignore files apply below their own
// directory, and .dockerignore at the root on top.
func TestFilterOutsideGit(t *testing.T) {
	root := t.TempDir()
	for n, body := range map[string]string{
		".gitignore":     ".env\n",
		".dockerignore":  "docs\n",
		"sub/.gitignore": "*.tmp\n!keep.tmp\n",
	} {
		p := filepath.Join(root, n)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	f, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	if f.tracked != nil {
		t.Fatal("a temporary directory is in a git work tree")
	}
	for _, c := range []struct {
		path string
		dir  bool
		want bool
	}{
		{".env", false, false},
		{"sub/.env", false, false},
		{"docs", true, false},
		{"sub/x.tmp", false, false},
		{"sub/keep.tmp", false, true},
		{"x.tmp", false, true}, // sub's rule stays in sub
		{"main.go", false, true},
	} {
		got, err := f.Include(c.path, c.dir)
		if err != nil || got != c.want {
			t.Errorf("%s: include %v (%v), want %v", c.path, got, err, c.want)
		}
	}
}
