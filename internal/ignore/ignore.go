// Package ignore decides which files of a source directory go into a build
// context: in a git work tree, only the files git tracks; elsewhere, those
// .gitignore files don't ignore. A .dockerignore at the directory's root
// applies on top, as Docker reads it.
package ignore

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// Filter is the set of rules for one source directory.
type Filter struct {
	root string
	// tracked holds the files git tracks below root (slash-separated,
	// relative to it), and every directory holding one; nil outside git.
	tracked map[string]bool
	// gitignore holds the rules of each .gitignore read so far, by the
	// directory (relative to root, "" for root) it is in.
	gitignore map[string][]rule
	docker    []rule
	// skipped are the untracked files left out (in git), for a note.
	Skipped []string
}

type rule struct {
	re      *regexp.Regexp
	negate  bool
	dirOnly bool
}

// New reads the rules for root.
func New(root string) (*Filter, error) {
	f := &Filter{root: root, gitignore: map[string][]rule{}}
	inGit, err := inWorkTree(root)
	if err != nil {
		return nil, err
	}
	if inGit {
		if f.tracked, err = trackedFiles(root); err != nil {
			return nil, err
		}
	}
	b, err := os.ReadFile(filepath.Join(root, ".dockerignore"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	f.docker = parseDockerignore(b)
	return f, nil
}

// inWorkTree reports whether dir is in a git work tree: it or a parent
// holds .git.
func inWorkTree(dir string) (bool, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return false, err
	}
	for d := abs; ; d = filepath.Dir(d) {
		if _, err := os.Lstat(filepath.Join(d, ".git")); err == nil {
			return true, nil
		}
		if filepath.Dir(d) == d {
			return false, nil
		}
	}
}

// trackedFiles lists what git tracks below root (submodules included).
func trackedFiles(root string) (map[string]bool, error) {
	cmd := exec.Command("git", "-C", root, "ls-files", "-z", "--cached", "--recurse-submodules")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s is in a git work tree, and listing the files git tracks failed (only those go into the build): %w\n%s", root, err, strings.TrimSpace(stderr.String()))
	}
	tracked := map[string]bool{}
	for _, p := range strings.Split(string(out), "\x00") {
		if p == "" {
			continue
		}
		for d := p; d != "." && d != "/" && !tracked[d]; d = path.Dir(d) {
			tracked[d] = true
		}
	}
	return tracked, nil
}

// Include reports whether rel (slash-separated, relative to root) goes into
// the context. Directories are asked before their contents, as a walk
// visits them; an excluded directory's contents are excluded too.
func (f *Filter) Include(rel string, isDir bool) (bool, error) {
	// A directory .dockerignore excludes is still entered when an
	// exception could bring back something below it.
	if dockerExcluded(f.docker, rel) && !(isDir && hasException(f.docker)) {
		return false, nil
	}
	if f.tracked != nil {
		if !f.tracked[rel] {
			if isDir {
				rel += "/"
			}
			f.Skipped = append(f.Skipped, rel)
			return false, nil
		}
		return true, nil
	}
	// Outside git: each .gitignore from the root down to rel's directory,
	// the deeper ones last, so they win.
	dir := path.Dir(rel)
	if dir == "." {
		dir = ""
	}
	var dirs []string
	for d := dir; ; d = path.Dir(d) {
		if d == "." {
			d = ""
		}
		dirs = append([]string{d}, dirs...)
		if d == "" {
			break
		}
	}
	ignored := false
	for _, d := range dirs {
		rules, err := f.gitignoreIn(d)
		if err != nil {
			return false, err
		}
		sub := rel
		if d != "" {
			sub = strings.TrimPrefix(rel, d+"/")
		}
		if m, ok := lastMatch(rules, sub, isDir); ok {
			ignored = m
		}
	}
	return !ignored, nil
}

func (f *Filter) gitignoreIn(dir string) ([]rule, error) {
	if rules, ok := f.gitignore[dir]; ok {
		return rules, nil
	}
	b, err := os.ReadFile(filepath.Join(f.root, filepath.FromSlash(dir), ".gitignore"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	rules := parseGitignore(b)
	f.gitignore[dir] = rules
	return rules, nil
}

// lastMatch returns whether the last rule matching rel ignores it, and
// whether any matched.
func lastMatch(rules []rule, rel string, isDir bool) (ignored, matched bool) {
	for _, r := range rules {
		if r.dirOnly && !isDir {
			continue
		}
		if r.re.MatchString(rel) {
			ignored, matched = !r.negate, true
		}
	}
	return ignored, matched
}

// dockerExcluded applies Docker's rules: the last pattern matching rel or
// one of its parent directories decides.
func dockerExcluded(rules []rule, rel string) bool {
	excluded := false
	for _, r := range rules {
		hit := r.re.MatchString(rel)
		for d := path.Dir(rel); !hit && d != "." && d != "/"; d = path.Dir(d) {
			hit = r.re.MatchString(d)
		}
		if hit {
			excluded = !r.negate
		}
	}
	return excluded
}

func hasException(rules []rule) bool {
	for _, r := range rules {
		if r.negate {
			return true
		}
	}
	return false
}

// parseGitignore reads .gitignore rules: a pattern without a slash but at
// its end matches a name at any depth; one with a slash is anchored to the
// file's directory; ** spans directories; ! re-includes; a trailing slash
// matches directories only.
func parseGitignore(b []byte) []rule {
	var rules []rule
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.HasSuffix(line, `\ `) {
			line = strings.TrimSuffix(line, `\ `) + " "
		} else {
			line = strings.TrimRight(line, " ")
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var r rule
		switch {
		case strings.HasPrefix(line, "!"):
			r.negate, line = true, line[1:]
		case strings.HasPrefix(line, `\!`), strings.HasPrefix(line, `\#`):
			line = line[1:]
		}
		if strings.HasSuffix(line, "/") {
			r.dirOnly, line = true, strings.TrimRight(line, "/")
		}
		anchored := strings.Contains(line, "/")
		line = strings.TrimPrefix(line, "/")
		if line == "" {
			continue
		}
		expr := globRegexp(line)
		if !anchored {
			expr = "(?:.*/)?" + expr
		}
		re, err := regexp.Compile("^" + expr + "$")
		if err != nil {
			continue
		}
		r.re = re
		rules = append(rules, r)
	}
	return rules
}

// parseDockerignore reads .dockerignore rules as Docker does: every pattern
// is relative to the context's root (after cleaning it), ** spans
// directories, and ! makes an exception.
func parseDockerignore(b []byte) []rule {
	var rules []rule
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var r rule
		if strings.HasPrefix(line, "!") {
			r.negate, line = true, strings.TrimSpace(line[1:])
		}
		line = strings.TrimPrefix(path.Clean("/"+line), "/")
		if line == "" {
			continue
		}
		re, err := regexp.Compile("^" + globRegexp(line) + "$")
		if err != nil {
			continue
		}
		r.re = re
		rules = append(rules, r)
	}
	return rules
}

// globRegexp turns a slash-separated glob into a regular expression: *
// and ? stay within a path segment, [...] is a class, and ** spans any
// number of segments.
func globRegexp(glob string) string {
	var b strings.Builder
	for i := 0; i < len(glob); i++ {
		c := glob[i]
		switch {
		case c == '*' && strings.HasPrefix(glob[i:], "**/"):
			b.WriteString("(?:.*/)?")
			i += 2
		case c == '*' && strings.HasPrefix(glob[i:], "**") && i+2 == len(glob):
			b.WriteString(".*")
			i++
		case c == '*':
			b.WriteString("[^/]*")
		case c == '?':
			b.WriteString("[^/]")
		case c == '[':
			end := strings.IndexByte(glob[i+1:], ']')
			if end < 0 {
				b.WriteString(`\[`)
				continue
			}
			class := glob[i+1 : i+1+end]
			if strings.HasPrefix(class, "!") {
				class = "^" + class[1:]
			}
			b.WriteString("[" + strings.ReplaceAll(class, `\`, `\\`) + "]")
			i += end + 1
		case c == '\\' && i+1 < len(glob):
			i++
			b.WriteString(regexp.QuoteMeta(string(glob[i])))
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	return b.String()
}
