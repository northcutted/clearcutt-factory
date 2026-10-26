package factory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/northcutted/clearcutt-factory/internal/manifest"
)

// AffectedOptions are affected's settings.
type AffectedOptions struct {
	// Changed is a file listing the changed paths, one per line, relative
	// to the current directory, as git diff --name-only or --name-status
	// prints them (STATUS<TAB>PATH; a rename or copy, STATUS<TAB>OLD<TAB>NEW,
	// counts as OLD deleted and NEW changed). "-" reads standard input.
	Changed string
	// Manifests are the manifests to choose from.
	Manifests []string
}

// Affected prints which of the manifests the changed files affect, one per
// line, and writes manifests=… (a JSON array) to $GITHUB_OUTPUT, for a
// pull request that builds only what it changed. A changed file that no
// manifest owns (an org profile's shared profile, a VEX document, a
// workflow) affects every manifest, since nothing says it doesn't; a
// deleted file that none owns affects none. See affectedManifests.
func Affected(ctx context.Context, opts Options, ao AffectedOptions) error {
	changes, err := readChanges(ao.Changed)
	if err != nil {
		return err
	}
	affected, all, err := affectedManifests(ao.Manifests, changes)
	if err != nil {
		return err
	}
	if all != "" {
		opts.logf("%s changed, which no manifest owns: every manifest may be affected", all)
	}
	for _, m := range affected {
		opts.printf("%s", m)
	}
	if path := os.Getenv("GITHUB_OUTPUT"); path != "" {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(f, "manifests=%s\n", jsonStrings(affected)); err != nil {
			_ = f.Close()
			return err
		}
		return f.Close()
	}
	return nil
}

// change is a changed path, relative to the current directory with
// forward slashes, and whether it was deleted.
type change struct {
	path    string
	deleted bool
}

// readChanges reads git diff --name-only or --name-status output, with or
// without -z (NUL-terminated, paths as they are; else one per line, a path
// git quoted, "…", unquoted).
func readChanges(path string) ([]change, error) {
	var b []byte
	var err error
	if path == "-" {
		b, err = io.ReadAll(os.Stdin)
	} else {
		b, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	if bytes.IndexByte(b, 0) >= 0 {
		return parseChangesZ(strings.Split(strings.TrimSuffix(string(b), "\x00"), "\x00"))
	}
	var out []change
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) == 1 || !isStatus(fields[0]) {
			out = append(out, change{path: cleanRel(unquote(line))})
			continue
		}
		for i := range fields[1:] {
			fields[i+1] = unquote(fields[i+1])
		}
		c, err := statusChanges(fields[0], fields[1:])
		if err != nil {
			return nil, fmt.Errorf("%s: %q: %w", path, line, err)
		}
		out = append(out, c...)
	}
	return out, nil
}

// parseChangesZ reads git diff -z output: --name-status (STATUS, then one
// path, or two for a rename or copy) or --name-only (paths).
func parseChangesZ(tokens []string) ([]change, error) {
	var out []change
	if len(tokens) == 0 || !isStatus(tokens[0]) {
		for _, t := range tokens {
			if t != "" {
				out = append(out, change{path: cleanRel(t)})
			}
		}
		return out, nil
	}
	for i := 0; i < len(tokens); {
		status := tokens[i]
		n := 1
		if status != "" && (status[0] == 'R' || status[0] == 'C') {
			n = 2
		}
		if !isStatus(status) || i+n >= len(tokens) {
			return nil, fmt.Errorf("git diff -z output: expected a status and %d path(s) at %q", n, status)
		}
		c, err := statusChanges(status, tokens[i+1:i+1+n])
		if err != nil {
			return nil, err
		}
		out = append(out, c...)
		i += 1 + n
	}
	return out, nil
}

// statusChanges is one --name-status entry: a rename (R) deletes its first
// path and changes its second; a copy (C) changes only its second; D
// deletes its path; anything else changes it.
func statusChanges(status string, paths []string) ([]change, error) {
	switch status[0] {
	case 'R', 'C':
		if len(paths) != 2 {
			return nil, fmt.Errorf("status %s needs two paths", status)
		}
		if status[0] == 'C' {
			return []change{{path: cleanRel(paths[1])}}, nil
		}
		return []change{{path: cleanRel(paths[0]), deleted: true}, {path: cleanRel(paths[1])}}, nil
	}
	if len(paths) != 1 {
		return nil, fmt.Errorf("status %s needs one path", status)
	}
	return []change{{path: cleanRel(paths[0]), deleted: status[0] == 'D'}}, nil
}

// unquote undoes git's quoting of a path with unusual characters ("…",
// with C escapes); any other string is returned as it is.
func unquote(p string) string {
	if len(p) >= 2 && p[0] == '"' && p[len(p)-1] == '"' {
		if u, err := strconv.Unquote(p); err == nil {
			return u
		}
	}
	return p
}

// isStatus reports whether s is a git diff status (A, M, D, T, U, X, B,
// or R100, C75).
func isStatus(s string) bool {
	if s == "" || !strings.ContainsRune("AMDTUXBRC", rune(s[0])) {
		return false
	}
	for _, c := range s[1:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// cleanRel normalizes a path relative to the current directory: forward
// slashes, no leading "./".
func cleanRel(p string) string {
	p = filepath.ToSlash(filepath.Clean(filepath.FromSlash(strings.TrimSpace(p))))
	return strings.TrimPrefix(p, "./")
}

// affectedManifests picks the manifests the changes affect, in the order
// given. A manifest owns the files under its directory (its lock and
// Containerfile among them), the files it extends, its VEX documents, its
// files: sources and an app's source directory (also outside its
// directory), and an app's stack file with the manifests of the stack's
// build and run images and the files they extend, which give the app's
// lock its build image and base; a factory.org.yaml is owned by every
// manifest below its directory. A changed file no manifest owns affects
// every manifest (all names it, the first such), since nothing says it
// doesn't: the shared profile and the trust policy and VEX documents it
// names, a workflow. A deleted file no manifest owns affects none: nothing
// left can read it.
func affectedManifests(manifests []string, changes []change) (affected []string, all string, err error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, "", err
	}
	rel := func(abs string) string {
		r, err := filepath.Rel(cwd, abs)
		if err != nil {
			return cleanRel(abs)
		}
		return cleanRel(r)
	}
	type owner struct {
		dirs  []string // the manifest's own first; "." owns everything
		files []string
	}
	owners := make([]owner, len(manifests))
	for i, path := range manifests {
		m, err := manifest.Load(path)
		if err != nil {
			return nil, "", err
		}
		o := owner{dirs: []string{rel(filepath.Dir(m.Path))}}
		for _, f := range m.Chain {
			o.files = append(o.files, rel(f))
		}
		if m.Kind == manifest.KindApp && m.Spec.SourceDir != "" {
			o.dirs = append(o.dirs, rel(m.Spec.SourceDir))
		}
		for _, f := range m.Spec.Files {
			// A source may be a file or a directory; under covers both.
			o.dirs = append(o.dirs, rel(f.AbsSrc))
		}
		for _, v := range m.Spec.VEXFiles {
			o.files = append(o.files, rel(v))
		}
		if m.Spec.StackPath != "" {
			o.files = append(o.files, rel(m.Spec.StackPath))
			images, err := stackImageFiles(m.Spec.StackPath)
			if err != nil {
				return nil, "", fmt.Errorf("%s: %w", path, err)
			}
			for _, f := range images {
				o.files = append(o.files, rel(f))
			}
		}
		owners[i] = o
	}
	under := func(p, dir string) bool {
		return dir == "." || p == dir || strings.HasPrefix(p, dir+"/")
	}
	picked := make([]bool, len(manifests))
	for _, c := range changes {
		p := cleanRel(c.path)
		owned := false
		for i, o := range owners {
			owns := slices.Contains(o.files, p)
			for _, d := range o.dirs {
				owns = owns || under(p, d)
			}
			if filepath.Base(p) == manifest.OrgFileName {
				owns = owns || under(o.dirs[0], cleanRel(filepath.Dir(p)))
			}
			if owns {
				picked[i], owned = true, true
			}
		}
		if !owned && !c.deleted && all == "" {
			all = p
		}
	}
	if all != "" {
		return slices.Clone(manifests), all, nil
	}
	for i, m := range manifests {
		if picked[i] {
			affected = append(affected, m)
		}
	}
	return affected, "", nil
}

// stackImageFiles returns the files behind the stack's build and run
// images, where it names them by manifest path: each manifest and the
// files it extends. An image named by reference has none here.
func stackImageFiles(stackPath string) ([]string, error) {
	st, err := manifest.LoadStack(stackPath)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, v := range []string{st.Spec.Build, st.Spec.Run} {
		if !manifest.IsStackFile(v) {
			continue
		}
		m, err := manifest.Load(filepath.Join(filepath.Dir(stackPath), v))
		if err != nil {
			return nil, err
		}
		out = append(out, m.Chain...)
	}
	return out, nil
}

// jsonStrings encodes strings as a JSON array, [] for none, without HTML
// escaping.
func jsonStrings(ss []string) string {
	if ss == nil {
		ss = []string{}
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(ss)
	return strings.TrimSuffix(b.String(), "\n")
}
