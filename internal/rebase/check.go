package rebase

import (
	"archive/tar"
	"bufio"
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"maps"
	"path"
	"slices"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// Report is what Analyze found for one platform.
type Report struct {
	// Violations mean the app's layers change or depend on base files, so
	// rebasing would keep stale copies or hide the new base's. Never safe.
	Violations []string
	// Breaks are differences between the bases that may break the app
	// (another distribution release, a library the app's programs load
	// that the new base lacks, a missing entrypoint). Rebuild the app
	// instead, or force the rebase.
	Breaks []string
}

// OK reports whether the rebase is safe without forcing.
func (r *Report) OK() bool { return len(r.Violations) == 0 && len(r.Breaks) == 0 }

// Layers are the inputs Analyze reads: the old and new base layers, the
// app's layers above the old base, and the app's configuration.
type Layers struct {
	OldBase, NewBase, App []v1.Layer
	Config                v1.Config
}

// Package-manager state. App layers that write here installed OS packages,
// which a rebase would roll back to the app's copy of the database.
var packageDBs = []string{
	"var/lib/dpkg/", "var/lib/rpm/", "usr/lib/sysimage/rpm/", "lib/apk/db/", "var/lib/apk/", "etc/apk/",
}

// maxPaths caps how many paths each message lists.
const maxPaths = 10

// Analyze checks that moving the app's layers from the old base to the new
// one is safe.
//
// The app's layers must only add files: not modify, delete, or shadow
// anything in either base, not write through a base's symlinks, and not
// touch package-manager state. Otherwise the rebased image would carry the
// app's stale copies over the new base's files (an old libssl, say).
//
// The bases must be compatible: the same distribution release, every
// shared library the app's programs load (and their ELF interpreter)
// still provided, and the app's entrypoint still there.
func Analyze(in Layers) (*Report, error) {
	oldFS, err := readTree(in.OldBase)
	if err != nil {
		return nil, fmt.Errorf("reading old base: %w", err)
	}
	newFS, err := readTree(in.NewBase)
	if err != nil {
		return nil, fmt.Errorf("reading new base: %w", err)
	}
	var app []entry
	for _, l := range in.App {
		es, err := layerEntries(l, true)
		if err != nil {
			return nil, fmt.Errorf("reading app layer: %w", err)
		}
		app = append(app, es...)
	}

	r := &Report{}
	var modified, shadowed, deleted, through, pkgs []string
	for _, e := range app {
		if e.whiteout != "" {
			if e.whiteout == opaque {
				if oldFS.hasUnder(e.path) {
					deleted = append(deleted, "/"+e.path+"/ (all of it)")
				}
			} else if oldFS.has(e.whiteout) {
				deleted = append(deleted, "/"+e.whiteout)
			}
			continue
		}
		for _, db := range packageDBs {
			if strings.HasPrefix(e.path+"/", db) && e.typ != tar.TypeDir {
				pkgs = append(pkgs, "/"+e.path)
			}
		}
		if l, ok := oldFS.symlinkAncestor(e.path); ok {
			through = append(through, fmt.Sprintf("/%s (/%s is a symlink in the old base)", e.path, l))
		} else if l, ok := newFS.symlinkAncestor(e.path); ok {
			through = append(through, fmt.Sprintf("/%s (/%s is a symlink in the new base)", e.path, l))
		}
		if t, ok := oldFS.entries[e.path]; ok && (t != tar.TypeDir || e.typ != tar.TypeDir) {
			modified = append(modified, "/"+e.path)
		} else if t, ok := newFS.entries[e.path]; ok && (t != tar.TypeDir || e.typ != tar.TypeDir) {
			shadowed = append(shadowed, "/"+e.path)
		}
	}
	add := func(list []string, msg string) {
		if len(list) > 0 {
			r.Violations = append(r.Violations, msg+": "+listPaths(list))
		}
	}
	add(pkgs, "app layers install OS packages (package database changes)")
	add(modified, "app layers replace files of the old base")
	add(shadowed, "app layers would hide files of the new base")
	add(deleted, "app layers delete files of the old base")
	add(through, "app layers write through base symlinks")

	oldRel, newRel := oldFS.osRelease(), newFS.osRelease()
	if oldRel != newRel {
		r.Breaks = append(r.Breaks, fmt.Sprintf("distribution changed: %s → %s", orNone(oldRel), orNone(newRel)))
	}
	oldAll, newAll := oldFS.with(app), newFS.with(app)
	oldLibs, newLibs := oldAll.libraries(), newAll.libraries()
	var missing []string
	for _, e := range app {
		if e.interp != "" && oldAll.exists(e.interp) && !newAll.exists(e.interp) {
			missing = append(missing, fmt.Sprintf("/%s needs %s", e.path, e.interp))
		}
		for _, lib := range e.needed {
			if oldLibs[lib] && !newLibs[lib] {
				missing = append(missing, fmt.Sprintf("/%s needs %s", e.path, lib))
			}
		}
	}
	if len(missing) > 0 {
		r.Breaks = append(r.Breaks, "the new base lacks libraries the app loads: "+listPaths(missing))
	}

	cmd := in.Config.Entrypoint
	if len(cmd) == 0 {
		cmd = in.Config.Cmd
	}
	if len(cmd) > 0 && path.IsAbs(cmd[0]) && oldAll.exists(cmd[0]) && !newAll.exists(cmd[0]) {
		r.Breaks = append(r.Breaks, fmt.Sprintf("entrypoint %s is missing from the new base", cmd[0]))
	}
	return r, nil
}

func listPaths(paths []string) string {
	paths = slices.Compact(paths)
	if len(paths) > maxPaths {
		return strings.Join(paths[:maxPaths], ", ") + fmt.Sprintf(", and %d more", len(paths)-maxPaths)
	}
	return strings.Join(paths, ", ")
}

func orNone(s string) string {
	if s == "" {
		return "(no os-release)"
	}
	return s
}

const opaque = "\x00opaque"

// entry is one tar entry of a layer. Whiteouts name what they delete.
type entry struct {
	path     string
	typ      byte
	link     string
	whiteout string // deleted path, or opaque (path's contents)
	data     []byte // os-release contents
	// ELF programs and libraries (app layers only): the shared libraries
	// they load and their interpreter.
	needed []string
	interp string
}

// maxELF caps the size of an app file read to find its libraries.
const maxELF = 1 << 30

// osReleasePaths are read so the distribution can be compared.
var osReleasePaths = map[string]bool{"etc/os-release": true, "usr/lib/os-release": true}

// layerEntries lists a layer's entries; with elfDeps it also reads which
// libraries each ELF file loads.
func layerEntries(l v1.Layer, elfDeps bool) ([]entry, error) {
	rc, err := l.Uncompressed()
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	var out []entry
	tr := tar.NewReader(rc)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		p := clean(h.Name)
		if p == "" {
			continue
		}
		dir, base := path.Split(p)
		dir = strings.TrimSuffix(dir, "/")
		switch {
		case base == ".wh..wh..opq":
			out = append(out, entry{path: dir, whiteout: opaque})
			continue
		case strings.HasPrefix(base, ".wh."):
			out = append(out, entry{path: p, whiteout: path.Join(dir, strings.TrimPrefix(base, ".wh."))})
			continue
		}
		e := entry{path: p, typ: h.Typeflag, link: h.Linkname}
		if e.typ == '\x00' { // pre-POSIX regular file
			e.typ = tar.TypeReg
		}
		if osReleasePaths[p] && e.typ == tar.TypeReg && h.Size < 64<<10 {
			if e.data, err = io.ReadAll(tr); err != nil {
				return nil, err
			}
		} else if elfDeps && e.typ == tar.TypeReg && h.Size > 4 && h.Size < maxELF {
			if e.needed, e.interp, err = elfDependencies(tr); err != nil {
				return nil, fmt.Errorf("/%s: %w", p, err)
			}
		}
		out = append(out, e)
	}
}

// elfDependencies returns the shared libraries and interpreter of an ELF
// file; other files return nothing.
func elfDependencies(r io.Reader) ([]string, string, error) {
	br := bufio.NewReader(r)
	magic, err := br.Peek(4)
	if err != nil || string(magic) != elf.ELFMAG {
		return nil, "", nil
	}
	b, err := io.ReadAll(br)
	if err != nil {
		return nil, "", err
	}
	f, err := elf.NewFile(bytes.NewReader(b))
	if err != nil {
		return nil, "", nil // not a well-formed ELF file; nothing to check
	}
	defer func() { _ = f.Close() }()
	libs, _ := f.ImportedLibraries()
	interp := ""
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			if s, err := io.ReadAll(p.Open()); err == nil {
				interp = strings.TrimRight(string(s), "\x00")
			}
		}
	}
	return libs, interp, nil
}

func clean(name string) string {
	return strings.TrimPrefix(path.Clean("/"+name), "/")
}

// tree is a flattened filesystem: every path with its type.
type tree struct {
	entries map[string]byte
	links   map[string]string
	data    map[string][]byte
}

func newTree() *tree {
	return &tree{entries: map[string]byte{}, links: map[string]string{}, data: map[string][]byte{}}
}

func readTree(layers []v1.Layer) (*tree, error) {
	t := newTree()
	for _, l := range layers {
		es, err := layerEntries(l, false)
		if err != nil {
			return nil, err
		}
		t.apply(es)
	}
	return t, nil
}

// apply lays a layer's entries over the tree: whiteouts first (they only
// affect lower layers), then additions.
func (t *tree) apply(es []entry) {
	for _, e := range es {
		switch {
		case e.whiteout == opaque:
			t.removeUnder(e.path)
		case e.whiteout != "":
			t.remove(e.whiteout)
			t.removeUnder(e.whiteout)
		}
	}
	for _, e := range es {
		if e.whiteout != "" {
			continue
		}
		if old, ok := t.entries[e.path]; ok && old == tar.TypeDir && e.typ != tar.TypeDir {
			t.removeUnder(e.path)
		}
		t.entries[e.path] = e.typ
		delete(t.links, e.path)
		delete(t.data, e.path)
		if e.typ == tar.TypeSymlink {
			t.links[e.path] = e.link
		}
		if e.data != nil {
			t.data[e.path] = e.data
		}
	}
}

func (t *tree) remove(p string) {
	delete(t.entries, p)
	delete(t.links, p)
	delete(t.data, p)
}

func (t *tree) removeUnder(dir string) {
	prefix := dir + "/"
	if dir == "" {
		prefix = ""
	}
	for p := range t.entries {
		if strings.HasPrefix(p, prefix) && p != dir {
			t.remove(p)
		}
	}
}

func (t *tree) has(p string) bool {
	_, ok := t.entries[p]
	return ok
}

func (t *tree) hasUnder(dir string) bool {
	for p := range t.entries {
		if strings.HasPrefix(p, dir+"/") {
			return true
		}
	}
	return false
}

// symlinkAncestor returns the nearest ancestor of p that is not a
// directory in the tree.
func (t *tree) symlinkAncestor(p string) (string, bool) {
	parts := strings.Split(p, "/")
	for i := 1; i < len(parts); i++ {
		a := strings.Join(parts[:i], "/")
		if typ, ok := t.entries[a]; ok && typ != tar.TypeDir {
			return a, true
		}
	}
	return "", false
}

// with returns a copy of the tree with app entries laid over it.
func (t *tree) with(es []entry) *tree {
	c := &tree{entries: maps.Clone(t.entries), links: maps.Clone(t.links), data: maps.Clone(t.data)}
	c.apply(es)
	return c
}

// resolve follows symlinks (in every component) to the path p names.
func (t *tree) resolve(p string) (string, bool) {
	parts := strings.Split(clean(p), "/")
	cur := ""
	for hops := 0; len(parts) > 0; {
		next := path.Join(cur, parts[0])
		parts = parts[1:]
		typ, ok := t.entries[next]
		if !ok && t.hasUnder(next) {
			typ, ok = tar.TypeDir, true // parent directories may be implied
		}
		if !ok {
			return "", false
		}
		if typ == tar.TypeSymlink {
			if hops++; hops > 40 {
				return "", false
			}
			target := t.links[next]
			if !path.IsAbs(target) {
				target = path.Join(cur, target)
			}
			parts = append(strings.Split(clean(target), "/"), parts...)
			cur = ""
			if parts[0] == "" {
				parts = parts[1:]
			}
			continue
		}
		cur = next
	}
	return cur, true
}

func (t *tree) exists(p string) bool {
	_, ok := t.resolve(p)
	return ok
}

// osRelease returns "<ID> <VERSION_ID>" from os-release, or "".
func (t *tree) osRelease() string {
	for _, p := range []string{"etc/os-release", "usr/lib/os-release"} {
		r, ok := t.resolve(p)
		if !ok {
			continue
		}
		vals := map[string]string{}
		sc := bufio.NewScanner(bytes.NewReader(t.data[r]))
		for sc.Scan() {
			k, v, ok := strings.Cut(sc.Text(), "=")
			if ok {
				vals[k] = strings.Trim(v, `"'`)
			}
		}
		if vals["ID"] != "" {
			return strings.TrimSpace(vals["ID"] + " " + vals["VERSION_ID"])
		}
	}
	return ""
}

// libraries lists the file names in library directories: what the dynamic
// loader finds a DT_NEEDED name like libssl.so.3 by.
func (t *tree) libraries() map[string]bool {
	out := map[string]bool{}
	for p, typ := range t.entries {
		if typ != tar.TypeReg && typ != tar.TypeSymlink {
			continue
		}
		if dir, name := path.Split(p); inLibDir(dir) {
			out[name] = true
		}
	}
	return out
}

func inLibDir(dir string) bool {
	for _, c := range strings.Split(strings.TrimSuffix(dir, "/"), "/") {
		if c == "lib" || c == "lib64" || c == "lib32" {
			return true
		}
	}
	return false
}
