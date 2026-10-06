// Package factory implements the CLI commands: lock, render, build, verify.
package factory

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/northcutted/clearcutt-factory/internal/container"
	"github.com/northcutted/clearcutt-factory/internal/lock"
	"github.com/northcutted/clearcutt-factory/internal/manifest"
	"github.com/northcutted/clearcutt-factory/internal/policy"
	"github.com/northcutted/clearcutt-factory/internal/registry"
	"github.com/northcutted/clearcutt-factory/internal/render"
	"github.com/northcutted/clearcutt-factory/internal/resolve"
)

// Options are shared by every command.
type Options struct {
	ManifestPath string
	OrgPath      string
	Version      string
	Verbose      bool
	Stdout       io.Writer
	Stderr       io.Writer
}

func (o Options) printf(format string, a ...any) { _, _ = fmt.Fprintf(o.Stdout, format+"\n", a...) }
func (o Options) logf(format string, a ...any)   { _, _ = fmt.Fprintf(o.Stderr, format+"\n", a...) }

func load(opts Options) (*manifest.Manifest, *manifest.Org, error) {
	m, err := manifest.Load(opts.ManifestPath)
	if err != nil {
		return nil, nil, err
	}
	org, err := manifest.LoadOrg(opts.OrgPath, m.Dir())
	if err != nil {
		return nil, nil, err
	}
	if err := m.ApplyOrg(org); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", opts.ManifestPath, err)
	}
	return m, org, nil
}

// loadLocked loads the manifest and a lock that is current for it.
func loadLocked(opts Options) (*manifest.Manifest, *manifest.Org, *lock.Lock, error) {
	m, org, err := load(opts)
	if err != nil {
		return nil, nil, nil, err
	}
	l, err := lock.Read(m.LockPath())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, nil, fmt.Errorf("%s does not exist; run clearcutt-factory lock", filepath.Base(m.LockPath()))
	}
	if err != nil {
		return nil, nil, nil, err
	}
	if l.InputsDigest != lock.InputsOf(m, org).Digest() {
		return nil, nil, nil, fmt.Errorf("%s is stale (the manifest or org builder settings changed); run clearcutt-factory lock", filepath.Base(m.LockPath()))
	}
	return m, org, l, nil
}

type LockOptions struct {
	// Update re-resolves every input instead of keeping unchanged pins.
	Update bool
	// UpdateBase re-resolves only the base (an app's run image) and what
	// depends on it, e.g. after the published image was rebased.
	UpdateBase bool
	// BaseDigest pins the base to this digest instead of resolving its tag.
	BaseDigest string
}

// Lock resolves the manifest and writes the lockfile and Containerfile,
// printing what changed.
func Lock(ctx context.Context, opts Options, lo LockOptions) error {
	m, org, err := load(opts)
	if err != nil {
		return err
	}
	_, err = lockManifest(ctx, opts, m, org, lo)
	return err
}

func lockManifest(ctx context.Context, opts Options, m *manifest.Manifest, org *manifest.Org, lo LockOptions) (changed bool, err error) {
	prev, err := lock.Read(m.LockPath())
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	base := prev
	if lo.UpdateBase && prev != nil {
		p := *prev
		p.Base = lock.Image{Ref: m.Spec.Base, Digest: lo.BaseDigest}
		if p.App != nil {
			a := *p.App
			a.RunPlatforms = nil
			p.App = &a
		}
		base = &p
	}
	r := resolve.New()
	r.Log = opts.Stderr
	r.Run = container.Runner{Runtime: org.Builder.Runtime}.Run
	l, err := r.LockFrom(ctx, m, org, base, prev, lo.Update)
	if err != nil {
		return false, err
	}
	if err := policy.Check(m, org, l); err != nil {
		return false, err
	}
	if prev != nil && bytes.Equal(prev.Marshal(), l.Marshal()) {
		opts.printf("%s is up to date", rel(m.LockPath()))
	} else {
		for _, c := range lock.Changes(prev, l) {
			opts.printf("  %s", c)
		}
		if err := l.Write(m.LockPath()); err != nil {
			return false, err
		}
		opts.printf("wrote %s", rel(m.LockPath()))
		changed = true
	}
	return changed, writeContainerfile(opts, m, l)
}

func writeContainerfile(opts Options, m *manifest.Manifest, l *lock.Lock) error {
	out, err := render.Render(m, l)
	if err != nil {
		return err
	}
	if old, err := os.ReadFile(m.ContainerfilePath()); err == nil && bytes.Equal(old, out.Containerfile) {
		return nil
	}
	if err := os.WriteFile(m.ContainerfilePath(), out.Containerfile, 0o644); err != nil {
		return err
	}
	opts.printf("wrote %s", rel(m.ContainerfilePath()))
	return nil
}

// Render writes the Containerfile, checks it is current, or stages a full
// build context that plain buildctl can build.
func Render(ctx context.Context, opts Options, check bool, contextDir string) error {
	m, _, l, err := loadLocked(opts)
	if err != nil {
		return err
	}
	out, err := render.Render(m, l)
	if err != nil {
		return err
	}
	if check {
		old, err := os.ReadFile(m.ContainerfilePath())
		if err != nil || !bytes.Equal(old, out.Containerfile) {
			return fmt.Errorf("%s is out of date; run clearcutt-factory render", rel(m.ContainerfilePath()))
		}
		opts.printf("%s is up to date", rel(m.ContainerfilePath()))
	} else if err := writeContainerfile(opts, m, l); err != nil {
		return err
	}
	if contextDir != "" {
		if err := stage(out, contextDir); err != nil {
			return err
		}
		opts.printf("staged build context in %s", contextDir)
	}
	return nil
}

// stage writes a self-contained build context: the Containerfile plus the
// declared local files at the paths the Containerfile expects.
func stage(out *render.Output, dir string) error {
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, render.ContainerfileName), out.Containerfile, 0o644); err != nil {
		return err
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	for _, f := range out.Context {
		dst := filepath.Join(abs, filepath.FromSlash(f.Rel))
		if err := copyTree(f.Src, dst, f.Exclude, abs); err != nil {
			return err
		}
	}
	return nil
}

// copyTree copies src to dst, leaving out excluded paths and skip (the
// context being staged, should it sit inside src).
func copyTree(src, dst string, exclude []string, skip string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		r, _ := filepath.Rel(src, p)
		if p == skip || (r != "." && excluded(filepath.ToSlash(r), exclude)) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		target := filepath.Join(dst, r)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if d.Type()&fs.ModeSymlink != 0 {
			link, err := os.Readlink(p)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			return os.Symlink(link, target)
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%s: only regular files, directories, and symlinks can be copied into the build", p)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		return os.WriteFile(target, b, info.Mode().Perm())
	})
}

// excluded reports whether rel (slash-separated, relative to the source)
// matches a pattern. As in .gitignore, a pattern with a slash at the start
// or in the middle is relative to the source root, any other matches a name
// at any depth, and a match covers everything below it.
func excluded(rel string, patterns []string) bool {
	parts := strings.Split(rel, "/")
	for _, pat := range patterns {
		pat = strings.TrimSuffix(pat, "/")
		if anchored := strings.TrimPrefix(pat, "/"); anchored != pat || strings.Contains(pat, "/") {
			n := strings.Count(anchored, "/") + 1
			if n <= len(parts) {
				if ok, _ := path.Match(anchored, strings.Join(parts[:n], "/")); ok {
					return true
				}
			}
			continue
		}
		for _, part := range parts {
			if ok, _ := path.Match(pat, part); ok {
				return true
			}
		}
	}
	return false
}

// registriesOf lists the registries a build pulls from, for credentials.
func registriesOf(l *lock.Lock) []string {
	refs := []string{l.Base.Ref, l.Builder.Frontend.Ref, l.Builder.Toolbox.Ref}
	if l.App != nil {
		refs = append(refs, l.App.Build.Ref)
	}
	for _, t := range l.Tools {
		if t.Image != nil {
			refs = append(refs, t.Image.Ref)
		}
	}
	var regs []string
	for _, r := range refs {
		if reg, err := registry.Registry(r); err == nil && !slices.Contains(regs, reg) {
			regs = append(regs, reg)
		}
	}
	return regs
}

// rel shortens a path relative to the working directory for messages.
func rel(p string) string {
	wd, err := os.Getwd()
	if err != nil {
		return p
	}
	if r, err := filepath.Rel(wd, p); err == nil && !strings.HasPrefix(r, "..") {
		return r
	}
	return p
}
