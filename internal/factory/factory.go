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
	"github.com/northcutted/clearcutt-factory/internal/ignore"
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
	// Reverify checks a shared profile's signature with cosign on every
	// load, instead of reusing a check this machine made in the last
	// profileVerifiedFor (see reverify).
	Reverify bool
	Stdout   io.Writer
	Stderr   io.Writer
}

func (o Options) printf(format string, a ...any) { _, _ = fmt.Fprintf(o.Stdout, format+"\n", a...) }
func (o Options) logf(format string, a ...any)   { _, _ = fmt.Fprintf(o.Stderr, format+"\n", a...) }

// load reads the manifest and its org profile, fetching a registry stack
// and a shared profile the org profile extends at the digests its lock
// pins (or, with fresh or no pin, where their references point now), and
// checking their signatures: the shared profile's always, the stack's under
// policy.requireSignedStacks. Every command that reads a manifest loads it
// here, so a lock edited to pin an unsigned stack or profile fails
// wherever it is used.
func load(ctx context.Context, opts Options, fresh bool) (*manifest.Manifest, *manifest.Org, error) {
	return loadWith(ctx, opts, fresh, fresh)
}

// loadWith is load, moving the stack and the shared profile separately.
func loadWith(ctx context.Context, opts Options, freshStack, freshProfile bool) (*manifest.Manifest, *manifest.Org, error) {
	m, err := manifest.Load(opts.ManifestPath)
	if err != nil {
		return nil, nil, err
	}
	pin := lockedProfile(m)
	if freshProfile {
		pin = nil
	}
	org, err := loadOrg(ctx, opts, m.Dir(), pin)
	if err != nil {
		return nil, nil, err
	}
	if err := fetchAppStack(ctx, m, freshStack); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", opts.ManifestPath, err)
	}
	if err := verifyStack(ctx, m, org); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", opts.ManifestPath, err)
	}
	if err := m.ApplyOrg(org); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", opts.ManifestPath, err)
	}
	return m, org, nil
}

// loadLocked loads the manifest and a lock that is current for it: written
// by this release or an older one, intact (its content digest matches),
// and resolved from this manifest and org profile.
func loadLocked(ctx context.Context, opts Options) (*manifest.Manifest, *manifest.Org, *lock.Lock, error) {
	m, org, err := load(ctx, opts, false)
	if err != nil {
		return nil, nil, nil, err
	}
	l, err := lock.ReadFor(m.LockPath(), opts.Version)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, nil, fmt.Errorf("%s does not exist; run clearcutt-factory lock", filepath.Base(m.LockPath()))
	}
	if err != nil {
		return nil, nil, nil, err
	}
	if l.InputsDigest != lock.InputsOf(m, org).Digest() {
		return nil, nil, nil, fmt.Errorf("%s is stale (the manifest or org builder settings changed); run clearcutt-factory lock", filepath.Base(m.LockPath()))
	}
	switch sp := org.Shared; {
	case sp != nil && (l.Profile == nil || l.Profile.Ref != sp.Ref || l.Profile.Path != sp.Path):
		return nil, nil, nil, fmt.Errorf("%s is stale (it doesn't pin the shared profile %s the org profile extends); run clearcutt-factory lock", filepath.Base(m.LockPath()), sp.Name())
	case sp == nil && l.Profile != nil:
		return nil, nil, nil, fmt.Errorf("%s is stale (it pins the shared profile %s, which the org profile no longer extends); run clearcutt-factory lock", filepath.Base(m.LockPath()), l.Profile.Name())
	case sp != nil && l.Profile.Digest != sp.Digest:
		// The repository's own shared profile (extends.path) changed since
		// the lock pinned it. (A published one loads at the digest pinned.)
		return nil, nil, nil, fmt.Errorf("%s is stale (the shared profile %s changed since it was pinned at %s); run clearcutt-factory lock", filepath.Base(m.LockPath()), sp.Name(), l.Profile.Digest)
	}
	return m, org, l, nil
}

// lockPins reads the lock at path for the pins commands follow before the
// lock is checked in full (a registry stack's digest, the shared
// profile's): an intact lock, or one written before content digests. An
// edited lock pins nothing.
func lockPins(path string) *lock.Lock {
	l, err := lock.Read(path)
	if _, missing := lock.IsEdited(err); err == nil || missing {
		return l
	}
	return nil
}

type LockOptions struct {
	// Update re-resolves every input instead of keeping unchanged pins.
	Update bool
	// UpdateBase re-resolves only the base (an app's run image) and what
	// depends on it, e.g. after the published image was rebased.
	UpdateBase bool
	// UpdateStack is UpdateBase that also re-resolves an app's stack (a
	// registry stack to where its reference points now) and its build
	// image, keeping every other pin: a rebuild on the stack's newest
	// images, as the platform team rebuilt them (a toolchain fix, say).
	// Lock loads the manifest with the stack fresh for it; lockManifest
	// expects its caller to have.
	UpdateStack bool
	// BaseDigest pins the base to this digest instead of resolving its tag.
	BaseDigest string
	// UpdatePackages re-resolves only these distro packages (and what
	// their new versions need), keeping every other pin, e.g. to take a
	// CVE fix or release a hold without unrelated updates.
	UpdatePackages []string
}

// Lock resolves the manifest and writes the lockfile and Containerfile,
// printing what changed.
func Lock(ctx context.Context, opts Options, lo LockOptions) error {
	if lo.UpdateStack && (lo.Update || lo.UpdateBase) {
		return errors.New("--update-stack moves the stack and its images; it doesn't go with --update or --update-base")
	}
	// --update-stack moves a registry stack to its newest version, and
	// keeps the shared profile's pin.
	m, org, err := loadWith(ctx, opts, lo.Update || lo.UpdateStack, lo.Update)
	if err != nil {
		return err
	}
	if lo.UpdateStack && m.Kind != manifest.KindApp {
		return fmt.Errorf("%s is a %s: --update-stack moves an app's stack and its images; --update-base moves an image's base", rel(m.Path), m.Kind)
	}
	return lockManifest(ctx, opts, m, org, lo)
}

func lockManifest(ctx context.Context, opts Options, m *manifest.Manifest, org *manifest.Org, lo LockOptions) error {
	prev, err := lock.ReadFor(m.LockPath(), opts.Version)
	edited, missing := lock.IsEdited(err)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		prev, err = nil, nil
	case edited && missing:
		// Written before content digests: its pins are reused and the
		// digest written.
	case edited && !lo.Update:
		return fmt.Errorf("%w (nothing in it is reused; --update resolves every input again)", err)
	case edited:
		// Nothing is reused from an edited lock; it only shows in what
		// changed.
	case err != nil:
		return err
	}
	if len(lo.UpdatePackages) > 0 {
		switch {
		case lo.Update || lo.UpdateBase || lo.UpdateStack:
			return errors.New("--update-package moves only the packages it names; it doesn't go with --update or --update-base")
		case prev == nil:
			return fmt.Errorf("--update-package: %s does not exist; run clearcutt-factory lock", rel(m.LockPath()))
		}
	}
	reuse, orig := prev, prev
	if edited && !missing {
		reuse, orig = nil, nil
	}
	base := reuse
	if (lo.UpdateBase || lo.UpdateStack) && reuse != nil {
		p := *reuse
		p.Base = lock.Image{Ref: m.Spec.Base, Digest: lo.BaseDigest}
		if p.App != nil {
			a := *p.App
			a.RunPlatforms = nil
			if lo.UpdateStack {
				a.Build = lock.Image{}
			}
			p.App = &a
		}
		base = &p
	}
	r := resolve.New()
	r.Log = opts.Stderr
	r.Run = container.Runner{Runtime: org.Builder.Runtime}.Run
	r.UpdatePackages = lo.UpdatePackages
	l, err := r.LockFrom(ctx, m, org, base, orig, lo.Update)
	if err != nil {
		return err
	}
	if err := policy.Check(m, org, l); err != nil {
		return err
	}
	// Rendered before anything is written: a lock the Containerfile can't
	// be rendered from is never on disk.
	out, err := render.Render(m, l)
	if err != nil {
		return err
	}
	if prev != nil && !edited && bytes.Equal(prev.Content(), l.Content()) {
		opts.printf("%s is up to date", rel(m.LockPath()))
	} else {
		for _, c := range lock.Changes(prev, l) {
			opts.printf("  %s", c)
		}
		l.Generator = lock.Generator(opts.Version)
		if err := l.Write(m.LockPath()); err != nil {
			return err
		}
		opts.printf("wrote %s", rel(m.LockPath()))
	}
	return writeContainerfile(opts, m, out)
}

// writeContainerfile writes the rendered Containerfile when it changed,
// atomically.
func writeContainerfile(opts Options, m *manifest.Manifest, out *render.Output) error {
	if old, err := os.ReadFile(m.ContainerfilePath()); err == nil && bytes.Equal(old, out.Containerfile) {
		return nil
	}
	if err := lock.WriteFileAtomic(m.ContainerfilePath(), out.Containerfile, 0o644); err != nil {
		return err
	}
	opts.printf("wrote %s", rel(m.ContainerfilePath()))
	return nil
}

// Render writes the Containerfile, checks it is current, or stages a full
// build context that plain buildctl can build.
func Render(ctx context.Context, opts Options, check bool, contextDir string) error {
	m, _, l, err := loadLocked(ctx, opts)
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
	} else if err := writeContainerfile(opts, m, out); err != nil {
		return err
	}
	if contextDir != "" {
		if err := stage(out, contextDir, opts.logf); err != nil {
			return err
		}
		opts.printf("staged build context in %s", contextDir)
	}
	return nil
}

// stage writes a self-contained build context: the Containerfile plus the
// declared local files at the paths the Containerfile expects.
func stage(out *render.Output, dir string, note func(format string, a ...any)) error {
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
		skipped, err := copyTree(f.Src, dst, f.Exclude, abs)
		if err != nil {
			return err
		}
		if len(skipped) > 0 && note != nil {
			more := ""
			if len(skipped) > 5 {
				skipped, more = skipped[:5], fmt.Sprintf(", and %d more", len(skipped)-5)
			}
			note("note: left out of the build what git doesn't track in %s: %s%s (commit it to build with it)", rel(f.Src), strings.Join(skipped, ", "), more)
		}
	}
	return nil
}

// copyTree copies src to dst, leaving out excluded paths and skip (the
// context being staged, should it sit inside src). A directory's files are
// filtered as ignore reads them: in a git work tree only what git tracks,
// elsewhere what .gitignore files don't ignore, and in both what
// .dockerignore doesn't exclude. It returns the untracked paths it left out.
func copyTree(src, dst string, exclude []string, skip string) ([]string, error) {
	var filter *ignore.Filter
	if st, err := os.Stat(src); err == nil && st.IsDir() {
		if filter, err = ignore.New(src); err != nil {
			return nil, err
		}
	}
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		r, _ := filepath.Rel(src, p)
		leave := p == skip || (r != "." && excluded(filepath.ToSlash(r), exclude))
		if !leave && r != "." && filter != nil {
			ok, err := filter.Include(filepath.ToSlash(r), d.IsDir())
			if err != nil {
				return err
			}
			leave = !ok
		}
		if leave {
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
	if err != nil || filter == nil {
		return nil, err
	}
	return filter.Skipped, nil
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
