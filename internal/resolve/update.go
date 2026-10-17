package resolve

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/northcutted/clearcutt-factory/internal/lock"
	"github.com/northcutted/clearcutt-factory/internal/manifest"
)

// keeping is what `lock --update-package` keeps: every locked package but
// the named ones, per platform, at its locked version. The solver may add
// packages the updated ones now need, and drop kept ones nothing needs any
// more, but not move a kept one.
type keeping struct {
	update    []string
	platforms []string
	native    bool
	pins      map[string]map[string]lock.Package // platform → name → locked package
	// Pins that can't be kept: their names, and why (→ the platforms).
	blocked  map[string]bool
	problems map[string][]string
}

// keepingFor checks the names r.UpdatePackages lists against the manifest
// and the lock, and returns what to keep.
func (r *Resolver) keepingFor(m *manifest.Manifest, mgr string, prev lock.Packages) (*keeping, error) {
	var names []string
	for _, n := range r.UpdatePackages {
		if n = strings.TrimSpace(n); n != "" && !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("--update-package: name the packages to update")
	}
	if len(prev.Platforms) > 0 && prev.EffectiveManager() != mgr {
		return nil, fmt.Errorf("--update-package: the lock's packages are %s packages, but the base now uses %s; run clearcutt-factory lock --update", prev.EffectiveManager(), mgr)
	}
	locked := map[string]bool{}
	for _, pkgs := range prev.Platforms {
		for _, p := range pkgs {
			locked[p.Name] = true
		}
	}
	var unknown []string
	for _, n := range names {
		if !locked[n] && !slices.ContainsFunc(m.Spec.Packages, func(e string) bool { return mentions(e, n, mgr) }) {
			unknown = append(unknown, n)
		}
	}
	if len(unknown) > 0 {
		return nil, fmt.Errorf("--update-package: %s is neither in spec.packages nor in the lock", strings.Join(unknown, ", "))
	}
	k := &keeping{
		update: names, platforms: m.Spec.Platforms, native: mgr != lock.ManagerAPK,
		pins: map[string]map[string]lock.Package{}, blocked: map[string]bool{}, problems: map[string][]string{},
	}
	for plat, pkgs := range prev.Platforms {
		k.pins[plat] = map[string]lock.Package{}
		for _, p := range pkgs {
			if !slices.Contains(names, p.Name) {
				k.pins[plat][p.Name] = p
			}
		}
	}
	return k, nil
}

// mentions reports whether a spec.packages entry asks for the package
// name: the name alone, or with a version (apk name=1.2-r0 or name>=1.2,
// apt name=1.2-1 or name/suite, dnf name-1.2-1.fc44 or name.aarch64).
func mentions(entry, name, mgr string) bool {
	rest, ok := strings.CutPrefix(entry, name)
	switch {
	case !ok:
		return false
	case rest == "":
		return true
	case mgr == lock.ManagerAPK:
		return strings.ContainsAny(rest[:1], "<>=~")
	case mgr == lock.ManagerAPT:
		return strings.ContainsAny(rest[:1], "=/:")
	}
	if v, ok := strings.CutPrefix(rest, "-"); ok {
		return v != "" && v[0] >= '0' && v[0] <= '9'
	}
	return slices.Contains([]string{".x86_64", ".aarch64", ".noarch", ".i686", ".ppc64le", ".s390x"}, rest)
}

// list returns the packages kept on platform, by name.
func (k *keeping) list(platform string) []lock.Package {
	if k == nil {
		return nil
	}
	pins := k.pins[platform]
	out := make([]lock.Package, 0, len(pins))
	for _, n := range slices.Sorted(maps.Keys(pins)) {
		out = append(out, pins[n])
	}
	return out
}

// versions returns the versions kept on platform (nil when not updating).
func (k *keeping) versions(platform string) map[string]string {
	if k == nil {
		return nil
	}
	out := map[string]string{}
	for n, p := range k.pins[platform] {
		out[n] = p.Version
	}
	return out
}

// block records pins that can't be kept on platform.
func (k *keeping) block(platform string, names, problems []string) {
	for _, n := range names {
		k.blocked[n] = true
	}
	for _, p := range problems {
		if !slices.Contains(k.problems[p], platform) {
			k.problems[p] = append(k.problems[p], platform)
		}
	}
}

// check fails if a resolution moved a kept package, or if one couldn't
// be kept, naming them.
func (k *keeping) check(out lock.Packages) error {
	for _, plat := range slices.Sorted(maps.Keys(out.Platforms)) {
		for _, p := range out.Platforms[plat] {
			if old, ok := k.pins[plat][p.Name]; ok && old.Version != p.Version && !k.blocked[p.Name] {
				k.block(plat, []string{p.Name}, []string{fmt.Sprintf("%s would move from %s to %s", p.Name, old.Version, p.Version)})
			}
		}
	}
	if len(k.blocked) == 0 {
		return nil
	}
	var lines []string
	for p, plats := range k.problems {
		if len(plats) < len(k.platforms) {
			slices.Sort(plats)
			p += " (on " + strings.Join(plats, ", ") + ")"
		}
		lines = append(lines, p)
	}
	slices.Sort(lines)
	if k.native {
		lines = append(lines, "(a locked version may be gone from the repositories, or the updated packages need another)")
	}
	moved := slices.Sorted(maps.Keys(k.blocked))
	return fmt.Errorf("--update-package %s can't keep every other package where it is:\n  %s\n%s would have to move too; to update them as well: --update-package %s",
		strings.Join(k.update, ","), strings.Join(lines, "\n  "), strings.Join(moved, ", "), strings.Join(append(slices.Clone(k.update), moved...), ","))
}

// restore puts each kept package's locked entry back as it was, so the
// lock's diff shows only what moved.
func (k *keeping) restore(out *lock.Packages) {
	for plat, pkgs := range out.Platforms {
		for i, p := range pkgs {
			if old, ok := k.pins[plat][p.Name]; ok && old.Version == p.Version {
				pkgs[i] = old
			}
		}
	}
}
