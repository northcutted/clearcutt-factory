package apk

import (
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
)

// Resolve picks the newest version of every root and of its transitive
// dependencies (and of install_if packages that would be pulled in), so the
// resulting set can be passed to `apk add name=version …` with nothing left for
// apk to choose at build time.
func (idx *Index) Resolve(roots []string) ([]*Package, error) {
	return idx.ResolveKeeping(roots, nil)
}

// ResolveKeeping is Resolve that takes each package in pins (name → version)
// at that version wherever it selects it, as `lock --update-package` does
// with every package it wasn't asked to update. Everything else is the
// newest, and a pinned package nothing needs any more is left out. When a
// pin can't be kept (its version is gone from the repositories, or
// something now needs another version), it returns a *PinError naming it.
func (idx *Index) ResolveKeeping(roots []string, pins map[string]string) ([]*Package, error) {
	s := &solver{idx: idx, pins: pins, sel: map[string]*Package{}, moved: map[string]bool{}}
	// Select roots before any dependency so explicit choices win provider ties.
	for _, r := range roots {
		s.choose(r, "spec.packages")
	}
	for {
		for len(s.queue) > 0 {
			p := s.queue[0]
			s.queue = s.queue[1:]
			for _, d := range p.Depends {
				s.choose(d, p.Name+"-"+p.Version)
			}
		}
		if !s.addInstallIf() {
			break
		}
	}
	if len(s.moved) > 0 {
		slices.Sort(s.conflicts)
		return nil, &PinError{Arch: idx.Arch, Names: slices.Sorted(maps.Keys(s.moved)), Problems: slices.Compact(s.conflicts)}
	}
	if len(s.errs) > 0 {
		slices.Sort(s.errs)
		return nil, fmt.Errorf("resolving packages for %s:\n  %s", idx.Arch, strings.Join(slices.Compact(s.errs), "\n  "))
	}

	out := make([]*Package, 0, len(s.sel))
	for _, p := range s.sel {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// PinError names the pinned packages a resolution couldn't keep at their
// versions, and why.
type PinError struct {
	Arch     string
	Names    []string
	Problems []string
}

func (e *PinError) Error() string {
	return fmt.Sprintf("resolving packages for %s keeps %s where they can't stay:\n  %s", e.Arch, strings.Join(e.Names, ", "), strings.Join(e.Problems, "\n  "))
}

type solver struct {
	idx   *Index
	pins  map[string]string
	sel   map[string]*Package // by package name
	queue []*Package
	errs  []string
	// Pins that can't be kept, and why.
	moved     map[string]bool
	conflicts []string
}

func (s *solver) add(p *Package) {
	s.sel[p.Name] = p
	s.queue = append(s.queue, p)
}

func (s *solver) cantKeep(name, problem string) {
	s.moved[name] = true
	s.conflicts = append(s.conflicts, problem)
}

// pinned returns the pinned version of name, if it is pinned and that
// version is in the index (p is nil when it is pinned but gone).
func (s *solver) pinned(name string) (p *Package, v string, ok bool) {
	if v, ok = s.pins[name]; !ok {
		return nil, "", false
	}
	for _, c := range s.idx.byName[name] {
		if c.Version == v {
			return c, v, true
		}
	}
	return nil, v, true
}

func (s *solver) choose(dep, why string) {
	name, op, ver := splitDep(dep)
	if strings.HasPrefix(name, "!") {
		return
	}
	if p := s.sel[name]; p != nil {
		if !Satisfies(p.Version, op, ver) {
			s.errs = append(s.errs, fmt.Sprintf("%s needs %s but %s-%s is selected", why, dep, p.Name, p.Version))
		}
		return
	}
	if p, v, ok := s.pinned(name); ok && s.idx.Has(name) {
		switch {
		case p == nil:
			s.cantKeep(name, fmt.Sprintf("%s needs %s, but %s %s is no longer in the repositories", why, dep, name, v))
		case !Satisfies(p.Version, op, ver):
			s.cantKeep(name, fmt.Sprintf("%s needs %s, but %s is pinned at %s", why, dep, name, v))
		default:
			s.add(p)
		}
		return
	}
	if p := s.idx.best(s.idx.byName[name], op, ver); p != nil {
		s.add(p)
		return
	}
	cands := s.idx.provides[name]
	for _, c := range cands {
		if sp := s.sel[c.Name]; sp != nil && providesSatisfying(sp, name, op, ver) {
			return
		}
	}
	// A pinned provider is only a candidate at its pinned version. If one
	// would do at another version, the pin moves rather than another
	// package taking its place.
	var ok, held []*Package
	for _, c := range cands {
		if !providesSatisfying(c, name, op, ver) || s.sel[c.Name] != nil {
			continue
		}
		if v, pinned := s.pins[c.Name]; pinned && c.Version != v {
			held = append(held, c)
			continue
		}
		ok = append(ok, c)
	}
	keepsPin := slices.ContainsFunc(ok, func(c *Package) bool { _, p := s.pins[c.Name]; return p })
	if len(held) > 0 && !keepsPin {
		for _, c := range held {
			if !s.moved[c.Name] {
				s.cantKeep(c.Name, fmt.Sprintf("%s needs %s, which %s doesn't provide at its pinned %s", why, dep, c.Name, s.pins[c.Name]))
			}
		}
		return
	}
	if len(ok) == 0 {
		s.errs = append(s.errs, fmt.Sprintf("nothing provides %s (needed by %s)", dep, why))
		return
	}
	sort.SliceStable(ok, func(i, j int) bool {
		_, pi := s.pins[ok[i].Name]
		_, pj := s.pins[ok[j].Name]
		if pi != pj {
			return pi // keep the provider the lock already has
		}
		if ok[i].ProviderPrio != ok[j].ProviderPrio {
			return ok[i].ProviderPrio > ok[j].ProviderPrio
		}
		if ok[i].Name != ok[j].Name {
			return ok[i].Name < ok[j].Name
		}
		return CompareVersions(ok[i].Version, ok[j].Version) > 0
	})
	p := ok[0]
	if _, pinned := s.pins[p.Name]; !pinned {
		if best := s.idx.best(s.idx.byName[p.Name], "", ""); providesSatisfying(best, name, op, ver) {
			p = best
		}
	}
	s.add(p)
}

// addInstallIf selects packages apk would auto-install because every condition
// in their install_if is met. Returns whether anything was added.
func (s *solver) addInstallIf() bool {
	added := false
	names := make([]string, 0, len(s.idx.byName))
	for n := range s.idx.byName {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if s.sel[n] != nil || s.moved[n] {
			continue
		}
		p := s.idx.best(s.idx.byName[n], "", "")
		pin, v, isPinned := s.pinned(n)
		if isPinned && pin != nil {
			p = pin
		}
		if len(p.InstallIf) == 0 || !s.met(p.InstallIf) {
			continue
		}
		if isPinned && pin == nil {
			s.cantKeep(n, fmt.Sprintf("%s would be installed (install_if), but %s %s is no longer in the repositories", n, n, v))
			continue
		}
		s.add(p)
		added = true
	}
	return added
}

func (s *solver) met(conds []string) bool {
	for _, cond := range conds {
		name, op, ver := splitDep(cond)
		if sp := s.sel[name]; sp == nil || !Satisfies(sp.Version, op, ver) {
			return false
		}
	}
	return true
}

// best returns the newest candidate satisfying op/ver.
func (idx *Index) best(cands []*Package, op, ver string) *Package {
	var best *Package
	for _, c := range cands {
		if !Satisfies(c.Version, op, ver) {
			continue
		}
		if best == nil || CompareVersions(c.Version, best.Version) > 0 {
			best = c
		}
	}
	return best
}

func providesSatisfying(p *Package, name, op, ver string) bool {
	for _, prov := range p.Provides {
		n, _, v := splitDep(prov)
		if n != name {
			continue
		}
		if op == "" {
			return true
		}
		if v == "" {
			v = p.Version
		}
		if Satisfies(v, op, ver) {
			return true
		}
	}
	return false
}
