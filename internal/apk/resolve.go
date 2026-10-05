package apk

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// Resolve picks the newest version of every root and of its transitive
// dependencies (and of install_if packages that would be pulled in), so the
// resulting set can be passed to `apk add name=version …` with nothing left for
// apk to choose at build time.
func (idx *Index) Resolve(roots []string) ([]*Package, error) {
	sel := map[string]*Package{} // by package name
	var queue []*Package
	var errs []string

	choose := func(dep, why string) {
		name, op, ver := splitDep(dep)
		if strings.HasPrefix(name, "!") {
			return
		}
		if p := sel[name]; p != nil {
			if !Satisfies(p.Version, op, ver) {
				errs = append(errs, fmt.Sprintf("%s needs %s but %s-%s is selected", why, dep, p.Name, p.Version))
			}
			return
		}
		if p := idx.best(idx.byName[name], op, ver); p != nil {
			sel[name] = p
			queue = append(queue, p)
			return
		}
		cands := idx.provides[name]
		for _, c := range cands {
			if s := sel[c.Name]; s != nil && providesSatisfying(s, name, op, ver) {
				return
			}
		}
		var ok []*Package
		for _, c := range cands {
			if providesSatisfying(c, name, op, ver) && sel[c.Name] == nil {
				ok = append(ok, c)
			}
		}
		if len(ok) == 0 {
			errs = append(errs, fmt.Sprintf("nothing provides %s (needed by %s)", dep, why))
			return
		}
		sort.SliceStable(ok, func(i, j int) bool {
			if ok[i].ProviderPrio != ok[j].ProviderPrio {
				return ok[i].ProviderPrio > ok[j].ProviderPrio
			}
			if ok[i].Name != ok[j].Name {
				return ok[i].Name < ok[j].Name
			}
			return CompareVersions(ok[i].Version, ok[j].Version) > 0
		})
		p := idx.best(idx.byName[ok[0].Name], "", "")
		if !providesSatisfying(p, name, op, ver) {
			p = ok[0]
		}
		sel[p.Name] = p
		queue = append(queue, p)
	}

	// Select roots before any dependency so explicit choices win provider ties.
	for _, r := range roots {
		choose(r, "spec.packages")
	}
	for {
		for len(queue) > 0 {
			p := queue[0]
			queue = queue[1:]
			for _, d := range p.Depends {
				choose(d, p.Name)
			}
		}
		if !idx.addInstallIf(sel, &queue) {
			break
		}
	}
	if len(errs) > 0 {
		slices.Sort(errs)
		return nil, fmt.Errorf("resolving packages for %s:\n  %s", idx.Arch, strings.Join(slices.Compact(errs), "\n  "))
	}

	out := make([]*Package, 0, len(sel))
	for _, p := range sel {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// addInstallIf selects packages apk would auto-install because every condition
// in their install_if is met. Returns whether anything was added.
func (idx *Index) addInstallIf(sel map[string]*Package, queue *[]*Package) bool {
	added := false
	names := make([]string, 0, len(idx.byName))
	for n := range idx.byName {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if sel[n] != nil {
			continue
		}
		p := idx.best(idx.byName[n], "", "")
		if len(p.InstallIf) == 0 {
			continue
		}
		met := true
		for _, cond := range p.InstallIf {
			name, op, ver := splitDep(cond)
			if s := sel[name]; s == nil || !Satisfies(s.Version, op, ver) {
				met = false
				break
			}
		}
		if met {
			sel[n] = p
			*queue = append(*queue, p)
			added = true
		}
	}
	return added
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
