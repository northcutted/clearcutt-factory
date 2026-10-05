package lock

import (
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
)

// Changes describes, one line each, what moved between two locks: image
// digests, package versions, and tool versions or hashes. It is what a
// reviewer of a lock update needs to read.
func Changes(old, cur *Lock) []string {
	if old == nil {
		old = &Lock{}
	}
	var out []string
	image := func(label string, a, b Image) {
		switch {
		case a.Digest == b.Digest && a.Ref == b.Ref:
		case a.Digest == "":
			out = append(out, fmt.Sprintf("%s %s: pinned at %s", label, b.Ref, short(b.Digest)))
		case a.Ref != b.Ref:
			out = append(out, fmt.Sprintf("%s: %s → %s (%s)", label, a.Ref, b.Ref, short(b.Digest)))
		default:
			out = append(out, fmt.Sprintf("%s %s: %s → %s", label, b.Ref, short(a.Digest), short(b.Digest)))
		}
	}
	image("base", old.Base, cur.Base)
	image("buildkit", old.Builder.BuildKit, cur.Builder.BuildKit)
	image("frontend", old.Builder.Frontend, cur.Builder.Frontend)
	image("toolbox", old.Builder.Toolbox, cur.Builder.Toolbox)
	if cur.App != nil {
		var oa App
		if old.App != nil {
			oa = *old.App
		}
		image("build image", oa.Build, cur.App.Build)
		if oa.StackDigest != "" && oa.StackDigest != cur.App.StackDigest {
			out = append(out, fmt.Sprintf("stack %s changed", cur.App.Stack))
		}
	}
	out = append(out, packageChanges(old.Packages, cur.Packages)...)
	for _, t := range cur.Tools {
		o := old.Tool(t.Name)
		switch {
		case o == nil:
			out = append(out, fmt.Sprintf("tool %s: added %s", t.Name, t.Version))
		case o.Version != t.Version:
			out = append(out, fmt.Sprintf("tool %s: %s → %s", t.Name, o.Version, t.Version))
		case toolPins(*o) != toolPins(t):
			out = append(out, fmt.Sprintf("tool %s: new hashes or digests", strings.TrimSpace(t.Name+" "+t.Version)))
		}
	}
	for _, t := range old.Tools {
		if cur.Tool(t.Name) == nil {
			out = append(out, fmt.Sprintf("tool %s: removed", t.Name))
		}
	}
	return out
}

// packageChanges lists version changes, naming platforms only when they
// differ.
func packageChanges(old, cur Packages) []string {
	byChange := map[string][]string{}
	plats := slices.Sorted(maps.Keys(cur.Platforms))
	for p := range old.Platforms {
		if _, ok := cur.Platforms[p]; !ok {
			plats = append(plats, p)
		}
	}
	for _, p := range plats {
		ov, cv := versions(old.Platforms[p]), versions(cur.Platforms[p])
		for name, v := range cv {
			switch o, ok := ov[name]; {
			case !ok:
				k := fmt.Sprintf("package %s: added %s", name, v)
				byChange[k] = append(byChange[k], p)
			case o != v:
				k := fmt.Sprintf("package %s: %s → %s", name, o, v)
				byChange[k] = append(byChange[k], p)
			}
		}
		for name, o := range ov {
			if _, ok := cv[name]; !ok {
				k := fmt.Sprintf("package %s: removed (%s)", name, o)
				byChange[k] = append(byChange[k], p)
			}
		}
	}
	var out []string
	for k, ps := range byChange {
		if len(ps) == len(plats) {
			out = append(out, k)
		} else {
			sort.Strings(ps)
			out = append(out, k+" on "+strings.Join(ps, ", "))
		}
	}
	sort.Strings(out)
	return out
}

func versions(pkgs []Package) map[string]string {
	m := make(map[string]string, len(pkgs))
	for _, p := range pkgs {
		m[p.Name] = p.Version
	}
	return m
}

// SameContent reports whether two package locks install exactly the same
// files, whatever URLs or snapshot they were resolved through.
func (p Packages) SameContent(o Packages) bool {
	if p.EffectiveManager() != o.EffectiveManager() || p.Distro != o.Distro || len(p.Platforms) != len(o.Platforms) {
		return false
	}
	for plat, pkgs := range p.Platforms {
		other, ok := o.Platforms[plat]
		if !ok || len(other) != len(pkgs) {
			return false
		}
		for i, x := range pkgs {
			y := other[i]
			if x.Name != y.Name || x.Version != y.Version || x.Arch != y.Arch || x.SHA256 != y.SHA256 || x.Checksum != y.Checksum {
				return false
			}
		}
	}
	return true
}

// SamePins reports whether two locks of a tool pin the same version and
// content (hashes, image digests, Nix store paths).
func (t Tool) SamePins(o Tool) bool {
	return t.Version == o.Version && t.Verification == o.Verification && toolPins(t) == toolPins(o)
}

func toolPins(t Tool) string {
	var b strings.Builder
	for _, p := range slices.Sorted(maps.Keys(t.Artifacts)) {
		b.WriteString(p + t.Artifacts[p].SHA256)
	}
	if t.Image != nil {
		b.WriteString(t.Image.Digest)
	}
	for _, p := range slices.Sorted(maps.Keys(t.Nix)) {
		b.WriteString(p + t.Nix[p].Path)
	}
	return b.String()
}

// short abbreviates a digest for messages.
func short(d string) string {
	algo, hex, ok := strings.Cut(d, ":")
	if !ok || len(hex) <= 12 {
		return d
	}
	return algo + ":" + hex[:12]
}
