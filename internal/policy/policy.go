// Package policy enforces the org profile's rules on a manifest and its lock.
package policy

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/northcutted/clearcutt-factory/internal/lock"
	"github.com/northcutted/clearcutt-factory/internal/manifest"
	"github.com/northcutted/clearcutt-factory/internal/nix"
)

// Check returns every violation of o.Policy by m and l.
func Check(m *manifest.Manifest, o *manifest.Org, l *lock.Lock) error {
	p := o.Policy
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf("policy: "+format, a...)) }

	if p.RequireNonRoot {
		u, _, _ := strings.Cut(m.Spec.User, ":")
		if u == "" || u == "root" || u == "0" {
			add("spec.user must be a non-root user (requireNonRoot)")
		}
	}
	for _, k := range p.RequiredLabels {
		if m.Spec.Labels[k] == "" {
			add("label %q is required", k)
		}
	}

	images := []lock.Image{l.Base, l.Builder.BuildKit, l.Builder.Frontend, l.Builder.Toolbox}
	if l.App != nil {
		images = append(images, l.App.Build)
	}
	for _, t := range l.Tools {
		if t.Image != nil {
			images = append(images, *t.Image)
		}
		if t.Verification == lock.VerifiedTOFU && !p.AllowTOFU {
			add("tool %s has no checksum source (pin sha256, set checksum/checksums, or allow TOFU in the org profile)", t.Name)
		}
		for plat, a := range t.Artifacts {
			if !hostAllowed(a.URL, p.AllowedHosts) {
				add("tool %s (%s) downloads from a host not in allowedHosts: %s", t.Name, plat, a.URL)
			}
		}
		if t.From == manifest.FromNix && !hostAllowed(nix.DefaultCache, p.AllowedHosts) {
			add("tool %s downloads from %s, which is not in allowedHosts", t.Name, nix.DefaultCache)
		}
	}
	reported := map[string]bool{}
	for _, pkgs := range l.Packages.Platforms {
		for _, pk := range pkgs {
			if pk.URL == "" || hostAllowed(pk.URL, p.AllowedHosts) {
				continue
			}
			if u, err := url.Parse(pk.URL); err == nil && !reported[u.Host] {
				reported[u.Host] = true
				add("packages download from a host not in allowedHosts: %s (e.g. %s)", u.Host, pk.Filename)
			}
		}
	}
	if len(p.AllowedRegistries) > 0 {
		for _, img := range images {
			if !registryAllowed(img.Ref, p.AllowedRegistries) {
				add("image %s is not under allowedRegistries", img.Ref)
			}
		}
	}
	return errors.Join(errs...)
}

// CheckImages applies allowedRegistries to image references (e.g. the base
// a rebase moves an image onto).
func CheckImages(o *manifest.Org, refs ...string) error {
	var errs []error
	for _, r := range refs {
		if len(o.Policy.AllowedRegistries) > 0 && !registryAllowed(r, o.Policy.AllowedRegistries) {
			errs = append(errs, fmt.Errorf("policy: image %s is not under allowedRegistries", r))
		}
	}
	return errors.Join(errs...)
}

func hostAllowed(raw string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	h := u.Hostname()
	for _, a := range allowed {
		if h == a || (strings.HasPrefix(a, ".") && strings.HasSuffix(h, a)) {
			return true
		}
	}
	return false
}

func registryAllowed(ref string, allowed []string) bool {
	full := ref
	if !strings.Contains(strings.Split(ref, "/")[0], ".") && !strings.HasPrefix(ref, "localhost") {
		// Docker Hub short names: golang:1 → docker.io/library/golang:1.
		if !strings.Contains(ref, "/") {
			full = "docker.io/library/" + ref
		} else {
			full = "docker.io/" + ref
		}
	}
	for _, a := range allowed {
		if strings.HasPrefix(full, a) {
			return true
		}
	}
	return false
}
