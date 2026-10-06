package resolve

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/northcutted/clearcutt-factory/internal/lock"
	"github.com/northcutted/clearcutt-factory/internal/manifest"
	"github.com/northcutted/clearcutt-factory/internal/nix"
)

var commitRE = regexp.MustCompile(`^[0-9a-f]{40}$`)

// lockNixTools pins nix tools: nixpkgs to a commit, each attribute to a store
// path per platform, and each store path to its signed closure.
func (r *Resolver) lockNixTools(ctx context.Context, tools []manifest.Tool, platforms []string) (map[string]*lock.Tool, error) {
	var systems []string
	sysOf := map[string]string{}
	for _, p := range platforms {
		_, arch, _ := manifest.SplitPlatform(p)
		sys, ok := nix.Systems[arch]
		if !ok {
			return nil, fmt.Errorf("nix tools: unsupported architecture %s", arch)
		}
		sysOf[p] = sys
		systems = append(systems, sys)
	}

	type group struct {
		ref   string
		image lock.Image
		tools []manifest.Tool
	}
	var groups []*group
	byKey := map[string]*group{}
	for _, t := range tools {
		ref, err := r.nixpkgsRef(ctx, t.Nixpkgs)
		if err != nil {
			return nil, fmt.Errorf("tool %s: %w", t.Name, err)
		}
		img, err := r.pinImage(ctx, t.Image, lock.Image{})
		if err != nil {
			return nil, fmt.Errorf("tool %s: %w", t.Name, err)
		}
		key := ref + "|" + img.Pinned()
		g := byKey[key]
		if g == nil {
			g = &group{ref: ref, image: img}
			byKey[key] = g
			groups = append(groups, g)
		}
		g.tools = append(g.tools, t)
	}

	out := map[string]*lock.Tool{}
	for _, g := range groups {
		var attrs []string
		for _, t := range g.tools {
			attrs = append(attrs, t.Package)
		}
		r.logf("evaluating %s in %s for %s", strings.Join(attrs, ", "), g.ref, strings.Join(systems, ", "))
		paths, err := nix.Eval(ctx, r.Run, g.image.Pinned(), g.ref, systems, attrs)
		if err != nil {
			return nil, err
		}
		for _, t := range g.tools {
			img := g.image
			lt := &lock.Tool{
				Name: t.Name, From: t.From, Package: t.Package, Nixpkgs: g.ref, Image: &img,
				Verification: lock.VerifiedNixSignature, SpecDigest: lock.Digest(t),
				Nix: map[string]lock.NixOutput{},
			}
			for _, p := range platforms {
				sp := paths[sysOf[p]][t.Package]
				if sp == "" {
					return nil, fmt.Errorf("tool %s: nix eval returned no store path for %s", t.Name, sysOf[p])
				}
				r.logf("checking closure of %s", sp)
				closure, err := nix.Closure(ctx, r.HTTP, r.NixCache, r.NixKeys, sp)
				if err != nil {
					return nil, fmt.Errorf("tool %s (%s): %w", t.Name, p, err)
				}
				lt.Nix[p] = lock.NixOutput{Path: sp, Closure: closure}
				if lt.Version == "" {
					_, lt.Version = nix.NameVersion(sp)
				}
			}
			out[t.Name] = lt
		}
	}
	return out, nil
}

// nixpkgsRef locks a nixpkgs reference to a commit: "nixos-26.05", a commit,
// or a full "github:owner/repo[/ref]" flake reference.
func (r *Resolver) nixpkgsRef(ctx context.Context, ref string) (string, error) {
	owner, repo, rev := "NixOS", "nixpkgs", ref
	if rest, ok := strings.CutPrefix(ref, "github:"); ok {
		parts := strings.SplitN(rest, "/", 3)
		if len(parts) < 2 {
			return "", fmt.Errorf("nixpkgs %q must look like github:owner/repo[/ref]", ref)
		}
		owner, repo, rev = parts[0], parts[1], "HEAD"
		if len(parts) == 3 {
			rev = parts[2]
		}
	}
	if !commitRE.MatchString(rev) {
		var c struct {
			SHA string `json:"sha"`
		}
		url := fmt.Sprintf("%s/repos/%s/%s/commits/%s", strings.TrimSuffix(r.GitHubAPI, "/"), owner, repo, rev)
		headers := map[string]string{"Accept": "application/vnd.github+json"}
		if tok := firstEnv("GITHUB_TOKEN", "GH_TOKEN"); tok != "" {
			headers["Authorization"] = "Bearer " + tok
		}
		if err := r.getJSON(ctx, url, headers, &c); err != nil {
			return "", fmt.Errorf("resolving nixpkgs %s: %w", ref, err)
		}
		if !commitRE.MatchString(c.SHA) {
			return "", fmt.Errorf("resolving nixpkgs %s: unexpected commit %q", ref, c.SHA)
		}
		rev = c.SHA
	}
	return fmt.Sprintf("github:%s/%s/%s", owner, repo, rev), nil
}
