package resolve

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/northcutted/declarative-image-factory/internal/apk"
	"github.com/northcutted/declarative-image-factory/internal/lock"
	"github.com/northcutted/declarative-image-factory/internal/manifest"
	"github.com/northcutted/declarative-image-factory/internal/native"
)

var apkArch = map[string]string{"amd64": "x86_64", "arm64": "aarch64"}

const (
	apkReposPath   = "etc/apk/repositories"
	apkDBPath      = "lib/apk/db/installed"
	apkDBPathV3    = "usr/lib/apk/db/installed"
	apkKeysDir     = "etc/apk/keys/"
	osReleasePath  = "etc/os-release"
	osReleasePath2 = "usr/lib/os-release"
)

func (r *Resolver) lockPackages(ctx context.Context, m *manifest.Manifest, base lock.Image, prev lock.Packages) (lock.Packages, error) {
	if len(m.Spec.Packages) == 0 {
		return lock.Packages{}, nil
	}
	inputs := lock.Digest(struct {
		Base      string
		Manager   string
		Repos     []string
		Packages  []string
		Platforms []string
	}{base.Digest, m.Spec.PackageManager, m.Spec.Repositories, m.Spec.Packages, m.Spec.Platforms})
	if prev.InputsDigest == inputs {
		return prev, nil
	}

	mgr := m.Spec.PackageManager
	if mgr == "" {
		files, err := r.ReadImageFiles(ctx, base.Pinned(), m.Spec.Platforms[0], apkDBPath, apkDBPathV3, osReleasePath, osReleasePath2)
		if err != nil {
			return lock.Packages{}, err
		}
		osr := files[osReleasePath]
		if osr == nil {
			osr = files[osReleasePath2]
		}
		switch {
		case files[apkDBPath] != nil || files[apkDBPathV3] != nil:
			mgr = lock.ManagerAPK
		default:
			mgr = native.DetectManager(native.OSRelease(osr))
		}
		if mgr == "" {
			return lock.Packages{}, fmt.Errorf("packages: can't tell which package manager %s uses; set spec.packageManager", base.Ref)
		}
	}
	if mgr != lock.ManagerAPK && len(m.Spec.Repositories) > 0 {
		return lock.Packages{}, fmt.Errorf("spec.repositories only applies to apk; for %s, configure repositories in the base image", mgr)
	}

	var out lock.Packages
	var err error
	if mgr == lock.ManagerAPK {
		out, err = r.lockAPK(ctx, m, base)
	} else {
		out, err = r.lockNative(ctx, m, base, mgr)
	}
	if err != nil {
		return lock.Packages{}, err
	}
	out.Manager = mgr
	out.InputsDigest = inputs
	return out, nil
}

func (r *Resolver) lockAPK(ctx context.Context, m *manifest.Manifest, base lock.Image) (lock.Packages, error) {
	out := lock.Packages{Platforms: map[string][]lock.Package{}}
	indexes := map[string]*apk.Index{}
	for _, plat := range m.Spec.Platforms {
		_, arch, _ := manifest.SplitPlatform(plat)
		aarch, ok := apkArch[arch]
		if !ok {
			return lock.Packages{}, fmt.Errorf("packages: unsupported architecture %s", arch)
		}
		files, err := r.ReadImageFiles(ctx, base.Pinned(), plat, apkReposPath, apkDBPath, apkDBPathV3, apkKeysDir)
		if err != nil {
			return lock.Packages{}, err
		}
		db := files[apkDBPath]
		if db == nil {
			db = files[apkDBPathV3]
		}
		if db == nil {
			return lock.Packages{}, fmt.Errorf("packages: base %s has no apk database", base.Ref)
		}
		installed, err := apk.ParseIndex(bytes.NewReader(db))
		if err != nil {
			return lock.Packages{}, fmt.Errorf("parsing apk database of %s: %w", base.Ref, err)
		}
		keys := map[string][]byte{}
		for p, b := range files {
			if strings.HasPrefix(p, apkKeysDir) {
				keys[path.Base(p)] = b
			}
		}
		repos := m.Spec.Repositories
		if len(repos) == 0 {
			repos = parseRepositories(files[apkReposPath])
		}
		if len(repos) == 0 {
			return lock.Packages{}, fmt.Errorf("packages: no repositories in spec.repositories or %s of the base", apkReposPath)
		}
		for _, repo := range repos {
			if !slices.Contains(out.Repositories, repo) {
				out.Repositories = append(out.Repositories, repo)
			}
		}

		key := aarch + "|" + strings.Join(repos, ",")
		idx := indexes[key]
		if idx == nil {
			r.logf("fetching APKINDEX for %s from %s", aarch, strings.Join(repos, ", "))
			if idx, err = r.FetchAPKIndex(ctx, repos, aarch, keys); err != nil {
				return lock.Packages{}, err
			}
			indexes[key] = idx
		}

		// Pin what the base already has too: otherwise apk may upgrade a base
		// package to whatever is newest on the day of the build.
		roots := slices.Clone(m.Spec.Packages)
		for _, p := range installed {
			if idx.Has(p.Name) {
				roots = append(roots, p.Name)
			} else {
				r.logf("warning: %s from the base is not in the repositories; leaving it as installed", p.Name)
			}
		}
		pkgs, err := idx.Resolve(roots)
		if err != nil {
			return lock.Packages{}, err
		}
		for _, p := range pkgs {
			out.Platforms[plat] = append(out.Platforms[plat], lock.Package{
				Name: p.Name, Version: p.Version, Arch: p.Arch, Checksum: p.Checksum,
				Origin: p.Origin, License: p.License, Repo: p.Repo,
			})
		}
	}
	return out, nil
}

// lockNative lets apt or dnf resolve inside the base image for each platform.
func (r *Resolver) lockNative(ctx context.Context, m *manifest.Manifest, base lock.Image, mgr string) (lock.Packages, error) {
	out := lock.Packages{Platforms: map[string][]lock.Package{}}
	snapshot := r.Now().UTC().Format("20060102T150405Z")
	for _, plat := range m.Spec.Platforms {
		r.logf("resolving %s packages for %s in %s", mgr, plat, base.Ref)
		var res *native.Result
		var err error
		if mgr == lock.ManagerAPT {
			res, err = native.ResolveAPT(ctx, r.Run, base.Pinned(), plat, snapshot, m.Spec.Packages)
		} else {
			res, err = native.ResolveDNF(ctx, r.Run, base.Pinned(), plat, m.Spec.Packages)
		}
		if err != nil {
			return lock.Packages{}, fmt.Errorf("packages (%s): %w", plat, err)
		}
		for _, w := range res.Warnings {
			r.logf("warning: %s", w)
		}
		out.Distro = res.Distro
		out.Snapshot = res.Snapshot
		for _, repo := range res.Repositories {
			if !slices.Contains(out.Repositories, repo) {
				out.Repositories = append(out.Repositories, repo)
			}
		}
		out.Platforms[plat] = res.Packages
	}
	slices.Sort(out.Repositories)
	return out, nil
}

func parseRepositories(b []byte) []string {
	var repos []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "@") {
			continue
		}
		repos = append(repos, line)
	}
	return repos
}
