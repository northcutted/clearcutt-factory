// Package resolve turns a manifest into a lockfile by pinning every input.
package resolve

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/northcutted/declarative-image-factory/internal/apk"
	"github.com/northcutted/declarative-image-factory/internal/container"
	"github.com/northcutted/declarative-image-factory/internal/lock"
	"github.com/northcutted/declarative-image-factory/internal/manifest"
	"github.com/northcutted/declarative-image-factory/internal/nix"
	"github.com/northcutted/declarative-image-factory/internal/registry"
)

// Resolver pins manifest inputs. Its fields are swappable for tests.
type Resolver struct {
	HTTP           *http.Client
	GitHubAPI      string
	GitHubDownload string
	GoProxy        string
	ImageDigest    func(ctx context.Context, ref string) (string, error)
	// PlatformDigests lists an image's per-platform digests (apps' run image).
	PlatformDigests func(ctx context.Context, ref string) (map[string]string, error)
	ReadImageFiles  func(ctx context.Context, ref, platform string, paths ...string) (map[string][]byte, error)
	FetchAPKIndex   func(ctx context.Context, repos []string, arch string, keys map[string][]byte) (*apk.Index, error)
	// Run executes lock-time scripts in containers (apt, dnf, nix).
	Run      container.RunFunc
	NixCache string
	NixKeys  []string
	Now      func() time.Time
	Log      io.Writer

	digests  map[string]string
	releases map[string]map[string]string
}

func New() *Resolver {
	r := &Resolver{
		HTTP:            &http.Client{Timeout: 10 * time.Minute},
		GitHubAPI:       "https://api.github.com",
		GitHubDownload:  "https://github.com",
		GoProxy:         "https://proxy.golang.org",
		ImageDigest:     registry.Digest,
		PlatformDigests: registry.PlatformDigests,
		ReadImageFiles:  registry.ReadFiles,
		Run:             container.Runner{}.Run,
		NixCache:        nix.DefaultCache,
		NixKeys:         []string{nix.DefaultKey},
		Now:             time.Now,
		Log:             os.Stderr,
	}
	r.FetchAPKIndex = func(ctx context.Context, repos []string, arch string, keys map[string][]byte) (*apk.Index, error) {
		return apk.FetchIndex(ctx, r.HTTP, repos, arch, keys)
	}
	return r
}

func (r *Resolver) logf(format string, a ...any) {
	if r.Log != nil {
		_, _ = fmt.Fprintf(r.Log, format+"\n", a...)
	}
}

// Lock resolves m against org o. Entries of prev whose inputs are unchanged are
// reused unless update is set, so `factory lock` only moves what you changed.
func (r *Resolver) Lock(ctx context.Context, m *manifest.Manifest, o *manifest.Org, prev *lock.Lock, update bool) (*lock.Lock, error) {
	return r.LockFrom(ctx, m, o, prev, prev, update)
}

// LockFrom is Lock reusing pins from reuse (prev with some pins dropped, to
// re-resolve just those), while orig, the lock on disk, decides whether the
// build timestamp moves.
func (r *Resolver) LockFrom(ctx context.Context, m *manifest.Manifest, o *manifest.Org, reuse, orig *lock.Lock, update bool) (*lock.Lock, error) {
	if orig == nil {
		orig = &lock.Lock{}
	}
	prev := reuse
	if prev == nil || update {
		prev = &lock.Lock{}
	}
	l := &lock.Lock{
		APIVersion:   manifest.APIVersion,
		Kind:         lock.Kind,
		InputsDigest: lock.InputsOf(m, o).Digest(),
	}
	var err error
	pin := func(ref string, old lock.Image) lock.Image {
		if err != nil {
			return lock.Image{}
		}
		var img lock.Image
		img, err = r.pinImage(ctx, ref, old)
		return img
	}
	l.Builder.BuildKit = pin(o.Builder.BuildKit, prev.Builder.BuildKit)
	l.Builder.Frontend = pin(o.Builder.Frontend, prev.Builder.Frontend)
	l.Builder.Toolbox = pin(o.Builder.Toolbox, prev.Builder.Toolbox)
	l.Base = pin(m.Spec.Base, prev.Base)
	if err != nil {
		return nil, err
	}
	if m.Stack != nil {
		if l.App, err = r.lockApp(ctx, m, l.Base, prev); err != nil {
			return nil, err
		}
	}

	if l.Packages, err = r.lockPackages(ctx, m, l.Base, prev.Packages); err != nil {
		return nil, err
	}
	// Nix tools are evaluated together (one nixpkgs download per revision).
	var nixPending []manifest.Tool
	for _, t := range m.Spec.Tools {
		spec := lock.Digest(t)
		if old := prev.Tool(t.Name); old != nil && old.SpecDigest == spec {
			l.Tools = append(l.Tools, *old)
			continue
		}
		if t.From == manifest.FromNix {
			nixPending = append(nixPending, t)
			l.Tools = append(l.Tools, lock.Tool{Name: t.Name})
			continue
		}
		r.logf("resolving tool %s (%s)", t.Name, t.From)
		lt, err := r.lockTool(ctx, t, m.Spec.Platforms)
		if err != nil {
			return nil, fmt.Errorf("tool %s: %w", t.Name, err)
		}
		lt.SpecDigest = spec
		l.Tools = append(l.Tools, *lt)
	}
	if len(nixPending) > 0 {
		resolved, err := r.lockNixTools(ctx, nixPending, m.Spec.Platforms)
		if err != nil {
			return nil, err
		}
		for i := range l.Tools {
			if lt, ok := resolved[l.Tools[i].Name]; ok {
				l.Tools[i] = *lt
			}
		}
	}

	// Keep the build timestamp unless the pins changed, so re-locking an
	// unchanged manifest doesn't change the image.
	l.SourceDateEpoch = orig.SourceDateEpoch
	if orig.SourceDateEpoch == 0 || !bytes.Equal(l.Marshal(), orig.Marshal()) {
		l.SourceDateEpoch = epochFor(r.Now())
	}
	return l, nil
}

// epochFor returns midnight UTC of the day before t. Files created during a
// build must be newer than SOURCE_DATE_EPOCH to be clamped to it, so the epoch
// sits safely in the past even for builders whose clocks lag by hours.
func epochFor(t time.Time) int64 {
	const day = 24 * 60 * 60
	return t.UTC().Unix()/day*day - day
}

// lockApp pins an app's build image and records its run image's
// per-platform digests.
func (r *Resolver) lockApp(ctx context.Context, m *manifest.Manifest, run lock.Image, prev *lock.Lock) (*lock.App, error) {
	var old lock.App
	if prev.App != nil {
		old = *prev.App
	}
	build, err := r.pinImage(ctx, m.Stack.BuildRef, old.Build)
	if err != nil {
		return nil, err
	}
	a := &lock.App{Stack: m.Stack.Metadata.Name, StackDigest: lock.StackDigest(m.Stack), Build: build, RunPlatforms: maps.Clone(old.RunPlatforms)}
	if prev.Base.Digest != run.Digest || a.RunPlatforms == nil {
		if a.RunPlatforms, err = r.PlatformDigests(ctx, run.Pinned()); err != nil {
			return nil, err
		}
	}
	for _, p := range m.Spec.Platforms {
		if a.RunPlatforms[p] == "" {
			return nil, fmt.Errorf("run image %s has no %s image", run.Ref, p)
		}
	}
	// Keep only the platforms the app is built for.
	for p := range a.RunPlatforms {
		if !slices.Contains(m.Spec.Platforms, p) {
			delete(a.RunPlatforms, p)
		}
	}
	return a, nil
}

func (r *Resolver) pinImage(ctx context.Context, ref string, old lock.Image) (lock.Image, error) {
	if old.Ref == ref && old.Digest != "" {
		return old, nil
	}
	if r.digests == nil {
		r.digests = map[string]string{}
	}
	if d, ok := r.digests[ref]; ok {
		return lock.Image{Ref: ref, Digest: d}, nil
	}
	r.logf("resolving image %s", ref)
	d, err := r.ImageDigest(ctx, ref)
	if err != nil {
		return lock.Image{}, err
	}
	r.digests[ref] = d
	return lock.Image{Ref: ref, Digest: d}, nil
}

func (r *Resolver) lockTool(ctx context.Context, t manifest.Tool, platforms []string) (*lock.Tool, error) {
	lt := &lock.Tool{Name: t.Name, From: t.From, Version: t.Version}
	switch t.From {
	case manifest.FromURL, manifest.FromGitHubRelease:
		lt.Repo = t.Repo
		lt.Artifacts = map[string]lock.Artifact{}
		for _, plat := range platforms {
			art, how, err := r.lockArtifact(ctx, t, plat)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", plat, err)
			}
			lt.Artifacts[plat] = art
			lt.Verification = weakest(lt.Verification, how)
		}
	case manifest.FromOCI, manifest.FromBuild:
		img, err := r.pinImage(ctx, t.Image, lock.Image{})
		if err != nil {
			return nil, err
		}
		lt.Image = &img
		lt.Verification = lock.VerifiedImageDigest
		if t.From == manifest.FromBuild {
			lt.Verification = lock.VerifiedUnverified
		}
	case manifest.FromGo:
		img, err := r.pinImage(ctx, t.Image, lock.Image{})
		if err != nil {
			return nil, err
		}
		lt.Image = &img
		lt.Package = t.Package
		lt.Verification = lock.VerifiedGoSumDB
		v := t.Version
		if v == "" || v == "latest" {
			if v, err = r.goLatest(ctx, t.Package); err != nil {
				return nil, err
			}
		} else if !strings.HasPrefix(v, "v") {
			v = "v" + v
		}
		lt.Version = v
	}
	return lt, nil
}

var verificationStrength = []string{
	lock.VerifiedUnverified, lock.VerifiedTOFU, lock.VerifiedGitHubDigest,
	lock.VerifiedChecksumFile, lock.VerifiedPinned,
}

// weakest keeps the least trustworthy verification seen across platforms.
func weakest(a, b string) string {
	if a == "" {
		return b
	}
	if slices.Index(verificationStrength, b) < slices.Index(verificationStrength, a) {
		return b
	}
	return a
}

func (r *Resolver) lockArtifact(ctx context.Context, t manifest.Tool, plat string) (lock.Artifact, string, error) {
	osName, arch, _ := manifest.SplitPlatform(plat)
	vars := map[string]string{"name": t.Name, "version": t.Version, "os": osName, "arch": arch}
	if a, ok := t.ArchMap[arch]; ok {
		vars["arch"] = a
	}
	var art lock.Artifact
	var err error
	if t.Extract != "" {
		if art.Extract, err = expand(t.Extract, vars); err != nil {
			return art, "", err
		}
	}

	var checksumURL string
	switch t.From {
	case manifest.FromURL:
		if art.URL, err = expand(t.URL, vars); err != nil {
			return art, "", err
		}
		if t.Checksum != "" {
			vars["url"] = art.URL
			if checksumURL, err = expand(t.Checksum, vars); err != nil {
				return art, "", err
			}
		}
	case manifest.FromGitHubRelease:
		tagTmpl := t.Tag
		if tagTmpl == "" {
			tagTmpl = "v{{version}}"
		}
		if vars["tag"], err = expand(tagTmpl, vars); err != nil {
			return art, "", err
		}
		if vars["asset"], err = expand(t.Asset, vars); err != nil {
			return art, "", err
		}
		art.URL = r.releaseURL(t.Repo, vars["tag"], vars["asset"])
		if t.Checksums != "" {
			name, err := expand(t.Checksums, vars)
			if err != nil {
				return art, "", err
			}
			checksumURL = r.releaseURL(t.Repo, vars["tag"], name)
		}
	}

	if pinned := t.SHA256.Get(arch); pinned != "" {
		art.SHA256 = strings.ToLower(strings.TrimPrefix(pinned, "sha256:"))
		if !hex64.MatchString(art.SHA256) {
			return art, "", fmt.Errorf("sha256 %q is not a hex sha256", pinned)
		}
		return art, lock.VerifiedPinned, nil
	}
	if checksumURL != "" {
		body, err := r.getBytes(ctx, checksumURL, nil)
		if err != nil {
			return art, "", err
		}
		if art.SHA256, err = parseChecksum(body, path.Base(art.URL)); err != nil {
			return art, "", fmt.Errorf("%s: %w", checksumURL, err)
		}
		return art, lock.VerifiedChecksumFile, nil
	}
	if t.From == manifest.FromGitHubRelease {
		if d, err := r.releaseAssetDigest(ctx, t.Repo, vars["tag"], vars["asset"]); err == nil && d != "" {
			art.SHA256 = d
			return art, lock.VerifiedGitHubDigest, nil
		} else if err != nil {
			r.logf("warning: GitHub API digest lookup for %s failed: %v", t.Name, err)
		}
	}
	r.logf("warning: %s has no checksum source; hashing the download (trust on first use)", art.URL)
	if art.SHA256, err = r.hashURL(ctx, art.URL); err != nil {
		return art, "", err
	}
	return art, lock.VerifiedTOFU, nil
}

func (r *Resolver) releaseURL(repo, tag, asset string) string {
	return fmt.Sprintf("%s/%s/releases/download/%s/%s", strings.TrimSuffix(r.GitHubDownload, "/"), repo, tag, asset)
}

// releaseAssetDigest returns the sha256 GitHub computed for a release asset.
func (r *Resolver) releaseAssetDigest(ctx context.Context, repo, tag, asset string) (string, error) {
	key := repo + "@" + tag
	if r.releases == nil {
		r.releases = map[string]map[string]string{}
	}
	digests, ok := r.releases[key]
	if !ok {
		var rel struct {
			Assets []struct {
				Name   string `json:"name"`
				Digest string `json:"digest"`
			} `json:"assets"`
		}
		headers := map[string]string{"Accept": "application/vnd.github+json"}
		if tok := firstEnv("GITHUB_TOKEN", "GH_TOKEN"); tok != "" {
			headers["Authorization"] = "Bearer " + tok
		}
		url := fmt.Sprintf("%s/repos/%s/releases/tags/%s", strings.TrimSuffix(r.GitHubAPI, "/"), repo, tag)
		if err := r.getJSON(ctx, url, headers, &rel); err != nil {
			return "", err
		}
		digests = map[string]string{}
		for _, a := range rel.Assets {
			if d, ok := strings.CutPrefix(a.Digest, "sha256:"); ok && hex64.MatchString(d) {
				digests[a.Name] = d
			}
		}
		r.releases[key] = digests
	}
	return digests[asset], nil
}

// goLatest asks the module proxy for the latest version of the module that
// contains pkg, trying the longest module path first.
func (r *Resolver) goLatest(ctx context.Context, pkg string) (string, error) {
	parts := strings.Split(pkg, "/")
	for n := len(parts); n >= 1; n-- {
		mod := strings.Join(parts[:n], "/")
		var info struct{ Version string }
		url := fmt.Sprintf("%s/%s/@latest", strings.TrimSuffix(r.GoProxy, "/"), escapeModule(mod))
		err := r.getJSON(ctx, url, nil, &info)
		var he *httpError
		if errors.As(err, &he) && (he.status == http.StatusNotFound || he.status == http.StatusGone) {
			continue
		}
		if err != nil {
			return "", err
		}
		return info.Version, nil
	}
	return "", fmt.Errorf("no module found for %s on %s", pkg, r.GoProxy)
}

// escapeModule applies the module proxy's case encoding (Upper → !upper).
func escapeModule(p string) string {
	var b strings.Builder
	for _, c := range p {
		if c >= 'A' && c <= 'Z' {
			b.WriteByte('!')
			c += 'a' - 'A'
		}
		b.WriteRune(c)
	}
	return b.String()
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}
