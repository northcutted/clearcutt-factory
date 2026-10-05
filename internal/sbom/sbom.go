// Package sbom builds CycloneDX SBOMs. The declared SBOM comes from the
// lockfile, so it names every input exactly (including binaries scanners can't
// identify); a syft scan of the built image is merged in when available.
package sbom

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/northcutted/declarative-image-factory/internal/lock"
	"github.com/northcutted/declarative-image-factory/internal/manifest"
	"github.com/northcutted/declarative-image-factory/internal/nix"
)

// BOM is the subset of CycloneDX 1.6 that factory writes.
type BOM struct {
	BOMFormat    string      `json:"bomFormat"`
	SpecVersion  string      `json:"specVersion"`
	SerialNumber string      `json:"serialNumber,omitempty"`
	Version      int         `json:"version"`
	Metadata     *Metadata   `json:"metadata,omitempty"`
	Components   []Component `json:"components"`
}

type Metadata struct {
	Timestamp string     `json:"timestamp,omitempty"`
	Tools     any        `json:"tools,omitempty"`
	Component *Component `json:"component,omitempty"`
}

type Component struct {
	Type               string              `json:"type"`
	BOMRef             string              `json:"bom-ref,omitempty"`
	Name               string              `json:"name"`
	Version            string              `json:"version,omitempty"`
	PURL               string              `json:"purl,omitempty"`
	Hashes             []Hash              `json:"hashes,omitempty"`
	Licenses           []License           `json:"licenses,omitempty"`
	ExternalReferences []ExternalReference `json:"externalReferences,omitempty"`
	Properties         []Property          `json:"properties,omitempty"`
}

type Hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type License struct {
	Expression string `json:"expression,omitempty"`
}

type ExternalReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func newBOM(ref, platform, imageDigest string, ts time.Time, version string) *BOM {
	return &BOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.6",
		Version:     1,
		Metadata: &Metadata{
			Timestamp: ts.UTC().Format(time.RFC3339),
			Tools: map[string]any{"components": []Component{{
				Type: "application", Name: "factory", Version: version,
				PURL: "pkg:github/northcutted/declarative-image-factory@" + version,
			}}},
			Component: &Component{
				Type: "container", Name: ref, Version: imageDigest,
				PURL: ociPURL(ref, imageDigest, platform),
			},
		},
	}
}

// Rebased returns the declared SBOM of a rebased platform image: the new
// base, and the image whose layers were moved onto it (its own SBOM lists
// what those layers hold).
func Rebased(ref, platform, imageDigest string, created time.Time, base, from lock.Image, version string) *BOM {
	b := newBOM(ref, platform, imageDigest, created, version)
	for _, x := range []struct {
		img    lock.Image
		source string
	}{{base, "base"}, {from, "rebased-from"}} {
		b.Components = append(b.Components, Component{
			Type: "container", Name: lock.RepoOf(x.img.Ref), Version: x.img.Digest,
			PURL:       ociPURL(x.img.Ref, x.img.Digest, platform),
			Properties: []Property{{"factory:source", x.source}, {"factory:verification", lock.VerifiedImageDigest}},
		})
	}
	return b
}

// Declared returns the SBOM implied by the lock for one platform image.
func Declared(m *manifest.Manifest, l *lock.Lock, platform, imageDigest, version string) *BOM {
	b := newBOM(m.Metadata.Ref, platform, imageDigest, time.Unix(l.SourceDateEpoch, 0), version)
	add := func(c Component, source, verification string) {
		c.Properties = append(c.Properties, Property{"factory:source", source})
		if verification != "" {
			c.Properties = append(c.Properties, Property{"factory:verification", verification})
		}
		b.Components = append(b.Components, c)
	}

	add(Component{Type: "container", Name: lock.RepoOf(l.Base.Ref), Version: l.Base.Digest,
		PURL: ociPURL(l.Base.Ref, l.Base.Digest, platform)}, "base", lock.VerifiedImageDigest)
	if l.App != nil {
		add(Component{Type: "application", Name: m.Metadata.Name, Properties: []Property{
			{"factory:stack", l.App.Stack},
			{"factory:build-image", l.App.Build.Pinned()},
		}}, "app", "")
	}

	for _, p := range l.Packages.Platforms[platform] {
		c := Component{Type: "library", Name: p.Name, Version: p.Version, PURL: packagePURL(l.Packages, p)}
		if p.License != "" {
			c.Licenses = []License{{Expression: p.License}}
		}
		if p.Checksum != "" {
			c.Properties = append(c.Properties, Property{"factory:apk-checksum", p.Checksum})
		}
		if p.SHA256 != "" {
			c.Hashes = []Hash{{"SHA-256", p.SHA256}}
			c.ExternalReferences = []ExternalReference{{"distribution", p.URL}}
		}
		add(c, "package:"+l.Packages.EffectiveManager(), "")
	}

	// Nix store paths, once each even when tools share dependencies.
	seenStore := map[string]bool{}

	for _, t := range l.Tools {
		c := Component{Type: "application", Name: t.Name, Version: t.Version}
		switch t.From {
		case manifest.FromURL, manifest.FromGitHubRelease:
			a := t.Artifacts[platform]
			c.Hashes = []Hash{{"SHA-256", a.SHA256}}
			c.ExternalReferences = []ExternalReference{{"distribution", a.URL}}
			if t.From == manifest.FromGitHubRelease {
				c.PURL = fmt.Sprintf("pkg:github/%s@%s", strings.ToLower(t.Repo), releaseTag(a.URL, t.Version))
			} else {
				c.PURL = fmt.Sprintf("pkg:generic/%s@%s?download_url=%s", t.Name, t.Version, url.QueryEscape(a.URL))
			}
		case manifest.FromOCI:
			c.Version = t.Image.Digest
			c.PURL = ociPURL(t.Image.Ref, t.Image.Digest, platform)
		case manifest.FromGo:
			c.Type = "application"
			c.PURL = fmt.Sprintf("pkg:golang/%s@%s", t.Package, t.Version)
		case manifest.FromNix:
			out := t.Nix[platform]
			c.PURL = nixPURL(out.Path)
			for _, p := range out.Closure {
				if p.Path == out.Path || seenStore[p.Path] {
					continue
				}
				seenStore[p.Path] = true
				name, version := nix.NameVersion(p.Path)
				b.Components = append(b.Components, Component{
					Type: "library", Name: name, Version: version, PURL: nixPURL(p.Path),
					Hashes: nixHash(p.NarHash),
					Properties: []Property{{"factory:source", "tool:nix"}, {"factory:nix-store-path", p.Path},
						{"factory:verification", lock.VerifiedNixSignature}},
				})
			}
			c.Properties = append(c.Properties, Property{"factory:nix-store-path", out.Path})
		case manifest.FromBuild:
			c.PURL = fmt.Sprintf("pkg:generic/%s@%s", t.Name, t.Version)
		}
		if c.Version == "" {
			c.PURL = strings.Replace(c.PURL, "@?", "?", 1)
			c.PURL = strings.TrimSuffix(c.PURL, "@")
		}
		add(c, "tool:"+t.From, t.Verification)
	}
	return b
}

// releaseTag recovers the release tag from a GitHub download URL
// (…/releases/download/<tag>/<asset>), which is what pkg:github versions name.
func releaseTag(u, fallback string) string {
	_, rest, ok := strings.Cut(u, "/releases/download/")
	if !ok {
		return fallback
	}
	tag, _, _ := strings.Cut(rest, "/")
	return tag
}

// ociPURL builds pkg:oci/<name>@<digest>?repository_url=<repo>&arch=<arch>.
func ociPURL(ref, digest, platform string) string {
	repo := lock.RepoOf(ref)
	name := repo[strings.LastIndex(repo, "/")+1:]
	_, arch, _ := manifest.SplitPlatform(platform)
	return fmt.Sprintf("pkg:oci/%s@%s?arch=%s&repository_url=%s", name, url.PathEscape(digest), arch, url.QueryEscape(repo))
}

// packagePURL names a distro package per the purl spec (apk, deb, rpm types).
func packagePURL(pk lock.Packages, p lock.Package) string {
	distroID, distroVer, _ := strings.Cut(pk.Distro, "-")
	switch pk.EffectiveManager() {
	case lock.ManagerAPT:
		q := "arch=" + p.Arch
		if pk.Distro != "" {
			q += "&distro=" + url.QueryEscape(pk.Distro)
		}
		return fmt.Sprintf("pkg:deb/%s/%s@%s?%s", firstNonEmpty(distroID, "debian"), p.Name, url.PathEscape(p.Version), q)
	case lock.ManagerDNF:
		version, epoch := p.Version, ""
		if e, v, ok := strings.Cut(p.Version, ":"); ok {
			epoch, version = e, v
		}
		q := "arch=" + p.Arch
		if epoch != "" {
			q += "&epoch=" + epoch
		}
		if pk.Distro != "" {
			q += "&distro=" + url.QueryEscape(distroID+"-"+distroVer)
		}
		return fmt.Sprintf("pkg:rpm/%s/%s@%s?%s", rpmNamespace(distroID), p.Name, url.PathEscape(version), q)
	}
	return fmt.Sprintf("pkg:apk/%s/%s@%s?arch=%s", apkNamespace(pk.Repositories), p.Name, url.PathEscape(p.Version), p.Arch)
}

func rpmNamespace(id string) string {
	switch id {
	case "rhel":
		return "redhat"
	case "amzn":
		return "amazonlinux"
	case "":
		return "rpm"
	}
	return id
}

// nixPURL follows syft's form so scanned and declared entries merge.
func nixPURL(storePath string) string {
	name, version := nix.NameVersion(storePath)
	return fmt.Sprintf("pkg:nix/%s@%s?outputhash=%s", name, url.PathEscape(version), nix.HashPart(storePath))
}

// nixHash converts a "sha256:<nix base32>" NarHash for CycloneDX, which wants
// hex; nix's base32 is kept as a property when conversion isn't possible.
func nixHash(narHash string) []Hash {
	if h, ok := strings.CutPrefix(narHash, "sha256:"); ok {
		if raw, err := nix.DecodeBase32(h); err == nil {
			return []Hash{{"SHA-256", hex.EncodeToString(raw)}}
		}
	}
	return nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func apkNamespace(repos []string) string {
	for _, r := range repos {
		switch {
		case strings.Contains(r, "wolfi.dev"):
			return "wolfi"
		case strings.Contains(r, "cgr.dev"):
			return "chainguard"
		case strings.Contains(r, "alpinelinux"):
			return "alpine"
		}
	}
	return "apk"
}

// Scan runs syft on a single-image OCI layout and returns its CycloneDX JSON.
func Scan(ctx context.Context, layoutDir string) ([]byte, error) {
	bin, err := exec.LookPath("syft")
	if err != nil {
		return nil, fmt.Errorf("syft not found on PATH")
	}
	cmd := exec.CommandContext(ctx, bin, "scan", "oci-dir:"+layoutDir, "-o", "cyclonedx-json", "-q")
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("syft: %w", err)
	}
	return out, nil
}

// Merge adds declared components missing from the scanned SBOM. Scanned
// components win because they carry file-level evidence; declared ones fill
// the gaps (downloaded binaries, provenance properties). The result keeps all
// of syft's fields.
func Merge(scanned []byte, declared *BOM) ([]byte, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(scanned, &doc); err != nil {
		return nil, fmt.Errorf("parsing syft SBOM: %w", err)
	}
	var comps []map[string]any
	if raw, ok := doc["components"]; ok {
		if err := json.Unmarshal(raw, &comps); err != nil {
			return nil, err
		}
	}
	have := map[string]bool{}
	for _, c := range comps {
		purl, _ := c["purl"].(string)
		name, _ := c["name"].(string)
		version, _ := c["version"].(string)
		if purl != "" {
			have[purlKey(purl)] = true
		}
		have[name+"@"+version] = true
	}
	for _, c := range declared.Components {
		if (c.PURL != "" && have[purlKey(c.PURL)]) || have[c.Name+"@"+c.Version] {
			continue
		}
		b, _ := json.Marshal(c)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		comps = append(comps, m)
	}
	raw, err := json.Marshal(comps)
	if err != nil {
		return nil, err
	}
	doc["components"] = raw
	return json.MarshalIndent(doc, "", "  ")
}

// purlKey drops qualifiers and namespace so pkg:apk/wolfi/x@1 matches
// pkg:apk/chainguard/x@1?arch=….
func purlKey(p string) string {
	if p == "" {
		return ""
	}
	p, _, _ = strings.Cut(p, "?")
	typ, rest, ok := strings.Cut(strings.TrimPrefix(p, "pkg:"), "/")
	if !ok {
		return p
	}
	name := rest
	if i := strings.LastIndex(rest[:strings.LastIndex(rest+"@", "@")], "/"); i >= 0 && typ == "apk" {
		name = rest[i+1:]
	}
	return typ + "/" + name
}
