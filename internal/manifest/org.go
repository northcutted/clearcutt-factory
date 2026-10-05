package manifest

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	KindOrg     = "OrgProfile"
	OrgFileName = "factory.org.yaml"
)

// Org holds the choices that differ between organizations: where images go,
// how they are built, signed, scanned, and what policy they must meet.
type Org struct {
	APIVersion      string          `yaml:"apiVersion"`
	Kind            string          `yaml:"kind"`
	Registry        string          `yaml:"registry,omitempty"`
	Tags            []string        `yaml:"tags,omitempty"`
	Defaults        OrgDefaults     `yaml:"defaults,omitempty"`
	Builder         Builder         `yaml:"builder,omitempty"`
	Signing         Signing         `yaml:"signing,omitempty"`
	SBOM            SBOM            `yaml:"sbom,omitempty"`
	Vulnerabilities Vulnerabilities `yaml:"vulnerabilities,omitempty"`
	Policy          Policy          `yaml:"policy,omitempty"`
	// Mirrors rewrite download URL prefixes (e.g. to Artifactory, Nexus, or
	// Pulp). Checksums still pin the content, so a mirror can't change it.
	Mirrors []Mirror `yaml:"mirrors,omitempty"`

	Path string `yaml:"-"`
}

// Mirror replaces the URL prefix From with To.
type Mirror struct {
	From string `yaml:"from"`
	To   string `yaml:"to"`
}

// Rewrite applies the longest matching mirror to u.
func Rewrite(mirrors []Mirror, u string) string {
	best := -1
	for i, m := range mirrors {
		if strings.HasPrefix(u, m.From) && (best < 0 || len(m.From) > len(mirrors[best].From)) {
			best = i
		}
	}
	if best < 0 {
		return u
	}
	return mirrors[best].To + strings.TrimPrefix(u, mirrors[best].From)
}

type OrgDefaults struct {
	Base      string            `yaml:"base,omitempty"`
	Platforms []string          `yaml:"platforms,omitempty"`
	Labels    map[string]string `yaml:"labels,omitempty"`
}

type Builder struct {
	// BuildKit is the moby/buildkit image used for every build. Pinning it is
	// what makes rebuilds bit-for-bit comparable across machines.
	BuildKit string `yaml:"buildkit,omitempty"`
	// Frontend is the Dockerfile frontend pinned via `# syntax=`.
	Frontend string `yaml:"frontend,omitempty"`
	// Toolbox runs fetch/extract steps on the build platform.
	Toolbox string `yaml:"toolbox,omitempty"`
	// Go is the default builder image for `from: go` tools.
	Go string `yaml:"go,omitempty"`
	// Nix is the image providing the nix CLI for `from: nix` tools.
	Nix string `yaml:"nix,omitempty"`
	// Nixpkgs is the default NixOS/nixpkgs branch for `from: nix` tools.
	Nixpkgs string `yaml:"nixpkgs,omitempty"`
	// Runtime runs the BuildKit container: auto, docker, or podman.
	Runtime string `yaml:"runtime,omitempty"`
	// Addr targets an existing buildkitd (e.g. tcp://buildkitd:1234) with the
	// local buildctl instead of starting a container.
	Addr string `yaml:"addr,omitempty"`
}

type Signing struct {
	// Mode is keyless (Sigstore OIDC), key (file or KMS URI), or none.
	Mode string   `yaml:"mode,omitempty"`
	Key  string   `yaml:"key,omitempty"`
	Args []string `yaml:"args,omitempty"`
	// Verify holds the identity verifiers expect, used by `factory verify --image`.
	Verify VerifyIdentity `yaml:"verify,omitempty"`
}

type VerifyIdentity struct {
	Key                       string   `yaml:"key,omitempty"`
	CertificateIdentityRegexp string   `yaml:"certificateIdentityRegexp,omitempty"`
	CertificateOIDCIssuer     string   `yaml:"certificateOIDCIssuer,omitempty"`
	Args                      []string `yaml:"args,omitempty"`
}

type SBOM struct {
	// Scan adds a syft scan to the SBOM declared from the lockfile.
	Scan *bool `yaml:"scan,omitempty"`
}

type Vulnerabilities struct {
	// Scanner is grype or none.
	Scanner string `yaml:"scanner,omitempty"`
	// FailOn blocks push/sign at or above this severity: negligible, low,
	// medium, high, critical. Empty never fails.
	FailOn string `yaml:"failOn,omitempty"`
	// OnlyFixed only counts vulnerabilities with a fix available toward FailOn.
	OnlyFixed bool `yaml:"onlyFixed,omitempty"`
}

type Policy struct {
	RequireNonRoot bool     `yaml:"requireNonRoot,omitempty"`
	RequiredLabels []string `yaml:"requiredLabels,omitempty"`
	// AllowTOFU permits tools whose hash was recorded on first download with
	// no publisher checksum or digest to compare against.
	AllowTOFU bool `yaml:"allowTOFU,omitempty"`
	// AllowedHosts restricts download hosts (exact, or ".suffix" matches).
	AllowedHosts []string `yaml:"allowedHosts,omitempty"`
	// AllowedRegistries restricts image references by prefix, e.g. cgr.dev/chainguard/.
	AllowedRegistries []string `yaml:"allowedRegistries,omitempty"`
}

// DefaultOrg is used when no org profile is found.
func DefaultOrg() *Org {
	o := &Org{APIVersion: APIVersion, Kind: KindOrg}
	o.setDefaults()
	return o
}

func (o *Org) setDefaults() {
	b := &o.Builder
	b.BuildKit = firstNonEmpty(b.BuildKit, "moby/buildkit:v0.33.1")
	b.Frontend = firstNonEmpty(b.Frontend, "docker/dockerfile:1")
	b.Toolbox = firstNonEmpty(b.Toolbox, "cgr.dev/chainguard/wolfi-base:latest")
	b.Go = firstNonEmpty(b.Go, "golang:1")
	b.Nix = firstNonEmpty(b.Nix, "nixos/nix:latest")
	b.Nixpkgs = firstNonEmpty(b.Nixpkgs, "nixos-26.05")
	b.Runtime = firstNonEmpty(b.Runtime, "auto")
	o.Signing.Mode = firstNonEmpty(o.Signing.Mode, "keyless")
	if o.SBOM.Scan == nil {
		t := true
		o.SBOM.Scan = &t
	}
	o.Vulnerabilities.Scanner = firstNonEmpty(o.Vulnerabilities.Scanner, "grype")
}

func (o *Org) validate() error {
	var errs []error
	switch o.Signing.Mode {
	case "keyless", "none":
	case "key":
		if o.Signing.Key == "" {
			errs = append(errs, errors.New("signing.key is required when signing.mode is key"))
		}
	default:
		errs = append(errs, fmt.Errorf("signing.mode %q must be keyless, key, or none", o.Signing.Mode))
	}
	switch o.Vulnerabilities.Scanner {
	case "grype", "none":
	default:
		errs = append(errs, fmt.Errorf("vulnerabilities.scanner %q must be grype or none", o.Vulnerabilities.Scanner))
	}
	if f := o.Vulnerabilities.FailOn; f != "" && SeverityRank(f) == 0 {
		errs = append(errs, fmt.Errorf("vulnerabilities.failOn %q must be negligible, low, medium, high, or critical", f))
	}
	for i, m := range o.Mirrors {
		if m.From == "" || m.To == "" {
			errs = append(errs, fmt.Errorf("mirrors[%d]: from and to are required", i))
		}
	}
	switch o.Builder.Runtime {
	case "auto", "docker", "podman":
	default:
		errs = append(errs, fmt.Errorf("builder.runtime %q must be auto, docker, or podman", o.Builder.Runtime))
	}
	return errors.Join(errs...)
}

// SeverityRank orders severities; unknown severities rank 0.
func SeverityRank(s string) int {
	switch strings.ToLower(s) {
	case "negligible":
		return 1
	case "low":
		return 2
	case "medium":
		return 3
	case "high":
		return 4
	case "critical":
		return 5
	}
	return 0
}

// LoadOrg loads the org profile at path, or, if path is empty, the nearest
// factory.org.yaml at or above startDir. No profile yields defaults.
func LoadOrg(path, startDir string) (*Org, error) {
	if path == "" {
		found, err := findUp(startDir, OrgFileName)
		if err != nil {
			return nil, err
		}
		if found == "" {
			return DefaultOrg(), nil
		}
		path = found
	}
	o, err := decodeFile[Org](path)
	if err != nil {
		return nil, err
	}
	if o.APIVersion != APIVersion || o.Kind != KindOrg {
		return nil, fmt.Errorf("%s: expected apiVersion %q and kind %q", path, APIVersion, KindOrg)
	}
	o.Path, _ = filepath.Abs(path)
	if o.Signing.Key != "" && !strings.Contains(o.Signing.Key, "://") && !filepath.IsAbs(o.Signing.Key) {
		o.Signing.Key = filepath.Join(filepath.Dir(o.Path), o.Signing.Key)
	}
	if k := o.Signing.Verify.Key; k != "" && !strings.Contains(k, "://") && !filepath.IsAbs(k) {
		o.Signing.Verify.Key = filepath.Join(filepath.Dir(o.Path), k)
	}
	o.setDefaults()
	if err := o.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return o, nil
}

func findUp(dir, name string) (string, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	for {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		} else if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", nil
		}
		dir = parent
	}
}
