package manifest

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const (
	KindOrg     = "OrgProfile"
	OrgFileName = "factory.org.yaml"
)

// Org holds the choices that differ between organizations: where images go,
// how they are built, signed, scanned, and what policy they must meet.
type Org struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	// Extends is a shared org profile, published with clearcutt-factory
	// profile push (or this repository's own, by path), that this one
	// builds on: what it sets is fixed, this profile adds what it leaves to
	// each repository, and may tighten (never loosen) its gate and policy.
	// Each manifest's lock pins its digest.
	Extends         *Extends        `yaml:"extends,omitempty"`
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
	// Trust is the trust policy signing.trustPolicy names, once loaded.
	Trust *TrustPolicy `yaml:"-"`
	// Shared is the shared profile this one extends, once loaded.
	Shared *SharedProfile `yaml:"-"`
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
	// Config is a buildkitd.toml for the BuildKit container, relative to
	// this profile: registry mirrors, plain-HTTP or insecure registries, CA
	// certificates. Not with addr (configure that buildkitd instead).
	Config string `yaml:"config,omitempty"`
	// Network is the BuildKit container's network (docker or podman run
	// --network), e.g. host, so BuildKit reaches a registry on this
	// machine's localhost. Not with addr.
	Network string `yaml:"network,omitempty"`
}

type Signing struct {
	// Mode is keyless (Sigstore OIDC), key (file or KMS URI), or none.
	Mode string `yaml:"mode,omitempty"`
	// Key signs images in key mode: a file (relative to this profile) or a
	// cosign KMS URI.
	Key string `yaml:"key,omitempty"`
	// StackKey signs stacks (stack push) in key mode instead of Key, so
	// stacks can have a signer of their own (see Stacks).
	StackKey string   `yaml:"stackKey,omitempty"`
	Args     []string `yaml:"args,omitempty"`
	// Verify is who signs this repository's images. `verify --image`, the
	// already-published check, and repeating rebases verify against it.
	Verify VerifyIdentity `yaml:"verify,omitempty"`
	// Stacks is who may sign the stacks manifests here build on, for
	// policy.requireSignedStacks. Stacks usually come from a platform
	// repository, so they need their own signer; empty means Verify.
	Stacks VerifyIdentity `yaml:"stacks,omitempty"`
	// TrustPolicy is a ClearCutt trust policy file (apiVersion
	// clearcutt.dev/v1, kind TrustPolicy), relative to this profile, shared
	// with clearcutt-verify. When set, its image signers replace verify and
	// its stack signers replace stacks.
	TrustPolicy string `yaml:"trustPolicy,omitempty"`
	// Profile is who signs this profile when profile push publishes it, so
	// that pushing it unchanged only moves its tag. Repositories that
	// extend it trust the signers they name in extends, not this.
	Profile VerifyIdentity `yaml:"profile,omitempty"`
}

// VerifyIdentity is one signer: a public key, or a keyless certificate
// identity with its OIDC issuer.
//
// Images signed in ClearCutt Factory's reusable workflows carry the called
// workflow as their certificate identity, and any repository can call them,
// so a keyless identity should also say which repository's runs count:
// sourceRepository, or sourceMatchesImage (the repository the image names as
// its source), optionally limited to sourceRepositoryOwner. cosign checks
// the certificate's GitHub workflow repository against it.
type VerifyIdentity struct {
	Key                       string `yaml:"key,omitempty"`
	CertificateIdentity       string `yaml:"certificateIdentity,omitempty"`
	CertificateIdentityRegexp string `yaml:"certificateIdentityRegexp,omitempty"`
	CertificateOIDCIssuer     string `yaml:"certificateOIDCIssuer,omitempty"`
	// SourceRepository is the repository whose workflow runs sign, e.g.
	// https://github.com/acme/checkout.
	SourceRepository string `yaml:"sourceRepository,omitempty"`
	// SourceRepositoryOwner accepts runs in any of the owner's repositories,
	// e.g. https://github.com/acme; it limits sourceMatchesImage.
	SourceRepositoryOwner string `yaml:"sourceRepositoryOwner,omitempty"`
	// SourceMatchesImage requires the run to be in the repository the image
	// names as its source (org.opencontainers.image.source). Images only: a
	// stack names no source, so a stack signer binds with sourceRepository.
	SourceMatchesImage bool `yaml:"sourceMatchesImage,omitempty"`
	// SourceRef is the ref the run was on, e.g. refs/heads/main.
	SourceRef string   `yaml:"sourceRef,omitempty"`
	Args      []string `yaml:"args,omitempty"`
	// Tlog false accepts this key signer's signatures and attestations
	// without a transparency log entry (cosign --insecure-ignore-tlog),
	// for a key that signs without one. Keyless signers can't set it.
	Tlog *bool `yaml:"tlog,omitempty"`
}

// IsZero reports whether no signer is set.
func (v VerifyIdentity) IsZero() bool {
	return v.Key == "" && v.CertificateIdentity == "" && v.CertificateIdentityRegexp == "" && v.CertificateOIDCIssuer == "" && len(v.Args) == 0
}

// IgnoresTlog reports whether the signer is a key whose evidence is
// accepted without a transparency log entry (tlog: false).
func (v VerifyIdentity) IgnoresTlog() bool {
	return v.Key != "" && v.Tlog != nil && !*v.Tlog
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
	// VEX are VEX documents (OpenVEX, or CSAF), relative to this profile,
	// applied to every scan, as a manifest's spec.vex is to its own.
	VEX []string `yaml:"vex,omitempty"`
	// AllowLocalVEX, in a shared profile, also applies the VEX statements
	// of the repositories that extend it (their profile's vex and their
	// manifests' spec.vex), which are refused otherwise: a statement that a
	// vulnerability doesn't apply lets an image past the gate.
	AllowLocalVEX bool `yaml:"allowLocalVEX,omitempty"`

	// VEXFiles are VEX resolved against their profile.
	VEXFiles []string `yaml:"-"`
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
	// RequireSignedStacks requires stacks fetched from a registry to carry
	// a signature from the org's stack signer: signing.stacks (else
	// signing.verify), or the stack signers of signing.trustPolicy.
	RequireSignedStacks bool `yaml:"requireSignedStacks,omitempty"`
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

// validate checks the profile. A shared one (profile push) may leave
// signing.key to the repositories that extend it.
func (o *Org) validate(shared bool) error {
	var errs []error
	switch o.Signing.Mode {
	case "keyless", "none":
	case "key":
		if o.Signing.Key == "" && !shared {
			errs = append(errs, errors.New("signing.key is required when signing.mode is key"))
		}
	default:
		errs = append(errs, fmt.Errorf("signing.mode %q must be keyless, key, or none", o.Signing.Mode))
	}
	if o.Signing.StackKey != "" && o.Signing.Mode != "key" {
		errs = append(errs, errors.New("signing.stackKey is only used when signing.mode is key (stack push --key signs with a key in any mode)"))
	}
	switch o.Vulnerabilities.Scanner {
	case "grype", "none":
	default:
		errs = append(errs, fmt.Errorf("vulnerabilities.scanner %q must be grype or none", o.Vulnerabilities.Scanner))
	}
	if f := o.Vulnerabilities.FailOn; f != "" && SeverityRank(f) == 0 {
		errs = append(errs, fmt.Errorf("vulnerabilities.failOn %q must be negligible, low, medium, high, or critical", f))
	}
	for _, v := range []struct {
		name string
		v    VerifyIdentity
	}{{"signing.verify", o.Signing.Verify}, {"signing.stacks", o.Signing.Stacks}, {"signing.profile", o.Signing.Profile}} {
		if err := v.v.validate(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", v.name, err))
		}
	}
	// A stack names no source repository, so sourceMatchesImage can't bind
	// a stack's signature to a run: a stack signer names its repository.
	const imagesOnly = "sourceMatchesImage only applies to images (a stack names no source repository)"
	if o.Signing.Stacks.SourceMatchesImage {
		errs = append(errs, fmt.Errorf("signing.stacks: %s; use sourceRepository", imagesOnly))
	}
	if o.Signing.Profile.SourceMatchesImage {
		errs = append(errs, errors.New("signing.profile: sourceMatchesImage only applies to images (a profile names no source repository); use sourceRepository"))
	}
	for _, v := range o.Vulnerabilities.VEXFiles {
		if st, err := os.Stat(v); err != nil || st.IsDir() {
			errs = append(errs, fmt.Errorf("vulnerabilities.vex: %s is not a file", v))
		}
	}
	if o.Policy.RequireSignedStacks {
		switch {
		case o.Trust != nil:
			for i, s := range o.Trust.Signers {
				if s.SourceMatchesImage && s.may(RoleStack) {
					errs = append(errs, fmt.Errorf("policy.requireSignedStacks: signing.trustPolicy signers[%d] %s signs stacks, but %s; give stacks a signer with sourceRepository", i, s.Name, imagesOnly))
				}
			}
		case o.Signing.Stacks.IsZero() && o.Signing.Verify.SourceMatchesImage:
			errs = append(errs, fmt.Errorf("policy.requireSignedStacks: signing.verify signs stacks while signing.stacks is unset, but %s; set signing.stacks", imagesOnly))
		}
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
	if b := o.Builder; b.Addr != "" && (b.Config != "" || b.Network != "") {
		errs = append(errs, errors.New("builder.config and builder.network set up the BuildKit container factory starts; with builder.addr, configure that buildkitd instead"))
	}
	if c := o.Builder.Config; c != "" {
		if st, err := os.Stat(c); err != nil || st.IsDir() {
			errs = append(errs, fmt.Errorf("builder.config: %s is not a file", c))
		}
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
// factory.org.yaml at or above startDir. No profile yields defaults. A
// profile that extends a shared one can't be loaded without a
// ProfileLoader (LoadOrgWith).
func LoadOrg(path, startDir string) (*Org, error) {
	return LoadOrgWith(path, startDir, nil)
}

// LoadOrgWith is LoadOrg for a profile that may extend a shared one, which
// shared fetches and verifies.
func LoadOrgWith(path, startDir string, shared ProfileLoader) (*Org, error) {
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
	o, set, err := decodeOrg(path)
	if err != nil {
		return nil, err
	}
	if err := o.resolve(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if o.Extends != nil {
		if o, err = o.extend(shared, set); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	o.setDefaults()
	if err := o.validate(false); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return o, nil
}

// decodeOrg reads an org profile as written, and which keys it sets.
func decodeOrg(path string) (*Org, keySet, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	o, err := decodeBytes[Org](path, b)
	if err != nil {
		return nil, nil, err
	}
	if o.APIVersion != APIVersion || o.Kind != KindOrg {
		return nil, nil, fmt.Errorf("%s: expected apiVersion %q and kind %q", path, APIVersion, KindOrg)
	}
	if o.Path, err = filepath.Abs(path); err != nil {
		return nil, nil, err
	}
	return o, keysOf(b), nil
}

// resolve makes the files the profile names relative to it absolute, and
// loads its trust policy.
func (o *Org) resolve() error {
	dir := filepath.Dir(o.Path)
	o.Signing.Key = keyPath(dir, o.Signing.Key)
	o.Signing.StackKey = keyPath(dir, o.Signing.StackKey)
	o.Signing.Verify.Key = keyPath(dir, o.Signing.Verify.Key)
	o.Signing.Stacks.Key = keyPath(dir, o.Signing.Stacks.Key)
	o.Signing.Profile.Key = keyPath(dir, o.Signing.Profile.Key)
	if e := o.Extends; e != nil {
		e.Signer.Key = keyPath(dir, e.Signer.Key)
		e.Signers = slices.Clone(e.Signers)
		for i := range e.Signers {
			e.Signers[i].Key = keyPath(dir, e.Signers[i].Key)
		}
	}
	if c := o.Builder.Config; c != "" {
		o.Builder.Config = filePath(dir, c)
	}
	o.Vulnerabilities.VEXFiles = nil
	for _, v := range o.Vulnerabilities.VEX {
		o.Vulnerabilities.VEXFiles = append(o.Vulnerabilities.VEXFiles, filePath(dir, v))
	}
	if t := o.Signing.TrustPolicy; t != "" {
		o.Signing.TrustPolicy = filePath(dir, t)
		var err error
		if o.Trust, err = LoadTrustPolicy(o.Signing.TrustPolicy); err != nil {
			return fmt.Errorf("signing.trustPolicy: %w", err)
		}
	}
	return nil
}

// filePath resolves p relative to dir unless it is absolute.
func filePath(dir, p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(dir, p)
}

// keyPath resolves a key file relative to dir, the directory of the file
// that names it. KMS and other cosign URIs (with "://") stay as they are.
func keyPath(dir, k string) string {
	if k == "" || strings.Contains(k, "://") || filepath.IsAbs(k) {
		return k
	}
	return filepath.Join(dir, k)
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
