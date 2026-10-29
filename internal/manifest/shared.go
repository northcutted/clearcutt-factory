package manifest

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// A shared org profile is published as an OCI artifact of
// ProfileArtifactType: the profile (factory.org.yaml) and the files it
// names (its trust policy, public keys, and VEX documents), each a layer
// titled with its path inside the artifact.
const (
	ProfileArtifactType  = "application/vnd.clearcutt.factory.org-profile.v1"
	ProfileMediaType     = "application/vnd.clearcutt.factory.org-profile.v1+yaml"
	TrustPolicyMediaType = "application/vnd.clearcutt.trust-policy.v1+yaml"
	PublicKeyMediaType   = "application/vnd.clearcutt.public-key.v1"
	VEXMediaType         = "application/vnd.clearcutt.vex.v1"
	// TrustPolicyFile is the trust policy's name inside the artifact.
	TrustPolicyFile = "trust-policy.yaml"
)

// Extends names a shared org profile: a published one and who may sign
// it, or this repository's own by path.
type Extends struct {
	// Ref is the shared profile, e.g. ghcr.io/acme/factory/org:1. Each
	// manifest's lock pins the digest it resolved to, and lock --update
	// moves it.
	Ref string `yaml:"ref,omitempty"`
	// Path is a shared profile in this repository, relative to this
	// profile, e.g. org/profile.yaml: for the platform repository that
	// publishes it, so it builds on what it publishes. It is this
	// repository's own file, so it names no signer and isn't verified; the
	// same merge rules apply. It and the files it names must be inside the
	// repository. Each manifest's lock pins the digest profile push would
	// publish it at, so a lock goes stale when it changes. Set ref or path,
	// not both.
	Path string `yaml:"path,omitempty"`
	// Signer is who may sign the shared profile: a key, or a keyless
	// certificate identity and issuer. It is stated here because the shared
	// profile names every other signer; the profile is verified against it
	// whenever it is loaded. Signers names several instead.
	Signer VerifyIdentity `yaml:"signer,omitempty"`
	// Signers are who may sign the shared profile, any one of them, so that
	// its signer can be rotated: list the new signer beside the old, then
	// drop the old once every version still in use is signed by the new.
	// Set signer or signers, not both.
	Signers []VerifyIdentity `yaml:"signers,omitempty"`
}

// UnmarshalYAML explains a bare reference, and refuses unknown fields as
// the rest of the profile does.
func (e *Extends) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		return fmt.Errorf("line %d: extends needs ref and signer, e.g. extends: {ref: %s, signer: {certificateIdentity: …, certificateOIDCIssuer: …}}: who may sign the shared profile is stated here", n.Line, n.Value)
	}
	b, err := yaml.Marshal(n)
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	type plain Extends
	if err := dec.Decode((*plain)(e)); err != nil {
		return fmt.Errorf("extends (line %d): %w", n.Line, err)
	}
	return nil
}

// AllSigners returns who may sign the shared profile: signers, or signer
// as a list of one.
func (e Extends) AllSigners() []VerifyIdentity {
	if len(e.Signers) > 0 {
		return e.Signers
	}
	if !e.Signer.IsZero() {
		return []VerifyIdentity{e.Signer}
	}
	return nil
}

// SignerField names the field the signers come from, for messages.
func (e Extends) SignerField() string {
	if len(e.Signers) > 0 {
		return "any of extends.signers"
	}
	return "extends.signer"
}

// Name is the shared profile as written: its reference or its path.
func (e Extends) Name() string { return firstNonEmpty(e.Ref, e.Path) }

func (e Extends) validate() error {
	var errs []error
	switch {
	case e.Ref != "" && e.Path != "":
		return errors.New("set ref (a published shared profile) or path (this repository's own), not both")
	case e.Path != "":
		if !e.Signer.IsZero() || e.Signers != nil {
			errs = append(errs, errors.New("path names this repository's own shared profile, which isn't signed: remove signer and signers"))
		}
		if filepath.IsAbs(e.Path) {
			errs = append(errs, fmt.Errorf("path %s must be relative to this profile", e.Path))
		}
		return errors.Join(errs...)
	case e.Ref == "":
		errs = append(errs, errors.New("ref is required: the shared profile's reference, e.g. ghcr.io/acme/factory/org:1 (or path, for this repository's own)"))
	}
	check := func(name string, v VerifyIdentity) {
		switch {
		case v.IsZero():
			errs = append(errs, fmt.Errorf("%s names no signer (a key, or certificateIdentity and certificateOIDCIssuer)", name))
			return
		case v.SourceMatchesImage:
			errs = append(errs, fmt.Errorf("%s: sourceMatchesImage only applies to images (a profile names no source repository); use sourceRepository", name))
		}
		if err := v.validate(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
	}
	switch {
	case !e.Signer.IsZero() && e.Signers != nil:
		errs = append(errs, errors.New("set signer or signers, not both (signer is signers with one entry)"))
	case e.Signers != nil:
		if len(e.Signers) == 0 {
			errs = append(errs, errors.New("signers is empty: name who may sign the shared profile"))
		}
		for i, v := range e.Signers {
			check(fmt.Sprintf("signers[%d]", i), v)
		}
	case e.Signer.IsZero():
		errs = append(errs, errors.New("signer is required: who may sign the shared profile (a key, or certificateIdentity and certificateOIDCIssuer; signers for several); the shared profile can't say who signs it"))
	default:
		check("signer", e.Signer)
	}
	return errors.Join(errs...)
}

// SharedProfile is the shared profile an org profile was loaded with.
type SharedProfile struct {
	Ref  string // as written in extends.ref
	Path string // as written in extends.path
	// Digest is the artifact's: for Path, the digest profile push would
	// publish it at.
	Digest string
	File   string // its factory.org.yaml, unpacked with the files it names
}

// Name is the shared profile as written: its reference or its path.
func (s SharedProfile) Name() string { return firstNonEmpty(s.Ref, s.Path) }

// ProfileLoader fetches the shared profile e names, checks that one of
// e.AllSigners signed it, unpacks it, and returns the path of its
// factory.org.yaml and the artifact's digest. For extends.path, e.Path is
// absolute (and inside the repository), and the loader packs it as profile
// push would, verifying nothing.
type ProfileLoader func(e Extends) (path, digest string, err error)

// extend loads the shared profile o extends and merges o over it.
func (o *Org) extend(load ProfileLoader, set keySet) (*Org, error) {
	e := *o.Extends
	if err := e.validate(); err != nil {
		return nil, fmt.Errorf("extends: %w", err)
	}
	if load == nil {
		return nil, fmt.Errorf("extends %s: this command can't load a shared profile", e.Name())
	}
	le := e
	if e.Path != "" {
		var err error
		if le.Path, err = o.localShared(e.Path); err != nil {
			return nil, fmt.Errorf("extends %s: %w", e.Path, err)
		}
	}
	path, digest, err := load(le)
	if err != nil {
		return nil, fmt.Errorf("extends %s: %w", e.Name(), err)
	}
	s, err := ReadShared(path)
	if err != nil {
		return nil, fmt.Errorf("extends %s: %w", e.Name(), err)
	}
	out, err := extendWith(s, o, set)
	if err != nil {
		return nil, fmt.Errorf("extends %s, which this profile may only add to and tighten:\n%w", e.Name(), err)
	}
	out.Shared = &SharedProfile{Ref: e.Ref, Path: e.Path, Digest: digest, File: path}
	return out, nil
}

// localShared resolves extends.path p against o's directory and checks
// that the shared profile there, and every file it names, is inside the
// repository: the directory holding .git at or above o, else o's own
// directory. A profile extended by path is the repository's own file, so
// what applies is what the repository holds.
func (o *Org) localShared(p string) (string, error) {
	dir := filepath.Dir(o.Path)
	root := dir
	if g, err := findUp(dir, ".git"); err != nil {
		return "", err
	} else if g != "" {
		root = filepath.Dir(g)
	}
	abs := filepath.Join(dir, filepath.FromSlash(p))
	// Through symlinks too.
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	if r, err := filepath.Rel(realRoot, real); err != nil || !filepath.IsLocal(r) {
		return "", fmt.Errorf("%s is outside the repository (%s)", real, root)
	}
	s, _, err := decodeOrg(abs)
	if err != nil {
		return "", err
	}
	if err := s.resolve(); err != nil {
		return "", fmt.Errorf("%s: %w", abs, err)
	}
	if err := s.checkInside(root, "the repository"); err != nil {
		return "", fmt.Errorf("%s: %w", abs, err)
	}
	return abs, nil
}

// ReadShared reads a shared profile unpacked from its artifact, as written
// (no defaults), checking that every file it names is inside the artifact
// and that a repository can extend it.
func ReadShared(path string) (*Org, error) {
	s, _, err := decodeOrg(path)
	if err != nil {
		return nil, err
	}
	if err := s.resolve(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := errors.Join(s.checkInside(filepath.Dir(s.Path), "the shared profile"), s.checkShared()); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// checkInside requires every file the (resolved) profile names to be in
// dir, which is what, for messages.
func (o *Org) checkInside(dir, what string) error {
	files := map[string]string{"signing.trustPolicy": o.Signing.TrustPolicy}
	for name, v := range map[string]VerifyIdentity{"signing.verify": o.Signing.Verify, "signing.stacks": o.Signing.Stacks, "signing.profile": o.Signing.Profile} {
		files[name+".key"] = v.Key
	}
	for i, v := range o.Vulnerabilities.VEXFiles {
		files[fmt.Sprintf("vulnerabilities.vex[%d]", i)] = v
	}
	if o.Trust != nil {
		for i, s := range o.Trust.Signers {
			files[fmt.Sprintf("signing.trustPolicy signers[%d].key", i)] = s.Key
		}
	}
	var errs []error
	for _, name := range slices.Sorted(maps.Keys(files)) {
		p := files[name]
		if p == "" || strings.Contains(p, "://") {
			continue
		}
		if r, err := filepath.Rel(dir, p); err != nil || !filepath.IsLocal(r) {
			errs = append(errs, fmt.Errorf("%s: %s is outside %s", name, p, what))
		}
	}
	return errors.Join(errs...)
}

// checkShared refuses what a shared profile can't hold.
func (o *Org) checkShared() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if o.Extends != nil {
		add("a shared profile can't extend another (extends %s)", o.Extends.Name())
	}
	b := o.Builder
	for _, f := range []struct{ name, v string }{{"runtime", b.Runtime}, {"addr", b.Addr}, {"config", b.Config}, {"network", b.Network}} {
		if f.v != "" {
			add("builder.%s describes the machine that builds, not the organization: set it in each repository's profile", f.name)
		}
	}
	for _, k := range []struct{ name, v string }{{"signing.key", o.Signing.Key}, {"signing.stackKey", o.Signing.StackKey}} {
		if k.v != "" && !strings.Contains(k.v, "://") {
			add("%s is a key file, and a published profile can't carry a private key: name a KMS key (awskms://…, gcpkms://…, hashivault://…), or leave it to each repository's profile", k.name)
		}
	}
	if o.Policy.RequireSignedStacks && len(o.Signers(RoleStack)) == 0 {
		add("policy.requireSignedStacks: name the stack signer (signing.stacks, signing.verify, or stack signers in signing.trustPolicy) in the shared profile itself, so the repositories that extend it can't choose whose stacks to trust")
	}
	if o.Policy.RequireSignedBases && len(o.BaseSigners()) == 0 {
		add("policy.requireSignedBases: name the image signer of the repository that publishes the stacks' images (with sourceRepository) in the shared profile itself, so the repositories that extend it can't choose whose bases to trust")
	}
	return errors.Join(errs...)
}

// extendWith merges l, a repository's profile, over s, the shared profile
// it extends (both as written, with their files resolved). set holds the
// keys l's file sets. l may add what s leaves unset and tighten s's gate
// and policy; anything that would change or loosen s is an error, so what
// the repository's file says is what applies.
func extendWith(s, l *Org, set keySet) (*Org, error) {
	var errs []error
	refuse := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	const remove = "remove it here, or ask the shared profile's owners to leave it to each repository"
	def := DefaultOrg()

	// Set by the shared profile, else by this repository.
	str := func(name, sv, lv string) string {
		if sv != "" && lv != "" && sv != lv {
			refuse("%s: the shared profile sets %s; %s", name, sv, remove)
		}
		return firstNonEmpty(sv, lv)
	}
	list := func(name string, sv, lv []string) []string {
		if len(sv) > 0 && len(lv) > 0 && !slices.Equal(sv, lv) {
			refuse("%s: the shared profile sets [%s]; %s", name, strings.Join(sv, ", "), remove)
		}
		if len(sv) > 0 {
			return sv
		}
		return lv
	}
	signer := func(name string, sv, lv VerifyIdentity) VerifyIdentity {
		if !sv.IsZero() && !lv.IsZero() && !reflect.DeepEqual(sv, lv) {
			refuse("%s: the shared profile names this signer; %s", name, remove)
		}
		if !sv.IsZero() {
			return sv
		}
		return lv
	}
	// The shared profile's, or factory's default: never this repository's.
	fixed := func(name, sv, lv, dv string) string {
		if eff := firstNonEmpty(sv, dv); lv != "" && lv != eff {
			refuse("%s: the shared profile sets %s, and a repository can't change it", name, eff)
		}
		return sv
	}
	// Can only turn on.
	on := func(name string, sv, lv bool) bool {
		if sv && !lv && set[name] {
			refuse("%s: the shared profile turns it on, and a repository can't turn it off", name)
		}
		return sv || lv
	}
	// Can only turn off.
	off := func(name string, sv, lv bool) bool {
		if !set[name] {
			return sv
		}
		if lv && !sv {
			refuse("%s: the shared profile leaves it off, and a repository can't turn it on", name)
			return sv
		}
		return lv
	}
	// This repository's list, every entry within the shared profile's (an
	// empty list allows anything).
	within := func(name string, sv, lv []string, covers func(entry, allowed string) bool) []string {
		if len(lv) == 0 {
			return sv
		}
		for _, e := range lv {
			if len(sv) > 0 && !slices.ContainsFunc(sv, func(a string) bool { return covers(e, a) }) {
				refuse("%s: %s is outside the shared profile's [%s]", name, e, strings.Join(sv, ", "))
			}
		}
		return lv
	}

	out := &Org{APIVersion: l.APIVersion, Kind: l.Kind, Extends: l.Extends, Path: l.Path}
	out.Registry = str("registry", s.Registry, l.Registry)
	out.Tags = list("tags", s.Tags, l.Tags)
	out.Defaults.Base = str("defaults.base", s.Defaults.Base, l.Defaults.Base)
	out.Defaults.Platforms = list("defaults.platforms", s.Defaults.Platforms, l.Defaults.Platforms)
	out.Defaults.Labels = maps.Clone(s.Defaults.Labels)
	for _, k := range slices.Sorted(maps.Keys(l.Defaults.Labels)) {
		if sv, ok := s.Defaults.Labels[k]; ok && sv != l.Defaults.Labels[k] {
			refuse("defaults.labels: the shared profile sets %s to %q; %s", k, sv, remove)
			continue
		}
		if out.Defaults.Labels == nil {
			out.Defaults.Labels = map[string]string{}
		}
		out.Defaults.Labels[k] = l.Defaults.Labels[k]
	}
	out.Mirrors = s.Mirrors
	if len(s.Mirrors) == 0 {
		out.Mirrors = l.Mirrors
	} else if len(l.Mirrors) > 0 && !slices.Equal(s.Mirrors, l.Mirrors) {
		refuse("mirrors: the shared profile sets them; %s", remove)
	}

	b, sb, lb := &out.Builder, s.Builder, l.Builder
	b.BuildKit = fixed("builder.buildkit", sb.BuildKit, lb.BuildKit, def.Builder.BuildKit)
	b.Frontend = fixed("builder.frontend", sb.Frontend, lb.Frontend, def.Builder.Frontend)
	b.Toolbox = fixed("builder.toolbox", sb.Toolbox, lb.Toolbox, def.Builder.Toolbox)
	b.Go = fixed("builder.go", sb.Go, lb.Go, def.Builder.Go)
	b.Nix = fixed("builder.nix", sb.Nix, lb.Nix, def.Builder.Nix)
	b.Nixpkgs = fixed("builder.nixpkgs", sb.Nixpkgs, lb.Nixpkgs, def.Builder.Nixpkgs)
	// The machine that builds is this repository's: a shared profile
	// can't set these (checkShared).
	b.Runtime, b.Addr, b.Config, b.Network = lb.Runtime, lb.Addr, lb.Config, lb.Network

	g, sg, lg := &out.Signing, s.Signing, l.Signing
	g.Mode = fixed("signing.mode", sg.Mode, lg.Mode, def.Signing.Mode)
	g.Key = str("signing.key", sg.Key, lg.Key)
	g.StackKey = str("signing.stackKey", sg.StackKey, lg.StackKey)
	g.Args = list("signing.args", sg.Args, lg.Args)
	g.TrustPolicy, out.Trust, g.Profile = sg.TrustPolicy, s.Trust, sg.Profile
	if lg.TrustPolicy != "" {
		refuse("signing.trustPolicy: whom to trust comes from the shared profile; remove it here")
	}
	if !lg.Profile.IsZero() {
		refuse("signing.profile is who signs a profile you publish; this one extends another, whose signers are in extends")
	}
	switch {
	case s.Trust != nil:
		g.Verify, g.Stacks = sg.Verify, sg.Stacks
		for _, v := range []struct {
			name string
			v    VerifyIdentity
		}{{"signing.verify", lg.Verify}, {"signing.stacks", lg.Stacks}} {
			if !v.v.IsZero() {
				refuse("%s: the shared profile's trust policy names who signs images and stacks; remove it here", v.name)
			}
		}
	default:
		g.Verify = signer("signing.verify", sg.Verify, lg.Verify)
		switch {
		case !sg.Stacks.IsZero():
			g.Stacks = signer("signing.stacks", sg.Stacks, lg.Stacks)
		case !sg.Verify.IsZero() && !lg.Stacks.IsZero():
			refuse("signing.stacks: the shared profile's signing.verify signs stacks too (it sets no signing.stacks); remove it here")
		default:
			g.Stacks = lg.Stacks
		}
	}

	out.SBOM.Scan = s.SBOM.Scan
	if l.SBOM.Scan != nil {
		if scans := s.SBOM.Scan == nil || *s.SBOM.Scan; scans && !*l.SBOM.Scan {
			refuse("sbom.scan: the shared profile scans, and a repository can't turn it off")
		} else {
			out.SBOM.Scan = l.SBOM.Scan
		}
	}

	v, sv, lv := &out.Vulnerabilities, s.Vulnerabilities, l.Vulnerabilities
	v.Scanner = fixed("vulnerabilities.scanner", sv.Scanner, lv.Scanner, def.Vulnerabilities.Scanner)
	v.FailOn = sv.FailOn
	if lv.FailOn != "" {
		if sv.FailOn != "" && SeverityRank(lv.FailOn) > SeverityRank(sv.FailOn) {
			refuse("vulnerabilities.failOn: %s is looser than the shared profile's %s", lv.FailOn, sv.FailOn)
		} else {
			v.FailOn = lv.FailOn
		}
	}
	v.OnlyFixed = off("vulnerabilities.onlyFixed", sv.OnlyFixed, lv.OnlyFixed)
	v.AllowLocalVEX = off("vulnerabilities.allowLocalVEX", sv.AllowLocalVEX, lv.AllowLocalVEX)
	v.VEX, v.VEXFiles = slices.Clone(sv.VEX), slices.Clone(sv.VEXFiles)
	if len(lv.VEX) > 0 {
		if !v.AllowLocalVEX {
			refuse("vulnerabilities.vex: the shared profile doesn't take VEX statements from the repositories that extend it (vulnerabilities.allowLocalVEX); add them to the shared profile")
		} else {
			v.VEX, v.VEXFiles = append(v.VEX, lv.VEX...), append(v.VEXFiles, lv.VEXFiles...)
		}
	}

	p, sp, lp := &out.Policy, s.Policy, l.Policy
	p.RequireNonRoot = on("policy.requireNonRoot", sp.RequireNonRoot, lp.RequireNonRoot)
	p.RequireSignedStacks = on("policy.requireSignedStacks", sp.RequireSignedStacks, lp.RequireSignedStacks)
	p.RequireSignedBases = on("policy.requireSignedBases", sp.RequireSignedBases, lp.RequireSignedBases)
	p.RequiredLabels = slices.Clone(sp.RequiredLabels)
	for _, k := range lp.RequiredLabels {
		if !slices.Contains(p.RequiredLabels, k) {
			p.RequiredLabels = append(p.RequiredLabels, k)
		}
	}
	p.AllowTOFU = off("policy.allowTOFU", sp.AllowTOFU, lp.AllowTOFU)
	p.AllowedHosts = within("policy.allowedHosts", sp.AllowedHosts, lp.AllowedHosts, func(e, a string) bool {
		return e == a || (strings.HasPrefix(a, ".") && strings.HasSuffix(e, a))
	})
	p.AllowedRegistries = within("policy.allowedRegistries", sp.AllowedRegistries, lp.AllowedRegistries, func(e, a string) bool {
		return RegistryCovers(a, e)
	})
	p.RequireOfflineBuildTools = on("policy.requireOfflineBuildTools", sp.RequireOfflineBuildTools, lp.RequireOfflineBuildTools)
	return out, errors.Join(errs...)
}

// keySet holds the dotted paths of the keys a YAML file sets, two levels
// deep (policy, policy.allowTOFU), to tell a false it says from one it
// leaves out.
type keySet map[string]bool

func keysOf(b []byte) keySet {
	var doc yaml.Node
	if yaml.Unmarshal(b, &doc) != nil || len(doc.Content) == 0 {
		return keySet{}
	}
	set := keySet{}
	var walk func(n *yaml.Node, prefix string, depth int)
	walk = func(n *yaml.Node, prefix string, depth int) {
		if n.Kind == yaml.AliasNode {
			n = n.Alias
		}
		if n == nil || n.Kind != yaml.MappingNode || depth > 2 {
			return
		}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := prefix + n.Content[i].Value
			set[k] = true
			walk(n.Content[i+1], k+".", depth+1)
		}
	}
	walk(doc.Content[0], "", 1)
	return set
}

// BundledFile is one file of a shared profile's artifact.
type BundledFile struct {
	Name      string // inside the artifact
	MediaType string
	Content   []byte
}

// PackProfile reads the org profile at path for profile push. It checks
// that repositories can extend it, and returns it as loaded (with
// defaults) and as files to publish: the profile, then the files it names
// (its trust policy, public keys, and VEX documents), renamed to paths
// inside the artifact. The files depend only on the profile's content, so
// an unchanged profile publishes to the same digest.
func PackProfile(path string) (*Org, []BundledFile, error) {
	o, _, err := decodeOrg(path)
	if err != nil {
		return nil, nil, err
	}
	if o.Extends != nil {
		return nil, nil, fmt.Errorf("%s extends %s: a shared profile can't extend another; publish that one, or this one without extends", path, o.Extends.Name())
	}
	if err := o.resolve(); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := o.checkShared(); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	loaded := *o
	loaded.setDefaults()
	if err := loaded.validate(true); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}

	// Publish the profile as written (what it leaves unset stays unset, to
	// each repository), with its files renamed.
	pub, _, err := decodeOrg(path)
	if err != nil {
		return nil, nil, err
	}
	var bd bundle
	for _, v := range []struct{ pub, abs *VerifyIdentity }{
		{&pub.Signing.Verify, &o.Signing.Verify}, {&pub.Signing.Stacks, &o.Signing.Stacks}, {&pub.Signing.Profile, &o.Signing.Profile},
	} {
		if v.pub.Key, err = bd.key(v.abs.Key); err != nil {
			return nil, nil, err
		}
	}
	if o.Trust != nil {
		t := *o.Trust
		t.Signers = slices.Clone(t.Signers)
		for i := range t.Signers {
			if t.Signers[i].Key, err = bd.key(t.Signers[i].Key); err != nil {
				return nil, nil, err
			}
		}
		bd.files = append(bd.files, BundledFile{TrustPolicyFile, TrustPolicyMediaType, marshalYAML(t)})
		pub.Signing.TrustPolicy = TrustPolicyFile
	}
	for i, v := range o.Vulnerabilities.VEXFiles {
		if pub.Vulnerabilities.VEX[i], err = bd.file("vex", v, VEXMediaType); err != nil {
			return nil, nil, err
		}
	}
	files := append([]BundledFile{{OrgFileName, ProfileMediaType, marshalYAML(pub)}}, bd.files...)
	return &loaded, files, nil
}

// bundle collects the files a published profile names.
type bundle struct{ files []BundledFile }

// key adds a public key file; a KMS or other cosign URI stays as it is.
func (b *bundle) key(p string) (string, error) {
	if p == "" || strings.Contains(p, "://") {
		return p, nil
	}
	return b.file("keys", p, PublicKeyMediaType)
}

// file adds the file at p under dir, by its base name (numbered when
// another file has that name), and returns its name in the artifact.
func (b *bundle) file(dir, p, mediaType string) (string, error) {
	content, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	if mediaType == PublicKeyMediaType && bytes.Contains(content, []byte("PRIVATE KEY")) {
		return "", fmt.Errorf("%s is a private key; a published profile names public keys", p)
	}
	base := filepath.Base(p)
	for i := 1; ; i++ {
		name := dir + "/" + base
		if i > 1 {
			name = fmt.Sprintf("%s/%d-%s", dir, i, base)
		}
		j := slices.IndexFunc(b.files, func(f BundledFile) bool { return f.Name == name })
		if j < 0 {
			b.files = append(b.files, BundledFile{name, mediaType, content})
			return name, nil
		}
		if bytes.Equal(b.files[j].Content, content) {
			return name, nil
		}
	}
}

func marshalYAML(v any) []byte {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	_ = enc.Encode(v)
	return buf.Bytes()
}
