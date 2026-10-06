// Package manifest defines the user-facing manifests (image.yaml for images,
// app.yaml for apps built on a stack), stacks, and the org profile
// (factory.org.yaml), and loads them with extends/default merging.
package manifest

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

const (
	APIVersion = "factory.clearcutt.dev/v1alpha1"
	KindImage  = "Image"
)

// Manifest is the intent: what the image should contain. Versions may be loose;
// the lockfile pins everything.
type Manifest struct {
	APIVersion string   `yaml:"apiVersion" json:"apiVersion"`
	Kind       string   `yaml:"kind" json:"kind"`
	Extends    string   `yaml:"extends,omitempty" json:"-"`
	Metadata   Metadata `yaml:"metadata" json:"metadata"`
	Spec       Spec     `yaml:"spec" json:"spec"`

	// Path is the absolute path of the top-level manifest file.
	Path string `yaml:"-" json:"-"`
	// Stack is the loaded stack of an App (set by ApplyOrg).
	Stack *Stack `yaml:"-" json:"-"`
	// StackFrom is set when spec.stack names a registry artifact: the
	// reference and the digest it was fetched at, with StackPath pointing
	// at the fetched file.
	StackFrom *StackArtifact `yaml:"-" json:"-"`
}

type Metadata struct {
	Name string   `yaml:"name" json:"name"`
	Ref  string   `yaml:"ref,omitempty" json:"ref,omitempty"`
	Tags []string `yaml:"tags,omitempty" json:"tags,omitempty"`
}

type Spec struct {
	Base      string   `yaml:"base,omitempty" json:"base,omitempty"`
	Platforms []string `yaml:"platforms,omitempty" json:"platforms,omitempty"`
	// PackageManager overrides detection from the base image: apk, apt, or dnf.
	PackageManager string            `yaml:"packageManager,omitempty" json:"packageManager,omitempty"`
	Repositories   []string          `yaml:"repositories,omitempty" json:"repositories,omitempty"`
	Packages       []string          `yaml:"packages,omitempty" json:"packages,omitempty"`
	Tools          []Tool            `yaml:"tools,omitempty" json:"tools,omitempty"`
	Files          []File            `yaml:"files,omitempty" json:"files,omitempty"`
	Env            map[string]string `yaml:"env,omitempty" json:"env,omitempty"`
	Labels         map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
	User           string            `yaml:"user,omitempty" json:"user,omitempty"`
	Workdir        string            `yaml:"workdir,omitempty" json:"workdir,omitempty"`
	Entrypoint     []string          `yaml:"entrypoint,omitempty" json:"entrypoint,omitempty"`
	Cmd            []string          `yaml:"cmd,omitempty" json:"cmd,omitempty"`
	VEX            []string          `yaml:"vex,omitempty" json:"vex,omitempty"`
	// Test is a smoke test run in each built or rebased platform image
	// before anything is pushed.
	Test *Test `yaml:"test,omitempty" json:"test,omitempty"`

	// App only: the stack to build with (a stack file, or a stack
	// published with clearcutt-factory stack push, by reference), the source
	// directory (default:
	// the manifest's directory), source paths to leave out, and variables
	// for the stack's build steps.
	Stack    string            `yaml:"stack,omitempty" json:"stack,omitempty"`
	Source   string            `yaml:"source,omitempty" json:"source,omitempty"`
	Exclude  []string          `yaml:"exclude,omitempty" json:"exclude,omitempty"`
	BuildEnv map[string]string `yaml:"buildEnv,omitempty" json:"buildEnv,omitempty"`

	// StackPath and SourceDir are Stack and Source resolved against their
	// declaring manifest.
	StackPath string `yaml:"-" json:"-"`
	SourceDir string `yaml:"-" json:"-"`
	// VEXFiles are the VEX paths resolved against their declaring manifest.
	VEXFiles []string `yaml:"-" json:"-"`
	// Mirrors are the org's download URL rewrites, applied when rendering.
	Mirrors []Mirror `yaml:"-" json:"-"`
}

// Tool sources.
const (
	FromURL           = "url"
	FromGitHubRelease = "github-release"
	FromOCI           = "oci"
	FromGo            = "go"
	FromNix           = "nix"
	FromBuild         = "build"
)

// Tool is anything not installed from the distro's package repository.
type Tool struct {
	Name    string `yaml:"name" json:"name"`
	From    string `yaml:"from" json:"from"`
	Version string `yaml:"version,omitempty" json:"version,omitempty"`

	// url
	URL      string  `yaml:"url,omitempty" json:"url,omitempty"`
	SHA256   ArchMap `yaml:"sha256,omitempty" json:"sha256,omitempty"`
	Checksum string  `yaml:"checksum,omitempty" json:"checksum,omitempty"`

	// github-release
	Repo      string `yaml:"repo,omitempty" json:"repo,omitempty"`
	Tag       string `yaml:"tag,omitempty" json:"tag,omitempty"`
	Asset     string `yaml:"asset,omitempty" json:"asset,omitempty"`
	Checksums string `yaml:"checksums,omitempty" json:"checksums,omitempty"`

	// url + github-release
	Extract string            `yaml:"extract,omitempty" json:"extract,omitempty"`
	ArchMap map[string]string `yaml:"archMap,omitempty" json:"archMap,omitempty"`

	// oci: source image; go/build: builder image
	Image string `yaml:"image,omitempty" json:"image,omitempty"`
	Path  string `yaml:"path,omitempty" json:"path,omitempty"`

	// go: Go package path; nix: nixpkgs attribute (e.g. ripgrep, python3Packages.black)
	Package string `yaml:"package,omitempty" json:"package,omitempty"`

	// nix: NixOS/nixpkgs branch, tag, or commit, or a full github: flake ref
	Nixpkgs string `yaml:"nixpkgs,omitempty" json:"nixpkgs,omitempty"`

	// build
	Run string `yaml:"run,omitempty" json:"run,omitempty"`

	Dest string `yaml:"dest,omitempty" json:"dest,omitempty"`
	Mode string `yaml:"mode,omitempty" json:"mode,omitempty"`
}

// Test is a smoke test: Command must exit 0, or, with HTTP, the container
// (running Command, else its own entrypoint) must answer an HTTP request
// with a non-error status, within Timeout.
type Test struct {
	Command []string  `yaml:"command,omitempty" json:"command,omitempty"`
	HTTP    *HTTPTest `yaml:"http,omitempty" json:"http,omitempty"`
	// Timeout is a duration like 30s (default 60s; emulated platforms are slow).
	Timeout string `yaml:"timeout,omitempty" json:"timeout,omitempty"`
}

// HTTPTest probes a port the container listens on.
type HTTPTest struct {
	Port int    `yaml:"port" json:"port"`
	Path string `yaml:"path,omitempty" json:"path,omitempty"`
}

// DefaultTestTimeout bounds a smoke test without a timeout.
const DefaultTestTimeout = 60 * time.Second

// TimeoutOrDefault parses Timeout.
func (t *Test) TimeoutOrDefault() time.Duration {
	if d, err := time.ParseDuration(t.Timeout); err == nil && d > 0 {
		return d
	}
	return DefaultTestTimeout
}

func (t *Test) validate() error {
	var errs []error
	if len(t.Command) == 0 && t.HTTP == nil {
		errs = append(errs, errors.New("spec.test needs a command, http, or both"))
	}
	if t.HTTP != nil && (t.HTTP.Port <= 0 || t.HTTP.Port > 65535) {
		errs = append(errs, fmt.Errorf("spec.test.http.port %d is not a port", t.HTTP.Port))
	}
	if t.Timeout != "" {
		if d, err := time.ParseDuration(t.Timeout); err != nil || d <= 0 {
			errs = append(errs, fmt.Errorf("spec.test.timeout %q must be a duration like 30s", t.Timeout))
		}
	}
	return errors.Join(errs...)
}

// File copies a file or directory from next to the manifest into the image.
type File struct {
	Src  string `yaml:"src" json:"src"`
	Dst  string `yaml:"dst" json:"dst"`
	Mode string `yaml:"mode,omitempty" json:"mode,omitempty"`

	// AbsSrc is Src resolved against the directory of the manifest that declared it.
	AbsSrc string `yaml:"-" json:"-"`
}

// ArchMap is either a single value for every architecture or a per-arch map.
// In YAML: `sha256: abc…` or `sha256: {amd64: abc…, arm64: def…}`.
type ArchMap map[string]string

const anyArch = "*"

func (a *ArchMap) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		*a = ArchMap{anyArch: n.Value}
		return nil
	case yaml.MappingNode:
		m := map[string]string{}
		if err := n.Decode(&m); err != nil {
			return err
		}
		*a = m
		return nil
	}
	return fmt.Errorf("line %d: expected a string or an arch→value map", n.Line)
}

// Get returns the value for arch, falling back to the any-arch value.
func (a ArchMap) Get(arch string) string {
	if v, ok := a[arch]; ok {
		return v
	}
	return a[anyArch]
}

// Load reads a manifest, applies its extends chain, and validates it.
func Load(path string) (*Manifest, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	m, err := loadChain(abs, nil)
	if err != nil {
		return nil, err
	}
	m.Path = abs
	if m.Kind == KindApp && m.Spec.SourceDir == "" {
		m.Spec.SourceDir = filepath.Dir(abs)
	}
	return m, nil
}

func loadChain(path string, seen []string) (*Manifest, error) {
	if slices.Contains(seen, path) {
		return nil, fmt.Errorf("extends cycle: %s", strings.Join(append(seen, path), " → "))
	}
	m, err := decodeFile[Manifest](path)
	if err != nil {
		return nil, err
	}
	if m.APIVersion != APIVersion || (m.Kind != KindImage && m.Kind != KindApp) {
		return nil, fmt.Errorf("%s: expected apiVersion %q and kind %q or %q", path, APIVersion, KindImage, KindApp)
	}
	dir := filepath.Dir(path)
	if IsStackFile(m.Spec.Stack) {
		m.Spec.StackPath = filepath.Join(dir, m.Spec.Stack)
	}
	if m.Spec.Source != "" {
		m.Spec.SourceDir = filepath.Join(dir, m.Spec.Source)
	}
	for i := range m.Spec.Files {
		m.Spec.Files[i].AbsSrc = filepath.Join(dir, m.Spec.Files[i].Src)
	}
	for _, v := range m.Spec.VEX {
		m.Spec.VEXFiles = append(m.Spec.VEXFiles, filepath.Join(dir, v))
	}
	if m.Extends == "" {
		return m, nil
	}
	parent, err := loadChain(filepath.Join(dir, m.Extends), append(seen, path))
	if err != nil {
		return nil, err
	}
	if parent.Kind != m.Kind {
		return nil, fmt.Errorf("%s: extends a %s; a %s can only extend a %s", path, parent.Kind, m.Kind, m.Kind)
	}
	merged := merge(parent, m)
	return merged, nil
}

// merge overlays child on parent. Scalars and the platform list are replaced,
// maps are merged, packages/files/vex are appended, tools are merged by name.
func merge(parent, child *Manifest) *Manifest {
	out := *child
	p, c := parent.Spec, child.Spec
	s := &out.Spec
	s.Base = firstNonEmpty(c.Base, p.Base)
	s.Stack, s.StackPath = firstNonEmpty(c.Stack, p.Stack), firstNonEmpty(c.StackPath, p.StackPath)
	s.Source, s.SourceDir = firstNonEmpty(c.Source, p.Source), firstNonEmpty(c.SourceDir, p.SourceDir)
	s.Exclude = append(slices.Clone(p.Exclude), c.Exclude...)
	s.BuildEnv = mergeMaps(p.BuildEnv, c.BuildEnv)
	s.User = firstNonEmpty(c.User, p.User)
	s.Workdir = firstNonEmpty(c.Workdir, p.Workdir)
	if len(c.Platforms) == 0 {
		s.Platforms = p.Platforms
	}
	if len(c.Repositories) == 0 {
		s.Repositories = p.Repositories
	}
	if len(c.Entrypoint) == 0 {
		s.Entrypoint = p.Entrypoint
	}
	if len(c.Cmd) == 0 {
		s.Cmd = p.Cmd
	}
	if c.Test == nil {
		s.Test = p.Test
	}
	s.Packages = append(slices.Clone(p.Packages), c.Packages...)
	s.Files = append(slices.Clone(p.Files), c.Files...)
	s.VEX = append(slices.Clone(p.VEX), c.VEX...)
	s.VEXFiles = append(slices.Clone(p.VEXFiles), c.VEXFiles...)
	s.Env = mergeMaps(p.Env, c.Env)
	s.Labels = mergeMaps(p.Labels, c.Labels)

	s.Tools = slices.Clone(p.Tools)
	for _, t := range c.Tools {
		if i := slices.IndexFunc(s.Tools, func(x Tool) bool { return x.Name == t.Name }); i >= 0 {
			s.Tools[i] = t
		} else {
			s.Tools = append(s.Tools, t)
		}
	}
	return &out
}

// ApplyOrg fills manifest gaps from the stack (for apps) and the org
// profile, and validates the result.
func (m *Manifest) ApplyOrg(o *Org) error {
	if m.Kind == KindApp {
		if err := m.applyStack(o); err != nil {
			return err
		}
	}
	if m.Metadata.Ref == "" && o.Registry != "" {
		m.Metadata.Ref = strings.TrimSuffix(o.Registry, "/") + "/" + m.Metadata.Name
	}
	for _, t := range o.Tags {
		if !slices.Contains(m.Metadata.Tags, t) {
			m.Metadata.Tags = append(m.Metadata.Tags, t)
		}
	}
	if m.Spec.Base == "" {
		m.Spec.Base = o.Defaults.Base
	}
	m.Spec.Mirrors = o.Mirrors
	if len(m.Spec.Platforms) == 0 {
		m.Spec.Platforms = o.Defaults.Platforms
	}
	if len(m.Spec.Platforms) == 0 {
		m.Spec.Platforms = []string{"linux/amd64", "linux/arm64"}
	}
	m.Spec.Labels = mergeMaps(o.Defaults.Labels, m.Spec.Labels)
	for i := range m.Spec.Tools {
		t := &m.Spec.Tools[i]
		if t.From == FromGo && t.Image == "" {
			t.Image = o.Builder.Go
		}
		if t.From == FromNix {
			if t.Image == "" {
				t.Image = o.Builder.Nix
			}
			if t.Nixpkgs == "" {
				t.Nixpkgs = o.Builder.Nixpkgs
			}
		}
	}
	return m.validate()
}

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

func (m *Manifest) validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if !nameRE.MatchString(m.Metadata.Name) {
		add("metadata.name %q must match %s", m.Metadata.Name, nameRE)
	}
	if m.Metadata.Ref == "" {
		add("metadata.ref is required (or set registry in the org profile)")
	}
	if m.Spec.Base == "" {
		add("spec.base is required")
	}
	switch m.Spec.PackageManager {
	case "", "apk", "apt", "dnf":
	default:
		add("spec.packageManager %q must be apk, apt, or dnf", m.Spec.PackageManager)
	}
	if m.Kind == KindApp {
		// An app adds only its build output, so it can be rebased.
		for _, f := range []struct {
			name string
			set  bool
		}{
			{"packages", len(m.Spec.Packages) > 0}, {"tools", len(m.Spec.Tools) > 0}, {"files", len(m.Spec.Files) > 0},
			{"repositories", len(m.Spec.Repositories) > 0}, {"packageManager", m.Spec.PackageManager != ""},
		} {
			if f.set {
				add("spec.%s is not allowed for kind App; put it in the stack's run image", f.name)
			}
		}
		if st, err := os.Stat(m.Spec.SourceDir); err != nil || !st.IsDir() {
			add("spec.source: %s is not a directory", m.Spec.SourceDir)
		}
	} else if m.Spec.Stack != "" || m.Spec.Source != "" || len(m.Spec.Exclude) > 0 || len(m.Spec.BuildEnv) > 0 {
		add("spec.stack, source, exclude, and buildEnv are only for kind App")
	}
	arches := map[string]bool{}
	for _, p := range m.Spec.Platforms {
		if _, arch, ok := SplitPlatform(p); ok {
			if arches[arch] {
				add("platforms: %s appears twice; each architecture may be built once", arch)
			}
			arches[arch] = true
		}
	}
	for _, p := range m.Spec.Platforms {
		if _, _, ok := SplitPlatform(p); !ok {
			add("platform %q must look like linux/amd64", p)
		}
	}
	seen := map[string]bool{}
	for i, t := range m.Spec.Tools {
		where := fmt.Sprintf("spec.tools[%d] (%s)", i, t.Name)
		if !nameRE.MatchString(t.Name) {
			add("%s: name must match %s", where, nameRE)
		}
		if seen[t.Name] {
			add("%s: duplicate tool name", where)
		}
		seen[t.Name] = true
		need := func(field, v string) {
			if v == "" {
				add("%s: %s is required for from: %s", where, field, t.From)
			}
		}
		switch t.From {
		case FromURL:
			need("url", t.URL)
		case FromGitHubRelease:
			need("repo", t.Repo)
			need("version", t.Version)
			need("asset", t.Asset)
		case FromOCI:
			need("image", t.Image)
			need("path", t.Path)
		case FromGo:
			need("package", t.Package)
			need("image", t.Image)
		case FromNix:
			need("package", t.Package)
		case FromBuild:
			need("image", t.Image)
			need("run", t.Run)
		default:
			add("%s: from must be one of url, github-release, oci, go, nix, build", where)
		}
		if t.Mode != "" && !modeRE.MatchString(t.Mode) {
			add("%s: mode %q must be octal like 0755", where, t.Mode)
		}
	}
	if m.Spec.Test != nil {
		if err := m.Spec.Test.validate(); err != nil {
			errs = append(errs, err)
		}
	}
	for i, f := range m.Spec.Files {
		if f.Src == "" || f.Dst == "" || !strings.HasPrefix(f.Dst, "/") {
			add("spec.files[%d]: src and an absolute dst are required", i)
			continue
		}
		if _, err := os.Stat(f.AbsSrc); err != nil {
			add("spec.files[%d]: %v", i, err)
		}
		if f.Mode != "" && !modeRE.MatchString(f.Mode) {
			add("spec.files[%d]: mode %q must be octal like 0644", i, f.Mode)
		}
	}
	return errors.Join(errs...)
}

var modeRE = regexp.MustCompile(`^0?[0-7]{3,4}$`)

// EffectiveYAML renders the merged, defaulted manifest (and an app's stack)
// for attestation.
func (m *Manifest) EffectiveYAML() []byte {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	var stack *StackDoc
	if m.Stack != nil {
		stack = &StackDoc{Metadata: m.Stack.Metadata, Spec: m.Stack.Spec}
	}
	_ = enc.Encode(struct {
		APIVersion string    `yaml:"apiVersion"`
		Kind       string    `yaml:"kind"`
		Metadata   Metadata  `yaml:"metadata"`
		Spec       Spec      `yaml:"spec"`
		Stack      *StackDoc `yaml:"stack,omitempty"`
	}{m.APIVersion, m.Kind, m.Metadata, m.Spec, stack})
	return buf.Bytes()
}

// StackDoc is the stack as embedded in an app's effective manifest.
type StackDoc struct {
	Metadata StackMetadata `yaml:"metadata"`
	Spec     StackSpec     `yaml:"spec"`
}

// Dir is the directory holding the top-level manifest.
func (m *Manifest) Dir() string { return filepath.Dir(m.Path) }

// Stem is the manifest filename without extension; sibling files derive from it
// (image.yaml → image.lock.yaml, image.Containerfile).
func (m *Manifest) Stem() string {
	base := filepath.Base(m.Path)
	return strings.TrimSuffix(strings.TrimSuffix(base, ".yaml"), ".yml")
}

func (m *Manifest) LockPath() string {
	return filepath.Join(m.Dir(), m.Stem()+".lock.yaml")
}

func (m *Manifest) ContainerfilePath() string {
	return filepath.Join(m.Dir(), m.Stem()+".Containerfile")
}

// SplitPlatform splits "linux/amd64" into os and arch.
func SplitPlatform(p string) (os, arch string, ok bool) {
	os, arch, ok = strings.Cut(p, "/")
	return os, arch, ok && os != "" && arch != "" && !strings.Contains(arch, "/")
}

func decodeFile[T any](path string) (*T, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var v T
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &v, nil
}

func mergeMaps(a, b map[string]string) map[string]string {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	out := make(map[string]string, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
