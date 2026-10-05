package manifest

import (
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"strings"
)

const (
	KindApp   = "App"
	KindStack = "Stack"
)

// Stack is a platform team's recipe for building apps: the image the build
// runs in, the image apps ship on, the build steps, and defaults for the
// app's configuration. Apps name a stack and add little more than their
// source.
type Stack struct {
	APIVersion string        `yaml:"apiVersion" json:"apiVersion"`
	Kind       string        `yaml:"kind" json:"kind"`
	Metadata   StackMetadata `yaml:"metadata" json:"metadata"`
	Spec       StackSpec     `yaml:"spec" json:"spec"`

	// Path is the absolute path of the stack file.
	Path string `yaml:"-" json:"-"`
	// BuildRef and RunRef are Spec.Build and Spec.Run as image references.
	BuildRef string `yaml:"-" json:"-"`
	RunRef   string `yaml:"-" json:"-"`
}

type StackMetadata struct {
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

type StackSpec struct {
	// Build is the image the steps run in, and Run the image apps ship on:
	// each an image reference, or the path of a factory manifest
	// (image.yaml) whose published image to use.
	Build     string   `yaml:"build" json:"build"`
	Run       string   `yaml:"run" json:"run"`
	Platforms []string `yaml:"platforms,omitempty" json:"platforms,omitempty"`
	// CrossCompile runs the steps on the build machine's platform, once per
	// target, with TARGETOS and TARGETARCH set (for toolchains that cross
	// compile, like Go). Otherwise they run on each target platform.
	CrossCompile bool `yaml:"crossCompile,omitempty" json:"crossCompile,omitempty"`
	// BuildEnv is set for the steps; apps add to it.
	BuildEnv map[string]string `yaml:"buildEnv,omitempty" json:"buildEnv,omitempty"`
	// Caches are directories kept between builds (BuildKit cache mounts),
	// e.g. /root/.cache/go-build. Rebuilds without cache must give the
	// same result.
	Caches []string `yaml:"caches,omitempty" json:"caches,omitempty"`
	// Steps run in the app's source (/src) and write the app to /out.
	Steps []Step `yaml:"steps" json:"steps"`
	// AppDir is where /out lands in the run image (default /app). The app
	// adds nothing else, which is what lets factory rebase it.
	AppDir string `yaml:"appDir,omitempty" json:"appDir,omitempty"`

	// Defaults for apps; {{name}} is the app's name.
	Env        map[string]string `yaml:"env,omitempty" json:"env,omitempty"`
	Labels     map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
	User       string            `yaml:"user,omitempty" json:"user,omitempty"`
	Workdir    string            `yaml:"workdir,omitempty" json:"workdir,omitempty"`
	Entrypoint []string          `yaml:"entrypoint,omitempty" json:"entrypoint,omitempty"`
	Cmd        []string          `yaml:"cmd,omitempty" json:"cmd,omitempty"`
	// Test is the default smoke test for apps.
	Test *Test `yaml:"test,omitempty" json:"test,omitempty"`
}

// Step is one build command (a shell script).
type Step struct {
	Run string `yaml:"run" json:"run"`
}

// DefaultAppDir is where an app's files go unless the stack says otherwise.
const DefaultAppDir = "/app"

// LoadStack reads and validates a stack file.
func LoadStack(p string) (*Stack, error) {
	s, err := decodeFile[Stack](p)
	if err != nil {
		return nil, err
	}
	if s.APIVersion != APIVersion || s.Kind != KindStack {
		return nil, fmt.Errorf("%s: expected apiVersion %q and kind %q", p, APIVersion, KindStack)
	}
	s.Path = p
	if s.Spec.AppDir == "" {
		s.Spec.AppDir = DefaultAppDir
	}
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if !nameRE.MatchString(s.Metadata.Name) {
		add("metadata.name %q must match %s", s.Metadata.Name, nameRE)
	}
	if s.Spec.Build == "" {
		add("spec.build is required")
	}
	if s.Spec.Run == "" {
		add("spec.run is required")
	}
	if len(s.Spec.Steps) == 0 {
		add("spec.steps is required")
	}
	for i, st := range s.Spec.Steps {
		if strings.TrimSpace(st.Run) == "" {
			add("spec.steps[%d]: run is required", i)
		}
	}
	if d := s.Spec.AppDir; !path.IsAbs(d) || path.Clean(d) == "/" {
		add("spec.appDir %q must be an absolute directory other than /", d)
	}
	for _, c := range s.Spec.Caches {
		if !path.IsAbs(c) {
			add("spec.caches: %q must be absolute", c)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	return s, nil
}

// imageRef resolves a stack's build or run image: an image reference as is,
// or a factory manifest's published reference and first tag.
func (s *Stack) imageRef(v string, o *Org) (string, error) {
	if !strings.HasSuffix(v, ".yaml") && !strings.HasSuffix(v, ".yml") {
		return v, nil
	}
	m, err := Load(filepath.Join(filepath.Dir(s.Path), v))
	if err != nil {
		return "", err
	}
	if m.Kind != KindImage {
		return "", fmt.Errorf("%s is a %s; a stack's images must be kind %s", v, m.Kind, KindImage)
	}
	if err := m.ApplyOrg(o); err != nil {
		return "", fmt.Errorf("%s: %w", v, err)
	}
	tag := "latest"
	if len(m.Metadata.Tags) > 0 {
		tag = m.Metadata.Tags[0]
	}
	return m.Metadata.Ref + ":" + tag, nil
}

// applyStack loads the app's stack and fills the app's base and defaults
// from it. App values win over the stack's.
func (m *Manifest) applyStack(o *Org) error {
	if m.Spec.StackPath == "" {
		return errors.New("spec.stack is required for kind App")
	}
	if m.Spec.Base != "" {
		return errors.New("spec.base is not allowed for kind App; the stack's run image is the base")
	}
	st, err := LoadStack(m.Spec.StackPath)
	if err != nil {
		return err
	}
	if st.RunRef, err = st.imageRef(st.Spec.Run, o); err != nil {
		return err
	}
	if st.BuildRef, err = st.imageRef(st.Spec.Build, o); err != nil {
		return err
	}
	m.Stack = st
	s := &m.Spec
	s.Base = st.RunRef
	if len(s.Platforms) == 0 {
		s.Platforms = st.Spec.Platforms
	}
	s.Env = mergeMaps(st.Spec.Env, s.Env)
	s.Labels = mergeMaps(st.Spec.Labels, s.Labels)
	s.BuildEnv = mergeMaps(st.Spec.BuildEnv, s.BuildEnv)
	s.User = firstNonEmpty(s.User, st.Spec.User)
	s.Workdir = firstNonEmpty(s.Workdir, st.Spec.Workdir)
	if len(s.Entrypoint) == 0 {
		s.Entrypoint = st.Spec.Entrypoint
	}
	if len(s.Cmd) == 0 {
		s.Cmd = st.Spec.Cmd
	}
	if s.Test == nil && st.Spec.Test != nil {
		t := *st.Spec.Test
		s.Test = &t
	}

	name := func(v string) string { return strings.ReplaceAll(v, "{{name}}", m.Metadata.Name) }
	names := func(vs []string) []string {
		out := make([]string, len(vs))
		for i, v := range vs {
			out[i] = name(v)
		}
		return out
	}
	s.Workdir = name(s.Workdir)
	s.Entrypoint, s.Cmd = names(s.Entrypoint), names(s.Cmd)
	if s.Test != nil {
		t := *s.Test
		t.Command = names(t.Command)
		s.Test = &t
	}
	for _, mp := range []map[string]string{s.Env, s.Labels, s.BuildEnv} {
		for k, v := range mp {
			mp[k] = name(v)
		}
	}
	return nil
}

// StepScript returns step i with {{name}} filled in.
func (m *Manifest) StepScript(i int) string {
	return strings.ReplaceAll(m.Stack.Spec.Steps[i].Run, "{{name}}", m.Metadata.Name)
}
