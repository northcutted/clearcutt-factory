package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadExtendsAndOrg(t *testing.T) {
	m, err := Load("testdata/fleet/team/app/image.yaml")
	if err != nil {
		t.Fatal(err)
	}
	o, err := LoadOrg("", m.Dir())
	if err != nil {
		t.Fatal(err)
	}
	if err := m.ApplyOrg(o); err != nil {
		t.Fatal(err)
	}
	s := m.Spec
	if got := strings.Join(s.Packages, ","); got != "bash,jq" {
		t.Errorf("packages = %s", got)
	}
	if len(s.Tools) != 2 || s.Tools[0].Version != "2.0" || s.Tools[1].Name != "crane" {
		t.Errorf("tools not merged by name: %+v", s.Tools)
	}
	if s.Env["A"] != "base" || s.Env["B"] != "app" || s.User != "65532" {
		t.Errorf("env/user not merged: %v %q", s.Env, s.User)
	}
	if m.Metadata.Ref != "registry.example/fleet/app" || strings.Join(m.Metadata.Tags, ",") != "latest" {
		t.Errorf("org registry/tags not applied: %+v", m.Metadata)
	}
	if strings.Join(s.Platforms, ",") != "linux/arm64" || s.Labels["vendor"] != "acme" {
		t.Errorf("org defaults not applied: %v %v", s.Platforms, s.Labels)
	}
	if want, _ := filepath.Abs("testdata/fleet/team/app/config"); s.Files[0].AbsSrc != want {
		t.Errorf("file src not resolved against its manifest: %s", s.Files[0].AbsSrc)
	}
	if want, _ := filepath.Abs("testdata/fleet/cosign.key"); o.Signing.Key != want {
		t.Errorf("signing key not resolved against the org profile: %s", o.Signing.Key)
	}
	if m.LockPath() != filepath.Join(m.Dir(), "image.lock.yaml") || m.ContainerfilePath() != filepath.Join(m.Dir(), "image.Containerfile") {
		t.Error("sibling paths")
	}
}

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "image.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestValidation(t *testing.T) {
	p := write(t, `apiVersion: factory.dev/v1alpha1
kind: Image
metadata: {name: Bad_Name}
spec:
  platforms: [amd64]
  tools:
    - {name: a, from: url}
    - {name: a, from: github-release, repo: x/y, version: "1", asset: z}
    - {name: b, from: carrier-pigeon}
    - {name: c, from: oci, image: x, path: /x, mode: rwx}
  files:
    - {src: missing, dst: relative}
`)
	m, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	err = m.ApplyOrg(DefaultOrg())
	if err == nil {
		t.Fatal("expected validation errors")
	}
	for _, want := range []string{"metadata.name", "metadata.ref", "spec.base", `platform "amd64"`,
		"url is required", "duplicate tool name", "from must be one of", "mode", "spec.files[0]"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in:\n%v", want, err)
		}
	}
}

func TestUnknownFieldsRejected(t *testing.T) {
	p := write(t, "apiVersion: factory.dev/v1alpha1\nkind: Image\nmetadata: {name: x}\nspec:\n  pakages: [bash]\n")
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "pakages") {
		t.Fatalf("expected unknown field error, got %v", err)
	}
}

func TestArchMap(t *testing.T) {
	p := write(t, `apiVersion: factory.dev/v1alpha1
kind: Image
metadata: {name: x}
spec:
  tools:
    - {name: a, from: url, url: u, sha256: abc}
    - {name: b, from: url, url: u, sha256: {amd64: one, arm64: two}}
`)
	m, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if m.Spec.Tools[0].SHA256.Get("arm64") != "abc" || m.Spec.Tools[1].SHA256.Get("arm64") != "two" || m.Spec.Tools[1].SHA256.Get("riscv64") != "" {
		t.Errorf("unexpected arch maps: %+v", m.Spec.Tools)
	}
}

func TestExtendsCycle(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.yaml")
	b := filepath.Join(dir, "b.yaml")
	for p, body := range map[string]string{
		a: "apiVersion: factory.dev/v1alpha1\nkind: Image\nextends: b.yaml\nmetadata: {name: a}\n",
		b: "apiVersion: factory.dev/v1alpha1\nkind: Image\nextends: a.yaml\nmetadata: {name: b}\n",
	} {
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Load(a); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("expected cycle error, got %v", err)
	}
}

func TestApp(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"factory.org.yaml":      "apiVersion: factory.dev/v1alpha1\nkind: OrgProfile\nregistry: registry.example/acme\ntags: [stable]\ndefaults: {labels: {vendor: acme}}\n",
		"images/run/image.yaml": "apiVersion: factory.dev/v1alpha1\nkind: Image\nmetadata: {name: go-run}\nspec: {base: cgr.dev/chainguard/static:latest}\n",
		"stacks/go.yaml": `apiVersion: factory.dev/v1alpha1
kind: Stack
metadata: {name: go}
spec:
  build: golang:1
  run: ../images/run/image.yaml
  platforms: [linux/amd64, linux/arm64]
  crossCompile: true
  buildEnv: {CGO_ENABLED: "0", MAIN: "./cmd/{{name}}"}
  caches: [/root/.cache/go-build]
  steps:
    - run: go build -o /out/{{name}} "$MAIN"
  env: {GODEBUG: x=1}
  user: "65532"
  entrypoint: ["/app/{{name}}"]
`,
		"apps/hello/app.yaml": `apiVersion: factory.dev/v1alpha1
kind: App
metadata: {name: hello}
spec:
  stack: ../../stacks/go.yaml
  platforms: [linux/arm64]
  env: {PORT: "8080"}
  buildEnv: {MAIN: .}
`,
	}
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	m, err := Load(filepath.Join(dir, "apps/hello/app.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	o, err := LoadOrg("", m.Dir())
	if err != nil {
		t.Fatal(err)
	}
	if err := m.ApplyOrg(o); err != nil {
		t.Fatal(err)
	}
	s := m.Spec
	if s.Base != "registry.example/acme/go-run:stable" || m.Stack.BuildRef != "golang:1" {
		t.Errorf("stack images: base %q, build %q", s.Base, m.Stack.BuildRef)
	}
	if s.SourceDir != filepath.Join(dir, "apps/hello") || m.LockPath() != filepath.Join(dir, "apps/hello/app.lock.yaml") {
		t.Errorf("paths: source %s, lock %s", s.SourceDir, m.LockPath())
	}
	if strings.Join(s.Platforms, ",") != "linux/arm64" || s.User != "65532" || strings.Join(s.Entrypoint, " ") != "/app/hello" {
		t.Errorf("defaults: %v %q %v", s.Platforms, s.User, s.Entrypoint)
	}
	if s.Env["GODEBUG"] != "x=1" || s.Env["PORT"] != "8080" || s.Labels["vendor"] != "acme" {
		t.Errorf("env/labels: %v %v", s.Env, s.Labels)
	}
	if s.BuildEnv["MAIN"] != "." || s.BuildEnv["CGO_ENABLED"] != "0" || m.StepScript(0) != `go build -o /out/hello "$MAIN"` {
		t.Errorf("build env/steps: %v %q", s.BuildEnv, m.StepScript(0))
	}
	if !strings.Contains(string(m.EffectiveYAML()), "crossCompile: true") {
		t.Errorf("effective manifest lacks the stack:\n%s", m.EffectiveYAML())
	}

	bad := filepath.Join(dir, "apps/hello/bad.yaml")
	if err := os.WriteFile(bad, []byte("apiVersion: factory.dev/v1alpha1\nkind: App\nmetadata: {name: bad}\nspec:\n  stack: ../../stacks/go.yaml\n  packages: [curl]\n  source: missing\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err = Load(bad)
	if err != nil {
		t.Fatal(err)
	}
	err = m.ApplyOrg(o)
	for _, want := range []string{"spec.packages is not allowed for kind App", "spec.source"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in %v", want, err)
		}
	}
}
