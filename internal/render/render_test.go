package render

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt-factory/internal/lock"
	"github.com/northcutted/clearcutt-factory/internal/manifest"
)

var update = flag.Bool("update", false, "rewrite golden files")

func fixture(t *testing.T) (*manifest.Manifest, *lock.Lock) {
	t.Helper()
	src, _ := filepath.Abs("testdata/src")
	img := func(ref, d string) lock.Image { return lock.Image{Ref: ref, Digest: "sha256:" + strings.Repeat(d, 64)} }
	m := &manifest.Manifest{
		Path:     filepath.Join(src, "image.yaml"),
		Metadata: manifest.Metadata{Name: "demo", Ref: "registry.example/demo"},
		Spec: manifest.Spec{
			Base:      "cgr.dev/chainguard/wolfi-base:latest",
			Platforms: []string{"linux/amd64", "linux/arm64"},
			Packages:  []string{"jq"},
			Tools: []manifest.Tool{
				{Name: "helm", From: "url", Version: "4.3.0", URL: "https://get.helm.sh/helm-{{arch}}.tar.gz", Extract: "x"},
				{Name: "script", From: "url", URL: "https://example.com/install.sh", Dest: "/opt/install.sh", Mode: "644"},
				{Name: "crane", From: "oci", Image: "gcr.io/go-containerregistry/crane:latest", Path: "/ko-app/crane"},
				{Name: "yq", From: "go", Package: "github.com/mikefarah/yq/v4", Version: "v4.54.1", Image: "golang:1"},
				{Name: "awscli", From: "build", Image: "python:3", Run: "pip install --prefix=/out/usr/local awscli==2.0.0\n"},
			},
			Files: []manifest.File{
				{Src: "conf/", Dst: "/etc/demo/", AbsSrc: filepath.Join(src, "conf")},
				{Src: "hello world.sh", Dst: "/usr/local/bin/", Mode: "0755", AbsSrc: filepath.Join(src, "hello world.sh")},
			},
			Env:        map[string]string{"B": `say "$HI"`, "A": "1"},
			Labels:     map[string]string{"org.opencontainers.image.source": "https://example.com"},
			User:       "65532",
			Entrypoint: []string{"/bin/sh", "-c", "a && b <c>"},
		},
	}
	l := &lock.Lock{
		SourceDateEpoch: 1700000000,
		Builder: lock.Builder{
			BuildKit: img("moby/buildkit:v0.33.1", "b"),
			Frontend: img("docker/dockerfile:1", "f"),
			Toolbox:  img("cgr.dev/chainguard/wolfi-base:latest", "t"),
		},
		Base: img("cgr.dev/chainguard/wolfi-base:latest", "0"),
		Packages: lock.Packages{
			Repositories: []string{"https://apk.cgr.dev/chainguard"},
			Platforms: map[string][]lock.Package{
				"linux/amd64": {{Name: "jq", Version: "1.8.2-r2", Checksum: "Q1cIjjnzqrowWo6jY/D8dmbkQ8mdk="}, {Name: "oniguruma", Version: "6.9.10-r5", Checksum: "Q1aaaaaaaaaaaaaaaaaaaaaaaaaaa="}},
				"linux/arm64": {{Name: "jq", Version: "1.8.2-r1", Checksum: "Q1UVd+QYZzLs19UhTnUAfchEVOH8Q="}, {Name: "oniguruma", Version: "6.9.10-r5", Checksum: "Q1bbbbbbbbbbbbbbbbbbbbbbbbbbb="}},
			},
		},
	}
	for _, t := range m.Spec.Tools {
		lt := lock.Tool{Name: t.Name, From: t.From, Version: t.Version, SpecDigest: lock.Digest(t)}
		switch t.From {
		case "url":
			lt.Verification = lock.VerifiedChecksumFile
			lt.Artifacts = map[string]lock.Artifact{}
			for _, p := range m.Spec.Platforms {
				_, arch, _ := manifest.SplitPlatform(p)
				a := lock.Artifact{URL: strings.ReplaceAll(t.URL, "{{arch}}", arch), SHA256: strings.Repeat("a", 64), Extract: t.Extract}
				if strings.Contains(t.URL, "{{arch}}") {
					a.Extract = "linux-" + arch + "/helm"
					a.SHA256 = strings.Repeat(map[string]string{"amd64": "1", "arm64": "2"}[arch], 64)
				}
				lt.Artifacts[p] = a
			}
		case "oci", "go", "build":
			i := img(t.Image, "c")
			lt.Image = &i
			lt.Verification = map[string]string{"oci": lock.VerifiedImageDigest, "go": lock.VerifiedGoSumDB, "build": lock.VerifiedUnverified}[t.From]
		}
		l.Tools = append(l.Tools, lt)
	}
	return m, l
}

func TestRenderGolden(t *testing.T) {
	m, l := fixture(t)
	out, err := Render(m, l)
	if err != nil {
		t.Fatal(err)
	}
	golden := "testdata/golden.Containerfile"
	if *update {
		if err := os.WriteFile(golden, out.Containerfile, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != string(out.Containerfile) {
		t.Errorf("Containerfile differs from %s (run go test ./internal/render -update):\n%s", golden, out.Containerfile)
	}
	if len(out.Context) != 2 || out.Context[0].Rel != "files/0" || out.Context[1].Rel != "files/1/hello world.sh" {
		t.Errorf("context: %+v", out.Context)
	}
}

func TestRenderRejectsStaleLock(t *testing.T) {
	m, l := fixture(t)
	m.Spec.Tools[0].Version = "9.9.9"
	if _, err := Render(m, l); err == nil || !strings.Contains(err.Error(), "run clearcutt-factory lock") {
		t.Fatalf("expected stale lock error, got %v", err)
	}
}

func nativeFixture(manager string) (*manifest.Manifest, *lock.Lock) {
	img := func(ref, d string) lock.Image { return lock.Image{Ref: ref, Digest: "sha256:" + strings.Repeat(d, 64)} }
	src, _ := filepath.Abs("testdata/src")
	m := &manifest.Manifest{
		Path:     filepath.Join(src, "image.yaml"),
		Metadata: manifest.Metadata{Name: "native", Ref: "registry.example/native"},
		Spec: manifest.Spec{
			Base:      "debian:trixie-slim",
			Platforms: []string{"linux/amd64", "linux/arm64"},
			Packages:  []string{"jq"},
			Tools: []manifest.Tool{
				{Name: "ripgrep", From: "nix", Package: "ripgrep", Image: "nixos/nix:latest", Nixpkgs: "nixos-26.05"},
				{Name: "fd", From: "nix", Package: "fd", Image: "nixos/nix:latest", Nixpkgs: "nixos-26.05"},
			},
			Mirrors: []manifest.Mirror{{From: "https://snapshot.debian.org/", To: "https://artifactory.example/debian-snapshot/"}},
		},
	}
	l := &lock.Lock{
		SourceDateEpoch: 1700000000,
		Builder: lock.Builder{
			BuildKit: img("moby/buildkit:v0.33.1", "b"),
			Frontend: img("docker/dockerfile:1", "f"),
			Toolbox:  img("cgr.dev/chainguard/wolfi-base:latest", "t"),
		},
		Base: img("debian:trixie-slim", "0"),
	}
	ext, url := ".deb", "https://snapshot.debian.org/archive/debian/20261003T000000Z/pool/main/j/jq/"
	l.Packages = lock.Packages{Manager: manager, Distro: "debian-13", Snapshot: "20261003T000000Z"}
	if manager == lock.ManagerDNF {
		ext, url = ".rpm", "https://kojipkgs.fedoraproject.org/packages/jq/1.8.1/3.fc44/"
		l.Packages = lock.Packages{Manager: manager, Distro: "fedora-44"}
	}
	l.Packages.Platforms = map[string][]lock.Package{}
	for _, arch := range []string{"amd64", "arm64"} {
		file := "jq_1.7.1_" + arch + ext
		l.Packages.Platforms["linux/"+arch] = []lock.Package{{Name: "jq", Version: "1.7.1", Arch: arch, Filename: file, URL: url + file, SHA256: strings.Repeat("9", 64)}}
	}
	nixImg := img("nixos/nix:latest", "n")
	for i, t := range m.Spec.Tools {
		lt := lock.Tool{Name: t.Name, From: t.From, Version: "1.0", Verification: lock.VerifiedNixSignature,
			SpecDigest: lock.Digest(t), Image: &nixImg, Nix: map[string]lock.NixOutput{}}
		for j, p := range m.Spec.Platforms {
			path := "/nix/store/" + strings.Repeat(string(rune('a'+i*2+j)), 32) + "-" + t.Name + "-1.0"
			lt.Nix[p] = lock.NixOutput{Path: path}
		}
		l.Tools = append(l.Tools, lt)
	}
	return m, l
}

func TestRenderNativeGolden(t *testing.T) {
	for _, mgr := range []string{lock.ManagerAPT, lock.ManagerDNF} {
		t.Run(mgr, func(t *testing.T) {
			m, l := nativeFixture(mgr)
			out, err := Render(m, l)
			if err != nil {
				t.Fatal(err)
			}
			golden := "testdata/" + mgr + ".Containerfile"
			if *update {
				if err := os.WriteFile(golden, out.Containerfile, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatal(err)
			}
			if string(want) != string(out.Containerfile) {
				t.Errorf("Containerfile differs from %s (run go test ./internal/render -update):\n%s", golden, out.Containerfile)
			}
		})
	}
	m, l := nativeFixture(lock.ManagerAPT)
	out, _ := Render(m, l)
	s := string(out.Containerfile)
	if !strings.Contains(s, "https://artifactory.example/debian-snapshot/archive/debian/") || strings.Contains(s, "ADD --checksum=sha256:"+strings.Repeat("9", 64)+" https://snapshot.debian.org") {
		t.Error("mirror was not applied to package downloads")
	}
	if strings.Count(s, "nix --extra-experimental-features nix-command copy") != 2 {
		t.Error("expected one combined nix stage per architecture")
	}
}

func appFixture(t *testing.T) (*manifest.Manifest, *lock.Lock) {
	t.Helper()
	src, _ := filepath.Abs("testdata/src")
	img := func(ref, d string) lock.Image { return lock.Image{Ref: ref, Digest: "sha256:" + strings.Repeat(d, 64)} }
	st := &manifest.Stack{
		Metadata: manifest.StackMetadata{Name: "go"},
		Spec: manifest.StackSpec{
			Build: "golang:1", Run: "registry.example/go-run:latest", CrossCompile: true,
			Caches: []string{"/root/.cache/go-build", "/go/pkg/mod"},
			Steps:  []manifest.Step{{Run: "go mod download"}, {Run: "go build -trimpath -o /out/{{name}} .\n"}},
			AppDir: "/app",
		},
		BuildRef: "golang:1", RunRef: "registry.example/go-run:latest",
	}
	m := &manifest.Manifest{
		Kind:     manifest.KindApp,
		Path:     filepath.Join(src, "app.yaml"),
		Metadata: manifest.Metadata{Name: "hello", Ref: "registry.example/hello"},
		Stack:    st,
		Spec: manifest.Spec{
			Base:       st.RunRef,
			Platforms:  []string{"linux/amd64", "linux/arm64"},
			SourceDir:  src,
			Exclude:    []string{"docs/"},
			BuildEnv:   map[string]string{"CGO_ENABLED": "0"},
			Env:        map[string]string{"PORT": "8080"},
			User:       "65532",
			Entrypoint: []string{"/app/hello"},
		},
	}
	l := &lock.Lock{
		SourceDateEpoch: 1700000000,
		Builder: lock.Builder{
			BuildKit: img("moby/buildkit:v0.33.1", "b"),
			Frontend: img("docker/dockerfile:1", "f"),
			Toolbox:  img("cgr.dev/chainguard/wolfi-base:latest", "t"),
		},
		Base: img("registry.example/go-run:latest", "0"),
		App: &lock.App{
			Stack: "go", StackDigest: lock.StackDigest(st), Build: img("golang:1", "c"),
			RunPlatforms: map[string]string{"linux/amd64": "sha256:" + strings.Repeat("1", 64), "linux/arm64": "sha256:" + strings.Repeat("2", 64)},
		},
	}
	return m, l
}

// TestAppOwnFiles checks that factory's own files are left out of an app's
// source when they are in it, wherever the source is.
func TestAppOwnFiles(t *testing.T) {
	dir := t.TempDir()
	for _, c := range []struct {
		name, manifest, source, org string
		want                        string
	}{
		{"source is the manifest's directory", "app.yaml", ".", "factory.org.yaml", "/app.lock.yaml,/app.Containerfile,/factory.org.yaml"},
		{"org profile above the source", "app.yaml", ".", "../factory.org.yaml", "/app.lock.yaml,/app.Containerfile"},
		{"default org profile", "app.yaml", ".", "", "/app.lock.yaml,/app.Containerfile"},
		{"source above the manifest", "apps/web/web.yaml", ".", "factory.org.yaml", "/apps/web/web.lock.yaml,/apps/web/web.Containerfile,/factory.org.yaml"},
		{"source beside the manifest", "deploy/app.yaml", "src", "deploy/factory.org.yaml", ""},
		{"names with pattern characters", "[x]/a*.yaml", ".", "", `/\[x]/a\*.lock.yaml,/\[x]/a\*.Containerfile`},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := &manifest.Manifest{Path: filepath.Join(dir, c.manifest)}
			m.Spec.SourceDir = filepath.Join(dir, c.source)
			if c.org != "" {
				m.Spec.OrgFile = filepath.Join(dir, c.org)
			}
			got := ownFiles(m)
			if strings.Join(got, ",") != c.want {
				t.Errorf("ownFiles = %q, want %q", got, c.want)
			}
		})
	}
}

func TestRenderApp(t *testing.T) {
	m, l := appFixture(t)
	out, err := Render(m, l)
	if err != nil {
		t.Fatal(err)
	}
	golden := "testdata/app.Containerfile"
	if *update {
		if err := os.WriteFile(golden, out.Containerfile, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != string(out.Containerfile) {
		t.Errorf("Containerfile differs from %s (run go test ./internal/render -update):\n%s", golden, out.Containerfile)
	}
	if len(out.Context) != 1 || out.Context[0].Rel != "src" || strings.Join(out.Context[0].Exclude, ",") != ".git,/out,/app.lock.yaml,/app.Containerfile,docs/" {
		t.Errorf("context: %+v", out.Context)
	}
	// The build stage runs as root whatever the build image's user, and the
	// app as the stack's user.
	s := string(out.Containerfile)
	build, app, _ := strings.Cut(s, "# ---- app ----")
	if !strings.Contains(build, " AS build\n# never shipped; root so the steps can write /out, /src, and the caches\nUSER 0\nARG ") ||
		strings.Count(s, "USER ") != 2 || !strings.Contains(app, "USER 65532\n") {
		t.Errorf("build stage should run as root and the app as 65532:\n%s", s)
	}
	wantAnn := "annotation-manifest[linux/arm64].org.opencontainers.image.base.digest=sha256:" + strings.Repeat("2", 64)
	if len(out.Annotations) != 4 || out.Annotations[3] != wantAnn ||
		out.Annotations[0] != "annotation-manifest[linux/amd64].org.opencontainers.image.base.name=registry.example/go-run:latest" {
		t.Errorf("annotations: %q", out.Annotations)
	}

	m.Spec.Platforms = []string{"linux/arm64"}
	if out, err = Render(m, l); err != nil || out.Annotations[1] != "annotation-manifest.org.opencontainers.image.base.digest=sha256:"+strings.Repeat("2", 64) {
		t.Errorf("single-platform annotations: %q, %v", out.Annotations, err)
	}

	m.Stack.Spec.Steps[0].Run = "changed"
	if _, err := Render(m, l); err == nil || !strings.Contains(err.Error(), "run clearcutt-factory lock") {
		t.Errorf("expected stale stack error, got %v", err)
	}
}

// TestRenderAPKChecksums: each platform's install checks every package's
// checksum against the lock, so a lock without them can't be rendered
// (#10).
func TestRenderAPKChecksums(t *testing.T) {
	m, l := fixture(t)
	out, err := Render(m, l)
	if err != nil {
		t.Fatal(err)
	}
	ins := parse(t, out.Containerfile)
	var checked []string
	for _, in := range ins {
		if in.name == "run" && len(in.heredocs) == 1 && strings.Contains(in.heredocs[0], "apk add ") {
			_, locked, ok := strings.Cut(in.heredocs[0], "/lib/apk/db/installed <<'LOCKED'\n")
			if !ok || !strings.HasSuffix(locked, "\nLOCKED\n") {
				t.Fatalf("no check after the install:\n%s", in.heredocs[0])
			}
			checked = append(checked, strings.TrimSuffix(locked, "LOCKED\n"))
		}
	}
	want := []string{
		"jq 1.8.2-r2 Q1cIjjnzqrowWo6jY/D8dmbkQ8mdk=\noniguruma 6.9.10-r5 Q1aaaaaaaaaaaaaaaaaaaaaaaaaaa=\n",
		"jq 1.8.2-r1 Q1UVd+QYZzLs19UhTnUAfchEVOH8Q=\noniguruma 6.9.10-r5 Q1bbbbbbbbbbbbbbbbbbbbbbbbbbb=\n",
	}
	if strings.Join(checked, "|") != strings.Join(want, "|") {
		t.Errorf("checked %q, want %q", checked, want)
	}

	l.Packages.Platforms["linux/arm64"][1].Checksum = ""
	if _, err := Render(m, l); err == nil || !strings.Contains(err.Error(), "lock packages linux/arm64 (oniguruma): checksum \"\" is not an APKINDEX checksum") {
		t.Errorf("no checksum: %v", err)
	}
}

// TestRenderOfflineBuildTools: under policy.requireOfflineBuildTools, a
// from: build script runs with no network; other stages are unchanged.
func TestRenderOfflineBuildTools(t *testing.T) {
	m, l := fixture(t)
	online, err := Render(m, l)
	if err != nil {
		t.Fatal(err)
	}
	m.Spec.OfflineBuildTools = true
	offline, err := Render(m, l)
	if err != nil {
		t.Fatal(err)
	}
	var runs []string
	for _, in := range parse(t, offline.Containerfile) {
		if in.name == "run" && slicesContain(in.flags, "--network=none") {
			runs = append(runs, in.heredocs...)
		}
	}
	if len(runs) != 1 || !strings.Contains(runs[0], "pip install --prefix=/out/usr/local awscli") {
		t.Errorf("offline RUNs: %q\n%s", runs, offline.Containerfile)
	}
	if strings.Contains(string(online.Containerfile), "--network") {
		t.Error("without the policy, the build tool's network changed")
	}
	if a, b := parse(t, online.Containerfile), parse(t, offline.Containerfile); len(a) != len(b) {
		t.Errorf("%d instructions online, %d offline", len(a), len(b))
	}
}

func slicesContain(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
