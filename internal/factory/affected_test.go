package factory

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// affectedRepo writes a repository with two org profiles, build and run
// images (one extending a shared file), a tools image with files: and vex:
// outside its directory, a local stack naming the build and run images by
// manifest, an app on it, an app on a registry stack with its source
// elsewhere, a shared profile with its trust policy and VEX, and a
// workflow; it changes to it and returns the manifests.
func affectedRepo(t *testing.T) []string {
	t.Helper()
	dir := t.TempDir()
	image := func(name, extra string) string {
		return "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: Image\nmetadata: {name: " + name + "}\n" + extra + "spec: {base: cgr.dev/chainguard/wolfi-base:latest}\n"
	}
	files := map[string]string{
		"factory.org.yaml":                "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\nregistry: r.example/p\nsigning: {mode: none}\n",
		"images/factory.org.yaml":         "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\nregistry: r.example/images\nsigning: {mode: none}\n",
		"images/_shared/build.yaml":       image("shared", ""),
		"images/build-go/image.yaml":      image("build-go", "extends: ../_shared/build.yaml\n"),
		"images/build-go/image.lock.yaml": "lock\n",
		"images/run-go/image.yaml":        image("run-go", ""),
		"images/run-go/image.lock.yaml":   "lock\n",
		"images/tools/image.yaml":         "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: Image\nmetadata: {name: tools}\nspec:\n  base: cgr.dev/chainguard/wolfi-base:latest\n  files: [{src: ../../assets/motd, dst: /etc/motd}]\n  vex: [../../org/vex/tools.openvex.json]\n",
		"assets/motd":                     "hi\n",
		"org/vex/tools.openvex.json":      "{}\n",
		"org/vex/other.openvex.json":      "{}\n",
		"org/profile.yaml":                "shared profile\n",
		"org/trust.yaml":                  "trust policy\n",
		"stacks/go.yaml":                  "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: Stack\nmetadata: {name: go}\nspec:\n  build: ../images/build-go/image.yaml\n  run: ../images/run-go/image.yaml\n  steps: [{run: make}]\n",
		"apps/svc/app.yaml":               "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: App\nmetadata: {name: svc}\nspec: {stack: ../../stacks/go.yaml}\n",
		"apps/svc/main.go":                "package main\n",
		"apps/web/app.yaml":               "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: App\nmetadata: {name: web}\nspec: {stack: r.example/stacks/go:1, source: ../../src/web}\n",
		"src/web/index.html":              "<html>\n",
		"README.md":                       "readme\n",
		".github/workflows/clearcutt.yml": "name: x\n",
	}
	for n, body := range files {
		p := filepath.Join(dir, n)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(dir)
	return []string{"images/build-go/image.yaml", "images/run-go/image.yaml", "images/tools/image.yaml", "apps/svc/app.yaml", "apps/web/app.yaml"}
}

// TestAffectedManifests: which manifests a pull request's changed files
// affect. A manifest owns its directory, the files it extends, its VEX
// documents, its files: and source, and an app its stack file and the
// stack's image manifests; a factory.org.yaml is owned by the manifests
// below it. Anything else changed means every manifest, unless it was
// deleted.
func TestAffectedManifests(t *testing.T) {
	manifests := affectedRepo(t)
	all := manifests
	const (
		buildGo = "images/build-go/image.yaml"
		runGo   = "images/run-go/image.yaml"
		tools   = "images/tools/image.yaml"
		svc     = "apps/svc/app.yaml"
		web     = "apps/web/app.yaml"
	)
	mod := func(p string) change { return change{path: p} }
	del := func(p string) change { return change{path: p, deleted: true} }
	for _, c := range []struct {
		name    string
		changed []change
		want    []string
		all     string // the unowned file that made it every manifest
	}{
		{"nothing changed", nil, nil, ""},
		{"a lock", []change{mod("images/run-go/image.lock.yaml")}, []string{runGo}, ""},
		{"two images' files, one written ./", []change{mod("images/run-go/image.lock.yaml"), mod("./images/build-go/image.Containerfile")}, []string{buildGo, runGo}, ""},
		{"a build image's lock: not the apps on it, whose locks pin the published one", []change{mod("images/build-go/image.lock.yaml")}, []string{buildGo}, ""},
		{"a build image's manifest: the apps on it too", []change{mod(buildGo)}, []string{buildGo, svc}, ""},
		{"a file a build image extends: the apps on it too", []change{mod("images/_shared/build.yaml")}, []string{buildGo, svc}, ""},
		{"a run image's manifest: the apps on it too", []change{mod(runGo)}, []string{runGo, svc}, ""},
		{"a stack file: the apps on it", []change{mod("stacks/go.yaml")}, []string{svc}, ""},
		{"the images' org profile", []change{mod("images/factory.org.yaml")}, []string{buildGo, runGo, tools}, ""},
		{"the root org profile", []change{mod("factory.org.yaml")}, all, ""},
		{"a files: source outside the directory", []change{mod("assets/motd")}, []string{tools}, ""},
		{"a manifest's VEX document", []change{mod("org/vex/tools.openvex.json")}, []string{tools}, ""},
		{"an app's source", []change{mod("apps/svc/main.go")}, []string{svc}, ""},
		{"a source directory elsewhere", []change{mod("src/web/index.html")}, []string{web}, ""},
		{"the shared profile", []change{mod("org/profile.yaml")}, all, "org/profile.yaml"},
		{"the trust policy", []change{mod("org/trust.yaml")}, all, "org/trust.yaml"},
		{"a VEX document no manifest names (the profile's)", []change{mod("org/vex/other.openvex.json")}, all, "org/vex/other.openvex.json"},
		{"a workflow, with a lock", []change{mod(".github/workflows/clearcutt.yml"), mod("images/run-go/image.lock.yaml")}, all, ".github/workflows/clearcutt.yml"},
		{"a README", []change{mod("README.md")}, all, "README.md"},
		{"a new file nobody owns", []change{mod("images/new/notes.txt")}, all, "images/new/notes.txt"},
		{"a deleted image nobody owns now", []change{del("images/old/image.yaml"), del("images/old/image.lock.yaml")}, all, "images/old/image.yaml"},
		{"a deleted file with an owner", []change{del("images/run-go/image.lock.yaml")}, []string{runGo}, ""},
		{"a deleted stray and an app's source", []change{del("old.txt"), mod("apps/svc/main.go")}, all, "old.txt"},
		{"a rename within an app", []change{del("apps/svc/old.go"), mod("apps/svc/new.go")}, []string{svc}, ""},
		{"a rename from one image to another", []change{del("images/run-go/motd"), mod("images/tools/motd")}, []string{runGo, tools}, ""},
		{"a rename into an app from nowhere", []change{del("docs/x.go"), mod("apps/svc/x.go")}, all, "docs/x.go"},
		{"a rename out of an app to nowhere", []change{del("apps/svc/x.go"), mod("misc/x.go")}, all, "misc/x.go"},
	} {
		got, gotAll, err := affectedManifests(manifests, c.changed)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if !reflect.DeepEqual(got, c.want) || gotAll != c.all {
			t.Errorf("%s: got %v (all: %q), want %v (all: %q)", c.name, got, gotAll, c.want, c.all)
		}
	}

	// A root manifest is selected for its directory, but cannot swallow shared changes.
	if err := os.WriteFile("app.yaml", []byte("apiVersion: factory.clearcutt.dev/v1alpha1\nkind: App\nmetadata: {name: root}\nspec: {stack: stacks/go.yaml}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, gotAll, err := affectedManifests([]string{"app.yaml", runGo}, []change{mod("images/run-go/image.lock.yaml")}); err != nil || gotAll != "" || !reflect.DeepEqual(got, []string{"app.yaml", runGo}) {
		t.Errorf("root manifest: %v (all: %q), %v", got, gotAll, err)
	}
	for _, shared := range []string{".github/workflows/clearcutt.yml", "org/profile.yaml", "org/trust.yaml"} {
		got, _, err := affectedManifests([]string{"app.yaml", runGo}, []change{mod(shared)})
		if err != nil || !reflect.DeepEqual(got, []string{"app.yaml", runGo}) {
			t.Errorf("root swallowed %s: %v %v", shared, got, err)
		}
	}
	// A manifest (or its stack) that doesn't load is an error: the
	// workflow then builds everything.
	if _, _, err := affectedManifests([]string{"nowhere/image.yaml"}, nil); err == nil {
		t.Error("a missing manifest was accepted")
	}
	if err := os.WriteFile("stacks/go.yaml", []byte("kind: Stack\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := affectedManifests([]string{svc}, nil); err == nil {
		t.Error("an app whose stack doesn't load was accepted")
	}
}

// TestReadChanges: git diff --name-only and --name-status output, with or
// without -z; a rename deletes its old path, a copy changes only its new
// one, and a path git quoted is unquoted.
func TestReadChanges(t *testing.T) {
	dir := t.TempDir()
	for _, c := range []struct {
		name, in string
		want     []change
	}{
		{"empty", "", nil},
		{"name-only", "a/b.yaml\n./c\n\nd e\r\n", []change{{path: "a/b.yaml"}, {path: "c"}, {path: "d e"}}},
		{"name-status", "M\timages/run-go/image.lock.yaml\nD\tgone.txt\nA\tnew.txt\nR100\tapps/svc/old.go\tapps/svc/new.go\nC75\tsrc.go\tcopy.go\nT\tlink\n",
			[]change{{path: "images/run-go/image.lock.yaml"}, {path: "gone.txt", deleted: true}, {path: "new.txt"}, {path: "apps/svc/old.go", deleted: true}, {path: "apps/svc/new.go"}, {path: "copy.go"}, {path: "link"}}},
		{"quoted", "M\t\"a/na\\303\\257ve\\tname\"\n\"b/\\\"q\\\"\"\n", []change{{path: "a/naïve\tname"}, {path: "b/\"q\""}}},
		{"name-status -z", "M\x00a\tb\x00R087\x00x\x00y\x00D\x00z\x00C100\x00p\x00q\x00",
			[]change{{path: "a\tb"}, {path: "x", deleted: true}, {path: "y"}, {path: "z", deleted: true}, {path: "q"}}},
		{"name-only -z", "a\x00b c\x00", []change{{path: "a"}, {path: "b c"}}},
	} {
		f := filepath.Join(dir, "changed")
		if err := os.WriteFile(f, []byte(c.in), 0o644); err != nil {
			t.Fatal(err)
		}
		got, err := readChanges(f)
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v, %v; want %v", c.name, got, err, c.want)
		}
	}
	for _, bad := range []string{"R100\x00only-one\x00", "M\x00"} {
		f := filepath.Join(dir, "bad")
		if err := os.WriteFile(f, []byte(bad), 0o644); err != nil {
			t.Fatal(err)
		}
		if got, err := readChanges(f); err == nil {
			t.Errorf("%q: accepted as %v", bad, got)
		}
	}
	if _, err := readChanges(filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing file was accepted")
	}
}

// TestAffected: the command prints the affected manifests and writes them
// to $GITHUB_OUTPUT as a JSON array ([] for none), and names the file that
// made it every manifest.
func TestAffected(t *testing.T) {
	manifests := affectedRepo(t)
	gho := filepath.Join(t.TempDir(), "gho")
	t.Setenv("GITHUB_OUTPUT", gho)
	run := func(changed string) (stdout, stderr, output string) {
		t.Helper()
		f := filepath.Join(t.TempDir(), "changed")
		if err := os.WriteFile(f, []byte(changed), 0o644); err != nil {
			t.Fatal(err)
		}
		_ = os.Remove(gho)
		var out, errOut bytes.Buffer
		if err := Affected(context.Background(), Options{Stdout: &out, Stderr: &errOut}, AffectedOptions{Changed: f, Manifests: manifests}); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(gho)
		return out.String(), errOut.String(), string(b)
	}
	out, errOut, gh := run("M\timages/run-go/image.lock.yaml\nR100\tapps/svc/old.go\tapps/svc/new.go\nassets/motd\n")
	if out != "images/run-go/image.yaml\nimages/tools/image.yaml\napps/svc/app.yaml\n" || gh != `manifests=["images/run-go/image.yaml","images/tools/image.yaml","apps/svc/app.yaml"]`+"\n" || errOut != "" {
		t.Errorf("stdout %q, GITHUB_OUTPUT %q, stderr %q", out, gh, errOut)
	}
	out, errOut, gh = run("")
	if out != "" || gh != "manifests=[]\n" || errOut != "" {
		t.Errorf("nothing: stdout %q, GITHUB_OUTPUT %q, stderr %q", out, gh, errOut)
	}
	out, errOut, gh = run("README.md\n")
	if strings.Count(out, "\n") != len(manifests) || !strings.HasPrefix(gh, `manifests=["images/build-go/image.yaml",`) || !strings.Contains(errOut, "README.md changed, which no manifest owns") {
		t.Errorf("README: stdout %q, GITHUB_OUTPUT %q, stderr %q", out, gh, errOut)
	}
}

func TestAffectedOrgReferences(t *testing.T) {
	manifests := affectedRepo(t)
	if err := os.WriteFile("images/factory.org.yaml", []byte("apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\nextends: {path: ../org/profile.yaml}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The shared VEX lives inside one image's directory but serves all
	// manifests using the root profile, including apps elsewhere.
	if err := os.WriteFile("factory.org.yaml", []byte("apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\nextends: {path: org/profile.yaml}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("org/profile.yaml", []byte("apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\nsigning: {trustPolicy: trust.yaml}\nvulnerabilities: {vex: [../images/build-go/shared-vex.json]}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"org/profile.yaml", "org/trust.yaml", "images/build-go/shared-vex.json"} {
		for _, deleted := range []bool{false, true} {
			got, _, err := affectedManifests(manifests, []change{{path: p, deleted: deleted}})
			if err != nil || !reflect.DeepEqual(got, manifests) {
				t.Errorf("%s deleted=%v: %v %v", p, deleted, got, err)
			}
		}
	}
}
