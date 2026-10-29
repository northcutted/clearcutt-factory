package factory

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/northcutted/clearcutt-factory/internal/manifest"
)

// fakeMachine stands in for the programs doctor runs: each answer is
// keyed by the program's base name and its first argument.
type fakeMachine struct {
	paths   map[string]string // name → path; absent: not on PATH
	answers map[string]fakeAnswer
	env     map[string]string
	ran     [][]string
}

type fakeAnswer struct {
	stdout, stderr string
	err            error
}

func (f *fakeMachine) doctorEnv(t *testing.T) doctorEnv {
	return doctorEnv{
		run: func(_ context.Context, name string, args ...string) ([]byte, []byte, error) {
			f.ran = append(f.ran, append([]string{name}, args...))
			key := filepath.Base(name)
			if len(args) > 0 {
				key += " " + args[0]
			}
			a, ok := f.answers[key]
			if !ok {
				return nil, nil, errors.New("unexpected: " + name + " " + strings.Join(args, " "))
			}
			return []byte(a.stdout), []byte(a.stderr), a.err
		},
		lookPath: func(n string) (string, error) {
			if p, ok := f.paths[n]; ok {
				return p, nil
			}
			return "", errors.New(n + ": not found")
		},
		getenv:    func(k string) string { return f.env[k] },
		http:      http.DefaultClient,
		apiURL:    "http://github.invalid",
		checkPush: func(context.Context, string) error { return nil },
		now:       time.Now,
	}
}

func orgWith(edit func(o *manifest.Org)) *manifest.Org {
	o := manifest.DefaultOrg()
	if edit != nil {
		edit(o)
	}
	return o
}

var failed = errors.New("exit status 1")

func TestDoctorRuntime(t *testing.T) {
	for _, c := range []struct {
		name    string
		m       fakeMachine
		org     *manifest.Org
		status  string
		want    string // in detail and fix
		runtime string // what later checks get
	}{
		{"none", fakeMachine{}, orgWith(nil), DoctorFail, "install Docker or Podman", ""},
		{"podman wanted, docker found", fakeMachine{paths: map[string]string{"docker": "/bin/docker"}}, orgWith(func(o *manifest.Org) { o.Builder.Runtime = "podman" }), DoctorFail, "podman (builder.runtime or CLEARCUTT_FACTORY_RUNTIME) is not on PATH", ""},
		{"podman machine down", fakeMachine{paths: map[string]string{"podman": "/bin/podman"}, answers: map[string]fakeAnswer{
			"podman --version": {stdout: "podman version 6.1.4\n"},
			"podman info":      {stderr: "Cannot connect to Podman. Please verify your connection\n", err: failed}}},
			orgWith(nil), DoctorFail, "podman machine start", ""},
		{"docker down", fakeMachine{paths: map[string]string{"docker": "/bin/docker"}, answers: map[string]fakeAnswer{
			"docker --version": {stdout: "Docker version 29.0.0\n"},
			"docker info":      {stderr: "Cannot connect to the Docker daemon\n", err: failed}}},
			orgWith(nil), DoctorFail, "start Docker", ""},
		{"podman up", fakeMachine{paths: map[string]string{"podman": "/bin/podman"}, answers: map[string]fakeAnswer{
			"podman --version": {stdout: "podman version 6.1.4\n"}, "podman info": {}}},
			orgWith(nil), DoctorOK, "podman version 6.1.4, its server answers", "/bin/podman"},
		{"CLEARCUTT_FACTORY_RUNTIME", fakeMachine{paths: map[string]string{"docker": "/bin/docker", "podman": "/bin/podman"}, env: map[string]string{"CLEARCUTT_FACTORY_RUNTIME": "podman"}, answers: map[string]fakeAnswer{
			"podman --version": {stdout: "podman version 6.1.4\n"}, "podman info": {}}},
			orgWith(nil), DoctorOK, "podman", "/bin/podman"},
	} {
		st := &doctorState{org: c.org}
		got := doctorRuntime(context.Background(), c.m.doctorEnv(t), st)
		if got.Status != c.status || !strings.Contains(got.Detail+" "+got.Fix, c.want) || st.runtime != c.runtime {
			t.Errorf("%s: %+v (runtime %q), want %s with %q (runtime %q)", c.name, got, st.runtime, c.status, c.want, c.runtime)
		}
		if got.Status == DoctorFail && got.Fix == "" {
			t.Errorf("%s: a failure without a fix", c.name)
		}
	}
}

func TestDoctorFileSharing(t *testing.T) {
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "repo")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	resolved, _ := filepath.EvalSymlinks(real)
	for _, c := range []struct {
		name   string
		st     doctorState
		answer fakeAnswer
		status string
		want   string
	}{
		{"remote BuildKit", doctorState{org: orgWith(func(o *manifest.Org) { o.Builder.Addr = "tcp://buildkit:1234" }), runtime: "/bin/podman"}, fakeAnswer{}, DoctorSkip, "builder.addr"},
		{"no runtime", doctorState{org: orgWith(nil)}, fakeAnswer{}, DoctorSkip, "no container runtime"},
		{"not shared", doctorState{org: orgWith(nil), runtime: "/bin/podman"}, fakeAnswer{stderr: "Error: statfs /opt/work/out: no such file or directory\n", err: failed}, DoctorFail, "podman can't see /opt/work/out"},
		{"other failure", doctorState{org: orgWith(nil), runtime: "/bin/docker"}, fakeAnswer{stderr: "Error: image not known\n", err: failed}, DoctorFail, "image not known"},
		{"shared", doctorState{org: orgWith(nil), runtime: "/bin/podman"}, fakeAnswer{}, DoctorOK, "podman sees the repository (" + resolved + ")"},
	} {
		m := fakeMachine{answers: map[string]fakeAnswer{"podman run": c.answer, "docker run": c.answer}}
		c.st.dir = link
		got := doctorFileSharing(context.Background(), m.doctorEnv(t), &c.st, filepath.Join(link, "out"))
		if got.Status != c.status || !strings.Contains(got.Detail+" "+got.Fix, c.want) {
			t.Errorf("%s: %+v, want %s with %q", c.name, got, c.status, c.want)
		}
		// The runtime is given real paths, as build gives them.
		if c.status == DoctorOK && !strings.Contains(strings.Join(m.ran[0], " "), "source="+resolved+",target=/repo") {
			t.Errorf("%s: ran %q", c.name, m.ran[0])
		}
	}
}

func TestDoctorBuildKit(t *testing.T) {
	workers := func(platforms ...string) string {
		var ps []map[string]string
		for _, p := range platforms {
			os, arch, _ := strings.Cut(p, "/")
			ps = append(ps, map[string]string{"os": os, "architecture": arch})
		}
		b, _ := json.Marshal([]map[string]any{{"platforms": ps, "buildkitVersion": map[string]string{"version": "v0.33.1"}}})
		return string(b)
	}
	twoPlatforms := orgWith(func(o *manifest.Org) { o.Defaults.Platforms = []string{"linux/amd64", "linux/arm64"} })
	for _, c := range []struct {
		name               string
		st                 doctorState
		m                  fakeMachine
		bkStatus, emStatus string
		want               string
	}{
		{"both platforms", doctorState{org: twoPlatforms, runtime: "/bin/podman"},
			fakeMachine{answers: map[string]fakeAnswer{"podman run": {stdout: workers("linux/arm64", "linux/amd64", "linux/386")}}},
			DoctorOK, DoctorOK, "BuildKit builds linux/amd64, linux/arm64"},
		{"no emulation", doctorState{org: twoPlatforms, runtime: "/bin/docker"},
			fakeMachine{answers: map[string]fakeAnswer{"docker run": {stdout: workers("linux/amd64")}}},
			DoctorOK, DoctorFail, "tonistiigi/binfmt --install all"},
		{"the manifest's platforms", doctorState{org: twoPlatforms, runtime: "/bin/docker", m: &manifest.Manifest{Path: "img/image.yaml", Spec: manifest.Spec{Platforms: []string{"linux/amd64"}}}},
			fakeMachine{answers: map[string]fakeAnswer{"docker run": {stdout: workers("linux/amd64")}}},
			DoctorOK, DoctorOK, "img/image.yaml"},
		{"BuildKit doesn't start", doctorState{org: twoPlatforms, runtime: "/bin/podman"},
			fakeMachine{answers: map[string]fakeAnswer{"podman run": {stderr: "Error: crun: privileged containers are not allowed\n", err: failed}}},
			DoctorFail, DoctorSkip, "privileged containers"},
		{"remote BuildKit without buildctl", doctorState{org: orgWith(func(o *manifest.Org) { o.Builder.Addr = "tcp://bk:1234" })},
			fakeMachine{}, DoctorFail, DoctorSkip, "buildctl is not on PATH"},
		{"remote BuildKit", doctorState{org: orgWith(func(o *manifest.Org) {
			o.Builder.Addr = "tcp://bk:1234"
			o.Defaults.Platforms = []string{"linux/amd64"}
		})},
			fakeMachine{paths: map[string]string{"buildctl": "/bin/buildctl"}, answers: map[string]fakeAnswer{"buildctl --addr": {stdout: workers("linux/amd64")}}},
			DoctorOK, DoctorOK, "at tcp://bk:1234"},
	} {
		got := doctorBuildKit(context.Background(), c.m.doctorEnv(t), &c.st)
		if got[0].Status != c.bkStatus || got[1].Status != c.emStatus || !strings.Contains(got[0].Detail+got[0].Fix+got[1].Detail+got[1].Fix, c.want) {
			t.Errorf("%s: %+v, want %s and %s with %q", c.name, got, c.bkStatus, c.emStatus, c.want)
		}
	}
}

func TestDoctorTools(t *testing.T) {
	all := map[string]string{"syft": "/bin/syft", "grype": "/bin/grype", "cosign": "/bin/cosign"}
	ok := map[string]fakeAnswer{
		"syft version":   {stdout: `{"version": "1.55.0"}`},
		"grype version":  {stdout: `{"version": "0.121.0"}`},
		"cosign version": {stdout: `{"gitVersion": "v3.1.4"}`},
	}
	with := func(k string, a fakeAnswer) map[string]fakeAnswer {
		m := map[string]fakeAnswer{}
		for kk, v := range ok {
			m[kk] = v
		}
		m[k] = a
		return m
	}
	without := func(n string) map[string]string {
		m := map[string]string{}
		for k, v := range all {
			if k != n {
				m[k] = v
			}
		}
		return m
	}
	scansOff := orgWith(func(o *manifest.Org) { f := false; o.SBOM.Scan = &f })
	for _, c := range []struct {
		name string
		m    fakeMachine
		org  *manifest.Org
		want string // "tool status", space-separated
	}{
		{"all there", fakeMachine{paths: all, answers: ok}, orgWith(nil), "syft ok grype ok cosign ok"},
		{"cosign 2", fakeMachine{paths: all, answers: with("cosign version", fakeAnswer{stdout: `{"gitVersion": "v2.6.1"}`})}, orgWith(nil), "syft ok grype ok cosign warn"},
		{"no syft", fakeMachine{paths: without("syft"), answers: ok}, orgWith(nil), "syft fail grype ok cosign ok"},
		{"no syft, scans off", fakeMachine{paths: without("syft"), answers: ok}, scansOff, "syft skip grype ok cosign ok"},
		{"no cosign", fakeMachine{paths: without("cosign"), answers: ok}, orgWith(nil), "syft ok grype ok cosign fail"},
		{"grype says nothing", fakeMachine{paths: all, answers: with("grype version", fakeAnswer{stdout: "grype 0.1"})}, orgWith(nil), "syft ok grype warn cosign ok"},
	} {
		var got []string
		for _, ch := range doctorTools(context.Background(), c.m.doctorEnv(t), &doctorState{org: c.org}) {
			got = append(got, ch.Name+" "+ch.Status)
			if ch.Status == DoctorFail && ch.Fix == "" {
				t.Errorf("%s: %s fails without a fix", c.name, ch.Name)
			}
		}
		if strings.Join(got, " ") != c.want {
			t.Errorf("%s: %s, want %s", c.name, strings.Join(got, " "), c.want)
		}
	}
}

func TestDoctorRegistry(t *testing.T) {
	m := &manifest.Manifest{Metadata: manifest.Metadata{Ref: "ghcr.io/acme/checkout"}}
	denied := func(context.Context, string) error { return errors.New("UNAUTHORIZED") }
	for _, c := range []struct {
		name   string
		st     doctorState
		push   func(context.Context, string) error
		env    map[string]string
		status string
	}{
		{"no manifest", doctorState{}, nil, nil, DoctorSkip},
		{"may push", doctorState{m: m}, nil, nil, DoctorOK},
		{"may not, here", doctorState{m: m}, denied, nil, DoctorWarn},
		{"may not, in Actions", doctorState{m: m}, denied, map[string]string{"GITHUB_ACTIONS": "true"}, DoctorFail},
	} {
		f := fakeMachine{env: c.env}
		env := f.doctorEnv(t)
		var asked string
		env.checkPush = func(ctx context.Context, repo string) error {
			asked = repo
			if c.push != nil {
				return c.push(ctx, repo)
			}
			return nil
		}
		got := doctorRegistry(context.Background(), env, &c.st)
		if got.Status != c.status || (c.st.m != nil && asked != "ghcr.io/acme/checkout") {
			t.Errorf("%s: %+v (asked about %q), want %s", c.name, got, asked, c.status)
		}
	}
}

// fakeGitHub answers GET /repos/acme/checkout/installation for an App JWT
// signed by key and issued by "Iv1.app", and GET /repos/acme/checkout for
// the token "good".
func fakeGitHub(t *testing.T, key *rsa.PrivateKey, perms map[string]string, installed bool) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		switch r.URL.Path {
		case "/repos/acme/checkout/installation":
			parts := strings.Split(auth, ".")
			ok := len(parts) == 3
			if ok {
				sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
				sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
				claims, _ := base64.RawURLEncoding.DecodeString(parts[1])
				var c struct {
					Iss      string `json:"iss"`
					Iat, Exp int64
				}
				_ = json.Unmarshal(claims, &c)
				ok = rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, sum[:], sig) == nil && c.Iss == "Iv1.app" && c.Exp > time.Now().Unix() && c.Iat <= time.Now().Unix()
			}
			switch {
			case !ok:
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"message": "A JSON web token could not be decoded"}`))
			case !installed:
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"message": "Not Found"}`))
			default:
				_ = json.NewEncoder(w).Encode(map[string]any{"id": 1, "permissions": perms})
			}
		case "/repos/acme/checkout":
			if auth != "good" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"message": "Bad credentials"}`))
				return
			}
			_, _ = w.Write([]byte(`{"full_name": "acme/checkout"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDoctorGitHub(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemOf := func(k *rsa.PrivateKey, pkcs8 bool) string {
		if pkcs8 {
			b, _ := x509.MarshalPKCS8PrivateKey(k)
			return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}))
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}))
	}
	full := map[string]string{"contents": "write", "pull_requests": "write", "metadata": "read"}
	repo := map[string]string{"GITHUB_REPOSITORY": "acme/checkout"}
	app := func(k string, extra map[string]string) map[string]string {
		m := map[string]string{"CLEARCUTT_APP_ID": "Iv1.app", "CLEARCUTT_APP_PRIVATE_KEY": k, "GITHUB_REPOSITORY": "acme/checkout"}
		for kk, v := range extra {
			m[kk] = v
		}
		return m
	}
	for _, c := range []struct {
		name      string
		env       map[string]string
		perms     map[string]string
		installed bool
		status    string
		want      string
	}{
		{"App with the permissions", app(pemOf(key, false), nil), full, true, DoctorOK, "installed on acme/checkout with contents and pull-requests write"},
		{"App, PKCS #8 key", app(pemOf(key, true), nil), full, true, DoctorOK, "installed"},
		{"App without pull requests", app(pemOf(key, false), nil), map[string]string{"contents": "write", "pull_requests": "read"}, true, DoctorFail, `pull-requests write (has "read")`},
		{"App not installed", app(pemOf(key, false), nil), full, false, DoctorFail, "isn't installed on acme/checkout"},
		{"another App's key", app(pemOf(other, false), nil), full, true, DoctorFail, "refuses the App's credentials"},
		{"not a key", app("-----BEGIN NOTHING-----\nAAAA\n-----END NOTHING-----\n", nil), full, true, DoctorFail, "not an RSA private key"},
		{"half an App", map[string]string{"CLEARCUTT_APP_ID": "Iv1.app", "GITHUB_ACTIONS": "true"}, full, true, DoctorFail, "only one of"},
		{"token", map[string]string{"CLEARCUTT_BOT_TOKEN": "good", "GITHUB_REPOSITORY": "acme/checkout"}, nil, true, DoctorOK, "reads acme/checkout"},
		{"bad token", map[string]string{"CLEARCUTT_BOT_TOKEN": "expired", "GITHUB_REPOSITORY": "acme/checkout"}, nil, true, DoctorFail, "Bad credentials"},
		{"nothing, in Actions", map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "acme/checkout"}, nil, true, DoctorWarn, "GITHUB_TOKEN's"},
		{"nothing, here", repo, nil, true, DoctorSkip, "not in GitHub Actions"},
	} {
		srv := fakeGitHub(t, key, c.perms, c.installed)
		f := fakeMachine{env: c.env}
		env := f.doctorEnv(t)
		env.apiURL = srv.URL
		got := doctorGitHub(context.Background(), env, &doctorState{dir: t.TempDir()})
		if got.Status != c.status || !strings.Contains(got.Detail, c.want) {
			t.Errorf("%s: %+v, want %s with %q", c.name, got, c.status, c.want)
		}
		if got.Status == DoctorFail && got.Fix == "" {
			t.Errorf("%s: a failure without a fix", c.name)
		}
	}
}

func TestDoctorVersions(t *testing.T) {
	const sha = "0123456789abcdef0123456789abcdef01234567"
	caller := func(ref string) string {
		return "# uses: northcutted/clearcutt-factory/.github/workflows/app.yml@v0.0.1 (a comment)\njobs:\n  app:\n    uses: northcutted/clearcutt-factory/.github/workflows/app.yml@" + ref + "\n"
	}
	for _, c := range []struct {
		name   string
		files  map[string]string
		local  string
		tags   string // git ls-remote output
		status string
		want   string
	}{
		{"same release", map[string]string{"factory.yml": caller("v1.2.3")}, "v1.2.3", "", DoctorOK, "v1.2.3, as the workflows use (v1.2.3 in factory.yml)"},
		{"older here", map[string]string{"factory.yml": caller("v1.2.3")}, "v1.2.2", "", DoctorWarn, "records v1.2.2 as its generator, and CI checks it with v1.2.3"},
		{"development build", map[string]string{"factory.yml": caller("v1.2.3")}, "dev", "", DoctorWarn, "development build"},
		{"two releases", map[string]string{"factory.yml": caller("v1.2.3"), "other.yml": "    steps:\n      - uses: northcutted/clearcutt-factory@v1.2.2\n"}, "v1.2.3", "", DoctorWarn, "more than one"},
		{"factory-version wins", map[string]string{"factory.yml": caller("v1.2.3") + "    with:\n      factory-version: v1.2.2 # pinned\n"}, "v1.2.2", "", DoctorOK, "v1.2.2 in factory.yml (factory-version)"},
		{"a release's commit", map[string]string{"factory.yml": caller(sha)}, "v1.2.3", sha + "\trefs/tags/v1.2.3^{}\nfeedface\trefs/tags/v1.2.3\n", DoctorOK, "v1.2.3 in factory.yml"},
		{"another commit", map[string]string{"factory.yml": caller(sha)}, "v1.2.3", "", DoctorWarn, "a commit no release tag names"},
		{"main", map[string]string{"factory.yml": caller("main")}, "v1.2.3", "", DoctorWarn, "follow main"},
		{"no factory", map[string]string{"ci.yml": "jobs: {}\n"}, "v1.2.3", "", DoctorSkip, "no workflow"},
	} {
		dir := t.TempDir()
		for n, body := range c.files {
			p := filepath.Join(dir, ".github", "workflows", n)
			_ = os.MkdirAll(filepath.Dir(p), 0o755)
			_ = os.WriteFile(p, []byte(body), 0o644)
		}
		f := fakeMachine{answers: map[string]fakeAnswer{"git ls-remote": {stdout: c.tags}}}
		got := doctorVersions(context.Background(), f.doctorEnv(t), &doctorState{dir: dir}, c.local)
		if got.Status != c.status || !strings.Contains(got.Detail, c.want) {
			t.Errorf("%s: %+v, want %s with %q", c.name, got, c.status, c.want)
		}
	}
}

// The manifest check loads the manifest, its org profile, and its lock:
// a lock a newer release wrote fails with the release to install, one not
// written yet warns.
func TestDoctorManifest(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"factory.org.yaml":      "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\nregistry: ghcr.io/acme\n",
		"img/image.yaml":        "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: Image\nmetadata: {name: img}\nspec:\n  base: cgr.dev/chainguard/wolfi-base:latest\n  platforms: [linux/amd64]\n",
		"newer/image.yaml":      "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: Image\nmetadata: {name: newer}\nspec:\n  base: cgr.dev/chainguard/wolfi-base:latest\n",
		"newer/image.lock.yaml": "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: Lock\ngenerator: clearcutt-factory v9.9.0\n",
	})
	for _, c := range []struct {
		manifest, status, want string
	}{
		{"img/image.yaml", DoctorWarn, "isn't locked yet"},
		{"newer/image.yaml", DoctorFail, "install v9.9.0 or later"},
		{"none/image.yaml", DoctorSkip, "factory.org.yaml"},
	} {
		st := &doctorState{}
		opts := Options{ManifestPath: filepath.Join(dir, c.manifest), Version: "v1.2.3", Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}
		if c.status == DoctorSkip {
			t.Chdir(dir)
		}
		got := doctorManifest(context.Background(), opts, st)
		if got.Status != c.status || !strings.Contains(got.Detail+" "+got.Fix, c.want) || st.org == nil {
			t.Errorf("%s: %+v, want %s with %q", c.manifest, got, c.status, c.want)
		}
		if c.status != DoctorSkip && (st.m == nil || st.m.Metadata.Ref == "") {
			t.Errorf("%s: the manifest isn't handed on: %+v", c.manifest, st.m)
		}
	}
}

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for n, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(n))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// One failed check fails doctor; the JSON report has every check.
func TestDoctorReport(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	f := fakeMachine{}
	r := doctor(context.Background(), Options{ManifestPath: "image.yaml", Version: "v1.2.3", Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}, DoctorOptions{}, f.doctorEnv(t))
	if r.OK {
		t.Errorf("no container runtime, and doctor is ok: %+v", r)
	}
	var names []string
	for _, c := range r.Checks {
		names = append(names, c.Name)
		if c.Status == DoctorFail && c.Fix == "" {
			t.Errorf("%s fails without a fix", c.Name)
		}
	}
	want := "manifest, container runtime, file sharing, buildkit, platforms, syft, grype, cosign, registry push, github app, factory version"
	if strings.Join(names, ", ") != want {
		t.Errorf("checks %s, want %s", strings.Join(names, ", "), want)
	}
	var out bytes.Buffer
	printDoctor(&out, r)
	if !strings.Contains(out.String(), "FAIL  container runtime") || !strings.Contains(out.String(), "fix: install Docker or Podman") {
		t.Errorf("text report:\n%s", out.String())
	}
	b, _ := json.Marshal(r)
	var back DoctorReport
	if err := json.Unmarshal(b, &back); err != nil || back.OK || len(back.Checks) != len(r.Checks) || back.Version != "v1.2.3" {
		t.Errorf("JSON report %s", b)
	}
}
