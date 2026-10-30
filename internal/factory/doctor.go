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
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/northcutted/clearcutt-factory/internal/builder"
	"github.com/northcutted/clearcutt-factory/internal/lock"
	"github.com/northcutted/clearcutt-factory/internal/manifest"
	"github.com/northcutted/clearcutt-factory/internal/registry"
)

// DoctorOptions are doctor's own flags.
type DoctorOptions struct {
	// OutDir is where builds write (build --out), which the container
	// runtime must see.
	OutDir string
	// JSON prints the report as JSON instead of text.
	JSON bool
}

// Doctor check statuses.
const (
	DoctorOK   = "ok"
	DoctorWarn = "warn"
	DoctorFail = "fail"
	DoctorSkip = "skip"
)

// DoctorCheck is one thing doctor checked: what it found and, when it
// isn't ok, how to fix it.
type DoctorCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
	Fix    string `json:"fix,omitempty"`
}

// DoctorReport is doctor's output (--json).
type DoctorReport struct {
	Version string        `json:"version"`
	OK      bool          `json:"ok"`
	Checks  []DoctorCheck `json:"checks"`
}

// ErrDoctor means a check failed; the report says which and how to fix it.
var ErrDoctor = errors.New("doctor found problems; each failed check says how to fix it")

// doctorEnv is what doctor checks through, so tests can stand in for the
// machine.
type doctorEnv struct {
	// run runs a program and returns its stdout and stderr.
	run      func(ctx context.Context, name string, args ...string) (stdout, stderr []byte, err error)
	lookPath func(string) (string, error)
	getenv   func(string) string
	// http calls the GitHub API, at apiURL.
	http   *http.Client
	apiURL string
	// checkPush checks that the registry's credentials may push to repo
	// without pushing anything.
	checkPush func(ctx context.Context, repo string) error
	now       func() time.Time
}

func systemDoctorEnv() doctorEnv {
	return doctorEnv{
		run: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
			cmd := exec.CommandContext(ctx, name, args...)
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			return stdout.Bytes(), stderr.Bytes(), err
		},
		lookPath: exec.LookPath,
		getenv:   os.Getenv,
		http:     &http.Client{Timeout: 20 * time.Second},
		apiURL:   firstNonEmpty(os.Getenv("GITHUB_API_URL"), "https://api.github.com"),
		checkPush: func(ctx context.Context, repo string) error {
			ref, err := name.ParseReference(repo + ":clearcutt-doctor")
			if err != nil {
				return err
			}
			// Starts an upload and abandons it: nothing is pushed.
			return remote.CheckPushPermission(ref, authn.DefaultKeychain, remote.DefaultTransport)
		},
		now: time.Now,
	}
}

// Doctor checks that this machine (or CI runner) can do what factory
// does: a container runtime that can see the repository and the out
// directory, BuildKit with every platform the manifest builds, syft,
// grype, and cosign, push access to the registry, the GitHub App or token
// the workflows open pull requests with, and the same factory release as
// the repository's workflows. It prints a fix for each failure, and fails
// when any check does.
func Doctor(ctx context.Context, opts Options, do DoctorOptions) error {
	r := doctor(ctx, opts, do, systemDoctorEnv())
	if do.JSON {
		enc := json.NewEncoder(opts.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(r); err != nil {
			return err
		}
	} else {
		printDoctor(opts.Stdout, r)
	}
	if !r.OK {
		return ErrDoctor
	}
	return nil
}

func printDoctor(w io.Writer, r DoctorReport) {
	fmt.Fprintf(w, "clearcutt-factory doctor (%s)\n", r.Version)
	width := 0
	for _, c := range r.Checks {
		width = max(width, len(c.Name))
	}
	counts := map[string]int{}
	for _, c := range r.Checks {
		counts[c.Status]++
		fmt.Fprintf(w, "%-5s %-*s  %s\n", strings.ToUpper(c.Status), width, c.Name, c.Detail)
		if c.Fix != "" {
			fmt.Fprintf(w, "%-5s %-*s  fix: %s\n", "", width, "", c.Fix)
		}
	}
	fmt.Fprintf(w, "%d ok, %d warnings, %d failed, %d skipped\n", counts[DoctorOK], counts[DoctorWarn], counts[DoctorFail], counts[DoctorSkip])
}

// doctorState is what the checks learn and hand on.
type doctorState struct {
	m   *manifest.Manifest
	org *manifest.Org
	// runtime is the container runtime's binary, when its server answers.
	runtime string
	// dir is the repository's top level.
	dir string
}

func doctor(ctx context.Context, opts Options, do DoctorOptions, env doctorEnv) DoctorReport {
	r := DoctorReport{Version: opts.Version}
	add := func(c DoctorCheck) { r.Checks = append(r.Checks, c) }
	st := &doctorState{}

	add(doctorManifest(ctx, opts, st))
	st.dir = repoTop(ctx, env, st)
	add(doctorRuntime(ctx, env, st))
	add(doctorFileSharing(ctx, env, st, do.OutDir))
	for _, c := range doctorBuildKit(ctx, env, st) {
		add(c)
	}
	for _, c := range doctorTools(ctx, env, st) {
		add(c)
	}
	add(doctorRegistry(ctx, env, st))
	add(doctorGitHub(ctx, env, st))
	add(doctorVersions(ctx, env, st, opts.Version))

	r.OK = !slices.ContainsFunc(r.Checks, func(c DoctorCheck) bool { return c.Status == DoctorFail })
	return r
}

// doctorManifest loads the manifest, its org profile (checking a shared
// profile's signature), and its lock, for the checks that follow; without
// a manifest, the nearest org profile, or factory's defaults.
func doctorManifest(ctx context.Context, opts Options, st *doctorState) DoctorCheck {
	c := DoctorCheck{Name: "manifest"}
	if _, err := os.Stat(opts.ManifestPath); err != nil {
		org, err := loadOrg(ctx, opts, ".", nil)
		switch {
		case err != nil:
			st.org = manifest.DefaultOrg()
			c.Status, c.Detail, c.Fix = DoctorFail, "the org profile doesn't load: "+err.Error(), "fix the org profile (factory.org.yaml), or pass the one to use with --org"
		case org.Path != "":
			st.org = org
			c.Status, c.Detail = DoctorSkip, fmt.Sprintf("no %s here (-f names one); checking with %s", opts.ManifestPath, rel(org.Path))
		default:
			st.org = org
			c.Status, c.Detail = DoctorSkip, fmt.Sprintf("no %s or org profile here (-f, --org); checking with factory's defaults", opts.ManifestPath)
		}
		return c
	}
	m, org, l, err := loadLocked(ctx, opts)
	if err == nil {
		st.m, st.org = m, org
		c.Status, c.Detail = DoctorOK, fmt.Sprintf("%s loads with its org profile, and %s is current", opts.ManifestPath, filepath.Base(m.LockPath()))
		if l.Generator != "" {
			c.Detail += " (written by " + strings.TrimPrefix(l.Generator, lock.GeneratorName+" ") + ")"
		}
		return c
	}
	// Load without the lock, for the checks that need the manifest.
	m, org, lerr := load(ctx, opts, false)
	if lerr != nil {
		st.org = manifest.DefaultOrg()
		if o, err := loadOrg(ctx, opts, filepath.Dir(opts.ManifestPath), nil); err == nil {
			st.org = o
		}
		c.Status, c.Detail, c.Fix = DoctorFail, lerr.Error(), "fix the manifest or its org profile (the message says where)"
		return c
	}
	st.m, st.org = m, org
	var newer *lock.NewerError
	switch {
	case errors.As(err, &newer):
		c.Status, c.Detail, c.Fix = DoctorFail, err.Error(), "install "+strings.TrimPrefix(newer.Generator, lock.GeneratorName+" ")+" or later (docs/adopting.md#1-install)"
	case errors.Is(err, fs.ErrNotExist) || strings.Contains(err.Error(), "does not exist; run clearcutt-factory lock"):
		c.Status, c.Detail, c.Fix = DoctorWarn, fmt.Sprintf("%s isn't locked yet", opts.ManifestPath), "clearcutt-factory lock -f "+opts.ManifestPath
	default:
		c.Status, c.Detail, c.Fix = DoctorWarn, err.Error(), "clearcutt-factory lock -f "+opts.ManifestPath
	}
	return c
}

// repoTop is the git top level of the manifest's directory (or this one).
func repoTop(ctx context.Context, env doctorEnv, st *doctorState) string {
	dir := "."
	if st.m != nil {
		dir = st.m.Dir()
	}
	if out, _, err := env.run(ctx, "git", "-C", dir, "rev-parse", "--show-toplevel"); err == nil {
		if top := strings.TrimSpace(string(out)); top != "" {
			return top
		}
	}
	if abs, err := filepath.Abs(dir); err == nil {
		return abs
	}
	return dir
}

func doctorRuntime(ctx context.Context, env doctorEnv, st *doctorState) DoctorCheck {
	c := DoctorCheck{Name: "container runtime"}
	pref := st.org.Builder.Runtime
	if e := env.getenv("CLEARCUTT_FACTORY_RUNTIME"); e != "" {
		pref = e
	}
	rt := ""
	for _, cand := range []string{"docker", "podman"} {
		if pref != "" && pref != "auto" && pref != cand {
			continue
		}
		if p, err := env.lookPath(cand); err == nil {
			rt = p
			break
		}
	}
	if rt == "" {
		c.Status, c.Detail = DoctorFail, "no container runtime on PATH"
		if pref != "" && pref != "auto" {
			c.Detail = pref + " (builder.runtime or CLEARCUTT_FACTORY_RUNTIME) is not on PATH"
		}
		c.Fix = "install Docker or Podman: builds run BuildKit in a container, and smoke tests run the image"
		return c
	}
	short := filepath.Base(rt)
	version := short
	if out, _, err := env.run(ctx, rt, "--version"); err == nil {
		version = strings.TrimSpace(string(out))
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if _, stderr, err := env.run(ctx, rt, "info"); err != nil {
		c.Status, c.Detail = DoctorFail, fmt.Sprintf("%s, but its server doesn't answer: %s", version, stderrLine(stderr, err))
		if strings.Contains(short, "podman") {
			c.Fix = "start the Podman machine (podman machine start); if it runs, check that the default connection points at it (podman system connection list)"
		} else {
			c.Fix = "start Docker (Docker Desktop, or the docker service), and check DOCKER_HOST and docker context"
		}
		return c
	}
	st.runtime = rt
	c.Status, c.Detail = DoctorOK, version+", its server answers"
	return c
}

// doctorFileSharing checks that a container sees the repository and the
// out directory, which builds mount into the BuildKit container: a runtime
// in a VM (a Podman machine, Docker Desktop) sees only shared directories.
func doctorFileSharing(ctx context.Context, env doctorEnv, st *doctorState, outDir string) DoctorCheck {
	c := DoctorCheck{Name: "file sharing"}
	switch {
	case st.org.Builder.Addr != "":
		c.Status, c.Detail = DoctorSkip, "builder.addr names a BuildKit of its own, which reads the context through buildctl"
		return c
	case st.runtime == "":
		c.Status, c.Detail = DoctorSkip, "no container runtime answers"
		return c
	}
	out := existingDir(firstNonEmpty(outDir, "out"))
	repo, outReal := builder.HostPath(st.dir), builder.HostPath(out)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	_, stderr, err := env.run(ctx, st.runtime, "run", "--rm",
		"--mount", "type=bind,source="+repo+",target=/repo,readonly",
		"--mount", "type=bind,source="+outReal+",target=/out,readonly",
		"--entrypoint", "sh", registry.Qualify(st.org.Builder.BuildKit), "-c", "test -d /repo && test -d /out")
	if err != nil {
		var nse *builder.NotSharedError
		if e := builder.NotShared(st.runtime, string(stderr)); errors.As(e, &nse) {
			c.Status, c.Detail = DoctorFail, nse.Path+" isn't visible to "+filepath.Base(st.runtime)
			c.Fix = nse.Error()
			return c
		}
		c.Status, c.Detail = DoctorFail, "a container couldn't mount "+repo+" and "+outReal+": "+stderrLine(stderr, err)
		c.Fix = "check that " + filepath.Base(st.runtime) + " can run " + st.org.Builder.BuildKit + " and mount these directories"
		return c
	}
	c.Status, c.Detail = DoctorOK, fmt.Sprintf("%s sees the repository (%s) and the out directory (%s)", filepath.Base(st.runtime), repo, outReal)
	return c
}

// existingDir is p, or the nearest directory above it that exists.
func existingDir(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	for {
		if fi, err := os.Stat(abs); err == nil && fi.IsDir() {
			return abs
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			return abs
		}
		abs = parent
	}
}

// doctorBuildKit checks that BuildKit starts and builds every platform the
// manifest (or the org profile's defaults) builds, natively or emulated.
func doctorBuildKit(ctx context.Context, env doctorEnv, st *doctorState) []DoctorCheck {
	bk := DoctorCheck{Name: "buildkit"}
	emu := DoctorCheck{Name: "platforms"}
	var stdout, stderr []byte
	var err error
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	switch {
	case st.org.Builder.Addr != "":
		bin, lerr := env.lookPath("buildctl")
		if lerr != nil {
			bk.Status, bk.Detail, bk.Fix = DoctorFail, "builder.addr is set, but buildctl is not on PATH", "install buildctl (BuildKit's client), or remove builder.addr to run BuildKit in a container"
			emu.Status, emu.Detail = DoctorSkip, "BuildKit doesn't answer"
			return []DoctorCheck{bk, emu}
		}
		stdout, stderr, err = env.run(ctx, bin, "--addr", st.org.Builder.Addr, "debug", "workers", "--format", "{{json .}}")
	case st.runtime == "":
		bk.Status, bk.Detail = DoctorSkip, "no container runtime answers"
		emu.Status, emu.Detail = DoctorSkip, "no container runtime answers"
		return []DoctorCheck{bk, emu}
	default:
		stdout, stderr, err = env.run(ctx, st.runtime, "run", "--rm", "--privileged", "--entrypoint", "buildctl-daemonless.sh",
			registry.Qualify(st.org.Builder.BuildKit), "debug", "workers", "--format", "{{json .}}")
	}
	var workers []struct {
		Platforms []struct {
			OS           string `json:"os"`
			Architecture string `json:"architecture"`
			Variant      string `json:"variant"`
		} `json:"platforms"`
		BuildkitVersion struct {
			Version string `json:"version"`
		} `json:"buildkitVersion"`
	}
	if err == nil {
		err = json.Unmarshal(bytes.TrimSpace(stdout), &workers)
	}
	if err != nil || len(workers) == 0 {
		bk.Status, bk.Detail = DoctorFail, "BuildKit didn't start: "+stderrLine(stderr, err)
		if st.org.Builder.Addr != "" {
			bk.Fix = "check that buildkitd answers at " + st.org.Builder.Addr
		} else {
			bk.Fix = "check that " + filepath.Base(st.runtime) + " can pull " + st.org.Builder.BuildKit + " and run privileged containers (rootless Podman: podman machine set --rootful, or a Docker runtime)"
		}
		emu.Status, emu.Detail = DoctorSkip, "BuildKit doesn't answer"
		return []DoctorCheck{bk, emu}
	}
	have := map[string]bool{}
	var names []string
	for _, w := range workers {
		for _, p := range w.Platforms {
			n := p.OS + "/" + p.Architecture
			if !have[n] {
				names = append(names, n)
			}
			have[n] = true
			if p.Variant != "" {
				have[n+"/"+p.Variant] = true
			}
		}
	}
	where := "in a container"
	if st.org.Builder.Addr != "" {
		where = "at " + st.org.Builder.Addr
	}
	bk.Status, bk.Detail = DoctorOK, fmt.Sprintf("BuildKit %s answers %s", firstNonEmpty(workers[0].BuildkitVersion.Version, "(version unknown)"), where)

	want := st.org.Defaults.Platforms
	from := "the org profile's defaults"
	if st.m != nil {
		want, from = st.m.Spec.Platforms, st.m.Path
	}
	if len(want) == 0 {
		want = []string{"linux/amd64", "linux/arm64"}
	}
	var missing []string
	for _, p := range want {
		if !have[p] {
			missing = append(missing, p)
		}
	}
	if len(missing) > 0 {
		emu.Status = DoctorFail
		emu.Detail = fmt.Sprintf("BuildKit can't build %s, which %s builds (it builds %s)", strings.Join(missing, ", "), from, strings.Join(names, ", "))
		emu.Fix = "register QEMU emulation for them: " + filepath.Base(firstNonEmpty(st.runtime, "docker")) + " run --privileged --rm tonistiigi/binfmt --install all (on a Podman machine or Docker Desktop, inside its VM); or build only the platforms this machine has"
		return []DoctorCheck{bk, emu}
	}
	emu.Status, emu.Detail = DoctorOK, fmt.Sprintf("BuildKit builds %s (%s; it builds %s)", strings.Join(want, ", "), from, strings.Join(names, ", "))
	return []DoctorCheck{bk, emu}
}

// doctorTools checks syft, grype, and cosign, and their versions.
func doctorTools(ctx context.Context, env doctorEnv, st *doctorState) []DoctorCheck {
	scans := st.org.SBOM.Scan == nil || *st.org.SBOM.Scan
	var out []DoctorCheck
	for _, t := range []struct {
		name, why, install string
		args               []string
		field              string
		needed             bool
		minMajor           int
	}{
		{"syft", "SBOMs", "https://github.com/anchore/syft#installation", []string{"version", "-o", "json"}, "version", scans, 0},
		{"grype", "vulnerability scans", "https://github.com/anchore/grype#installation", []string{"version", "-o", "json"}, "version", scans, 0},
		{"cosign", "signing and verifying", "https://docs.sigstore.dev/cosign/system_config/installation/", []string{"version", "--json"}, "gitVersion", st.org.Signing.Mode != "none", 3},
	} {
		c := DoctorCheck{Name: t.name}
		bin, err := env.lookPath(t.name)
		if err != nil {
			c.Status, c.Detail, c.Fix = DoctorFail, t.name+" is not on PATH ("+t.why+")", "install "+t.name+": "+t.install
			if t.name != "cosign" {
				c.Fix += "; or build with --no-scan"
			}
			if !t.needed {
				c.Status, c.Fix = DoctorSkip, ""
				c.Detail += ", which the org profile turns off"
			}
			out = append(out, c)
			continue
		}
		stdout, stderr, err := env.run(ctx, bin, t.args...)
		var v map[string]any
		if err == nil {
			err = json.Unmarshal(stdout, &v)
		}
		version, _ := v[t.field].(string)
		if err != nil || version == "" {
			c.Status, c.Detail, c.Fix = DoctorWarn, fmt.Sprintf("%s doesn't say its version: %s", bin, stderrLine(stderr, err)), "reinstall "+t.name+": "+t.install
			out = append(out, c)
			continue
		}
		version = "v" + strings.TrimPrefix(version, "v")
		c.Status, c.Detail = DoctorOK, version+" ("+bin+")"
		if major, ok := majorOf(version); t.minMajor > 0 && ok && major < t.minMajor {
			c.Status = DoctorWarn
			c.Detail = fmt.Sprintf("%s (%s): factory and its workflows use cosign %d (the bundles it writes, signing configs)", version, bin, t.minMajor)
			c.Fix = "install cosign v" + strconv.Itoa(t.minMajor) + ": " + t.install
		}
		out = append(out, c)
	}
	return out
}

func majorOf(v string) (int, bool) {
	m := regexp.MustCompile(`^v(\d+)\.`).FindStringSubmatch(v)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	return n, err == nil
}

// doctorRegistry checks, without pushing, that the credentials this
// machine has may push to the manifest's repository.
func doctorRegistry(ctx context.Context, env doctorEnv, st *doctorState) DoctorCheck {
	c := DoctorCheck{Name: "registry push"}
	if st.m == nil || st.m.Metadata.Ref == "" {
		c.Status, c.Detail = DoctorSkip, "no manifest (-f) to name the repository"
		return c
	}
	repo := st.m.Metadata.Ref
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if err := env.checkPush(ctx, repo); err != nil {
		host, _, _ := strings.Cut(repo, "/")
		c.Status, c.Detail = DoctorFail, "can't push to "+repo+": "+err.Error()
		c.Fix = "log in: docker login " + host + " (or podman login); for ghcr.io, a token with write:packages. In Actions the reusable workflows log in themselves (packages: write; REGISTRY_USERNAME/REGISTRY_PASSWORD or the OIDC inputs elsewhere)"
		if env.getenv("GITHUB_ACTIONS") != "true" {
			c.Status = DoctorWarn
			c.Detail += " (only build --push needs it; CI pushes)"
		}
		return c
	}
	c.Status, c.Detail = DoctorOK, "the credentials here may push to "+repo+" (checked without pushing)"
	return c
}

// doctorGitHub checks the identity the workflows open pull requests and
// dispatch with: the GitHub App (CLEARCUTT_APP_ID with
// CLEARCUTT_APP_PRIVATE_KEY) installed on the repository with contents
// and pull-requests write, or CLEARCUTT_BOT_TOKEN.
func doctorGitHub(ctx context.Context, env doctorEnv, st *doctorState) DoctorCheck {
	c := DoctorCheck{Name: "github app"}
	appID, key, token := env.getenv("CLEARCUTT_APP_ID"), env.getenv("CLEARCUTT_APP_PRIVATE_KEY"), env.getenv("CLEARCUTT_BOT_TOKEN")
	inActions := env.getenv("GITHUB_ACTIONS") == "true"
	repo := env.getenv("GITHUB_REPOSITORY")
	if repo == "" {
		repo = githubRepoWith(ctx, env, st.dir)
	}
	switch {
	case (appID == "") != (key == ""):
		c.Status, c.Detail = DoctorFail, "only one of CLEARCUTT_APP_ID and CLEARCUTT_APP_PRIVATE_KEY is set: the workflows fail rather than fall back to another identity"
		c.Fix = "set both: the App's Client ID as the CLEARCUTT_APP_ID variable, its private key as the CLEARCUTT_APP_PRIVATE_KEY secret"
		return c
	case appID != "" && repo == "":
		c.Status, c.Detail = DoctorSkip, "the GitHub App is set, but no GitHub repository is known to check it on (GITHUB_REPOSITORY, or an origin remote on GitHub)"
		return c
	case appID != "":
		return doctorApp(ctx, env, appID, key, repo)
	case token != "" && repo != "":
		status, body, err := githubGet(ctx, env, "/repos/"+repo, "Bearer "+token)
		switch {
		case err != nil:
			c.Status, c.Detail, c.Fix = DoctorWarn, "couldn't reach the GitHub API: "+err.Error(), "check the network, then run doctor again"
		case status == http.StatusOK:
			c.Name, c.Status = "github token", DoctorOK
			c.Detail = "CLEARCUTT_BOT_TOKEN reads " + repo + " (GitHub doesn't show a fine-grained token's permissions: it needs contents and pull-requests write)"
		default:
			c.Name, c.Status = "github token", DoctorFail
			c.Detail = fmt.Sprintf("CLEARCUTT_BOT_TOKEN can't read %s (HTTP %d: %s)", repo, status, apiMessage(body))
			c.Fix = "make a new fine-grained token with contents and pull-requests write on " + repo + ", or use a GitHub App (docs/adopting.md#a-github-app-for-the-automation)"
		}
		return c
	case inActions:
		c.Status, c.Detail = DoctorWarn, "no GitHub App (CLEARCUTT_APP_ID, CLEARCUTT_APP_PRIVATE_KEY) or CLEARCUTT_BOT_TOKEN: the bot's pull requests are GITHUB_TOKEN's, and GitHub holds their CI until someone approves it"
		c.Fix = "install a GitHub App with contents and pull-requests write and set CLEARCUTT_APP_ID and CLEARCUTT_APP_PRIVATE_KEY (docs/adopting.md#a-github-app-for-the-automation); pass them to this step's env to check them"
		return c
	}
	c.Status, c.Detail = DoctorSkip, "not in GitHub Actions, and CLEARCUTT_APP_ID/CLEARCUTT_APP_PRIVATE_KEY or CLEARCUTT_BOT_TOKEN aren't set here to check"
	return c
}

// doctorApp checks the App's credentials (a JWT signed with its key) and
// its installation on repo, with the permissions the workflows ask for.
func doctorApp(ctx context.Context, env doctorEnv, appID, key, repo string) DoctorCheck {
	c := DoctorCheck{Name: "github app"}
	jwt, err := appJWT(appID, key, env.now())
	if err != nil {
		c.Status, c.Detail, c.Fix = DoctorFail, "CLEARCUTT_APP_PRIVATE_KEY: "+err.Error(), "set it to the whole .pem file the App's settings generate (Generate a private key)"
		return c
	}
	status, body, err := githubGet(ctx, env, "/repos/"+repo+"/installation", "Bearer "+jwt)
	switch {
	case err != nil:
		c.Status, c.Detail, c.Fix = DoctorWarn, "couldn't reach the GitHub API: "+err.Error(), "check the network, then run doctor again"
		return c
	case status == http.StatusUnauthorized:
		c.Status, c.Detail = DoctorFail, fmt.Sprintf("GitHub refuses the App's credentials (HTTP 401: %s)", apiMessage(body))
		c.Fix = "CLEARCUTT_APP_ID must be the App's Client ID (or App ID), and CLEARCUTT_APP_PRIVATE_KEY one of its current private keys"
		return c
	case status == http.StatusNotFound:
		c.Status, c.Detail = DoctorFail, "the App isn't installed on "+repo
		c.Fix = "install it on " + repo + " (the App's settings → Install App), and on the repositories it dispatches to"
		return c
	case status != http.StatusOK:
		c.Status, c.Detail, c.Fix = DoctorWarn, fmt.Sprintf("GitHub answered HTTP %d: %s", status, apiMessage(body)), "run doctor again"
		return c
	}
	var inst struct {
		Permissions map[string]string `json:"permissions"`
	}
	if err := json.Unmarshal(body, &inst); err != nil {
		c.Status, c.Detail = DoctorWarn, "unreadable installation: "+err.Error()
		return c
	}
	var lacks []string
	for _, p := range []string{"contents", "pull_requests"} {
		if inst.Permissions[p] != "write" {
			lacks = append(lacks, fmt.Sprintf("%s write (has %q)", strings.ReplaceAll(p, "_", "-"), inst.Permissions[p]))
		}
	}
	if len(lacks) > 0 {
		c.Status, c.Detail = DoctorFail, "the App is installed on "+repo+" without "+strings.Join(lacks, ", ")
		c.Fix = "give the App Contents and Pull requests read and write (its settings → Permissions), and accept the new permissions on the installation"
		return c
	}
	c.Status, c.Detail = DoctorOK, "the App is installed on "+repo+" with contents and pull-requests write"
	return c
}

// appJWT is a GitHub App's JSON Web Token: RS256, issued by appID (its
// Client ID or App ID), valid for nine minutes.
func appJWT(appID, keyPEM string, now time.Time) (string, error) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return "", errors.New("not a PEM private key")
	}
	var key *rsa.PrivateKey
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		key = k
	} else if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return "", errors.New("not an RSA private key")
		}
		key = rk
	} else {
		return "", fmt.Errorf("not an RSA private key: %w", err)
	}
	enc := base64.RawURLEncoding
	header := enc.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, _ := json.Marshal(map[string]any{"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(9 * time.Minute).Unix(), "iss": appID})
	signing := header + "." + enc.EncodeToString(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + enc.EncodeToString(sig), nil
}

func githubGet(ctx context.Context, env doctorEnv, path, auth string) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(env.apiURL, "/")+path, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := env.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, err
}

func apiMessage(body []byte) string {
	var m struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &m) == nil && m.Message != "" {
		return m.Message
	}
	return strings.TrimSpace(string(body))
}

// githubRepoWith reads owner/name from the origin remote of dir.
func githubRepoWith(ctx context.Context, env doctorEnv, dir string) string {
	out, _, err := env.run(ctx, "git", "-C", dir, "config", "--get", "remote.origin.url")
	if err != nil {
		return ""
	}
	m := regexp.MustCompile(`github\.com[:/]([\w.-]+/[\w.-]+?)(?:\.git)?/?$`).FindStringSubmatch(strings.TrimSpace(string(out)))
	if m == nil {
		return ""
	}
	return m[1]
}

var (
	// A step's or job's uses: of factory's action or workflows (not a
	// comment), and a factory-version input given a release.
	factoryUseRE     = regexp.MustCompile(`(?m)^[ \t]*(?:-[ \t]+)?uses:[ \t]*["']?northcutted/clearcutt-factory(?:/\.github/workflows/[\w.-]+\.ya?ml)?@([\w./-]+)`)
	factoryVersionRE = regexp.MustCompile(`(?m)^[ \t]*factory-version:[ \t]*["']?(v\d[\w.-]*)["']?[ \t]*(?:#.*)?$`)
	shaRE            = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// doctorVersions compares this clearcutt-factory with the release the
// repository's workflows run (the ref they call factory's workflows and
// action at, or their factory-version input): a lock written here records
// this one as its generator, and CI checks it with that one.
func doctorVersions(ctx context.Context, env doctorEnv, st *doctorState, local string) DoctorCheck {
	c := DoctorCheck{Name: "factory version"}
	files, _ := filepath.Glob(filepath.Join(st.dir, ".github", "workflows", "*.y*ml"))
	pins := map[string][]string{} // release (or ref) → where
	var commits []string
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		where := filepath.Base(f)
		explicit := factoryVersionRE.FindAllStringSubmatch(string(b), -1)
		for _, m := range explicit {
			pins[m[1]] = appendUnique(pins[m[1]], where+" (factory-version)")
		}
		if len(explicit) > 0 {
			continue // the workflows install the release factory-version names
		}
		for _, m := range factoryUseRE.FindAllStringSubmatch(string(b), -1) {
			ref := m[1]
			if shaRE.MatchString(ref) {
				commits = appendUnique(commits, ref)
			}
			pins[ref] = appendUnique(pins[ref], where)
		}
	}
	if len(pins) == 0 {
		c.Status, c.Detail = DoctorSkip, "no workflow in "+filepath.Join(st.dir, ".github", "workflows")+" calls ClearCutt Factory"
		return c
	}
	// A commit stands for the release tagged at it.
	if len(commits) > 0 {
		tags := releaseTags(ctx, env)
		for _, sha := range commits {
			if tag, ok := tags[sha]; ok {
				pins[tag] = append(pins[tag], pins[sha]...)
				delete(pins, sha)
			}
		}
	}
	var refs []string
	for r := range pins {
		refs = append(refs, r)
	}
	slices.Sort(refs)
	var desc []string
	for _, r := range refs {
		desc = append(desc, r+" in "+strings.Join(pins[r], ", "))
	}
	used := strings.Join(desc, "; ")
	switch {
	case len(refs) > 1:
		c.Status, c.Detail = DoctorWarn, "the workflows use more than one factory: "+used
		c.Fix = "pin every workflow to the same release (Dependabot's clearcutt group moves them together)"
	case shaRE.MatchString(refs[0]):
		c.Status, c.Detail = DoctorWarn, "the workflows pin factory by a commit no release tag names: "+used
		c.Fix = "pin a release (or the commit a release tag names), so CI runs a signed release"
	case !releaseRE.MatchString(refs[0]):
		c.Status, c.Detail = DoctorWarn, "the workflows follow "+used+", not a release"
		c.Fix = "pin a release tag, as init writes it"
	case !releaseRE.MatchString(local):
		c.Status, c.Detail = DoctorWarn, "this is a development build ("+firstNonEmpty(local, "dev")+"); the workflows use "+used+": a lock it writes may not match CI's"
		c.Fix = "install clearcutt-factory " + refs[0] + " (docs/adopting.md#1-install)"
	case refs[0] != local:
		c.Status, c.Detail = DoctorWarn, "this is "+local+"; the workflows use "+used+": a lock written here records "+local+" as its generator, and CI checks it with "+refs[0]
		c.Fix = "install clearcutt-factory " + refs[0] + " (docs/adopting.md#1-install), or move the workflows to " + local
	default:
		c.Status, c.Detail = DoctorOK, local+", as the workflows use ("+used+")"
	}
	return c
}

// releaseTags maps each commit a release tag (vX.Y.Z) points at to the
// newest such tag, as the action picks the release to install at a commit:
// an annotated tag by the commit it peels to, not its tag object.
func releaseTags(ctx context.Context, env doctorEnv) map[string]string {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	out, _, err := env.run(ctx, "git", "ls-remote", "--tags", "https://github.com/northcutted/clearcutt-factory")
	tags := map[string]string{}
	if err != nil {
		return tags
	}
	direct, peeled := map[string]string{}, map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		sha, ref, ok := strings.Cut(strings.TrimSpace(line), "\t")
		if !ok {
			continue
		}
		tag := strings.TrimPrefix(ref, "refs/tags/")
		if t, ok := strings.CutSuffix(tag, "^{}"); ok {
			peeled[t] = sha
		} else {
			direct[tag] = sha
		}
	}
	for tag, sha := range direct {
		v := stableReleaseRE.FindStringSubmatch(tag)
		if v == nil {
			continue
		}
		if p, ok := peeled[tag]; ok {
			sha = p
		}
		if cur, ok := tags[sha]; !ok || releaseLess(stableReleaseRE.FindStringSubmatch(cur), v) {
			tags[sha] = tag
		}
	}
	return tags
}

var stableReleaseRE = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)$`)

// releaseLess orders two stableReleaseRE matches.
func releaseLess(a, b []string) bool {
	for i := 1; i <= 3; i++ {
		x, _ := strconv.Atoi(a[i])
		y, _ := strconv.Atoi(b[i])
		if x != y {
			return x < y
		}
	}
	return false
}

func appendUnique(s []string, v string) []string {
	if slices.Contains(s, v) {
		return s
	}
	return append(s, v)
}

// stderrLine is the first line of stderr worth showing, else err's message.
func stderrLine(stderr []byte, err error) string {
	for _, l := range strings.Split(string(stderr), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "Copying ") && !strings.HasPrefix(l, "Trying to pull") && !strings.HasPrefix(l, "Getting image") && !strings.HasPrefix(l, "Writing manifest") {
			return l
		}
	}
	if err != nil {
		return err.Error()
	}
	return "no output"
}
