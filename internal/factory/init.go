package factory

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"text/template"

	"github.com/northcutted/clearcutt-factory/internal/manifest"
)

// What init sets up (InitOptions.Kind).
const (
	// InitImages is a repository of images (and apps) that publishes and
	// maintains itself with one workflow: the default.
	InitImages = ""
	// InitApp is an app repository: an app.yaml and a caller of app.yml.
	InitApp = "app"
	// InitPlatform is a platform repository: run and build images, stacks,
	// and the shared org profile with the organization's trust policy.
	InitPlatform = "platform"
	// InitEstate is an estate repository: clearcutt-verify over the
	// organization's images, published with clearcutt-portal.
	InitEstate = "estate"
)

// The releases of the other ClearCutt tools the estate workflow uses, and
// the grype it rescans with (checked against its checksum). Dependabot
// moves the action pins in the repositories init writes.
const (
	verifyRelease = "v0.18.0"
	portalRelease = "v0.3.0"
	grypeVersion  = "0.120.1"
	grypeSHA256   = "0a9ee97ef5ae2ee953b0a80098105052e846cdbe319a57d808b519c33cd1343d"
	githubIssuer  = manifest.GitHubActionsIssuer
)

type InitOptions struct {
	// Dir is the repository to set up (default ".").
	Dir string
	// Repo is owner/name on GitHub, for the signer identity and image
	// labels. Default: the origin remote.
	Repo string
	// Registry receives the images (default ghcr.io/<owner>). A platform
	// publishes under <registry>/platform, /stacks, and /factory/org:1,
	// apps extending it under <registry>/apps, and the estate's report
	// bundle at <registry>/estate:latest.
	Registry string
	// Branch is the branch that publishes, which the signer identity
	// requires (sourceRef). Default: the origin remote's default branch,
	// else main.
	Branch string
	// Force overwrites existing files.
	Force bool
	// Extends makes the org profile extend this shared profile (published
	// with profile push), signed by ExtendsIdentity (a certificate
	// identity, with ExtendsIssuer, default GitHub Actions) or ExtendsKey.
	// Init checks the signature, and writes only what the shared profile
	// leaves to each repository.
	Extends, ExtendsIdentity, ExtendsIssuer, ExtendsKey string
	// Kind is what to set up: InitImages (the default), InitApp,
	// InitPlatform, or InitEstate.
	Kind string
	// Name is the app's (InitApp) or the estate's (InitEstate); default
	// the repository's name, or its owner's for an estate.
	Name string
	// Stack is the stack an app builds on (InitApp), such as
	// ghcr.io/acme/stacks/go:1; without it no app.yaml is written.
	Stack string
	// PlatformRepo is the platform repository (OWNER/NAME) that publishes
	// the shared profile, as init --platform sets it up: an app extends
	// it, and an estate reads its trust policy from it.
	PlatformRepo string
	// EstateRepo is the estate repository (OWNER/NAME) that verifies the
	// organization's images: an app and a platform send it
	// clearcutt.estate-changed, a platform's trust policy names its
	// workflow as the estate signer, and a platform wakes only the apps its
	// report proves are built on a run image.
	EstateRepo string
}

var (
	releaseRE = regexp.MustCompile(`^v\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$`)
	repoRE    = regexp.MustCompile(`^[\w.-]+/[\w.-]+$`)
	nameRE    = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$`)
)

//go:embed all:scaffold
var scaffoldFS embed.FS

// scaffold is what the templates under scaffold/ are rendered with.
type scaffold struct {
	// Ref is the release (or main) the workflows call factory's at.
	Ref string
	// Repo and Owner are the repository being set up.
	Repo, Owner string
	// Registry is the organization's registry (ghcr.io/<owner>).
	Registry string
	// LoginHost is the registry's host when it isn't ghcr.io, which the
	// workflows log in to with REGISTRY_USERNAME and REGISTRY_PASSWORD.
	LoginHost string
	Branch    string
	// IdentityRegexp matches the certificate identity of factory's signing
	// workflows.
	IdentityRegexp string
	Name, Stack    string
	// App is set for an app repository.
	App bool
	// Ecosystems are the app's own package ecosystems, for Dependabot.
	Ecosystems []ecosystem
	// Platform is the platform repository; ProfileRef and ProfileSigner
	// its shared profile and who signs it.
	Platform, ProfileRef, ProfileSigner string
	// Estate is the estate repository, EstateName the way a workflow in
	// this repository names it, EstateRef its report bundle and
	// EstateSigner who signs it.
	Estate, EstateName, EstateRef, EstateSigner string
	VerifyRef, PortalRef                        string
	GrypeVersion, GrypeSHA256                   string
}

type ecosystem struct{ Name, Dir string }

// Init scaffolds a repository of the kind io.Kind names: its org profile,
// manifests, GitHub Actions workflows that call ClearCutt Factory's
// reusable workflows, and a Dependabot configuration.
func Init(ctx context.Context, opts Options, io InitOptions) error {
	dir := io.Dir
	if dir == "" {
		dir = "."
	}
	if err := checkInitOptions(io); err != nil {
		return err
	}
	repo := io.Repo
	if repo == "" {
		repo = githubRepo(ctx, dir)
	}
	if repo != "" && !repoRE.MatchString(repo) {
		return fmt.Errorf("--repo %q must look like owner/name", repo)
	}
	owner, name, _ := strings.Cut(repo, "/")
	registry := strings.TrimSuffix(io.Registry, "/")
	if registry == "" && owner != "" {
		registry = "ghcr.io/" + strings.ToLower(owner)
	}
	if repo == "" {
		opts.logf("warning: no GitHub origin remote found; fill in OWNER/REPO (or pass --repo)")
		repo, owner, name, registry = "OWNER/REPO", "OWNER", "REPO", firstNonEmpty(registry, "ghcr.io/OWNER")
	}
	branch := io.Branch
	if branch == "" {
		branch = defaultBranch(ctx, dir)
	}
	if !regexp.MustCompile(`^[\w./-]+$`).MatchString(branch) || strings.HasPrefix(branch, "refs/") {
		return fmt.Errorf("--default-branch %q must be a branch name, like main", branch)
	}
	// Release builds pin what they are; development builds follow main.
	ref := "main"
	if releaseRE.MatchString(opts.Version) {
		ref = opts.Version
	}
	d := scaffold{
		Ref: ref, Repo: repo, Owner: owner, Registry: registry, Branch: branch,
		IdentityRegexp: workflowIdentityRegexp(ref),
		Stack:          io.Stack,
		VerifyRef:      verifyRelease, PortalRef: portalRelease,
		GrypeVersion: grypeVersion, GrypeSHA256: grypeSHA256,
	}
	if host, _, _ := strings.Cut(registry, "/"); host != "ghcr.io" {
		d.LoginHost = host
	}
	if io.PlatformRepo != "" {
		d.Platform = io.PlatformRepo
	} else if io.Kind == InitPlatform {
		d.Platform = repo
	}
	if d.Platform != "" {
		d.ProfileRef = registry + "/factory/org:1"
		d.ProfileSigner = "https://github.com/" + d.Platform + "/.github/workflows/profile.yml@refs/heads/" + branch
	}
	if io.EstateRepo != "" {
		d.Estate = io.EstateRepo
	} else if io.Kind == InitEstate {
		d.Estate = repo
	}
	if d.Estate != "" {
		d.EstateName = d.Estate
		if estateOwner, estateName, _ := strings.Cut(d.Estate, "/"); strings.EqualFold(estateOwner, owner) {
			d.EstateName = estateName
		}
		d.EstateRef = registry + "/estate:latest"
		d.EstateSigner = "https://github.com/" + d.Estate + "/.github/workflows/estate.yml@refs/heads/" + branch
	}
	switch io.Kind {
	case InitApp:
		d.App = true
		d.Name = firstNonEmpty(io.Name, strings.ToLower(name))
		d.Ecosystems = ecosystems(dir)
	case InitEstate:
		d.Name = firstNonEmpty(io.Name, owner)
	}
	if io.Kind == InitApp && d.Platform != "" && io.Registry == "" {
		// Apps go beside the platform's images: <registry>/apps/<name>.
		d.Registry = registry + "/apps"
	}

	// The org profile: an app's extends the platform's shared profile (or
	// the one --extends names), checking its signature now.
	org := ""
	if io.Kind == InitImages || io.Kind == InitApp {
		org = orgFile
		extends := io
		if io.PlatformRepo != "" {
			extends.Extends, extends.ExtendsIdentity = d.ProfileRef, d.ProfileSigner
		}
		if extends.Extends != "" || extends.ExtendsIdentity != "" || extends.ExtendsIssuer != "" || extends.ExtendsKey != "" {
			var err error
			if org, err = extendingOrg(ctx, opts, dir, extends, d.Registry); err != nil {
				return err
			}
		}
	}

	files, err := initFiles(io.Kind, org, d)
	if err != nil {
		return err
	}
	var wrote []string
	for _, f := range files {
		p := filepath.Join(dir, filepath.FromSlash(f.path))
		if _, err := os.Stat(p); err == nil && !io.Force {
			opts.printf("kept %s (exists; --force overwrites)", f.path)
			continue
		} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, f.body, 0o644); err != nil {
			return err
		}
		wrote = append(wrote, f.path)
	}
	for _, p := range wrote {
		opts.printf("wrote %s", p)
	}
	opts.printf("%s", nextSteps(io.Kind, d))
	return nil
}

// checkInitOptions refuses flags that don't apply to the kind of
// repository being set up.
func checkInitOptions(io InitOptions) error {
	kind := io.Kind
	switch kind {
	case InitImages, InitApp, InitPlatform, InitEstate:
	default:
		return fmt.Errorf("init sets up a repository of images (the default), an app, a platform, or an estate, not %q", kind)
	}
	what := map[string]string{InitImages: "a repository of images", InitApp: "--app", InitPlatform: "--platform", InitEstate: "--estate"}[kind]
	for _, c := range []struct {
		set   bool
		flag  string
		kinds []string
	}{
		{io.Stack != "", "--stack", []string{InitApp}},
		{io.Name != "", "--name", []string{InitApp, InitEstate}},
		{io.PlatformRepo != "", "--platform-repo", []string{InitApp, InitEstate}},
		{io.EstateRepo != "", "--estate-repo", []string{InitApp, InitPlatform}},
		{io.Extends != "" || io.ExtendsIdentity != "" || io.ExtendsIssuer != "" || io.ExtendsKey != "", "--extends", []string{InitImages, InitApp}},
	} {
		if c.set && !slices.Contains(c.kinds, kind) {
			return fmt.Errorf("%s doesn't apply to %s", c.flag, what)
		}
	}
	if io.PlatformRepo != "" && (io.Extends != "" || io.ExtendsIdentity != "" || io.ExtendsKey != "") {
		return errors.New("--platform-repo names the shared profile to extend (its profile.yml signs <registry>/factory/org:1); give it or --extends, not both")
	}
	if kind == InitEstate && io.PlatformRepo == "" {
		return errors.New("init --estate needs --platform-repo OWNER/NAME: the platform repository whose signed profile holds the trust policy")
	}
	for flag, r := range map[string]string{"--platform-repo": io.PlatformRepo, "--estate-repo": io.EstateRepo} {
		if r != "" && !repoRE.MatchString(r) {
			return fmt.Errorf("%s %q must look like owner/name", flag, r)
		}
	}
	if io.Name != "" && !nameRE.MatchString(io.Name) {
		return fmt.Errorf("--name %q must be lowercase letters, digits, '.', '_', and '-'", io.Name)
	}
	if s := io.Stack; s != "" && (strings.ContainsAny(s, " \t\n#'\"") || !strings.Contains(s, "/")) {
		return fmt.Errorf("--stack %q must be a stack reference, like ghcr.io/acme/stacks/go:1", s)
	}
	return nil
}

type initFile struct {
	path string
	body []byte
}

// initFiles renders what init writes for kind. org is the org profile's
// template, for the kinds that have one.
func initFiles(kind, org string, d scaffold) ([]initFile, error) {
	var paths []string
	switch kind {
	case InitImages:
		paths = []string{"images/images/example/image.yaml", "images/.github/workflows/clearcutt-factory.yml", "common/.github/dependabot.yml"}
	case InitApp:
		paths = []string{"app/.github/workflows/factory.yml", "common/.github/dependabot.yml", "common/.gitignore"}
		if d.Stack != "" {
			paths = append([]string{"app/app.yaml"}, paths...)
		}
	case InitPlatform:
		paths = []string{
			"platform/factory.org.yaml", "platform/org/profile.yaml", "platform/org/trust.yaml",
			"platform/images/run-go/image.yaml", "platform/images/build-go/image.yaml", "platform/stacks/go.yaml",
			"platform/.github/workflows/platform.yml", "platform/.github/workflows/stacks.yml", "platform/.github/workflows/profile.yml",
			"platform/.github/workflows/update-locks.yml", "platform/.github/workflows/reattest.yml",
			"common/.github/dependabot.yml", "common/.gitignore",
		}
	case InitEstate:
		paths = []string{"estate/.github/workflows/estate.yml", "estate/estate/policy.yaml", "estate/estate/refs.txt", "common/.github/dependabot.yml"}
	}
	var files []initFile
	if org != "" {
		body, err := renderScaffold("factory.org.yaml", org, d)
		if err != nil {
			return nil, err
		}
		files = append(files, initFile{"factory.org.yaml", body})
	}
	for _, p := range paths {
		tmpl, err := scaffoldFS.ReadFile(path.Join("scaffold", p+".tmpl"))
		if err != nil {
			return nil, err
		}
		body, err := renderScaffold(p, string(tmpl), d)
		if err != nil {
			return nil, err
		}
		_, out, _ := strings.Cut(p, "/")
		files = append(files, initFile{out, body})
	}
	return files, nil
}

// renderScaffold executes a scaffold template. Its actions are {% … %}, since the
// files hold GitHub Actions expressions (${{ … }}) and stack templates
// ({{name}}) of their own.
func renderScaffold(name, tmpl string, d scaffold) ([]byte, error) {
	t, err := template.New(name).Delims("{%", "%}").Option("missingkey=error").Parse(tmpl)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	if err := t.Execute(&b, d); err != nil {
		return nil, err
	}
	return []byte(strings.TrimRight(b.String(), "\n") + "\n"), nil
}

// ecosystems lists the package ecosystems Dependabot knows whose manifests
// are in dir, the app's source.
func ecosystems(dir string) []ecosystem {
	var out []ecosystem
	for _, e := range []struct {
		name  string
		files []string
	}{
		{"gomod", []string{"go.mod"}},
		{"npm", []string{"package.json"}},
		{"pip", []string{"requirements.txt", "pyproject.toml", "setup.py", "Pipfile"}},
		{"cargo", []string{"Cargo.toml"}},
		{"maven", []string{"pom.xml"}},
		{"gradle", []string{"build.gradle", "build.gradle.kts"}},
		{"bundler", []string{"Gemfile"}},
		{"composer", []string{"composer.json"}},
		{"nuget", []string{"packages.config", "Directory.Packages.props"}},
	} {
		for _, f := range e.files {
			if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
				out = append(out, ecosystem{Name: e.name, Dir: "/"})
				break
			}
		}
	}
	return out
}

func nextSteps(kind string, d scaffold) string {
	const automation = `  Commit and push. On GitHub, so that CI runs on the pull requests the weekly
  and daily jobs open: install a GitHub App with contents and pull-requests
  write, and set a CLEARCUTT_APP_ID variable (its Client ID) and a
  CLEARCUTT_APP_PRIVATE_KEY secret; or add a CLEARCUTT_BOT_TOKEN secret (a
  fine-grained token with the same permissions). Without either, allow GitHub
  Actions to create pull requests (Settings → Actions → General) and approve
  their CI runs by hand. See docs/adopting.md.`
	switch kind {
	case InitApp:
		s := "\nNext:\n"
		if d.Stack == "" {
			s += "  Write app.yaml naming the platform's stack (init --app --stack REF writes one).\n"
		}
		estate := "the estate repository's"
		if d.Estate != "" {
			estate = d.Estate + "'s"
		}
		s += `  clearcutt-factory lock  -f app.yaml   # pin the stack, its build and run images
  clearcutt-factory build -f app.yaml   # build, test, scan locally
` + automation + `
  Once it publishes, add ` + d.Registry + "/" + d.Name + `:latest to ` + estate + `
  estate/refs.txt: a new run image wakes the apps the estate's report proves,
  by layer digest, are built on it, so only apps whose images the estate
  verifies. For a run image the report can't answer for, the platform's
  notify job falls back to the topic: give this repository the topic
  clearcutt-app, and install the App on it. Require "app / images / result"
  in branch protection.`
		return s
	case InitPlatform:
		s := `
Next:
  clearcutt-factory lock -f images/run-go/image.yaml     # pin every input
  clearcutt-factory lock -f images/build-go/image.yaml
  clearcutt-factory build -f images/run-go/image.yaml    # build, test, scan locally
` + automation + `
  Install the App on the app repositories too, so notify.yml can wake them.
  Make the packages under ` + d.Registry + ` public (or grant the app and
  estate repositories read access to them). Each app repository:
    clearcutt-factory init --app --platform-repo ` + d.Repo + ` --stack ` + d.Registry + `/stacks/go:1`
		if d.Estate != "" {
			s += " --estate-repo " + d.Estate
		}
		return s
	case InitEstate:
		return `
Next:
  List the images to verify in estate/refs.txt, each app's as it starts
  publishing: the platform wakes, by layer digest, only apps whose images
  this report covers (the rest by topic). Commit and push; set Pages'
  source to GitHub Actions. The platform's trust policy must name this
  repository's estate.yml as its estate signer (init --platform --estate-repo
  ` + d.Repo + ` writes it), and its platform and apps send
  clearcutt.estate-changed here (init --platform/--app --estate-repo ` + d.Repo + `),
  with a GitHub App installed on this repository too.`
	}
	return `
Next:
  clearcutt-factory lock  -f images/example/image.yaml   # pin every input
  clearcutt-factory build -f images/example/image.yaml   # build, test, scan locally
` + automation
}

// extendingOrg checks the shared profile io.Extends names against its
// signer and returns an org profile template that extends it, adding only
// what it leaves to each repository: the registry (registry, unless the
// shared profile sets one), and who signs this repository's images.
func extendingOrg(ctx context.Context, opts Options, dir string, io InitOptions, registry string) (string, error) {
	if io.Extends == "" {
		return "", errors.New("--extends-identity, --extends-issuer, and --extends-key name who signs the shared profile --extends names")
	}
	e := manifest.Extends{Ref: io.Extends}
	var signer string
	switch {
	case (io.ExtendsIdentity == "") == (io.ExtendsKey == ""):
		return "", errors.New("--extends needs who signs the shared profile: --extends-identity (a certificate identity) or --extends-key")
	case io.ExtendsKey != "":
		if io.ExtendsIssuer != "" {
			return "", errors.New("--extends-issuer goes with --extends-identity, not --extends-key")
		}
		e.Signer.Key, signer = io.ExtendsKey, io.ExtendsKey
		if !strings.Contains(io.ExtendsKey, "://") {
			abs, err := filepath.Abs(io.ExtendsKey)
			if err != nil {
				return "", err
			}
			e.Signer.Key = abs
			if absDir, err := filepath.Abs(dir); err == nil {
				if r, err := filepath.Rel(absDir, abs); err == nil {
					signer = filepath.ToSlash(r)
				}
			}
		}
		signer = "    key: " + signer + "\n"
	default:
		e.Signer.CertificateIdentity = io.ExtendsIdentity
		e.Signer.CertificateOIDCIssuer = firstNonEmpty(io.ExtendsIssuer, githubIssuer)
		signer = "    certificateIdentity: " + e.Signer.CertificateIdentity + "\n    certificateOIDCIssuer: " + e.Signer.CertificateOIDCIssuer + "\n"
	}
	// Check the signature now, whatever this machine checked before: this
	// is where the repository starts trusting the profile.
	vopts := opts
	vopts.Reverify = true
	path, digest, err := fetchProfile(ctx, vopts, e, "")
	if err != nil {
		return "", fmt.Errorf("--extends %s: %w", io.Extends, err)
	}
	shared, err := manifest.ReadShared(path)
	if err != nil {
		return "", fmt.Errorf("--extends %s: %w", io.Extends, err)
	}
	opts.printf("%s (%s) is signed by the signer given", io.Extends, digest)

	var b strings.Builder
	b.WriteString(orgExtendsHeader)
	b.WriteString("extends:\n  ref: " + io.Extends + " # each manifest's lock pins its digest; lock --update moves it\n")
	b.WriteString("  signer: # who may sign the shared profile; checked whenever it is loaded\n" + signer)
	if shared.Registry == "" {
		b.WriteString("\nregistry: {% .Registry %} # images go to <registry>/<metadata.name>\n")
	} else if io.Registry != "" && registry != shared.Registry {
		opts.logf("warning: the shared profile sets the registry (%s), so %s isn't written", shared.Registry, registry)
	}
	if shared.Trust == nil && shared.Signing.Verify.IsZero() {
		if shared.Signing.Mode == "" || shared.Signing.Mode == "keyless" {
			b.WriteString(orgVerifyBlock)
		} else {
			b.WriteString("\n# The shared profile signs with keys; name this repository's public key:\n# signing:\n#   verify: {key: keys/images.pub}\n")
		}
	}
	return b.String(), nil
}

// workflowIdentityRegexp matches the certificate identity of ClearCutt
// Factory's signing reusable workflows (images.yml, fleet.yml, and
// reattest.yml) at the ref the generated workflows call them by: any
// release tag, or a commit (a caller that pins them by SHA, or app.yml at
// one), or, for a development build, main.
func workflowIdentityRegexp(ref string) string {
	at := `(refs/tags/v\d+\.\d+\.\d+|[0-9a-f]{40})$`
	if !releaseRE.MatchString(ref) {
		at = `refs/heads/` + regexp.QuoteMeta(ref) + `$`
	}
	return `^https://github\.com/northcutted/clearcutt-factory/\.github/workflows/(images|fleet|reattest)\.yml@` + at
}

// defaultBranch is the origin remote's default branch (its HEAD), else
// main.
func defaultBranch(ctx context.Context, dir string) string {
	out, err := exec.CommandContext(ctx, "git", "-C", dir, "symbolic-ref", "--quiet", "refs/remotes/origin/HEAD").Output()
	if b, ok := strings.CutPrefix(strings.TrimSpace(string(out)), "refs/remotes/origin/"); err == nil && ok && b != "" {
		return b
	}
	return "main"
}

// githubRepo reads owner/name from the origin remote, if it is on GitHub.
func githubRepo(ctx context.Context, dir string) string {
	out, err := exec.CommandContext(ctx, "git", "-C", dir, "config", "--get", "remote.origin.url").Output()
	if err != nil {
		return ""
	}
	m := regexp.MustCompile(`github\.com[:/]([\w.-]+/[\w.-]+?)(?:\.git)?/?$`).FindStringSubmatch(strings.TrimSpace(string(out)))
	if m == nil {
		return ""
	}
	return m[1]
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// orgFile is the standalone org profile: this repository's registry,
// signer, gate, and policy.
var orgFile = mustScaffold("images/factory.org.yaml")

func mustScaffold(p string) string {
	b, err := scaffoldFS.ReadFile(path.Join("scaffold", p+".tmpl"))
	if err != nil {
		panic(err)
	}
	return string(b)
}

const orgExtendsHeader = `# yaml-language-server: $schema=https://raw.githubusercontent.com/northcutted/clearcutt-factory/{% .Ref %}/schemas/org.schema.json
# Org profile. It extends the platform team's shared profile, which sets the
# builder, signing, vulnerability gate, and policy: this file adds what the
# shared profile leaves to each repository, and may tighten (never loosen)
# the gate and policy.
apiVersion: factory.clearcutt.dev/v1alpha1
kind: OrgProfile

`

const orgVerifyBlock = `
signing:
  verify:
    # Images are signed inside ClearCutt Factory's reusable workflows, so the
    # certificate names those workflows, at the release tag (or commit) they
    # are called by. Keep reattest in the regexp before enabling its
    # schedule: a newly attached report must verify too.
    # Any repository can call them, so
    # sourceRepository binds signatures to runs in this repository, and
    # sourceRef to runs on the branch that publishes (the reusable workflows
    # publish only from the default branch, or their publish-ref input).
    certificateIdentityRegexp: {% .IdentityRegexp %}
    certificateOIDCIssuer: https://token.actions.githubusercontent.com
    sourceRepository: https://github.com/{% .Repo %}
    sourceRef: refs/heads/{% .Branch %}
`
