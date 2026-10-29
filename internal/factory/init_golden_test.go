package factory

import (
	"bytes"
	"context"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/northcutted/clearcutt-factory/internal/manifest"
)

var updateGolden = flag.Bool("update", false, "rewrite init's golden files in testdata/init")

// initCase is one repository init sets up; its files are compared with
// testdata/init/<name>.
type initCase struct {
	name  string
	opts  InitOptions
	files map[string]string // in the directory before init runs
	// extends runs it against a registry and cosign of the test's, which
	// sign the shared profile; HOST stands for the registry in the files.
	extends bool
}

var initCases = []initCase{
	{name: "images", opts: InitOptions{Repo: "Acme/platform-images"}},
	{name: "app", opts: InitOptions{Kind: InitApp, Repo: "acme/checkout", Stack: "ghcr.io/acme/stacks/go:1", EstateRepo: "acme/estate"},
		files: map[string]string{"go.mod": "module example.com/checkout\n", "package.json": "{}\n"}},
	{name: "app-platform", opts: InitOptions{Kind: InitApp, Repo: "acme/storefront", PlatformRepo: "acme/platform", Stack: "HOST/stacks/node:24", EstateRepo: "acme/estate"}, extends: true},
	{name: "platform", opts: InitOptions{Kind: InitPlatform, Repo: "acme/platform", EstateRepo: "acme/estate"}},
	{name: "platform-registry", opts: InitOptions{Kind: InitPlatform, Repo: "acme/platform", Registry: "registry.example.com/acme", Branch: "trunk", AllowCommitPins: true}},
	{name: "estate", opts: InitOptions{Kind: InitEstate, Repo: "acme/estate", PlatformRepo: "acme/platform", Name: "acme"}},
}

// runInitCase sets up c in a new directory and returns it, with the
// registry's host (for HOST) when c.extends.
func runInitCase(t *testing.T, c initCase) (dir, host string) {
	t.Helper()
	ctx := context.Background()
	opts := c.opts
	if c.extends {
		w := newProfileWorld(t, map[string]string{
			"org/profile.yaml": "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\nsigning:\n  trustPolicy: trust.yaml\n  profile: {certificateIdentity: " + profileIdentity + ", certificateOIDCIssuer: " + ghIssuer + "}\n",
			"org/trust.yaml":   "apiVersion: clearcutt.dev/v1\nkind: TrustPolicy\nsigners:\n  - {name: images, identityRegexp: '" + workflowIdentityRegexp("v1.2.3", false) + "', issuer: " + ghIssuer + ", sourceRepositoryOwner: https://github.com/acme, sourceMatchesImage: true}\n",
		})
		digest := w.push("org/profile.yaml")
		newFakeCosign(t, "--certificate-identity "+profileIdentity, w.host+"/factory/org@"+digest)
		host = w.host
		opts.Registry = host
		opts.Stack = strings.ReplaceAll(opts.Stack, "HOST", host)
		ctx = w.ctx
	}
	dir = t.TempDir()
	for n, body := range c.files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	opts.Dir = dir
	var out bytes.Buffer
	if err := Init(ctx, Options{Version: "v1.2.3", Stdout: &out, Stderr: &out}, opts); err != nil {
		t.Fatalf("init %s: %v\n%s", c.name, err, out.String())
	}
	for n := range c.files {
		_ = os.Remove(filepath.Join(dir, n))
	}
	return dir, host
}

// readTree reads every file under dir, by slash path, with host replaced
// by HOST.
func readTree(t *testing.T, dir, host string) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		s := string(b)
		if host != "" {
			s = strings.ReplaceAll(s, host, "HOST")
		}
		files[filepath.ToSlash(rel)] = s
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// TestInitGolden: what init writes for a repository of images, an app (on
// its own, and on a platform's shared profile), a platform (on ghcr.io,
// and on a registry of its own), and an estate, file by file. go test
// ./internal/factory -run TestInitGolden -update rewrites them; review the
// diff like code, since the workflows are what adopters run.
func TestInitGolden(t *testing.T) {
	for _, c := range initCases {
		t.Run(c.name, func(t *testing.T) {
			dir, host := runInitCase(t, c)
			got := readTree(t, dir, host)
			golden := filepath.Join("testdata", "init", c.name)
			if *updateGolden {
				_ = os.RemoveAll(golden)
				for n, body := range got {
					p := filepath.Join(golden, filepath.FromSlash(n))
					if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
						t.Fatal(err)
					}
				}
				return
			}
			want := readTree(t, golden, "")
			for _, n := range keysOf(want) {
				if got[n] != want[n] {
					t.Errorf("%s differs from %s (go test -run TestInitGolden -update rewrites it):\n%s", n, filepath.Join(golden, n), lineDiff(want[n], got[n]))
				}
			}
			for _, n := range keysOf(got) {
				if _, ok := want[n]; !ok {
					t.Errorf("init wrote %s, which %s lacks", n, golden)
				}
			}
		})
	}
}

func keysOf[V any](m map[string]V) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// lineDiff shows the first lines where want and got differ.
func lineDiff(want, got string) string {
	w, g := strings.Split(want, "\n"), strings.Split(got, "\n")
	for i := 0; i < len(w) || i < len(g); i++ {
		var wl, gl string
		if i < len(w) {
			wl = w[i]
		}
		if i < len(g) {
			gl = g[i]
		}
		if wl != gl {
			return "line " + strconv.Itoa(i+1) + ":\n- " + wl + "\n+ " + gl
		}
	}
	return ""
}

// Every workflow init writes calls factory's reusable workflows (and its
// own, ./.github/workflows/…) as they take it: declared inputs and
// secrets, by name, with every permission they ask for, at the release
// init is.
func TestInitWorkflowsCallFactory(t *testing.T) {
	for _, c := range initCases {
		golden := filepath.Join("testdata", "init", c.name)
		workflows, _ := filepath.Glob(filepath.Join(golden, ".github", "workflows", "*.yml"))
		if len(workflows) == 0 {
			t.Errorf("%s: no workflows", golden)
		}
		for _, wf := range workflows {
			b, err := os.ReadFile(wf)
			if err != nil {
				t.Fatal(err)
			}
			refs := checkCalls(t, wf, b, func(p string) []byte {
				b, err := os.ReadFile(filepath.Join(golden, filepath.FromSlash(p)))
				if err != nil {
					t.Fatalf("%s calls %s: %v", wf, p, err)
				}
				return b
			})
			for _, r := range refs {
				if r != "v1.2.3" {
					t.Errorf("%s calls factory's workflows at %s, not the release init is (v1.2.3)", wf, r)
				}
			}
			// Actions are pinned by commit, ClearCutt's own by release tag
			// (Dependabot moves both).
			for _, m := range regexp.MustCompile(`(?m)^\s*(?:- )?uses: ([^\s]+)`).FindAllStringSubmatch(string(b), -1) {
				uses := m[1]
				switch {
				case strings.HasPrefix(uses, "./"):
				case strings.HasPrefix(uses, "northcutted/clearcutt-"):
					if !regexp.MustCompile(`@v\d+\.\d+\.\d+$`).MatchString(uses) {
						t.Errorf("%s: %s is not pinned to a release", wf, uses)
					}
				case !regexp.MustCompile(`@[0-9a-f]{40}$`).MatchString(uses):
					t.Errorf("%s: %s is not pinned by commit", wf, uses)
				}
			}
		}
	}
}

// What init writes loads: org profiles (with the platform's shared profile
// and trust policy), manifests, and stacks; the platform's trust policy
// takes any repository of the owner that an image names as its source, so
// a new app needs no change to it; Dependabot updates every ecosystem the
// app has, and groups the ClearCutt pins.
func TestInitScaffoldsLoad(t *testing.T) {
	platform := filepath.Join("testdata", "init", "platform")
	// The platform's profile extends org/profile.yaml by path.
	org, err := loadOrg(context.Background(), Options{OrgPath: filepath.Join(platform, "factory.org.yaml")}, platform, nil)
	if err != nil {
		t.Fatalf("platform org profile: %v", err)
	}
	if org.Registry != "ghcr.io/acme/platform" || !org.Policy.RequireSignedStacks {
		t.Errorf("platform org profile: registry %s, requireSignedStacks %v", org.Registry, org.Policy.RequireSignedStacks)
	}
	images := org.Signers(manifest.RoleImage)
	if len(images) != 1 || images[0].SourceRepositoryOwner != "https://github.com/acme" || !images[0].SourceMatchesImage || images[0].SourceRef != "refs/heads/main" {
		t.Fatalf("platform image signers: %+v", images)
	}
	for _, c := range []struct {
		source string
		ok     bool
	}{
		{"https://github.com/acme/checkout", true},
		{"https://github.com/acme/a-new-app", true},
		{"https://github.com/acme-evil/checkout", false},
		{"https://github.com/mallory/checkout", false},
		{"", false},
	} {
		args, err := identityArgs(images[0], c.source)
		if (err == nil) != c.ok {
			t.Errorf("an image whose source is %q: %q, %v", c.source, args, err)
		}
		if c.ok && !strings.Contains(strings.Join(args, " "), "--certificate-github-workflow-repository "+strings.TrimPrefix(c.source, "https://github.com/")) {
			t.Errorf("an image whose source is %s: cosign isn't held to that repository: %q", c.source, args)
		}
	}
	if s := org.Signers(manifest.RoleStack); len(s) != 1 || s[0].CertificateIdentity != "https://github.com/acme/platform/.github/workflows/stacks.yml@refs/heads/main" {
		t.Errorf("platform stack signers: %+v", s)
	}
	for _, s := range org.Trust.Signers {
		if slices.Contains(s.Roles, manifest.RoleEstate) && s.Identity != "https://github.com/acme/estate/.github/workflows/estate.yml@refs/heads/main" {
			t.Errorf("estate signer: %+v", s)
		}
	}
	for _, m := range []string{"images/run-go/image.yaml", "images/build-go/image.yaml"} {
		if _, err := manifest.Load(filepath.Join(platform, m)); err != nil {
			t.Errorf("%s: %v", m, err)
		}
	}
	if _, err := manifest.LoadStack(filepath.Join(platform, "stacks/go.yaml")); err != nil {
		t.Errorf("stacks/go.yaml: %v", err)
	}
	pr := filepath.Join("testdata", "init", "platform-registry")
	if o, err := loadOrg(context.Background(), Options{OrgPath: filepath.Join(pr, "factory.org.yaml")}, pr, nil); err != nil || o.Registry != "registry.example.com/acme/platform" {
		t.Errorf("platform-registry org profile: %v", err)
	} else if s := o.Signers(manifest.RoleImage); len(s) != 1 || s[0].SourceRef != "refs/heads/trunk" {
		t.Errorf("platform-registry image signers: %+v", s)
	}
	for _, c := range []string{"images", "app"} {
		if _, err := manifest.LoadOrg(filepath.Join("testdata", "init", c, "factory.org.yaml"), ""); err != nil {
			t.Errorf("%s org profile: %v", c, err)
		}
	}
	app, err := manifest.Load(filepath.Join("testdata", "init", "app", "app.yaml"))
	if err != nil {
		t.Fatalf("app.yaml: %v", err)
	}
	if app.Spec.Stack != "ghcr.io/acme/stacks/go:1" || app.Spec.Labels["org.opencontainers.image.source"] != "https://github.com/acme/checkout" {
		t.Errorf("app.yaml: stack %s, labels %v", app.Spec.Stack, app.Spec.Labels)
	}

	for c, want := range map[string][]string{"images": {"github-actions"}, "app": {"gomod", "npm", "github-actions"}, "platform": {"github-actions"}, "estate": {"github-actions"}} {
		var cfg struct {
			Updates []struct {
				Ecosystem string `yaml:"package-ecosystem"`
				Groups    map[string]struct {
					Patterns []string `yaml:"patterns"`
				} `yaml:"groups"`
			} `yaml:"updates"`
		}
		if err := yaml.Unmarshal(repoFile(t, "internal/factory/testdata/init/"+c+"/.github/dependabot.yml"), &cfg); err != nil {
			t.Fatalf("%s dependabot.yml: %v", c, err)
		}
		var got []string
		for _, u := range cfg.Updates {
			got = append(got, u.Ecosystem)
			if u.Ecosystem == "github-actions" && !slices.Equal(u.Groups["clearcutt"].Patterns, []string{"northcutted/clearcutt-*"}) {
				t.Errorf("%s dependabot.yml: the ClearCutt pins aren't grouped: %+v", c, u.Groups)
			}
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s dependabot.yml updates %v, want %v", c, got, want)
		}
	}
}

// Flags that don't apply to the kind of repository are refused before
// anything is written.
func TestInitRefusesFlagsOfOtherKinds(t *testing.T) {
	for _, c := range []struct {
		opts InitOptions
		want string
	}{
		{InitOptions{Stack: "ghcr.io/acme/stacks/go:1"}, "--stack doesn't apply"},
		{InitOptions{Kind: InitPlatform, Stack: "ghcr.io/acme/stacks/go:1"}, "--stack doesn't apply"},
		{InitOptions{Kind: InitPlatform, PlatformRepo: "acme/platform"}, "--platform-repo doesn't apply"},
		{InitOptions{Kind: InitEstate, EstateRepo: "acme/estate", PlatformRepo: "acme/platform"}, "--estate-repo doesn't apply"},
		{InitOptions{Kind: InitEstate}, "needs --platform-repo"},
		{InitOptions{Kind: InitPlatform, Extends: "ghcr.io/acme/factory/org:1", ExtendsIdentity: "x"}, "--extends doesn't apply"},
		{InitOptions{Kind: InitApp, PlatformRepo: "acme/platform", Extends: "ghcr.io/acme/factory/org:1", ExtendsIdentity: "x"}, "not both"},
		{InitOptions{Kind: InitApp, PlatformRepo: "acme"}, "must look like owner/name"},
		{InitOptions{Kind: InitApp, Name: "Checkout App"}, "--name"},
		{InitOptions{Kind: InitApp, Stack: "go:1 # x"}, "--stack"},
		{InitOptions{Kind: "service"}, "not \"service\""},
		{InitOptions{Kind: InitEstate, PlatformRepo: "acme/platform", AllowCommitPins: true}, "--allow-commit-pins doesn't apply"},
	} {
		dir := t.TempDir()
		c.opts.Dir, c.opts.Repo = dir, "acme/x"
		var out bytes.Buffer
		err := Init(context.Background(), Options{Version: "v1.2.3", Stdout: &out, Stderr: &out}, c.opts)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: got %v, want %q", c.opts, err, c.want)
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			t.Errorf("%+v: wrote %v", c.opts, entries)
		}
	}
}

// init --app's next steps say how the platform finds the app: by layer
// digest only once the estate verifies the app's image (its refs.txt lists
// it), and by the clearcutt-app topic otherwise.
func TestInitAppNextSteps(t *testing.T) {
	for _, c := range []struct {
		opts InitOptions
		want []string
	}{
		{InitOptions{Kind: InitApp, Repo: "acme/checkout", Stack: "ghcr.io/acme/stacks/go:1", EstateRepo: "acme/estate"},
			[]string{"ghcr.io/acme/checkout:latest", "acme/estate's estate/refs.txt", "by layer digest", "topic clearcutt-app"}},
		{InitOptions{Kind: InitApp, Repo: "acme/checkout", Stack: "ghcr.io/acme/stacks/go:1"},
			[]string{"ghcr.io/acme/checkout:latest", "the estate repository's estate/refs.txt", "by layer digest", "topic clearcutt-app"}},
	} {
		var out bytes.Buffer
		c.opts.Dir = t.TempDir()
		if err := Init(context.Background(), Options{Version: "v1.2.3", Stdout: &out, Stderr: &out}, c.opts); err != nil {
			t.Fatal(err)
		}
		text := strings.Join(strings.Fields(out.String()), " ")
		for _, w := range c.want {
			if !strings.Contains(text, w) {
				t.Errorf("%+v: next steps don't say %q:\n%s", c.opts, w, out.String())
			}
		}
	}
}
