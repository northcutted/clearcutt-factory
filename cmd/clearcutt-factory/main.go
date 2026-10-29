// Command clearcutt-factory builds signed, attested, reproducible OCI images
// from a declarative manifest. It is part of ClearCutt.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"

	"github.com/northcutted/clearcutt-factory/internal/factory"
)

var version = "" // set with -ldflags "-X main.version=…"

const usage = `clearcutt-factory: declarative, reproducible, signed OCI images (part of ClearCutt)

Usage:
  clearcutt-factory init    [--dir .] [--repo OWNER/NAME] [--registry REGISTRY] [--default-branch BRANCH] [--force]
                            [--extends REF (--extends-identity URL [--extends-issuer URL] | --extends-key K)]
      Set up a repository of images: an org profile, an example image, and a GitHub
      Actions workflow that publishes, updates, and rebases with ClearCutt Factory.
      --extends makes the org profile extend a shared one, signed by that identity or key.
  clearcutt-factory init --platform [--estate-repo OWNER/NAME] [same flags]
      A platform repository: run and build images, a stack, the shared org profile
      with the trust policy (images: any repository of the owner the image names as
      its source), and the workflows that publish them and wake the apps.
  clearcutt-factory init --app [--platform-repo OWNER/NAME] [--stack REF] [--name NAME] [--estate-repo OWNER/NAME]
      An app repository: app.yaml on the platform's stack, an org profile extending
      the platform's (its signature checked), and a caller of app.yml.
  clearcutt-factory init --estate --platform-repo OWNER/NAME [--name NAME]
      An estate repository: clearcutt-verify over the images, with the trust policy
      from the platform's signed profile, published with clearcutt-portal.
      Every kind writes a Dependabot configuration (the app's ecosystem too).
  clearcutt-factory lock    [-f image.yaml] [--update | --update-base | --update-stack | --update-package NAME[,NAME…]…]
      Pin every input and write the lock and Containerfile. --update re-resolves
      all of them; --update-base only the base; --update-stack an app's stack
      (a registry stack to its newest version), build image, and run image, for
      a rebuild on the platform's newest images; --update-package only the named
      distro packages (and what they now need), keeping every other package pin.
  clearcutt-factory render  [-f image.yaml] [--check] [--context-dir DIR]
      Regenerate (or check) the Containerfile.
  clearcutt-factory build   [-f image.yaml] [--push] [--out DIR] [--no-test] [--no-scan] [--no-sign] [--no-cache] [--force-tags]
      Build, smoke-test, SBOM, scan, gate; with --push also sign and attest.
      Tags never move back from a newer image to one published before, and
      an app whose tag holds an image on a newer build of its base is rebased
      onto that base before it takes the tag, unless --force-tags.
  clearcutt-factory verify  [-f image.yaml] --digest sha256:…
      Rebuild from source and compare.
  clearcutt-factory verify  --image repo@sha256:… [--attest] [--key K [--insecure-ignore-tlog] | --certificate-identity[-regexp] R
                            --certificate-oidc-issuer I [--certificate-github-workflow-repository OWNER/REPO]]
      Rebuild from the image's signed recipe (or repeat its recorded rebase) and compare;
      --attest then signs and attaches a reproduction attestation to the image.
  clearcutt-factory rebase  --image repo[:tag|@sha256:…] [--onto BASE] [--from BASE] [--check] [--force]
                            [--push] [--tag T]… [--force-tags] [--out DIR] [--no-scan] [--no-sign]
      Move the image's own layers onto a newer build of its base (default: the
      base it names, resolved again). A tag another publish takes meanwhile
      stays there, and the result is pushed by digest only.
  clearcutt-factory rebase  [-f app.yaml] [--update-lock] [--no-test] [same flags]
      Rebase the app's published image onto its stack's run image and smoke-test
      it; --update-lock then pins the lock to that base.
  clearcutt-factory reattest [-f image.yaml | --image repo[:tag|@sha256:…]] [--older-than 7d] [--out DIR] [--no-sign]
      Rescan the published image's verified SBOMs with grype's newest database
      and attach each platform's new vulnerability report to the same digest,
      signed as builds sign theirs; never rebuilds, never moves a tag. Says
      whether the image has a verified reproduction attestation (reproduced=
      in $GITHUB_OUTPUT), for verify --image … --attest to make one.
  clearcutt-factory affected --changed FILE MANIFEST…
      Print which of the manifests the changed files affect (FILE: git diff
      --name-only or --name-status output; - for stdin), and write manifests=
      to $GITHUB_OUTPUT, for a pull request that builds only what it changed.
      A changed file no manifest owns affects every manifest.
  clearcutt-factory roles   [-f image.yaml] [--dir .]
      Print what the stacks under --dir make of the image, one per line: build
      (a stack's spec.build names its manifest) and/or run (spec.run); nothing
      when no stack names it. images.yml records them so notify.yml can announce
      a build image as clearcutt.build-image-published.
  clearcutt-factory stack push [-f stack.yaml] --ref REGISTRY/REPOSITORY:TAG [--key K | --no-sign]
      Publish a stack so apps in any repository can name it (spec.stack: REF),
      and sign it (with --key K, signing.stackKey, or as images are signed).
      An unchanged stack the org's stack signer signed only moves the tag.
  clearcutt-factory profile push [-f factory.org.yaml] --ref REGISTRY/REPOSITORY:TAG [--key K | --no-sign]
      Publish an org profile, with the trust policy, keys, and VEX it names, so
      other repositories can extend it (extends: {ref: REF, signer: …}), and sign
      it as stacks are signed. An unchanged profile signing.profile signed only
      moves the tag.
  clearcutt-factory version

Common flags:
  -f FILE     manifest, kind Image or App (default image.yaml, else app.yaml)
  --org FILE  org profile (default: nearest factory.org.yaml above the manifest,
              or above the current directory for rebase and verify --image)
  --reverify  check the signature of a shared profile the org profile extends,
              even if this machine checked it in the last 24 hours (always
              checked in CI, and with CLEARCUTT_FACTORY_REVERIFY=1)
  -v          stream BuildKit output
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr), os.Stderr))
}

// exit reports err on stderr and returns the exit code: 2 with the usage
// (once) for a usage error, 1 for any other.
func exit(err error, stderr io.Writer) int {
	if err == nil {
		return 0
	}
	var ue usageError
	if errors.As(err, &ue) {
		if ue.err != nil {
			fmt.Fprintln(stderr, "error:", ue.err)
			fmt.Fprintln(stderr)
		}
		fmt.Fprint(stderr, usage)
		return 2
	}
	fmt.Fprintln(stderr, "error:", err)
	return 1
}

// usageError is a command line the program can't act on; err says what
// was wrong with it, if anything beyond its shape.
type usageError struct{ err error }

func (u usageError) Error() string {
	if u.err != nil {
		return u.err.Error()
	}
	return "usage"
}

// command is one subcommand: define adds its flags to fs (every flag with
// a help string, shown by -h) and returns what runs it.
type command struct {
	name   string
	define func(fs *flag.FlagSet, opts *factory.Options) func(ctx context.Context) error
}

// commands lists the subcommands that take flags; version and help are
// handled in run.
var commands = []command{
	{"lock", func(fs *flag.FlagSet, opts *factory.Options) func(context.Context) error {
		var lo factory.LockOptions
		fs.BoolVar(&lo.Update, "update", false, "re-resolve every input instead of keeping unchanged pins")
		fs.BoolVar(&lo.UpdateBase, "update-base", false, "re-resolve only the base (an app's run image) and what depends on it")
		fs.BoolVar(&lo.UpdateStack, "update-stack", false, "re-resolve only an app's stack (a registry stack to its newest version), its build image, and its run image, for a rebuild on the platform's newest images")
		fs.Var((*listFlag)(&lo.UpdatePackages), "update-package", "re-resolve only these distro packages (NAME[,NAME…], repeatable) and what their new versions need")
		return func(ctx context.Context) error { return factory.Lock(ctx, *opts, lo) }
	}},
	{"render", func(fs *flag.FlagSet, opts *factory.Options) func(context.Context) error {
		check := fs.Bool("check", false, "fail if the Containerfile is out of date instead of writing it")
		ctxDir := fs.String("context-dir", "", "also stage a self-contained build context in this directory")
		return func(ctx context.Context) error { return factory.Render(ctx, *opts, *check, *ctxDir) }
	}},
	{"build", func(fs *flag.FlagSet, opts *factory.Options) func(context.Context) error {
		var bo factory.BuildOptions
		fs.BoolVar(&bo.Push, "push", false, "push the image by digest, sign and attest it, then move its tags")
		fs.StringVar(&bo.OutDir, "out", "out", "directory for the build's outputs (result.json, attestations, logs)")
		fs.BoolVar(&bo.NoScan, "no-scan", false, "skip the syft SBOM scan and the grype vulnerability scan (refused with --push under a shared profile)")
		fs.BoolVar(&bo.NoSign, "no-sign", false, "push without signing or attesting")
		fs.BoolVar(&bo.NoCache, "no-cache", false, "build without BuildKit's cache")
		fs.BoolVar(&bo.NoTest, "no-test", false, "skip the smoke test")
		fs.BoolVar(&bo.ForceTags, "force-tags", false, "move the tags even to an image older than the one they hold (a rollback), and never rebase first")
		return func(ctx context.Context) error { return factory.Build(ctx, *opts, bo) }
	}},
	{"verify", func(fs *flag.FlagSet, opts *factory.Options) func(context.Context) error {
		var vo factory.VerifyOptions
		var key, identity, identityRegexp, issuer, workflowRepo string
		var noTlog bool
		fs.BoolVar(&noTlog, "insecure-ignore-tlog", false, "with --key: accept a signature without a transparency log entry")
		fs.StringVar(&vo.Image, "image", "", "a published image (repo@sha256:…) to rebuild from its signed recipe, or whose rebase to repeat")
		fs.StringVar(&vo.Digest, "digest", "", "the digest a rebuild from source must give (sha256:…)")
		fs.StringVar(&vo.OutDir, "out", "out", "directory for the rebuild's outputs")
		fs.StringVar(&key, "key", "", "verify the recipe with this public key (a file or KMS URI) instead of the org profile's signers")
		fs.StringVar(&identity, "certificate-identity", "", "verify the recipe against this exact certificate identity")
		fs.StringVar(&identityRegexp, "certificate-identity-regexp", "", "verify the recipe against a certificate identity matching this regexp")
		fs.StringVar(&issuer, "certificate-oidc-issuer", "", "the OIDC issuer of the certificate identity")
		fs.StringVar(&workflowRepo, "certificate-github-workflow-repository", "", "require the signing run to be in this GitHub repository (OWNER/REPO)")
		fs.BoolVar(&vo.Attest, "attest", false, "sign and attach a reproduction attestation to --image when it reproduces")
		return func(ctx context.Context) error {
			// With an image and no explicit manifest, trust the signed recipe.
			vo.FromSource = vo.Image == "" || flagSet(fs, "f")
			if noTlog && key == "" {
				return errors.New("--insecure-ignore-tlog applies to --key: a keyless certificate is only valid with a transparency log entry")
			}
			if key != "" {
				vo.VerifyArgs = append(vo.VerifyArgs, "--key", key)
			}
			if noTlog {
				vo.VerifyArgs = append(vo.VerifyArgs, "--insecure-ignore-tlog=true")
			}
			if identity != "" {
				vo.VerifyArgs = append(vo.VerifyArgs, "--certificate-identity", identity)
			}
			if identityRegexp != "" {
				vo.VerifyArgs = append(vo.VerifyArgs, "--certificate-identity-regexp", identityRegexp)
			}
			if issuer != "" {
				vo.VerifyArgs = append(vo.VerifyArgs, "--certificate-oidc-issuer", issuer)
			}
			if workflowRepo != "" {
				vo.VerifyArgs = append(vo.VerifyArgs, "--certificate-github-workflow-repository", workflowRepo)
			}
			return factory.Verify(ctx, *opts, vo)
		}
	}},
	{"rebase", func(fs *flag.FlagSet, opts *factory.Options) func(context.Context) error {
		var ro factory.RebaseOptions
		fs.StringVar(&ro.Image, "image", "", "the image to rebase (repo[:tag|@sha256:…]); default: the app manifest's published image")
		fs.StringVar(&ro.Onto, "onto", "", "the new base; default: the base the image names, resolved again")
		fs.StringVar(&ro.From, "from", "", "the old base, for an image without base annotations")
		fs.BoolVar(&ro.Check, "check", false, "only report whether the rebase is safe; change nothing")
		fs.BoolVar(&ro.Force, "force", false, "rebase despite compatibility breaks (never despite violations)")
		fs.BoolVar(&ro.Push, "push", false, "push the result by digest, sign and attest it, then move the tag")
		fs.Func("tag", "also move this tag to the result (repeatable)", func(s string) error { ro.Tags = append(ro.Tags, s); return nil })
		fs.BoolVar(&ro.ForceTags, "force-tags", false, "move the tags even if another publish took them meanwhile, or they hold a newer image")
		fs.StringVar(&ro.OutDir, "out", "out", "directory for the rebase's outputs")
		fs.BoolVar(&ro.NoScan, "no-scan", false, "skip the SBOM and vulnerability scans (refused with --push under a shared profile)")
		fs.BoolVar(&ro.NoSign, "no-sign", false, "push without signing or attesting")
		fs.BoolVar(&ro.NoTest, "no-test", false, "skip the app's smoke test")
		fs.BoolVar(&ro.UpdateLock, "update-lock", false, "with -f: then pin the app's lock to the base the image is on")
		return func(ctx context.Context) error { return factory.Rebase(ctx, *opts, ro) }
	}},
	{"init", func(fs *flag.FlagSet, opts *factory.Options) func(context.Context) error {
		var io factory.InitOptions
		fs.StringVar(&io.Dir, "dir", ".", "the repository to set up")
		fs.StringVar(&io.Repo, "repo", "", "the GitHub repository (OWNER/NAME); default: the origin remote")
		fs.StringVar(&io.Registry, "registry", "", "where images go; default: ghcr.io/<owner>")
		fs.StringVar(&io.Branch, "default-branch", "", "the branch that publishes (the signer's sourceRef); default: the origin remote's, else main")
		fs.BoolVar(&io.Force, "force", false, "overwrite files that exist")
		fs.StringVar(&io.Extends, "extends", "", "a shared org profile (published with profile push) for the org profile to extend")
		fs.StringVar(&io.ExtendsIdentity, "extends-identity", "", "the certificate identity that signs the shared profile")
		fs.StringVar(&io.ExtendsIssuer, "extends-issuer", "", "its OIDC issuer (default: GitHub Actions)")
		fs.StringVar(&io.ExtendsKey, "extends-key", "", "the public key that signs the shared profile instead of an identity")
		app := fs.Bool("app", false, "set up an app repository: app.yaml, an org profile, and a caller of app.yml")
		platform := fs.Bool("platform", false, "set up a platform repository: run and build images, a stack, the shared org profile and trust policy, and their workflows")
		estate := fs.Bool("estate", false, "set up an estate repository: clearcutt-verify and clearcutt-portal over the organization's images")
		fs.StringVar(&io.Name, "name", "", "the app's name (--app; default the repository's), or the estate's (--estate; default the owner)")
		fs.StringVar(&io.Stack, "stack", "", "the stack the app builds on (--app), e.g. ghcr.io/acme/stacks/go:1; writes app.yaml")
		fs.StringVar(&io.PlatformRepo, "platform-repo", "", "the platform repository (OWNER/NAME) whose profile.yml signs <registry>/factory/org:1: --app extends it, --estate reads its trust policy")
		fs.StringVar(&io.EstateRepo, "estate-repo", "", "the estate repository (OWNER/NAME): --app and --platform send it clearcutt.estate-changed; --platform trusts its estate.yml and wakes only the apps its report proves are built on a run image")
		return func(ctx context.Context) error {
			n := 0
			for kind, set := range map[string]bool{factory.InitApp: *app, factory.InitPlatform: *platform, factory.InitEstate: *estate} {
				if set {
					io.Kind = kind
					n++
				}
			}
			if n > 1 {
				return usageError{errors.New("init takes one of --app, --platform, and --estate")}
			}
			return factory.Init(ctx, *opts, io)
		}
	}},
	{"reattest", func(fs *flag.FlagSet, opts *factory.Options) func(context.Context) error {
		var ro factory.ReattestOptions
		fs.StringVar(&ro.Image, "image", "", "the published image to re-attest (repo[:tag|@sha256:…]); default: the manifest's, by its first tag")
		fs.Func("older-than", "rescan only platforms whose newest verified vulnerability report is older than this (7d, 36h); default: every platform", func(s string) error {
			d, err := factory.ParseAge(s)
			ro.OlderThan = d
			return err
		})
		fs.StringVar(&ro.OutDir, "out", "out", "directory for the SBOMs read and the new reports")
		fs.BoolVar(&ro.NoSign, "no-sign", false, "write the new reports without attaching them")
		return func(ctx context.Context) error {
			if ro.Image != "" && flagSet(fs, "f") {
				return usageError{errors.New("reattest takes -f or --image, not both")}
			}
			return factory.Reattest(ctx, *opts, ro)
		}
	}},
	{"affected", func(fs *flag.FlagSet, opts *factory.Options) func(context.Context) error {
		var ao factory.AffectedOptions
		fs.StringVar(&ao.Changed, "changed", "", "a file listing the changed paths (git diff --name-only or --name-status output; - for stdin)")
		return func(ctx context.Context) error {
			if ao.Changed == "" {
				return usageError{errors.New("affected needs --changed FILE")}
			}
			ao.Manifests = fs.Args()
			if len(ao.Manifests) == 0 {
				return usageError{errors.New("affected needs the manifests to choose from")}
			}
			return factory.Affected(ctx, *opts, ao)
		}
	}},
	{"roles", func(fs *flag.FlagSet, opts *factory.Options) func(context.Context) error {
		var ro factory.RolesOptions
		fs.StringVar(&ro.Dir, "dir", ".", "where to look for stacks (every kind Stack file below it)")
		return func(ctx context.Context) error { return factory.Roles(ctx, *opts, ro) }
	}},
	{"stack push", func(fs *flag.FlagSet, opts *factory.Options) func(context.Context) error {
		var so factory.StackPushOptions
		fs.StringVar(&so.Ref, "ref", "", "where to publish the stack (REGISTRY/REPOSITORY:TAG)")
		fs.StringVar(&so.Key, "key", "", "sign with this key (a file or KMS URI) instead of the org profile's settings")
		fs.BoolVar(&so.NoSign, "no-sign", false, "publish without signing")
		describeFile(fs, "the stack file", "stack.yaml")
		return func(ctx context.Context) error {
			file := "stack.yaml"
			if flagSet(fs, "f") {
				file = opts.ManifestPath
			}
			if so.Ref == "" {
				return errors.New("stack push needs --ref REGISTRY/REPOSITORY:TAG")
			}
			return factory.StackPushWith(ctx, *opts, file, so)
		}
	}},
	{"profile push", func(fs *flag.FlagSet, opts *factory.Options) func(context.Context) error {
		var po factory.ProfilePushOptions
		fs.StringVar(&po.Ref, "ref", "", "where to publish the profile (REGISTRY/REPOSITORY:TAG)")
		fs.StringVar(&po.Key, "key", "", "sign with this key (a file or KMS URI) instead of the org profile's settings")
		fs.BoolVar(&po.NoSign, "no-sign", false, "publish without signing")
		describeFile(fs, "the org profile to publish", "factory.org.yaml")
		return func(ctx context.Context) error {
			file := "factory.org.yaml"
			if flagSet(fs, "f") {
				file = opts.ManifestPath
			}
			if po.Ref == "" {
				return errors.New("profile push needs --ref REGISTRY/REPOSITORY:TAG")
			}
			return factory.ProfilePush(ctx, *opts, file, po)
		}
	}},
}

// describeFile sets what -h says of -f, for a command whose -f is not a
// manifest: its help string and the default the command uses.
func describeFile(fs *flag.FlagSet, usage, def string) {
	if f := fs.Lookup("f"); f != nil {
		f.Usage, f.DefValue = usage, def
	}
}

// flagsFor returns the flag set of cmd, with the common flags and the
// command's own (every one with a help string), and what runs it; nil for
// a command that doesn't exist.
func flagsFor(cmd string, stdout, stderr io.Writer) (*flag.FlagSet, *factory.Options, func(context.Context) error) {
	for _, c := range commands {
		if c.name != cmd {
			continue
		}
		fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
		// The flag package would print the error and the usage itself; run
		// reports both once, through exit.
		fs.SetOutput(io.Discard)
		fs.Usage = func() {}
		opts := &factory.Options{Version: versionString(), Stdout: stdout, Stderr: stderr}
		fs.StringVar(&opts.ManifestPath, "f", "image.yaml", "the manifest, kind Image or App (app.yaml when there is no image.yaml)")
		fs.StringVar(&opts.OrgPath, "org", "", "the org profile (default: the nearest factory.org.yaml above the manifest, or above the current directory for rebase and verify --image)")
		fs.BoolVar(&opts.Verbose, "v", false, "stream BuildKit output")
		fs.BoolVar(&opts.Reverify, "reverify", false, "check a shared profile's signature even if this machine checked it in the last 24 hours")
		return fs, opts, c.define(fs, opts)
	}
	return nil, nil, nil
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return usageError{}
	}
	cmd, args := args[0], args[1:]
	switch cmd {
	case "version", "--version":
		fmt.Fprintln(stdout, versionString())
		return nil
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return nil
	case "stack", "profile":
		if len(args) == 0 || args[0] != "push" {
			return usageError{fmt.Errorf("%s takes the subcommand push", cmd)}
		}
		cmd, args = cmd+" push", args[1:]
	}
	fs, _, exec := flagsFor(cmd, stdout, stderr)
	if fs == nil {
		return usageError{fmt.Errorf("unknown command %q", cmd)}
	}
	if err := parse(fs, args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, usage)
			fmt.Fprintf(stdout, "\nFlags of %s:\n", cmd)
			fs.SetOutput(stdout)
			fs.PrintDefaults()
			return nil
		}
		return err
	}
	return exec(ctx)
}

// listFlag collects a repeatable flag whose values may also be
// comma-separated.
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }

func (l *listFlag) Set(v string) error {
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			*l = append(*l, s)
		}
	}
	if len(*l) == 0 {
		return errors.New("name at least one package")
	}
	return nil
}

// takesArgs lists the commands that take arguments after their flags.
var takesArgs = map[string]bool{"affected": true}

// parse parses args into fs. A flag that doesn't exist, or a bad value, is
// a usage error, as are arguments after the flags, for a command that
// takes none; -h is flag.ErrHelp.
func parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return usageError{err}
	}
	if fs.NArg() > 0 && !takesArgs[fs.Name()] {
		return usageError{fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))}
	}
	// Without -f, use app.yaml when there is no image.yaml.
	if f := fs.Lookup("f"); f != nil && !flagSet(fs, "f") {
		if _, err := os.Stat("image.yaml"); err != nil {
			if _, err := os.Stat("app.yaml"); err == nil {
				_ = f.Value.Set("app.yaml")
			}
		}
	}
	return nil
}

func flagSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) { set = set || f.Name == name })
	return set
}

func versionString() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}
