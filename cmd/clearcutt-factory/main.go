// Command clearcutt-factory builds signed, attested, reproducible OCI images
// from a declarative manifest. It is part of ClearCutt.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"

	"github.com/northcutted/clearcutt-factory/internal/factory"
)

var version = "" // set with -ldflags "-X main.version=…"

const usage = `clearcutt-factory: declarative, reproducible, signed OCI images (part of ClearCutt)

Usage:
  clearcutt-factory init    [--dir .] [--repo OWNER/NAME] [--registry REGISTRY] [--force]
      Set up a repository: an org profile, an example image, and a GitHub
      Actions workflow that publishes, updates, and rebases with ClearCutt Factory.
  clearcutt-factory lock    [-f image.yaml] [--update | --update-base]
      Pin every input and write the lock and Containerfile. --update re-resolves
      all of them; --update-base only the base.
  clearcutt-factory render  [-f image.yaml] [--check] [--context-dir DIR]
      Regenerate (or check) the Containerfile.
  clearcutt-factory build   [-f image.yaml] [--push] [--out DIR] [--no-test] [--no-scan] [--no-sign] [--no-cache]
      Build, smoke-test, SBOM, scan, gate; with --push also sign and attest.
  clearcutt-factory verify  [-f image.yaml] --digest sha256:…
      Rebuild from source and compare.
  clearcutt-factory verify  --image repo@sha256:… [--key K | --certificate-identity[-regexp] R --certificate-oidc-issuer I
                            [--certificate-github-workflow-repository OWNER/REPO]]
      Rebuild from the image's signed recipe (or repeat its recorded rebase) and compare.
  clearcutt-factory rebase  --image repo[:tag|@sha256:…] [--onto BASE] [--from BASE] [--check] [--force]
                            [--push] [--tag T]… [--out DIR] [--no-scan] [--no-sign]
      Move the image's own layers onto a newer build of its base (default: the
      base it names, resolved again).
  clearcutt-factory rebase  [-f app.yaml] [--update-lock] [--no-test] [same flags]
      Rebase the app's published image onto its stack's run image and smoke-test
      it; --update-lock then pins the lock to that base.
  clearcutt-factory stack push [-f stack.yaml] --ref REGISTRY/REPOSITORY:TAG [--no-sign]
      Publish a stack so apps in any repository can name it (spec.stack: REF),
      and sign it.
  clearcutt-factory version

Common flags:
  -f FILE     manifest, kind Image or App (default image.yaml, else app.yaml)
  --org FILE  org profile (default: nearest factory.org.yaml above the manifest,
              or above the current directory for rebase and verify --image)
  -v          stream BuildKit output
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		var ue usageError
		if errors.As(err, &ue) {
			fmt.Fprint(os.Stderr, usage)
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

type usageError struct{}

func (usageError) Error() string { return "usage" }

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usageError{}
	}
	cmd, args := args[0], args[1:]
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	opts := factory.Options{Version: versionString(), Stdout: os.Stdout, Stderr: os.Stderr}
	fs.StringVar(&opts.ManifestPath, "f", "image.yaml", "")
	fs.StringVar(&opts.OrgPath, "org", "", "")
	fs.BoolVar(&opts.Verbose, "v", false, "")

	switch cmd {
	case "lock":
		var lo factory.LockOptions
		fs.BoolVar(&lo.Update, "update", false, "")
		fs.BoolVar(&lo.UpdateBase, "update-base", false, "")
		if err := parse(fs, args); err != nil {
			return err
		}
		return factory.Lock(ctx, opts, lo)

	case "render":
		check := fs.Bool("check", false, "")
		ctxDir := fs.String("context-dir", "", "")
		if err := parse(fs, args); err != nil {
			return err
		}
		return factory.Render(ctx, opts, *check, *ctxDir)

	case "build":
		var bo factory.BuildOptions
		fs.BoolVar(&bo.Push, "push", false, "")
		fs.StringVar(&bo.OutDir, "out", "out", "")
		fs.BoolVar(&bo.NoScan, "no-scan", false, "")
		fs.BoolVar(&bo.NoSign, "no-sign", false, "")
		fs.BoolVar(&bo.NoCache, "no-cache", false, "")
		fs.BoolVar(&bo.NoTest, "no-test", false, "")
		if err := parse(fs, args); err != nil {
			return err
		}
		return factory.Build(ctx, opts, bo)

	case "verify":
		var vo factory.VerifyOptions
		var key, identity, identityRegexp, issuer, workflowRepo string
		fs.StringVar(&vo.Image, "image", "", "")
		fs.StringVar(&vo.Digest, "digest", "", "")
		fs.StringVar(&vo.OutDir, "out", "out", "")
		fs.StringVar(&key, "key", "", "")
		fs.StringVar(&identity, "certificate-identity", "", "")
		fs.StringVar(&identityRegexp, "certificate-identity-regexp", "", "")
		fs.StringVar(&issuer, "certificate-oidc-issuer", "", "")
		fs.StringVar(&workflowRepo, "certificate-github-workflow-repository", "", "")
		if err := parse(fs, args); err != nil {
			return err
		}
		// With an image and no explicit manifest, trust the signed recipe.
		vo.FromSource = vo.Image == "" || flagSet(fs, "f")
		if key != "" {
			vo.VerifyArgs = append(vo.VerifyArgs, "--key", key)
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
		return factory.Verify(ctx, opts, vo)

	case "rebase":
		var ro factory.RebaseOptions
		fs.StringVar(&ro.Image, "image", "", "")
		fs.StringVar(&ro.Onto, "onto", "", "")
		fs.StringVar(&ro.From, "from", "", "")
		fs.BoolVar(&ro.Check, "check", false, "")
		fs.BoolVar(&ro.Force, "force", false, "")
		fs.BoolVar(&ro.Push, "push", false, "")
		fs.Func("tag", "", func(s string) error { ro.Tags = append(ro.Tags, s); return nil })
		fs.StringVar(&ro.OutDir, "out", "out", "")
		fs.BoolVar(&ro.NoScan, "no-scan", false, "")
		fs.BoolVar(&ro.NoSign, "no-sign", false, "")
		fs.BoolVar(&ro.NoTest, "no-test", false, "")
		fs.BoolVar(&ro.UpdateLock, "update-lock", false, "")
		if err := parse(fs, args); err != nil {
			return err
		}
		return factory.Rebase(ctx, opts, ro)

	case "init":
		var io factory.InitOptions
		fs.StringVar(&io.Dir, "dir", ".", "")
		fs.StringVar(&io.Repo, "repo", "", "")
		fs.StringVar(&io.Registry, "registry", "", "")
		fs.BoolVar(&io.Force, "force", false, "")
		if err := parse(fs, args); err != nil {
			return err
		}
		return factory.Init(ctx, opts, io)

	case "stack":
		if len(args) == 0 || args[0] != "push" {
			return usageError{}
		}
		ref := fs.String("ref", "", "")
		noSign := fs.Bool("no-sign", false, "")
		if err := parse(fs, args[1:]); err != nil {
			return err
		}
		file := "stack.yaml"
		if flagSet(fs, "f") {
			file = opts.ManifestPath
		}
		if *ref == "" {
			return errors.New("stack push needs --ref REGISTRY/REPOSITORY:TAG")
		}
		return factory.StackPush(ctx, opts, file, *ref, *noSign)

	case "version", "--version":
		fmt.Println(versionString())
		return nil

	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	}
	return usageError{}
}

func parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		return usageError{}
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
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
