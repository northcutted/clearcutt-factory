// Command factory builds signed, attested, reproducible OCI images from a
// declarative manifest.
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

	"github.com/northcutted/declarative-image-factory/internal/factory"
)

var version = "" // set with -ldflags "-X main.version=…"

const usage = `factory — declarative, reproducible, signed OCI images

Usage:
  factory lock    [-f image.yaml] [--update | --update-base]
                                                   pin every input (--update: re-resolve all of them;
                                                   --update-base: only the base); write the lock and
                                                   Containerfile
  factory render  [-f image.yaml] [--check] [--context-dir DIR]
                                                   regenerate (or check) the Containerfile
  factory build   [-f image.yaml] [--push] [--out DIR] [--no-test] [--no-scan] [--no-sign] [--no-cache]
                                                   build, smoke-test, SBOM, scan, gate; with --push also
                                                   sign + attest
  factory verify  [-f image.yaml] --digest sha256:…   rebuild from source and compare
  factory verify  --image repo@sha256:… [--key K | --certificate-identity-regexp R --certificate-oidc-issuer I]
                                                   rebuild from the image's signed recipe (or repeat its
                                                   recorded rebase) and compare
  factory rebase  --image repo[:tag|@sha256:…] [--onto BASE] [--from BASE] [--check] [--force]
                  [--push] [--tag T]… [--out DIR] [--no-scan] [--no-sign]
                                                   move the image's own layers onto a newer build of its
                                                   base (default: the base it names, resolved again)
  factory rebase  [-f app.yaml] [--update-lock] [--no-test] [same flags]
                                                   rebase the app's published image onto its stack's run
                                                   image and smoke-test it; --update-lock then pins the
                                                   lock to that base
  factory version

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
		var key, identity, issuer string
		fs.StringVar(&vo.Image, "image", "", "")
		fs.StringVar(&vo.Digest, "digest", "", "")
		fs.StringVar(&vo.OutDir, "out", "out", "")
		fs.StringVar(&key, "key", "", "")
		fs.StringVar(&identity, "certificate-identity-regexp", "", "")
		fs.StringVar(&issuer, "certificate-oidc-issuer", "", "")
		if err := parse(fs, args); err != nil {
			return err
		}
		// With an image and no explicit manifest, trust the signed recipe.
		vo.FromSource = vo.Image == "" || flagSet(fs, "f")
		if key != "" {
			vo.VerifyArgs = append(vo.VerifyArgs, "--key", key)
		}
		if identity != "" {
			vo.VerifyArgs = append(vo.VerifyArgs, "--certificate-identity-regexp", identity)
		}
		if issuer != "" {
			vo.VerifyArgs = append(vo.VerifyArgs, "--certificate-oidc-issuer", issuer)
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
