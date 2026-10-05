package factory

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"go.yaml.in/yaml/v3"

	"github.com/northcutted/declarative-image-factory/internal/attest"
	"github.com/northcutted/declarative-image-factory/internal/builder"
	"github.com/northcutted/declarative-image-factory/internal/diff"
	"github.com/northcutted/declarative-image-factory/internal/lock"
	"github.com/northcutted/declarative-image-factory/internal/manifest"
	"github.com/northcutted/declarative-image-factory/internal/registry"
	"github.com/northcutted/declarative-image-factory/internal/render"
)

type VerifyOptions struct {
	// Image is a pushed image by digest. Without FromSource, its signed recipe
	// attestation drives the rebuild.
	Image string
	// Digest is the expected digest when rebuilding from source.
	Digest string
	// FromSource rebuilds from the local manifest and lock.
	FromSource bool
	OutDir     string
	// VerifyArgs are passed to cosign verify-attestation (key or identity).
	VerifyArgs []string
}

// Verify rebuilds an image from scratch (no cache) and checks that the digest
// matches. Source is either the local manifest+lock or the image's signed recipe.
func Verify(ctx context.Context, opts Options, vo VerifyOptions) error {
	expected := vo.Digest
	if vo.Image != "" {
		d, err := name.NewDigest(vo.Image)
		if err != nil {
			return fmt.Errorf("--image must be pinned by digest (repo@sha256:…): %w", err)
		}
		if expected != "" && expected != d.DigestStr() {
			return errors.New("--digest and the digest in --image disagree")
		}
		expected = d.DigestStr()
	}
	if expected == "" {
		return errors.New("nothing to compare against: pass --image repo@sha256:… or --digest sha256:…")
	}

	var (
		req     builder.Request
		org     *manifest.Org
		label   string
		workDir string
		// previous is a local layout of the expected build, used to explain a
		// mismatch when there is no pushed image to compare against.
		previous string
	)
	if vo.FromSource {
		m, o, l, err := loadLocked(opts)
		if err != nil {
			return err
		}
		org = o
		out, err := render.Render(m, l)
		if err != nil {
			return err
		}
		workDir, err = filepath.Abs(filepath.Join(vo.OutDir, m.Metadata.Name+"-verify"))
		if err != nil {
			return err
		}
		if err := stage(out, filepath.Join(workDir, "context")); err != nil {
			return err
		}
		req = builder.Request{
			Platforms: m.Spec.Platforms, SourceDateEpoch: l.SourceDateEpoch,
			BuildKitImage: l.Builder.BuildKit.Pinned(), Registries: registriesOf(l),
			Annotations: out.Annotations,
		}
		label = rel(m.Path)
		previous = filepath.Join(vo.OutDir, m.Metadata.Name, "image")
	} else {
		var err error
		if org, err = manifest.LoadOrg(opts.OrgPath, "."); err != nil {
			return err
		}
		args := vo.VerifyArgs
		if len(args) == 0 {
			args = verifyArgs(org)
		}
		if len(args) == 0 {
			return errors.New("no signer identity to verify the recipe against: set signing.verify in the org profile or pass --key / --certificate-identity-regexp with --certificate-oidc-issuer")
		}
		opts.printf("verifying the recipe or rebase attestation on %s", vo.Image)
		recipe, err := attest.VerifyRecipe(ctx, vo.Image, args)
		if err != nil {
			// A rebased image carries a rebase record instead of a recipe.
			rec, rerr := attest.VerifyRebase(ctx, vo.Image, args)
			if rerr != nil {
				return fmt.Errorf("no verified recipe or rebase attestation on %s:\n%v\n%v", vo.Image, err, rerr)
			}
			return verifyRebase(ctx, opts, rec, expected)
		}
		if recipe.Image.Digest != expected {
			return fmt.Errorf("recipe was recorded for %s, not %s", recipe.Image.Digest, expected)
		}
		repo := lock.RepoOf(vo.Image)
		workDir, err = filepath.Abs(filepath.Join(vo.OutDir, safeName(repo)+"-verify"))
		if err != nil {
			return err
		}
		if err := recipe.Materialize(filepath.Join(workDir, "context"), render.ContainerfileName); err != nil {
			return err
		}
		var l lock.Lock
		if err := yaml.Unmarshal([]byte(recipe.Lock), &l); err != nil {
			return fmt.Errorf("recipe lock: %w", err)
		}
		req = builder.Request{
			Platforms: recipe.Build.Platforms, SourceDateEpoch: recipe.Build.SourceDateEpoch,
			BuildKitImage: recipe.Build.BuildKit, Registries: registriesOf(&l),
			Annotations: recipe.Build.Annotations,
		}
		label = "recipe of " + vo.Image
	}
	req.ContextDir = filepath.Join(workDir, "context")
	req.Containerfile = render.ContainerfileName
	req.OutDir = workDir
	req.NoCache = true

	opts.printf("rebuilding from %s without cache (%s)", label, strings.Join(req.Platforms, ", "))
	res, err := runBuild(ctx, opts, org, req, false)
	if err != nil {
		return err
	}
	if res.Digest == expected {
		opts.printf("reproducible: rebuilt %s matches", res.Digest)
		return nil
	}

	msg := fmt.Sprintf("NOT reproducible: expected %s, rebuilt %s", expected, res.Digest)
	var want *registry.Artifact
	if vo.Image != "" {
		want, err = registry.Fetch(ctx, vo.Image)
	} else if a, lerr := registry.OpenLayout(previous); lerr == nil && a.Digest == expected {
		want = a
	} else {
		err = fmt.Errorf("no pushed image or local build of %s to compare with", expected)
	}
	if err == nil {
		var explanation string
		if explanation, err = explain(want, res.LayoutDir); err == nil {
			msg += "\n" + explanation
		}
	}
	if err != nil {
		msg += fmt.Sprintf("\n(cannot explain the difference: %v)", err)
	}
	return errors.New(msg)
}

func explain(want *registry.Artifact, layoutDir string) (string, error) {
	got, err := registry.OpenLayout(layoutDir)
	if err != nil {
		return "", err
	}
	return diff.Artifacts(want, got, 30)
}

// safeName turns an image repository into a directory name.
func safeName(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' {
			return r
		}
		return '_'
	}, s)
}

func verifyArgs(o *manifest.Org) []string {
	v := o.Signing.Verify
	var args []string
	if v.Key != "" {
		args = append(args, "--key", v.Key)
	}
	if v.CertificateIdentityRegexp != "" {
		args = append(args, "--certificate-identity-regexp", v.CertificateIdentityRegexp)
	}
	if v.CertificateOIDCIssuer != "" {
		args = append(args, "--certificate-oidc-issuer", v.CertificateOIDCIssuer)
	}
	return append(args, v.Args...)
}
