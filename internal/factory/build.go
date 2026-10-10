package factory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/northcutted/clearcutt-factory/internal/attest"
	"github.com/northcutted/clearcutt-factory/internal/builder"
	"github.com/northcutted/clearcutt-factory/internal/lock"
	"github.com/northcutted/clearcutt-factory/internal/manifest"
	"github.com/northcutted/clearcutt-factory/internal/policy"
	"github.com/northcutted/clearcutt-factory/internal/registry"
	"github.com/northcutted/clearcutt-factory/internal/render"
	"github.com/northcutted/clearcutt-factory/internal/sbom"
	"github.com/northcutted/clearcutt-factory/internal/scan"
	"github.com/northcutted/clearcutt-factory/internal/smoke"
)

const cacheVolume = "clearcutt-factory-buildkit-cache"

type BuildOptions struct {
	Push    bool
	OutDir  string
	NoScan  bool
	NoSign  bool
	NoCache bool
	NoTest  bool
}

// Result is written to <out>/<name>/result.json for CI to consume.
type Result struct {
	Image           string            `json:"image,omitempty"`
	Repository      string            `json:"repository"`
	Digest          string            `json:"digest"`
	Tags            []string          `json:"tags,omitempty"`
	Platforms       map[string]string `json:"platforms"`
	Layout          string            `json:"layout"`
	SBOMs           map[string]string `json:"sboms"`
	Vulnerabilities map[string]any    `json:"vulnerabilities,omitempty"`
	Attestations    []string          `json:"attestations"`
	Signed          bool              `json:"signed"`
	// Tested reports that the smoke test passed on every platform.
	Tested bool `json:"tested"`
	// Published is false when the registry already had this digest with its
	// attestations (an unchanged rebuild), so only the tags moved.
	Published bool `json:"published"`
}

type platformOutputs struct {
	platform, digest string
	sbomPath         string
	vulnPath         string
	report           *scan.Report
}

// Build renders, builds, scans, gates, and (with Push) pushes, signs, and
// attests the image.
func Build(ctx context.Context, opts Options, bo BuildOptions) error {
	m, org, l, err := loadLocked(ctx, opts)
	if err != nil {
		return err
	}
	if err := policy.Check(m, org, l); err != nil {
		return err
	}
	out, err := render.Render(m, l)
	if err != nil {
		return err
	}
	if old, err := os.ReadFile(m.ContainerfilePath()); err != nil || !bytes.Equal(old, out.Containerfile) {
		opts.logf("warning: %s is missing or out of date; run clearcutt-factory render and commit it", rel(m.ContainerfilePath()))
	}

	work, err := filepath.Abs(filepath.Join(bo.OutDir, m.Metadata.Name))
	if err != nil {
		return err
	}
	ctxDir := filepath.Join(work, "context")
	if err := stage(out, ctxDir); err != nil {
		return err
	}

	opts.printf("building %s for %s", m.Metadata.Ref, strings.Join(m.Spec.Platforms, ", "))
	res, err := runBuild(ctx, opts, org, builder.Request{
		ContextDir:      ctxDir,
		Containerfile:   render.ContainerfileName,
		Platforms:       m.Spec.Platforms,
		SourceDateEpoch: l.SourceDateEpoch,
		OutDir:          work,
		NoCache:         bo.NoCache,
		BuildKitImage:   l.Builder.BuildKit.Pinned(),
		Registries:      registriesOf(l),
		Annotations:     out.Annotations,
	}, true)
	if err != nil {
		return err
	}
	art, err := registry.OpenLayout(res.LayoutDir)
	if err != nil {
		return err
	}
	if art.Digest != res.Digest {
		return fmt.Errorf("layout digest %s does not match build metadata %s", art.Digest, res.Digest)
	}
	plats, err := art.Platforms()
	if err != nil {
		return err
	}
	opts.printf("built %s", res.Digest)

	repo := lock.RepoOf(m.Metadata.Ref)
	result := Result{
		Repository: repo, Digest: res.Digest, Tags: m.Metadata.Tags,
		Platforms: map[string]string{}, Layout: res.LayoutDir, SBOMs: map[string]string{},
	}
	if m.Spec.Test != nil && !bo.NoTest {
		if err := smokeTest(ctx, opts, org, m.Spec.Test, m.Metadata.Name, plats, work); err != nil {
			return err
		}
		result.Tested = true
	}
	attDir := filepath.Join(work, "attestations")
	_ = os.RemoveAll(attDir)

	var outputs []platformOutputs
	var blocked []string
	for _, p := range plats {
		result.Platforms[p.Platform] = p.Digest
		declared := sbom.Declared(m, l, p.Platform, p.Digest, opts.Version)
		po, err := sbomAndScan(ctx, org, declared, m.Spec.VEXFiles, p, work, bo.NoScan)
		if err != nil {
			return err
		}
		outputs = append(outputs, po)
		result.SBOMs[p.Platform] = po.sbomPath
		if po.report != nil {
			if result.Vulnerabilities == nil {
				result.Vulnerabilities = map[string]any{}
			}
			result.Vulnerabilities[p.Platform] = po.report.Counts()
			opts.printf("  %s: %s", p.Platform, summarize(po.report.Counts()))
			for _, v := range scan.Gate(po.report, org.Vulnerabilities) {
				blocked = append(blocked, fmt.Sprintf("%s %s %s in %s %s", p.Platform, v.Severity, v.ID, v.Package, v.Version))
			}
		}
	}

	recipe, err := buildRecipe(opts, m, l, out, ctxDir, res.Digest, result.Platforms)
	if err != nil {
		return err
	}
	recipePath := filepath.Join(attDir, "recipe.predicate.json")
	if err := attest.WriteJSON(recipePath, recipe); err != nil {
		return err
	}
	if err := attest.WriteJSON(filepath.Join(attDir, "recipe.intoto.json"), attest.NewStatement(repo, res.Digest, attest.RecipePredicateType, recipe)); err != nil {
		return err
	}
	result.Attestations = append(result.Attestations, recipePath)
	for _, po := range outputs {
		result.Attestations = append(result.Attestations, po.sbomPath)
		if po.vulnPath != "" {
			result.Attestations = append(result.Attestations, po.vulnPath)
		}
	}

	if len(blocked) > 0 {
		_ = attest.WriteJSON(filepath.Join(work, "result.json"), result)
		return fmt.Errorf("vulnerability gate (failOn: %s) blocked the image:\n  %s", org.Vulnerabilities.FailOn, strings.Join(blocked, "\n  "))
	}

	if bo.Push {
		if result.Image, result.Published, result.Signed, err = publish(ctx, opts, org, art, repo, m.Metadata.Tags, attest.RecipePredicateType, recipePath, outputs, bo.NoSign); err != nil {
			return err
		}
		if err := githubOutput(result); err != nil {
			return err
		}
	} else {
		opts.printf("not pushed (use --push); unsigned attestations are in %s", rel(attDir))
	}
	resultPath := filepath.Join(work, "result.json")
	if err := attest.WriteJSON(resultPath, result); err != nil {
		return err
	}
	opts.printf("wrote %s", rel(resultPath))
	return nil
}

// smokeTest runs the test in each platform image (through emulation for
// other architectures).
func smokeTest(ctx context.Context, opts Options, org *manifest.Org, t *manifest.Test, label string, plats []registry.PlatformImage, work string) error {
	r := &smoke.Runner{Runtime: org.Builder.Runtime, WorkDir: filepath.Join(work, "smoke")}
	defer func() { _ = os.RemoveAll(r.WorkDir) }()
	for _, p := range plats {
		start := time.Now()
		if err := r.Run(ctx, p.Image, p.Platform, label, t); err != nil {
			return fmt.Errorf("smoke test (%s) failed on %s (skip with --no-test): %w", smoke.Describe(t), p.Platform, err)
		}
		opts.printf("  %s: smoke test passed (%s, %s)", p.Platform, smoke.Describe(t), time.Since(start).Round(100*time.Millisecond))
	}
	return nil
}

func runBuild(ctx context.Context, opts Options, org *manifest.Org, req builder.Request, cache bool) (*builder.Result, error) {
	logPath := filepath.Join(req.OutDir, "build.log")
	if err := os.MkdirAll(req.OutDir, 0o755); err != nil {
		return nil, err
	}
	logf, err := os.Create(logPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = logf.Close() }()
	var w io.Writer = logf
	if opts.Verbose {
		w = io.MultiWriter(logf, opts.Stderr)
	}
	cfg := builder.Config{
		Runtime: org.Builder.Runtime, Addr: org.Builder.Addr,
		Stdout: w, Stderr: w, WriteAuth: registry.WriteDockerConfig,
	}
	if cache {
		cfg.CacheVolume = cacheVolume
	}
	res, err := builder.Build(ctx, cfg, req)
	if err != nil {
		if !opts.Verbose {
			opts.logf("%s", tail(logPath, 40))
		}
		return nil, fmt.Errorf("%w (full log: %s)", err, rel(logPath))
	}
	return res, nil
}

// sbomAndScan writes the platform image's SBOM (the declared components,
// merged into a syft scan when enabled) and its vulnerability report.
func sbomAndScan(ctx context.Context, org *manifest.Org, declared *sbom.BOM, vex []string, p registry.PlatformImage, work string, noScan bool) (platformOutputs, error) {
	po := platformOutputs{platform: p.Platform, digest: p.Digest}
	slug := strings.ReplaceAll(p.Platform, "/", "-")

	var doc []byte
	var err error
	if *org.SBOM.Scan && !noScan {
		layout := filepath.Join(work, "platforms", slug)
		if err := registry.WriteImageLayout(layout, p.Image); err != nil {
			return po, err
		}
		scanned, err := sbom.Scan(ctx, layout)
		if err != nil {
			return po, fmt.Errorf("%w (install syft, or set sbom.scan: false / pass --no-scan for a declared-only SBOM)", err)
		}
		if doc, err = sbom.Merge(scanned, declared); err != nil {
			return po, err
		}
	} else if doc, err = json.MarshalIndent(declared, "", "  "); err != nil {
		return po, err
	}
	po.sbomPath = filepath.Join(work, "attestations", "sbom-"+slug+".cdx.json")
	if err := os.MkdirAll(filepath.Dir(po.sbomPath), 0o755); err != nil {
		return po, err
	}
	if err := os.WriteFile(po.sbomPath, doc, 0o644); err != nil {
		return po, err
	}

	if org.Vulnerabilities.Scanner == "none" || noScan {
		return po, nil
	}
	if po.report, err = scan.Grype(ctx, po.sbomPath, vex); err != nil {
		return po, fmt.Errorf("%w (install grype, or set vulnerabilities.scanner: none / pass --no-scan)", err)
	}
	po.vulnPath = filepath.Join(work, "attestations", "vuln-"+slug+".predicate.json")
	return po, attest.WriteJSON(po.vulnPath, po.report.Predicate())
}

func buildRecipe(opts Options, m *manifest.Manifest, l *lock.Lock, out *render.Output, ctxDir, digest string, plats map[string]string) (*attest.Recipe, error) {
	entries, err := attest.ContextEntries(ctxDir, render.ContainerfileName)
	if err != nil {
		return nil, err
	}
	return &attest.Recipe{
		Factory: attest.FactoryInfo{Version: opts.Version},
		Build: attest.BuildSettings{
			BuildKit:        l.Builder.BuildKit.Pinned(),
			Platforms:       m.Spec.Platforms,
			SourceDateEpoch: l.SourceDateEpoch,
			Output:          "type=oci,rewrite-timestamp=true",
			Annotations:     out.Annotations,
		},
		Containerfile: string(out.Containerfile),
		Manifest:      string(m.EffectiveYAML()),
		Lock:          string(l.Marshal()),
		Context:       entries,
		Image:         attest.ImageDigests{Ref: m.Metadata.Ref, Digest: digest, Platforms: plats},
	}, nil
}

// publish pushes the artifact, signs it, and attaches its attestations.
// When the registry already has this digest with its index attestation (an
// unchanged rebuild), it only moves the tags, so republishing doesn't pile
// up signatures and attestations on the same image.
func publish(ctx context.Context, opts Options, org *manifest.Org, art *registry.Artifact, repo string, tags []string, predicateType, predicatePath string, outputs []platformOutputs, noSign bool) (ref string, published, signed bool, err error) {
	ref = repo + "@" + art.Digest
	sign := org.Signing.Mode != "none" && !noSign
	exists, err := registry.Exists(ctx, ref)
	if err != nil {
		return "", false, false, err
	}
	if exists && (!sign || attested(ctx, org, ref, predicateType, art.Source())) {
		if err := registry.Tag(ctx, ref, tags); err != nil {
			return "", false, false, err
		}
		opts.printf("%s is already published; moved its tags (%s)", ref, strings.Join(tags, ", "))
		return ref, false, sign, nil
	}
	if _, err := registry.Push(ctx, art, repo, tags); err != nil {
		return "", false, false, err
	}
	opts.printf("pushed %s", ref)
	if sign {
		if err := signAndAttest(ctx, opts, org, repo, ref, predicateType, predicatePath, outputs); err != nil {
			return "", false, false, err
		}
		opts.printf("signed %s and attached its attestations", ref)
	}
	return ref, true, sign, nil
}

// attested reports whether ref already carries a verified attestation of
// predicateType from one of the org's image signers. source is the
// repository the image names as its source.
func attested(ctx context.Context, org *manifest.Org, ref, predicateType, source string) bool {
	signers, err := signerArgs(org, manifest.RoleImage, source)
	if err != nil || len(signers) == 0 {
		return false
	}
	_, err = firstVerified(signers, func(args []string) ([]byte, error) { return attest.VerifyPredicate(ctx, ref, predicateType, args) })
	return err == nil
}

// signAndAttest signs the pushed image and attaches the index-level
// predicate (recipe or rebase record) and each platform's SBOM and
// vulnerability report.
func signAndAttest(ctx context.Context, opts Options, org *manifest.Org, repo, ref, predicateType, predicatePath string, outputs []platformOutputs) error {
	c := attest.Cosign{Mode: org.Signing.Mode, Key: org.Signing.Key, Args: org.Signing.Args, Stdout: opts.Stderr, Stderr: opts.Stderr}
	if err := c.Sign(ctx, ref); err != nil {
		return err
	}
	if err := c.Attest(ctx, ref, predicateType, predicatePath); err != nil {
		return err
	}
	for _, po := range outputs {
		pref := repo + "@" + po.digest
		if err := c.Attest(ctx, pref, "cyclonedx", po.sbomPath); err != nil {
			return err
		}
		if po.vulnPath != "" {
			if err := c.Attest(ctx, pref, "vuln", po.vulnPath); err != nil {
				return err
			}
		}
	}
	return nil
}

// githubOutput exposes the digest to later workflow steps (e.g. provenance).
func githubOutput(r Result) error {
	path := os.Getenv("GITHUB_OUTPUT")
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(f, "image=%s\nrepository=%s\ndigest=%s\npublished=%t\n", r.Image, r.Repository, r.Digest, r.Published); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func summarize(c map[string]int) string {
	var parts []string
	for _, s := range []string{"critical", "high", "medium", "low", "negligible", "unknown"} {
		if c[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", c[s], s))
		}
	}
	if len(parts) == 0 {
		return "no known vulnerabilities"
	}
	return strings.Join(parts, ", ")
}

func tail(path string, n int) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
