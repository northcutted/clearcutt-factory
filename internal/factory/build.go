package factory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
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
	// ForceTags moves the tags to an image published before even when they
	// hold a newer one (a deliberate rollback).
	ForceTags bool
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
	// Published is true when this run pushed the image, or added a
	// signature or attestation it lacked (completing a run that failed
	// partway), and false when the registry already had it signed and
	// attested (an unchanged rebuild), so at most its tags moved.
	Published bool `json:"published"`
	// Rebased is the image the tags point at instead (repo@digest): this
	// one rebased onto a newer build of its base (see publishBuild).
	Rebased string `json:"rebased,omitempty"`
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
	if err := checkNoScan(org, bo.Push, bo.NoScan); err != nil {
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
	if err := stage(out, ctxDir, opts.logf); err != nil {
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
		po, err := sbomAndScan(ctx, org, declared, m.Spec.VEXFiles, scan.Image{Repository: repo, Tags: m.Metadata.Tags, Digests: []string{res.Digest, p.Digest}}, p, work, bo.NoScan)
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

	resultPath := filepath.Join(work, "result.json")
	write := func() error { return attest.WriteJSON(resultPath, result) }
	if len(blocked) > 0 {
		_ = write()
		return fmt.Errorf("vulnerability gate (failOn: %s) blocked the image:\n  %s", org.Vulnerabilities.FailOn, strings.Join(blocked, "\n  "))
	}

	// What was built is on record before anything is pushed, and each
	// step of publishing updates it, so a run that fails partway leaves
	// what it did for the steps after it (see publishBuild).
	if err := write(); err != nil {
		return err
	}
	if bo.Push {
		err := publishBuild(ctx, opts, org, m, art, bo, recipePath, outputs, &result, write)
		if werr := write(); err == nil {
			err = werr
		}
		if err != nil {
			return err
		}
	} else {
		opts.printf("not pushed (use --push); unsigned attestations are in %s", rel(attDir))
	}
	opts.printf("wrote %s", rel(resultPath))
	return nil
}

// checkNoScan refuses to publish without a scan under a shared profile:
// its vulnerability gate is the platform's, and --no-scan would skip it.
func checkNoScan(org *manifest.Org, push, noScan bool) error {
	if push && noScan && org.Shared != nil {
		return fmt.Errorf("--push with --no-scan: the shared profile %s sets the vulnerability gate every published image passes, and --no-scan skips it; drop --no-scan (it stays for builds that aren't pushed)", org.Shared.Name())
	}
	return nil
}

// publishBuild publishes a built image and moves its tags to it. When a tag
// of an app holds an image on a newer build of the app's base (see
// onNewerBase), say the fleet's rebase before the lock that pins its base
// is merged, the build is pushed by digest only and rebased onto the base's
// newest build as the fleet does it (safety checks, smoke test, scan, gate,
// signed rebase record). The tags move to that image instead, if they still
// hold what they did; if anything fails, they stay where they are.
//
// Once the image is published (signed and attested), write records the
// result and the GitHub Actions outputs say so, before any tag moves: a
// failure after that still leaves the published image for the steps that
// reproduce and announce it.
func publishBuild(ctx context.Context, opts Options, org *manifest.Org, m *manifest.Manifest, art *registry.Artifact, bo BuildOptions, recipePath string, outputs []platformOutputs, result *Result, write func() error) error {
	var why string
	var held map[string]string
	if m.Kind == manifest.KindApp && !bo.ForceTags {
		var err error
		if why, held, err = onNewerBase(ctx, art, result.Repository, m.Metadata.Tags); err != nil {
			return fmt.Errorf("checking what %s's tags hold before moving them (--force-tags skips the check): %w", result.Repository, err)
		}
	}
	tags := m.Metadata.Tags
	if why != "" {
		opts.printf("%s; pushing this image by digest only, to rebase it onto the newest build of its base", why)
		tags, result.Tags = nil, nil
	}
	var err error
	if result.Image, result.Published, result.Signed, err = publishImage(ctx, opts, org, art, result.Repository, attest.RecipePredicateType, recipePath, outputs, bo.NoSign); err != nil {
		return err
	}
	if err := write(); err != nil {
		return err
	}
	if err := githubOutput(*result); err != nil {
		return err
	}
	if why == "" {
		return tagPublished(ctx, opts, art, result.Repository, tags, bo.ForceTags, nil)
	}

	ro := RebaseOptions{
		Image: result.Image, Tags: m.Metadata.Tags, Push: true, OutDir: bo.OutDir,
		NoScan: bo.NoScan, NoSign: bo.NoSign, NoTest: bo.NoTest, held: held, vex: m.Spec.VEXFiles,
	}
	_, rebased, err := rebaseImage(ctx, opts, org, ro, m.Spec.Test, m.Metadata.Name)
	var moved movedTags
	switch {
	case errors.As(err, &moved):
		return fmt.Errorf("%w while this build was rebasing: another publish took it, so it stays there (build again to tag %s)", moved, rebased)
	case err == nil && rebased == "":
		err = errors.New("its base's tag went back to this image's base while rebasing")
	}
	if err != nil {
		return fmt.Errorf("%s, and this image could not be rebased onto that base, so the tags stay where they are: %w\nto publish this change, pin the newest base in %s (merge the fleet's pull request, or run clearcutt-factory lock --update-base) and build again; --force-tags tags this image anyway",
			why, err, rel(m.LockPath()))
	}
	result.Rebased = rebased
	opts.printf("tagged %s, this image rebased onto the newest build of its base", rebased)
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
		BuildkitdConfig: org.Builder.Config, Network: org.Builder.Network,
	}
	if cache {
		cfg.CacheVolume = cacheVolume
	}
	res, err := builder.Build(ctx, cfg, req)
	if err != nil {
		// The runtime couldn't see a directory: the error says why, and
		// the log holds nothing more.
		var nse *builder.NotSharedError
		if errors.As(err, &nse) {
			return nil, err
		}
		if !opts.Verbose {
			opts.logf("%s", buildFailure(logPath))
		}
		return nil, fmt.Errorf("%w (full log: %s)", err, rel(logPath))
	}
	return res, nil
}

// sbomAndScan writes the platform image's SBOM (the declared components,
// merged into a syft scan when enabled) and its vulnerability report, with
// the org's and the manifest's VEX statements applied as far as they are
// for img (see scan.Grype).
func sbomAndScan(ctx context.Context, org *manifest.Org, declared *sbom.BOM, vex []string, img scan.Image, p registry.PlatformImage, work string, noScan bool) (platformOutputs, error) {
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
	vex = append(slices.Clone(org.Vulnerabilities.VEXFiles), vex...)
	if po.report, err = scan.Grype(ctx, po.sbomPath, img, vex); err != nil {
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

// publish publishes art (publishImage) and then moves its tags to it
// (moveTags): tags move only to an image that is signed and carries every
// attestation, and never back to an image older than the one they hold
// unless forceTags is set.
//
// held maps tags to the digest each held when the caller decided to move it
// ("" for none). Unless forceTags is set, such a tag moves only if it still
// holds that digest (see retag). When one has moved, publish does all the
// rest and then returns ref with a movedTags error.
func publish(ctx context.Context, opts Options, org *manifest.Org, art *registry.Artifact, repo string, tags []string, predicateType, predicatePath string, outputs []platformOutputs, noSign, forceTags bool, held map[string]string) (ref string, published, signed bool, err error) {
	if ref, published, signed, err = publishImage(ctx, opts, org, art, repo, predicateType, predicatePath, outputs, noSign); err != nil {
		return "", false, false, err
	}
	return ref, published, signed, tagPublished(ctx, opts, art, repo, tags, forceTags, held)
}

// tagPublished moves tags to art once publishImage has published it.
func tagPublished(ctx context.Context, opts Options, art *registry.Artifact, repo string, tags []string, forceTags bool, held map[string]string) error {
	if forceTags {
		held = nil
	}
	moved, left, err := moveTags(ctx, opts, art, repo, tags, forceTags, held)
	if err != nil {
		return err
	}
	if len(moved) > 0 {
		opts.printf("moved its tags (%s) to %s@%s", strings.Join(moved, ", "), repo, art.Digest)
	}
	return left.orNil()
}

// publishImage pushes art to repo by digest (no tags), signs it, and
// attaches its attestations: the index-level predicate (recipe or rebase
// record) and each platform's SBOM and vulnerability report. It does only
// what the registry lacks, so a run that failed partway (cosign or the
// transparency log down) is completed by the next, and republishing an
// unchanged image doesn't pile up signatures and attestations. published
// reports that this run pushed the image or added anything to it.
//
// What the registry has is checked against the org's image signers
// (published); with none to check against, everything is signed and
// attested again. An empty predicatePath means there is no predicate to
// attach: the image must carry one already.
func publishImage(ctx context.Context, opts Options, org *manifest.Org, art *registry.Artifact, repo, predicateType, predicatePath string, outputs []platformOutputs, noSign bool) (ref string, published, signed bool, err error) {
	ref = repo + "@" + art.Digest
	sign := org.Signing.Mode != "none" && !noSign
	exists, err := registry.Exists(ctx, ref)
	if err != nil {
		return "", false, false, err
	}
	if !exists {
		if _, err := registry.Push(ctx, art, repo, nil); err != nil {
			return "", false, false, err
		}
		opts.printf("pushed %s (by digest; tags move once it is signed and attested)", ref)
	}
	if !sign {
		if exists {
			opts.printf("%s is already published", ref)
		}
		return ref, !exists, false, nil
	}
	var have *publication
	if exists {
		have = inspectPublication(ctx, org, ref, repo, predicateType, art.Source(), expected(outputs))
	}
	return completePublication(ctx, opts, org, ref, repo, predicateType, predicatePath, outputs, have)
}

// completePublication signs and attests what have (nil for an image just
// pushed) lacks of what outputs and the predicate need.
func completePublication(ctx context.Context, opts Options, org *manifest.Org, ref, repo, predicateType, predicatePath string, outputs []platformOutputs, have *publication) (string, bool, bool, error) {
	exists := have != nil
	todo := have.missing(outputs)
	if todo.len() == 0 {
		opts.printf("%s is already published, signed, and attested", ref)
		return ref, false, true, nil
	}
	if exists {
		opts.printf("%s is in the registry without %s; adding them", ref, strings.Join(todo.names(), ", "))
	}
	if err := todo.do(ctx, opts, org, repo, ref, predicateType, predicatePath); err != nil {
		return "", false, false, err
	}
	opts.printf("signed %s and attached its attestations", ref)
	return ref, true, true, nil
}

// publication is what the registry holds of an image, as the org's image
// signers verify it.
type publication struct {
	// signed: the index and every platform image carry a signature.
	signed bool
	// predicate: the index carries a recipe or a rebase record. Either
	// will do: a rebase gives the image a build from the lock it pinned
	// gives, so a build may find the rebased image published with its
	// rebase record, and a rebase the built one with its recipe.
	predicate bool
	// sbom and vuln: by platform image digest, what it carries.
	sbom, vuln map[string]bool
}

// platformCheck is a platform image and whether it should carry a
// vulnerability report (the org scans, and the run did).
type platformCheck struct {
	digest string
	vuln   bool
}

func expected(outputs []platformOutputs) []platformCheck {
	out := make([]platformCheck, len(outputs))
	for i, po := range outputs {
		out[i] = platformCheck{po.digest, po.vulnPath != ""}
	}
	return out
}

// inspectPublication checks what ref carries: each check passes when one
// of the org's image signers verifies it. source is the repository the
// image names as its source, for signers that must match it.
func inspectPublication(ctx context.Context, org *manifest.Org, ref, repo, predicateType, source string, plats []platformCheck) *publication {
	p := &publication{sbom: map[string]bool{}, vuln: map[string]bool{}}
	signers, err := signerArgs(org, manifest.RoleImage, source)
	if err != nil || len(signers) == 0 {
		return p
	}
	verify := func(check func(args []string) error) bool {
		_, err := firstVerified(signers, func(args []string) (struct{}, error) { return struct{}{}, check(args) })
		return err == nil
	}
	attestedAs := func(ref, typ string) bool {
		return verify(func(args []string) error { _, err := attest.VerifyPredicate(ctx, ref, typ, args); return err })
	}
	p.signed = verify(func(args []string) error { return attest.VerifySignature(ctx, ref, args) })
	for _, pc := range plats {
		pref := repo + "@" + pc.digest
		if pref != ref {
			p.signed = p.signed && verify(func(args []string) error { return attest.VerifySignature(ctx, pref, args) })
		}
	}
	other := attest.RebasePredicateType
	if predicateType == attest.RebasePredicateType {
		other = attest.RecipePredicateType
	}
	p.predicate = attestedAs(ref, predicateType) || attestedAs(ref, other)
	for _, pc := range plats {
		pref := repo + "@" + pc.digest
		p.sbom[pc.digest] = attestedAs(pref, attest.CycloneDXType)
		if pc.vuln {
			p.vuln[pc.digest] = attestedAs(pref, attest.VulnType)
		}
	}
	return p
}

// complete reports whether the image carries everything plats need.
func (p *publication) complete(plats []platformCheck) bool {
	if p == nil || !p.signed || !p.predicate {
		return false
	}
	for _, pc := range plats {
		if !p.sbom[pc.digest] || pc.vuln && !p.vuln[pc.digest] {
			return false
		}
	}
	return true
}

// publishSteps are what publishImage still has to do.
type publishSteps struct {
	sign, predicate bool
	sboms, vulns    []platformOutputs
}

// missing returns what outputs still need attached (everything, for an
// image not in the registry yet: p is nil).
func (p *publication) missing(outputs []platformOutputs) publishSteps {
	var s publishSteps
	s.sign = p == nil || !p.signed
	s.predicate = p == nil || !p.predicate
	for _, po := range outputs {
		if p == nil || !p.sbom[po.digest] {
			s.sboms = append(s.sboms, po)
		}
		if po.vulnPath != "" && (p == nil || !p.vuln[po.digest]) {
			s.vulns = append(s.vulns, po)
		}
	}
	return s
}

func (s publishSteps) len() int {
	n := len(s.sboms) + len(s.vulns)
	if s.sign {
		n++
	}
	if s.predicate {
		n++
	}
	return n
}

func (s publishSteps) names() []string {
	var out []string
	if s.sign {
		out = append(out, "its signature")
	}
	if s.predicate {
		out = append(out, "its recipe or rebase record")
	}
	for _, po := range s.sboms {
		out = append(out, "the "+po.platform+" SBOM")
	}
	for _, po := range s.vulns {
		out = append(out, "the "+po.platform+" vulnerability report")
	}
	return out
}

// do signs and attests what s lists, in that order: the signature (index
// and every platform image), the predicate, then each platform's SBOM and
// vulnerability report.
func (s publishSteps) do(ctx context.Context, opts Options, org *manifest.Org, repo, ref, predicateType, predicatePath string) error {
	if s.predicate && predicatePath == "" {
		return fmt.Errorf("%s carries no recipe or rebase record from the org's image signer, so this run can't vouch for it; rebuild it", ref)
	}
	c := attest.Cosign{Mode: org.Signing.Mode, Key: org.Signing.Key, Args: org.Signing.Args, Stdout: opts.Stderr, Stderr: opts.Stderr}
	if s.sign {
		if err := c.Sign(ctx, ref); err != nil {
			return err
		}
	}
	if s.predicate {
		if err := c.Attest(ctx, ref, predicateType, predicatePath); err != nil {
			return err
		}
	}
	for _, po := range s.sboms {
		if err := c.Attest(ctx, repo+"@"+po.digest, "cyclonedx", po.sbomPath); err != nil {
			return err
		}
	}
	for _, po := range s.vulns {
		if err := c.Attest(ctx, repo+"@"+po.digest, "vuln", po.vulnPath); err != nil {
			return err
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

// stepRE matches BuildKit's plain progress lines: "#12 0.345 output",
// "#12 ERROR: …".
var stepRE = regexp.MustCompile(`^#(\d+) (ERROR|CANCELED)?`)

// buildFailure is what a failed build's log says about the failure: the
// output of the step that failed (the last that BuildKit reports an ERROR
// for), up to its last 40 lines, then the log's last 40 lines, which hold
// BuildKit's summary and the Containerfile around the failing instruction.
// The summary alone would hide what the step printed (the package an apk
// check found, say).
func buildFailure(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	last := func(s []string, n int) []string {
		if len(s) > n {
			return s[len(s)-n:]
		}
		return s
	}
	end := last(lines, 40)
	id := ""
	for i := len(lines) - 1; i >= 0 && id == ""; i-- {
		if m := stepRE.FindStringSubmatch(lines[i]); m != nil && m[2] == "ERROR" {
			id = m[1]
		}
	}
	var step []string
	for _, l := range lines[:len(lines)-len(end)] {
		if m := stepRE.FindStringSubmatch(l); m != nil && m[1] == id {
			step = append(step, l)
		}
	}
	return strings.Join(append(last(step, 40), end...), "\n")
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
