package factory

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/northcutted/clearcutt-factory/internal/attest"
	"github.com/northcutted/clearcutt-factory/internal/lock"
	"github.com/northcutted/clearcutt-factory/internal/manifest"
	"github.com/northcutted/clearcutt-factory/internal/policy"
	"github.com/northcutted/clearcutt-factory/internal/rebase"
	"github.com/northcutted/clearcutt-factory/internal/registry"
	"github.com/northcutted/clearcutt-factory/internal/sbom"
	"github.com/northcutted/clearcutt-factory/internal/scan"
)

type RebaseOptions struct {
	// Image is the image to rebase, by tag or digest. Empty means the
	// published image of the app manifest (Options.ManifestPath), rebased
	// onto its stack's run image, with its smoke test.
	Image string
	// Onto is the new base. Empty means the base named in the image's
	// org.opencontainers.image.base.name annotation, resolved again.
	Onto string
	// From is the old base. Empty means the base the image's annotations
	// name (org.opencontainers.image.base.digest).
	From string
	// Check only reports whether the rebase is safe.
	Check bool
	// Force rebases despite compatibility breaks, never despite violations.
	Force bool
	Push  bool
	// Tags point at the result when pushing. Empty means the tag Image was
	// given by, if any.
	Tags   []string
	OutDir string
	NoScan bool
	NoSign bool
	NoTest bool
	// UpdateLock (manifest mode) then pins the app's lock to the base the
	// image is on, so the next build from source doesn't move it back. If
	// the rebase is refused, the lock still moves: building is the fix.
	UpdateLock bool
}

// refusedError means the rebase would be unsafe; rebuilding is the remedy.
type refusedError struct{ msg string }

func (e refusedError) Error() string { return e.msg }

// Rebase moves an image's layers onto a newer build of its base without
// rebuilding it, after checking that this is safe, then tests, scans, gates,
// and (with Push) pushes, signs, and attests the result like Build.
func Rebase(ctx context.Context, opts Options, ro RebaseOptions) error {
	if ro.Image != "" {
		if ro.UpdateLock {
			return errors.New("--update-lock needs the app manifest (-f app.yaml) instead of --image")
		}
		org, err := manifest.LoadOrg(opts.OrgPath, ".")
		if err != nil {
			return err
		}
		_, err = rebaseImage(ctx, opts, org, ro, nil, "")
		return err
	}

	m, org, err := load(ctx, opts, false)
	if err != nil {
		return err
	}
	if m.Kind != manifest.KindApp {
		return fmt.Errorf("%s is a %s: rebase -f works on apps; images install packages onto their base, so update them with clearcutt-factory lock --update-base and rebuild", rel(m.Path), m.Kind)
	}
	tag := "latest"
	if len(m.Metadata.Tags) > 0 {
		tag = m.Metadata.Tags[0]
	}
	ro.Image = m.Metadata.Ref + ":" + tag
	if ro.Onto == "" {
		ro.Onto = m.Spec.Base
	} else if ro.UpdateLock && ro.Onto != m.Spec.Base {
		return fmt.Errorf("--update-lock pins the stack's run image (%s); drop --onto, or change the stack", m.Spec.Base)
	}
	onto, err := rebaseImage(ctx, opts, org, ro, m.Spec.Test, m.Metadata.Name)
	var refused refusedError
	if err != nil && !errors.As(err, &refused) {
		return err
	}
	if ro.UpdateLock {
		if _, lerr := lockManifest(ctx, opts, m, org, LockOptions{UpdateBase: true, BaseDigest: onto}); lerr != nil {
			return errors.Join(err, lerr)
		}
		if refused.msg != "" {
			return fmt.Errorf("%w\n%s now pins the new base; build the app to move it", err, rel(m.LockPath()))
		}
	}
	return err
}

// rebaseImage rebases ro.Image and returns the digest of the base it is now
// on (also when it already was, or the rebase was refused).
func rebaseImage(ctx context.Context, opts Options, org *manifest.Org, ro RebaseOptions, test *manifest.Test, label string) (string, error) {
	plan, err := planRebase(ctx, rebaseInputs{image: ro.Image, from: ro.From, onto: ro.Onto})
	if err != nil {
		return "", err
	}
	onto := digestOf(plan.onto.Ref)
	if err := policy.CheckImages(org, plan.onto.Name); err != nil {
		return "", err
	}
	opts.printf("rebasing %s onto %s (%s)", plan.appRef, plan.onto.Name, digestOf(plan.onto.Ref))
	current := true
	for _, p := range plan.platforms {
		opts.printf("  %s: %s → %s", p.platform, p.oldRef, p.newDigest)
		current = current && digestOf(p.oldRef) == p.newDigest
	}
	if current {
		opts.printf("already on the newest base; nothing to do")
		return onto, nil
	}

	reports, err := plan.analyze()
	if err != nil {
		return "", err
	}
	var violations, breaks bool
	for _, p := range plan.platforms {
		r := reports[p.platform]
		if r.OK() {
			opts.printf("%s: safe to rebase", p.platform)
			continue
		}
		opts.printf("%s:", p.platform)
		for _, v := range r.Violations {
			opts.printf("  violation: %s", v)
		}
		for _, b := range r.Breaks {
			opts.printf("  incompatible: %s", b)
		}
		violations = violations || len(r.Violations) > 0
		breaks = breaks || len(r.Breaks) > 0
	}
	switch {
	case violations:
		return onto, refusedError{"not rebaseable: the image's own layers change or hide base files, so its copies would win over the new base's; rebuild it instead"}
	case breaks && !ro.Force:
		return onto, refusedError{"the new base may break this image; rebuild it, or pass --force to rebase anyway"}
	case ro.Check:
		return onto, nil
	}

	art, rebased, err := plan.build()
	if err != nil {
		return "", err
	}
	opts.printf("rebased %s", art.Digest)
	record := attest.Rebase{
		Factory: attest.FactoryInfo{Version: opts.Version},
		Image:   plan.appRef,
		From:    map[string]string{},
		Onto:    plan.onto,
		Config:  map[string][]string{},
		Result:  attest.ImageDigests{Ref: plan.repo, Digest: art.Digest, Platforms: map[string]string{}},
	}
	for _, p := range plan.platforms {
		record.From[p.platform] = p.oldRef
		if c := rebased[p.platform].Config; len(c) > 0 {
			record.Config[p.platform] = c
			for _, line := range c {
				opts.printf("  %s: %s", p.platform, line)
			}
		}
		for _, line := range rebased[p.platform].Kept {
			opts.printf("  %s: %s", p.platform, line)
		}
	}

	work, err := filepath.Abs(filepath.Join(ro.OutDir, safeName(lastElem(plan.repo))+"-rebase"))
	if err != nil {
		return "", err
	}
	layoutDir := filepath.Join(work, "image")
	if err := registry.WriteLayout(layoutDir, art); err != nil {
		return "", err
	}
	if art, err = registry.OpenLayout(layoutDir); err != nil {
		return "", err
	}
	if art.Digest != record.Result.Digest {
		return "", fmt.Errorf("written layout is %s, not %s", art.Digest, record.Result.Digest)
	}
	plats, err := art.Platforms()
	if err != nil {
		return "", err
	}

	tags := ro.Tags
	if len(tags) == 0 && plan.tag != "" {
		tags = []string{plan.tag}
	}
	result := Result{
		Repository: plan.repo, Digest: art.Digest, Tags: tags,
		Platforms: map[string]string{}, Layout: layoutDir, SBOMs: map[string]string{},
	}
	switch {
	case test != nil && !ro.NoTest:
		if err := smokeTest(ctx, opts, org, test, label, plats, work); err != nil {
			return "", err
		}
		result.Tested = true
	case test == nil && label == "":
		opts.printf("  no smoke test (rebase -f app.yaml runs the app's)")
	}
	var outputs []platformOutputs
	var blocked []string
	for _, p := range plats {
		result.Platforms[p.Platform] = p.Digest
		record.Result.Platforms[p.Platform] = p.Digest
		cf, err := p.Image.ConfigFile()
		if err != nil {
			return "", err
		}
		from := lock.Image{Ref: plan.repo, Digest: plan.platform(p.Platform).app.Digest}
		base := lock.Image{Ref: plan.onto.Name, Digest: plan.platform(p.Platform).newDigest}
		declared := sbom.Rebased(plan.repo, p.Platform, p.Digest, cf.Created.Time, base, from, opts.Version)
		po, err := sbomAndScan(ctx, org, declared, nil, p, work, ro.NoScan)
		if err != nil {
			return "", err
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

	attDir := filepath.Join(work, "attestations")
	recordPath := filepath.Join(attDir, "rebase.predicate.json")
	if err := attest.WriteJSON(recordPath, record); err != nil {
		return "", err
	}
	if err := attest.WriteJSON(filepath.Join(attDir, "rebase.intoto.json"), attest.NewStatement(plan.repo, art.Digest, attest.RebasePredicateType, record)); err != nil {
		return "", err
	}
	result.Attestations = append(result.Attestations, recordPath)
	for _, po := range outputs {
		result.Attestations = append(result.Attestations, po.sbomPath)
		if po.vulnPath != "" {
			result.Attestations = append(result.Attestations, po.vulnPath)
		}
	}
	resultPath := filepath.Join(work, "result.json")
	if len(blocked) > 0 {
		_ = attest.WriteJSON(resultPath, result)
		return "", fmt.Errorf("vulnerability gate (failOn: %s) blocked the image:\n  %s", org.Vulnerabilities.FailOn, strings.Join(blocked, "\n  "))
	}

	if ro.Push {
		if result.Image, result.Published, result.Signed, err = publish(ctx, opts, org, art, plan.repo, tags, attest.RebasePredicateType, recordPath, outputs, ro.NoSign); err != nil {
			return "", err
		}
		if err := githubOutput(result); err != nil {
			return "", err
		}
	} else {
		opts.printf("not pushed (use --push); unsigned attestations are in %s", rel(attDir))
	}
	if err := attest.WriteJSON(resultPath, result); err != nil {
		return "", err
	}
	opts.printf("wrote %s", rel(resultPath))
	return onto, nil
}

// rebaseInputs name what to rebase. From may be one old base for every
// platform, or (when repeating a recorded rebase) one per platform.
type rebaseInputs struct {
	image         string
	from          string
	fromPlatforms map[string]string
	onto          string
	ontoName      string
}

type rebasePlan struct {
	app    *registry.Artifact
	repo   string
	appRef string // repo@digest
	tag    string // the tag the image was named by, if any
	onto   attest.RebaseBase
	// platforms are in the image's order.
	platforms []*rebasePlatform
}

type rebasePlatform struct {
	platform  string
	app       registry.PlatformImage
	oldBase   v1.Image
	oldRef    string // repo@digest of the old base's platform image
	newBase   v1.Image
	newDigest string
}

func (p *rebasePlan) platform(plat string) *rebasePlatform {
	for _, x := range p.platforms {
		if x.platform == plat {
			return x
		}
	}
	return nil
}

// planRebase resolves the image, and for each of its platforms the old base
// and the new one.
func planRebase(ctx context.Context, in rebaseInputs) (*rebasePlan, error) {
	ref, err := name.ParseReference(in.image)
	if err != nil {
		return nil, err
	}
	app, err := registry.Fetch(ctx, in.image)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", in.image, err)
	}
	p := &rebasePlan{app: app, repo: lock.RepoOf(in.image)}
	p.appRef = p.repo + "@" + app.Digest
	if t, ok := ref.(name.Tag); ok {
		p.tag = t.TagStr()
	}
	plats, err := app.Platforms()
	if err != nil {
		return nil, err
	}

	fetched := map[string]*registry.Artifact{}
	fetch := func(r string) (*registry.Artifact, error) {
		if a, ok := fetched[r]; ok {
			return a, nil
		}
		a, err := registry.Fetch(ctx, r)
		if err != nil {
			return nil, fmt.Errorf("fetching %s: %w", r, err)
		}
		fetched[r] = a
		return a, nil
	}
	// pick returns the image for platform pl of the artifact at r.
	pick := func(r string, pl v1.Platform) (v1.Image, string, error) {
		a, err := fetch(r)
		if err != nil {
			return nil, "", err
		}
		img := a.Image
		if a.Index != nil {
			if img, err = rebase.Select(a.Index, pl); err != nil {
				return nil, "", fmt.Errorf("%s: %w", r, err)
			}
		}
		d, err := img.Digest()
		if err != nil {
			return nil, "", err
		}
		return img, d.String(), nil
	}

	onto, ontoName := in.onto, in.ontoName
	for _, pi := range plats {
		m, err := pi.Image.Manifest()
		if err != nil {
			return nil, err
		}
		if onto == "" {
			onto = m.Annotations[rebase.AnnotationBaseName]
			if onto == "" {
				return nil, fmt.Errorf("%s does not name its base (no %s annotation); pass --onto", in.image, rebase.AnnotationBaseName)
			}
		}
		from := in.from
		if f := in.fromPlatforms[pi.Platform]; f != "" {
			from = f
		}
		if from == "" {
			bn, bd := m.Annotations[rebase.AnnotationBaseName], m.Annotations[rebase.AnnotationBaseDigest]
			if bn == "" || bd == "" {
				return nil, fmt.Errorf("%s (%s) does not record its base (no %s annotation); pass --from", in.image, pi.Platform, rebase.AnnotationBaseDigest)
			}
			from = lock.RepoOf(bn) + "@" + bd
		}
		pl, err := rebase.Platform(pi.Image)
		if err != nil {
			return nil, err
		}
		oldBase, oldDigest, err := pick(from, pl)
		if err != nil {
			return nil, err
		}
		om, err := oldBase.Manifest()
		if err != nil {
			return nil, err
		}
		if err := rebase.BasedOn(m, om); err != nil {
			return nil, fmt.Errorf("%s: %s: %w", pi.Platform, from, err)
		}
		newBase, newDigest, err := pick(onto, pl)
		if err != nil {
			return nil, err
		}
		p.platforms = append(p.platforms, &rebasePlatform{
			platform: pi.Platform, app: pi,
			oldBase: oldBase, oldRef: lock.RepoOf(from) + "@" + oldDigest,
			newBase: newBase, newDigest: newDigest,
		})
	}
	if len(p.platforms) == 0 {
		return nil, fmt.Errorf("%s has no platform images", in.image)
	}
	ontoArt, err := fetch(onto)
	if err != nil {
		return nil, err
	}
	if ontoName == "" {
		ontoName = registry.Qualify(strings.SplitN(onto, "@", 2)[0])
	}
	p.onto = attest.RebaseBase{Name: ontoName, Ref: lock.RepoOf(onto) + "@" + ontoArt.Digest}
	return p, nil
}

// analyze checks every platform. The old base's files are read from the
// image's own lower layers, which are the same blobs.
func (p *rebasePlan) analyze() (map[string]*rebase.Report, error) {
	out := map[string]*rebase.Report{}
	for _, pp := range p.platforms {
		appLayers, err := pp.app.Image.Layers()
		if err != nil {
			return nil, err
		}
		om, err := pp.oldBase.Manifest()
		if err != nil {
			return nil, err
		}
		newLayers, err := pp.newBase.Layers()
		if err != nil {
			return nil, err
		}
		cf, err := pp.app.Image.ConfigFile()
		if err != nil {
			return nil, err
		}
		n := len(om.Layers)
		r, err := rebase.Analyze(rebase.Layers{OldBase: appLayers[:n], NewBase: newLayers, App: appLayers[n:], Config: cf.Config})
		if err != nil {
			return nil, fmt.Errorf("%s: %w", pp.platform, err)
		}
		out[pp.platform] = r
	}
	return out, nil
}

// build assembles the rebased image (an index when the input was one).
func (p *rebasePlan) build() (*registry.Artifact, map[string]*rebase.Rebased, error) {
	out := map[string]*rebase.Rebased{}
	byOld := map[v1.Hash]v1.Image{}
	for _, pp := range p.platforms {
		r, err := rebase.Image(pp.app.Image, pp.oldBase, pp.newBase, p.onto.Name)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", pp.platform, err)
		}
		out[pp.platform] = r
		h, err := v1.NewHash(pp.app.Digest)
		if err != nil {
			return nil, nil, err
		}
		byOld[h] = r.Image
	}
	if p.app.Index != nil {
		idx, err := rebase.Index(p.app.Index, byOld, p.onto.Name)
		if err != nil {
			return nil, nil, err
		}
		d, err := idx.Digest()
		if err != nil {
			return nil, nil, err
		}
		return &registry.Artifact{Digest: d.String(), Index: idx}, out, nil
	}
	img := out[p.platforms[0].platform].Image
	d, err := img.Digest()
	if err != nil {
		return nil, nil, err
	}
	return &registry.Artifact{Digest: d.String(), Image: img}, out, nil
}

// verifyRebase repeats a recorded rebase and compares the digest.
func verifyRebase(ctx context.Context, opts Options, rec *attest.Rebase, expected string) error {
	if rec.Result.Digest != expected {
		return fmt.Errorf("rebase record was made for %s, not %s", rec.Result.Digest, expected)
	}
	plan, err := planRebase(ctx, rebaseInputs{image: rec.Image, fromPlatforms: rec.From, onto: rec.Onto.Ref, ontoName: rec.Onto.Name})
	if err != nil {
		return err
	}
	opts.printf("repeating the rebase of %s onto %s", rec.Image, rec.Onto.Ref)
	art, _, err := plan.build()
	if err != nil {
		return err
	}
	if art.Digest != expected {
		return fmt.Errorf("NOT reproducible: expected %s, the rebase gives %s", expected, art.Digest)
	}
	opts.printf("reproducible: rebase gives %s again", art.Digest)
	return nil
}

func digestOf(ref string) string {
	_, d, _ := strings.Cut(ref, "@")
	return d
}

func lastElem(repo string) string {
	return repo[strings.LastIndex(repo, "/")+1:]
}
