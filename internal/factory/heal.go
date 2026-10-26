package factory

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/northcutted/clearcutt-factory/internal/attest"
	"github.com/northcutted/clearcutt-factory/internal/lock"
	"github.com/northcutted/clearcutt-factory/internal/manifest"
	"github.com/northcutted/clearcutt-factory/internal/registry"
	"github.com/northcutted/clearcutt-factory/internal/sbom"
	"github.com/northcutted/clearcutt-factory/internal/scan"
)

// healCurrent completes the publication of an image a rebase found already
// on the newest build of its base, where it has nothing else to do: an
// earlier publish may have failed after the push, or a version of factory
// that moved tags before signing left a tag on an image without its
// signature or attestations. It signs the image when the org's signer
// attested its recipe or rebase record (so the signer vouched for it
// already), and attaches each platform's missing SBOM and vulnerability
// report, made now. An image with neither record can't be vouched for here:
// that is an error, and rebuilding is the fix.
//
// It returns the image (repo@digest) when it added anything, and "" when
// nothing was missing.
func healCurrent(ctx context.Context, opts Options, org *manifest.Org, ro RebaseOptions, plan *rebasePlan) (string, error) {
	if org.Signing.Mode == "none" || ro.NoSign {
		opts.printf("already on the newest base; nothing to do")
		return "", nil
	}
	art := plan.app
	plats, err := art.Platforms()
	if err != nil {
		return "", err
	}
	scans := org.Vulnerabilities.Scanner != "none" && !ro.NoScan
	var checks []platformCheck
	for _, p := range plats {
		checks = append(checks, platformCheck{p.Digest, scans})
	}
	source := art.Source()
	if signers, err := signerArgs(org, manifest.RoleImage, source); err != nil || len(signers) == 0 {
		why := "the org profile names none"
		if err != nil {
			why = err.Error()
		}
		return "", fmt.Errorf("%s is on the newest base, and there is no image signer to check that it is signed and attested (%s): name one in signing.verify or signing.trustPolicy", plan.appRef, why)
	}
	have := inspectPublication(ctx, org, plan.appRef, plan.repo, attest.RebasePredicateType, source, checks)
	if have.complete(checks) {
		opts.printf("already on the newest base, signed, and attested; nothing to do")
		return "", nil
	}
	if !have.predicate {
		return "", fmt.Errorf("%s is on the newest base, but carries no recipe or rebase record from the org's image signer, so a rebase can't vouch for it (a publish may have tagged it before signing it); rebuild it", plan.appRef)
	}
	opts.printf("already on the newest base, but not fully signed and attested")

	work, err := filepath.Abs(filepath.Join(ro.OutDir, safeName(lastElem(plan.repo))+"-rebase"))
	if err != nil {
		return "", err
	}
	result := Result{
		Repository: plan.repo, Digest: art.Digest, Tags: nil,
		Platforms: map[string]string{}, SBOMs: map[string]string{},
	}
	var outputs []platformOutputs
	var blocked []string
	var declared map[string]*sbom.BOM
	for _, p := range plats {
		result.Platforms[p.Platform] = p.Digest
		if have.sbom[p.Digest] && (!scans || have.vuln[p.Digest]) {
			continue
		}
		if declared == nil {
			if declared, err = declaredSBOMs(ctx, opts, org, plan, source, plats); err != nil {
				return "", err
			}
		}
		po, err := sbomAndScan(ctx, org, declared[p.Platform], ro.vex, ro.scanImage(plan.repo, art.Digest, p.Digest), p, work, ro.NoScan)
		if err != nil {
			return "", err
		}
		outputs = append(outputs, po)
		result.SBOMs[p.Platform] = po.sbomPath
		result.Attestations = append(result.Attestations, po.sbomPath)
		if po.vulnPath != "" {
			result.Attestations = append(result.Attestations, po.vulnPath)
		}
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
	if result.Image, result.Published, result.Signed, err = completePublication(ctx, opts, org, plan.appRef, plan.repo, attest.RebasePredicateType, "", outputs, have); err != nil {
		return "", err
	}
	resultPath := filepath.Join(work, "result.json")
	if err := attest.WriteJSON(resultPath, result); err != nil {
		return "", err
	}
	opts.printf("wrote %s", rel(resultPath))
	if ro.held == nil {
		if err := githubOutput(result); err != nil {
			return "", err
		}
	}
	// The report is attached either way (it says what the image holds);
	// the gate still fails the run, so the published image gets a fix.
	if len(blocked) > 0 {
		return "", fmt.Errorf("%s is published, and the vulnerability gate (failOn: %s) blocks it:\n  %s", plan.appRef, org.Vulnerabilities.FailOn, strings.Join(blocked, "\n  "))
	}
	return result.Image, nil
}

// declaredSBOMs returns each platform's declared SBOM components for an
// image already published, from its verified rebase record (as a rebase
// declares them) or else its verified recipe (as a build does).
func declaredSBOMs(ctx context.Context, opts Options, org *manifest.Org, plan *rebasePlan, source string, plats []registry.PlatformImage) (map[string]*sbom.BOM, error) {
	signers, err := signerArgs(org, manifest.RoleImage, source)
	if err != nil {
		return nil, err
	}
	out := map[string]*sbom.BOM{}
	if rec, err := firstVerified(signers, func(args []string) (*attest.Rebase, error) { return attest.VerifyRebase(ctx, plan.appRef, args) }); err == nil {
		from, err := registry.PlatformDigests(ctx, rec.Image)
		if err != nil {
			return nil, fmt.Errorf("the image %s was rebased from: %w", rec.Image, err)
		}
		for _, p := range plats {
			cf, err := p.Image.ConfigFile()
			if err != nil {
				return nil, err
			}
			base := lock.Image{Ref: plan.onto.Name, Digest: plan.platform(p.Platform).newDigest}
			out[p.Platform] = sbom.Rebased(plan.repo, p.Platform, p.Digest, cf.Created.Time, base, lock.Image{Ref: plan.repo, Digest: from[p.Platform]}, opts.Version)
		}
		return out, nil
	}
	recipe, err := firstVerified(signers, func(args []string) (*attest.Recipe, error) { return attest.VerifyRecipe(ctx, plan.appRef, args) })
	if err != nil {
		return nil, fmt.Errorf("reading the recipe of %s: %w", plan.appRef, err)
	}
	var l lock.Lock
	if err := yaml.Unmarshal([]byte(recipe.Lock), &l); err != nil {
		return nil, fmt.Errorf("the recipe's lock: %w", err)
	}
	var doc struct {
		Kind     string            `yaml:"kind"`
		Metadata manifest.Metadata `yaml:"metadata"`
	}
	if err := yaml.Unmarshal([]byte(recipe.Manifest), &doc); err != nil {
		return nil, fmt.Errorf("the recipe's manifest: %w", err)
	}
	m := &manifest.Manifest{Kind: doc.Kind, Metadata: manifest.Metadata{Name: doc.Metadata.Name, Ref: recipe.Image.Ref}}
	for _, p := range plats {
		out[p.Platform] = sbom.Declared(m, &l, p.Platform, p.Digest, opts.Version)
	}
	return out, nil
}
