package factory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/northcutted/clearcutt-factory/internal/attest"
	"github.com/northcutted/clearcutt-factory/internal/lock"
	"github.com/northcutted/clearcutt-factory/internal/manifest"
	"github.com/northcutted/clearcutt-factory/internal/registry"
	"github.com/northcutted/clearcutt-factory/internal/scan"
)

// ReattestOptions are reattest's settings.
type ReattestOptions struct {
	// Image is the published image (repo[:tag|@sha256:…]); default: the
	// manifest's, by its reference and first tag.
	Image string
	// OlderThan rescans only the platforms whose newest verified
	// vulnerability report is older than this; 0 rescans every platform.
	OlderThan time.Duration
	// OutDir is where the SBOMs and new reports are written.
	OutDir string
	// NoSign writes the new reports without attaching them.
	NoSign bool
}

// ReattestResult is what reattest did, as it writes it to
// <out>/<name>-reattest/reattest.json.
type ReattestResult struct {
	// Image is the image re-attested (repository@digest).
	Image string `json:"image"`
	// Reproduced: the image carries a reproduction attestation the org's
	// image signer made.
	Reproduced bool `json:"reproduced"`
	// Platforms are what was done for each platform image.
	Platforms map[string]ReattestPlatform `json:"platforms"`
	// Blocked are the findings the vulnerability gate would block now.
	Blocked []string `json:"blocked,omitempty"`
}

// ReattestPlatform is what reattest did for a platform image.
type ReattestPlatform struct {
	Digest string `json:"digest"`
	// Rescanned: its verified SBOM was scanned again.
	Rescanned bool `json:"rescanned"`
	// Attached: the new report was signed and attached to the digest.
	Attached bool `json:"attached"`
	// Report is the new report's predicate file.
	Report string `json:"report,omitempty"`
	// Vulnerabilities counts the new report's findings by severity.
	Vulnerabilities map[string]int `json:"vulnerabilities,omitempty"`
	// Skipped says why it wasn't rescanned.
	Skipped string `json:"skipped,omitempty"`
}

// Reattest renews a published image's evidence without rebuilding it or
// moving a tag. For each platform image it reads the SBOM attestation the
// org's image signer made (never an SBOM nobody vouched for), scans it with
// grype after bringing grype's database up to date, and attaches the new
// vulnerability report to the same digest, signed as builds sign theirs,
// beside the reports already there; the report's metadata.rescan names the
// SBOM attestation it scanned. With OlderThan, a platform whose newest
// verified report is younger is left alone. It also says whether the
// image carries a verified reproduction attestation (reproduced= in
// $GITHUB_OUTPUT), so a workflow can reproduce the images that don't
// (verify --image … --attest).
//
// The gate doesn't fail a re-attestation: the image is out already, and
// the report says what it holds; findings the gate would block are
// listed. A platform whose SBOM isn't verified is an error, after the
// others are done.
func Reattest(ctx context.Context, opts Options, ro ReattestOptions) error {
	var (
		org  *manifest.Org
		vex  []string
		tags []string
		ref  = ro.Image
		err  error
	)
	if ref != "" {
		if org, err = loadOrg(ctx, opts, ".", nil); err != nil {
			return err
		}
	} else {
		var m *manifest.Manifest
		if m, org, err = load(ctx, opts, false); err != nil {
			return err
		}
		tag := "latest"
		if len(m.Metadata.Tags) > 0 {
			tag = m.Metadata.Tags[0]
		}
		ref = m.Metadata.Ref + ":" + tag
		vex, tags = m.Spec.VEXFiles, m.Metadata.Tags
	}
	if t := tagOf(ref); t != "" && !slices.Contains(tags, t) {
		tags = append(tags, t)
	}
	art, err := registry.Fetch(ctx, ref)
	if err != nil {
		return fmt.Errorf("%s: %w (has it been published?)", ref, err)
	}
	repo := lock.RepoOf(ref)
	image := repo + "@" + art.Digest
	signers, err := signerArgs(org, manifest.RoleImage, art.Source())
	if err != nil || len(signers) == 0 {
		why := "the org profile names none"
		if err != nil {
			why = err.Error()
		}
		return fmt.Errorf("no image signer to check %s against (%s): reattest reads only what the org's image signer attested; name one in signing.verify or signing.trustPolicy", image, why)
	}
	if _, err := firstVerified(signers, func(args []string) (struct{}, error) {
		return struct{}{}, attest.VerifySignature(ctx, image, args)
	}); err != nil {
		return fmt.Errorf("%s is not signed by the org's image signer, so there is nothing to re-attest: %w", image, err)
	}
	opts.printf("re-attesting %s (%s)", image, ref)
	result := ReattestResult{Image: image, Platforms: map[string]ReattestPlatform{}}

	_, rerr := firstVerified(signers, func(args []string) (json.RawMessage, error) {
		return attest.VerifyPredicate(ctx, image, attest.ReproductionPredicateType, args)
	})
	if result.Reproduced = rerr == nil; result.Reproduced {
		opts.printf("  reproduced: a verified reproduction attestation")
	} else {
		opts.printf("  reproduced: no verified reproduction attestation (clearcutt-factory verify --image %s --attest makes one)", image)
	}

	plats, err := art.Platforms()
	if err != nil {
		return err
	}
	type rescan struct {
		p    registry.PlatformImage
		sbom attest.Attested
	}
	var todo []rescan
	var problems []string
	if org.Vulnerabilities.Scanner == "none" {
		opts.printf("  vulnerabilities.scanner is none: nothing to rescan")
	}
	for _, p := range plats {
		if org.Vulnerabilities.Scanner == "none" {
			result.Platforms[p.Platform] = ReattestPlatform{Digest: p.Digest, Skipped: "vulnerabilities.scanner is none"}
			continue
		}
		pref := repo + "@" + p.Digest
		if ro.OlderThan > 0 {
			if newest, ok := newestScan(ctx, signers, pref); ok && time.Since(newest) < ro.OlderThan {
				why := fmt.Sprintf("its newest verified report is from %s, within %s", newest.UTC().Format(time.RFC3339), ro.OlderThan)
				opts.printf("  %s: %s; not rescanned", p.Platform, why)
				result.Platforms[p.Platform] = ReattestPlatform{Digest: p.Digest, Skipped: why}
				continue
			}
		}
		sbom, err := firstVerified(signers, func(args []string) (attest.Attested, error) {
			raw, ev, err := attest.VerifyPredicateFrom(ctx, pref, attest.CycloneDXType, args)
			return attest.Attested{Predicate: raw, Evidence: ev}, err
		})
		if err != nil {
			why := "no SBOM attestation the org's image signer made"
			problems = append(problems, fmt.Sprintf("%s (%s): %s: %v", p.Platform, p.Digest, why, firstLine(err)))
			result.Platforms[p.Platform] = ReattestPlatform{Digest: p.Digest, Skipped: why}
			continue
		}
		todo = append(todo, rescan{p, sbom})
	}

	work, err := filepath.Abs(filepath.Join(ro.OutDir, safeName(lastElem(repo))+"-reattest"))
	if err != nil {
		return err
	}
	if len(todo) > 0 {
		opts.printf("  updating grype's vulnerability database")
		if err := scan.UpdateDB(ctx, opts.Stderr); err != nil {
			return err
		}
	}
	vexFiles := append(slices.Clone(org.Vulnerabilities.VEXFiles), vex...)
	sign := org.Signing.Mode != "none" && !ro.NoSign
	c := attest.Cosign{Mode: org.Signing.Mode, Key: org.Signing.Key, Args: org.Signing.Args, Stdout: opts.Stderr, Stderr: opts.Stderr}
	for _, t := range todo {
		slug := strings.ReplaceAll(t.p.Platform, "/", "-")
		sbomPath := filepath.Join(work, "attestations", "sbom-"+slug+".cdx.json")
		if err := os.MkdirAll(filepath.Dir(sbomPath), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(sbomPath, t.sbom.Predicate, 0o644); err != nil {
			return err
		}
		report, err := scan.Grype(ctx, sbomPath, scan.Image{Repository: repo, Tags: tags, Digests: []string{art.Digest, t.p.Digest}}, vexFiles)
		if err != nil {
			return fmt.Errorf("%s: %w", t.p.Platform, err)
		}
		report.Rescan = &scan.Statement{PredicateType: t.sbom.Evidence.PredicateType, Digest: t.sbom.Evidence.Digest}
		vulnPath := filepath.Join(work, "attestations", "vuln-"+slug+".predicate.json")
		if err := attest.WriteJSON(vulnPath, report.Predicate()); err != nil {
			return err
		}
		pr := ReattestPlatform{Digest: t.p.Digest, Rescanned: true, Report: rel(vulnPath), Vulnerabilities: report.Counts()}
		opts.printf("  %s: %s", t.p.Platform, summarize(report.Counts()))
		for _, v := range scan.Gate(report, org.Vulnerabilities) {
			result.Blocked = append(result.Blocked, fmt.Sprintf("%s %s %s in %s %s", t.p.Platform, v.Severity, v.ID, v.Package, v.Version))
		}
		if sign {
			if err := c.Attest(ctx, repo+"@"+t.p.Digest, "vuln", vulnPath); err != nil {
				return fmt.Errorf("%s: %w", t.p.Platform, err)
			}
			pr.Attached = true
			if !verifiedRescan(ctx, signers, repo+"@"+t.p.Digest, report.Predicate()) {
				problems = append(problems, fmt.Sprintf("%s: the new vulnerability report was attached but the org's image signers do not verify it; reattest.yml signs as https://github.com/northcutted/clearcutt-factory/.github/workflows/reattest.yml@<workflow ref>. Add reattest beside images and fleet in signing.verify.certificateIdentityRegexp or the trust policy image signer's identityRegexp: (images|fleet|reattest)\\.yml; for key signing, check the configured public key", t.p.Platform))
			}
			opts.printf("  %s: attached the new vulnerability report to %s", t.p.Platform, t.p.Digest)
		}
		result.Platforms[t.p.Platform] = pr
	}
	if len(todo) > 0 && !sign {
		why := "--no-sign"
		if org.Signing.Mode == "none" {
			why = "signing.mode is none"
		}
		opts.printf("  %s: wrote the new reports under %s and attached none", why, rel(work))
	}
	if len(result.Blocked) > 0 {
		opts.printf("the vulnerability gate (failOn: %s) would block %s now (the image is published; the new report says so):\n  %s", org.Vulnerabilities.FailOn, image, strings.Join(result.Blocked, "\n  "))
	}
	if err := attest.WriteJSON(filepath.Join(work, "reattest.json"), result); err != nil {
		return err
	}
	if err := reattestOutput(result, len(todo)); err != nil {
		return err
	}
	if len(problems) > 0 {
		return errors.New("re-attestation incomplete:\n  " + strings.Join(problems, "\n  "))
	}
	return nil
}

// newestScan is when the newest vulnerability report on ref that one of
// signers verifies says its scan ran.
func newestScan(ctx context.Context, signers [][]string, ref string) (time.Time, bool) {
	var newest time.Time
	found := false
	for _, args := range signers {
		all, err := attest.VerifyPredicates(ctx, ref, attest.VulnType, args)
		if err != nil {
			continue
		}
		for _, a := range all {
			if t, ok := scan.ScanTime(a.Predicate); ok && (!found || t.After(newest)) {
				newest, found = t, true
			}
		}
	}
	return newest, found
}

// reattestOutput writes image=, rescanned= (how many platform images), and
// reproduced= to $GITHUB_OUTPUT.
func reattestOutput(r ReattestResult, rescanned int) error {
	path := os.Getenv("GITHUB_OUTPUT")
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(f, "image=%s\nrescanned=%d\nreproduced=%t\n", r.Image, rescanned, r.Reproduced); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// firstLine is the first line of err's message.
func firstLine(err error) string {
	s, _, _ := strings.Cut(err.Error(), "\n")
	return s
}

// ParseAge reads a duration such as 7d, 36h, or 90m (d is 24 hours).
func ParseAge(s string) (time.Duration, error) {
	if d, ok := strings.CutSuffix(s, "d"); ok {
		var n int
		if _, err := fmt.Sscanf(d, "%d", &n); err != nil || n < 0 || fmt.Sprint(n) != d {
			return 0, fmt.Errorf("%q: want a number of days (7d) or a duration (36h)", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("%q: want a number of days (7d) or a duration (36h)", s)
	}
	return d, nil
}

// verifiedRescan checks this exact predicate, not merely any older trusted
// vulnerability report of the same type attached to the image.
func verifiedRescan(ctx context.Context, signers [][]string, ref string, predicate any) bool {
	b, err := json.Marshal(predicate)
	if err != nil {
		return false
	}
	var want any
	if json.Unmarshal(b, &want) != nil {
		return false
	}
	for _, args := range signers {
		all, err := attest.VerifyPredicates(ctx, ref, attest.VulnType, args)
		if err != nil {
			continue
		}
		for _, a := range all {
			var got any
			if json.Unmarshal(a.Predicate, &got) == nil && reflect.DeepEqual(got, want) {
				return true
			}
		}
	}
	return false
}
