// Package scan runs the vulnerability scanner and evaluates the org's gate.
package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/northcutted/clearcutt-factory/internal/manifest"
)

// Report is a scanner run, kept raw for the attestation.
type Report struct {
	Raw      json.RawMessage
	Started  time.Time
	Finished time.Time
	Matches  []Match
	// VEX lists the VEX statements the scan was given, so the attestation
	// shows every suppression that may have applied.
	VEX []Applied
	// VEXDocuments are the documents passed to the scanner as they were
	// (not OpenVEX, so their statements aren't listed in VEX).
	VEXDocuments []string
	// Suppressed are the findings the scanner left out because of a VEX
	// statement, each with the statement that did it.
	Suppressed []Suppression
	// Rescan names the signed SBOM attestation a rescan read (clearcutt-
	// factory reattest); nil for a build's scan of the SBOM it made.
	Rescan *Statement
}

// Statement names an attestation: its predicate type and the digest of its
// in-toto statement (the signed payload).
type Statement struct {
	PredicateType string            `json:"predicateType"`
	Digest        map[string]string `json:"digest"`
}

// UpdateDB brings grype's vulnerability database up to the newest one
// published (grype db update), so a scan after it is as current as the
// database can be. grype's progress goes to stderr.
func UpdateDB(ctx context.Context, stderr io.Writer) error {
	bin, err := exec.LookPath("grype")
	if err != nil {
		return fmt.Errorf("grype not found on PATH")
	}
	cmd := exec.CommandContext(ctx, bin, "db", "update")
	cmd.Stdout, cmd.Stderr = stderr, stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("grype db update: %w", err)
	}
	return nil
}

// ScanTime is when a vulnerability attestation's predicate says its scan
// finished (else started), and whether it says.
func ScanTime(predicate json.RawMessage) (time.Time, bool) {
	var p struct {
		Metadata struct {
			ScanFinishedOn string `json:"scanFinishedOn"`
			ScanStartedOn  string `json:"scanStartedOn"`
		} `json:"metadata"`
	}
	if json.Unmarshal(predicate, &p) != nil {
		return time.Time{}, false
	}
	for _, v := range []string{p.Metadata.ScanFinishedOn, p.Metadata.ScanStartedOn} {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

type Match struct {
	ID       string
	Severity string
	Package  string
	Version  string
	Fixed    bool
}

// Grype scans an SBOM file of img, applying the VEX documents' statements
// that are for it: grype, given an SBOM, applies only statements whose
// product is a package, to every image, so statements whose product is
// this image (pkg:oci) are first rewritten to the packages they name
// (scopeStatements), and statements for other images left out. The
// statements passed are recorded in the report.
func Grype(ctx context.Context, sbomPath string, img Image, vex []string) (*Report, error) {
	bin, err := exec.LookPath("grype")
	if err != nil {
		return nil, fmt.Errorf("grype not found on PATH")
	}
	r := &Report{}
	args := []string{"sbom:" + sbomPath, "-o", "json", "-q"}
	if len(vex) > 0 {
		scoped := strings.TrimSuffix(sbomPath, filepath.Ext(sbomPath)) + ".openvex.json"
		applied, passthrough, err := scopeStatements(vex, img, sbomPath, scoped)
		if err != nil {
			return nil, fmt.Errorf("vex: %w", err)
		}
		if len(applied) > 0 {
			args = append(args, "--vex", scoped)
		}
		for _, v := range passthrough {
			args = append(args, "--vex", v)
			r.VEXDocuments = append(r.VEXDocuments, filepath.Base(v))
		}
		r.VEX = applied
	}
	r.Started = time.Now().UTC()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("grype: %w", err)
	}
	r.Finished = time.Now().UTC()
	r.Raw = out

	var doc struct {
		Matches []struct {
			Vulnerability struct {
				ID       string `json:"id"`
				Severity string `json:"severity"`
				Fix      struct {
					State string `json:"state"`
				} `json:"fix"`
			} `json:"vulnerability"`
			Artifact struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"artifact"`
		} `json:"matches"`
		IgnoredMatches []struct {
			Vulnerability struct {
				ID string `json:"id"`
			} `json:"vulnerability"`
			RelatedVulnerabilities []struct {
				ID string `json:"id"`
			} `json:"relatedVulnerabilities"`
			Artifact struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				PURL    string `json:"purl"`
			} `json:"artifact"`
			AppliedIgnoreRules []struct {
				Namespace string `json:"namespace"`
			} `json:"appliedIgnoreRules"`
		} `json:"ignoredMatches"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, fmt.Errorf("parsing grype output: %w", err)
	}
	for _, m := range doc.Matches {
		r.Matches = append(r.Matches, Match{
			ID: m.Vulnerability.ID, Severity: m.Vulnerability.Severity,
			Package: m.Artifact.Name, Version: m.Artifact.Version,
			Fixed: m.Vulnerability.Fix.State == "fixed",
		})
	}
	// What a VEX statement suppressed, and which statement.
	for _, m := range doc.IgnoredMatches {
		vex := false
		for _, rule := range m.AppliedIgnoreRules {
			vex = vex || rule.Namespace == "vex"
		}
		if !vex {
			continue
		}
		ids := []string{m.Vulnerability.ID}
		for _, rv := range m.RelatedVulnerabilities {
			ids = append(ids, rv.ID)
		}
		r.Suppressed = append(r.Suppressed, attribute(r.VEX, ids, Suppression{
			Vulnerability: m.Vulnerability.ID, Package: m.Artifact.Name, Version: m.Artifact.Version, PURL: m.Artifact.PURL,
		}))
	}
	return r, nil
}

// Predicate wraps the report in the cosign vulnerability attestation format
// (https://cosign.sigstore.dev/attestation/vuln/v1).
func (r *Report) Predicate() any {
	var desc struct {
		Descriptor struct {
			Name    string          `json:"name"`
			Version string          `json:"version"`
			DB      json.RawMessage `json:"db"`
		} `json:"descriptor"`
	}
	_ = json.Unmarshal(r.Raw, &desc)
	metadata := map[string]any{
		"scanStartedOn":  r.Started.Format(time.RFC3339),
		"scanFinishedOn": r.Finished.Format(time.RFC3339),
	}
	// Every VEX statement the scanner was given, so a suppression shows
	// in the attestation rather than only as a finding that isn't there.
	if len(r.VEX) > 0 || len(r.VEXDocuments) > 0 {
		vex := map[string]any{"statements": r.VEX}
		if len(r.VEXDocuments) > 0 {
			vex["documents"] = r.VEXDocuments
		}
		if r.VEX == nil {
			vex["statements"] = []Applied{}
		}
		suppressed := r.Suppressed
		if suppressed == nil {
			suppressed = []Suppression{}
		}
		vex["suppressed"] = suppressed
		metadata["vex"] = vex
	}
	// A rescan says which signed SBOM it scanned.
	if r.Rescan != nil {
		metadata["rescan"] = map[string]any{"sbom": r.Rescan}
	}
	return map[string]any{
		"invocation": map[string]any{"parameters": nil, "uri": "", "event_id": "", "builder.id": ""},
		"scanner": map[string]any{
			"uri":     "pkg:github/anchore/grype@" + desc.Descriptor.Version,
			"version": desc.Descriptor.Version,
			"db":      desc.Descriptor.DB,
			"result":  r.Raw,
		},
		"metadata": metadata,
	}
}

// Counts tallies matches by severity.
func (r *Report) Counts() map[string]int {
	c := map[string]int{}
	for _, m := range r.Matches {
		c[strings.ToLower(m.Severity)]++
	}
	return c
}

// Gate returns the matches that fail the org's vulnerability policy.
func Gate(r *Report, v manifest.Vulnerabilities) []Match {
	min := manifest.SeverityRank(v.FailOn)
	if min == 0 {
		return nil
	}
	var bad []Match
	for _, m := range r.Matches {
		if manifest.SeverityRank(m.Severity) >= min && (!v.OnlyFixed || m.Fixed) {
			bad = append(bad, m)
		}
	}
	sort.Slice(bad, func(i, j int) bool {
		if a, b := manifest.SeverityRank(bad[i].Severity), manifest.SeverityRank(bad[j].Severity); a != b {
			return a > b
		}
		return bad[i].ID < bad[j].ID
	})
	return bad
}
