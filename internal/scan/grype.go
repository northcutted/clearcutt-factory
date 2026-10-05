// Package scan runs the vulnerability scanner and evaluates the org's gate.
package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/northcutted/declarative-image-factory/internal/manifest"
)

// Report is a scanner run, kept raw for the attestation.
type Report struct {
	Raw      json.RawMessage
	Started  time.Time
	Finished time.Time
	Matches  []Match
}

type Match struct {
	ID       string
	Severity string
	Package  string
	Version  string
	Fixed    bool
}

// Grype scans an SBOM file, applying VEX documents.
func Grype(ctx context.Context, sbomPath string, vex []string) (*Report, error) {
	bin, err := exec.LookPath("grype")
	if err != nil {
		return nil, fmt.Errorf("grype not found on PATH")
	}
	args := []string{"sbom:" + sbomPath, "-o", "json", "-q"}
	for _, v := range vex {
		args = append(args, "--vex", v)
	}
	r := &Report{Started: time.Now().UTC()}
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
	return map[string]any{
		"invocation": map[string]any{"parameters": nil, "uri": "", "event_id": "", "builder.id": ""},
		"scanner": map[string]any{
			"uri":     "pkg:github/anchore/grype@" + desc.Descriptor.Version,
			"version": desc.Descriptor.Version,
			"db":      desc.Descriptor.DB,
			"result":  r.Raw,
		},
		"metadata": map[string]any{
			"scanStartedOn":  r.Started.Format(time.RFC3339),
			"scanFinishedOn": r.Finished.Format(time.RFC3339),
		},
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
