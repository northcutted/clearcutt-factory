package scan

import (
	"testing"

	"github.com/northcutted/declarative-image-factory/internal/manifest"
)

func TestGate(t *testing.T) {
	r := &Report{Matches: []Match{
		{ID: "CVE-1", Severity: "Critical", Fixed: false},
		{ID: "CVE-2", Severity: "High", Fixed: true},
		{ID: "CVE-3", Severity: "Medium", Fixed: true},
		{ID: "CVE-4", Severity: "Critical", Fixed: true},
	}}
	if got := Gate(r, manifest.Vulnerabilities{}); got != nil {
		t.Errorf("no failOn should never block, got %v", got)
	}
	got := Gate(r, manifest.Vulnerabilities{FailOn: "high"})
	if len(got) != 3 || got[0].ID != "CVE-1" || got[2].ID != "CVE-2" {
		t.Errorf("failOn high: %v", got)
	}
	got = Gate(r, manifest.Vulnerabilities{FailOn: "high", OnlyFixed: true})
	if len(got) != 2 || got[0].ID != "CVE-4" {
		t.Errorf("failOn high onlyFixed: %v", got)
	}
	if c := r.Counts(); c["critical"] != 2 || c["medium"] != 1 {
		t.Errorf("counts: %v", c)
	}
}
