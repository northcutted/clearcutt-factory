package scan

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/northcutted/clearcutt-factory/internal/manifest"
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

// TestRescanPredicate: a rescan's predicate names the signed SBOM it read
// and when it ran; a build's scan names no SBOM; ScanTime reads the time
// back, preferring when the scan finished.
func TestRescanPredicate(t *testing.T) {
	started := time.Date(2026, 10, 26, 6, 0, 0, 0, time.UTC)
	r := &Report{Raw: json.RawMessage(`{"matches":[],"descriptor":{"name":"grype","version":"0.120.1","db":{"built":"2026-10-26T01:00:00Z"}}}`), Started: started, Finished: started.Add(time.Minute)}
	b, _ := json.Marshal(r.Predicate())
	if strings.Contains(string(b), `"rescan"`) {
		t.Errorf("a build's scan names a rescan: %s", b)
	}
	if got, ok := ScanTime(b); !ok || !got.Equal(started.Add(time.Minute)) {
		t.Errorf("ScanTime: %v %v", got, ok)
	}
	r.Rescan = &Statement{PredicateType: "https://cyclonedx.org/bom", Digest: map[string]string{"sha256": "abc"}}
	b, _ = json.Marshal(r.Predicate())
	var p struct {
		Scanner  struct{ Version string }
		Metadata struct {
			Rescan struct{ SBOM Statement }
		}
	}
	if err := json.Unmarshal(b, &p); err != nil || p.Metadata.Rescan.SBOM.Digest["sha256"] != "abc" || p.Metadata.Rescan.SBOM.PredicateType != "https://cyclonedx.org/bom" || p.Scanner.Version != "0.120.1" {
		t.Errorf("rescan predicate: %v %s", err, b)
	}
	if got, ok := ScanTime(json.RawMessage(`{"metadata":{"scanStartedOn":"2026-10-01T00:00:00Z"}}`)); !ok || got.Day() != 1 {
		t.Errorf("started only: %v %v", got, ok)
	}
	for _, bad := range []string{`{}`, `not json`, `{"metadata":{"scanFinishedOn":"yesterday"}}`} {
		if _, ok := ScanTime(json.RawMessage(bad)); ok {
			t.Errorf("%s: a scan time", bad)
		}
	}
}
