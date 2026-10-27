package scan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Opt-in because this exercises the installed scanner and vulnerability DB.
func TestGrypeImageScopeEndToEnd(t *testing.T) {
	if os.Getenv("CLEARCUTT_FACTORY_GRYPE_E2E") != "1" {
		t.Skip("set CLEARCUTT_FACTORY_GRYPE_E2E=1 with grype and its DB installed")
	}
	t.Setenv("GRYPE_DB_AUTO_UPDATE", "false")
	dir := t.TempDir()
	sbom := writeVEX(t, dir, "sbom.cdx.json", `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[{"type":"library","name":"stdlib","version":"1.20.0","purl":"pkg:golang/stdlib@1.20.0"}]}`)
	image := Image{Repository: "example.com/apps/catalog", Digests: []string{"sha256:amd64"}}
	baseline, err := Grype(context.Background(), sbom, image, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(baseline.Matches) == 0 {
		t.Fatal("test requires vulnerability coverage of Go 1.20.0")
	}
	id := baseline.Matches[0].ID
	f := writeVEX(t, dir, "vex.json", strings.Replace(openvex, "%s", statement(id, `{"@id":"example.com/apps/catalog","subcomponents":[{"@id":"pkg:golang/stdlib"}]}`), 1))
	target, err := Grype(context.Background(), sbom, image, []string{f})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range target.Matches {
		if m.ID == id {
			t.Fatalf("real grype did not suppress image-scoped %s", id)
		}
	}
	found := false
	for _, m := range target.Suppressed {
		if m.Vulnerability == id && m.Document != "" {
			found = true
		}
	}
	if !found {
		t.Fatalf("suppression lacks attribution: %s", fmt.Sprint(target.Suppressed))
	}
	other, err := Grype(context.Background(), sbom, Image{Repository: "example.com/apps/checkout"}, []string{f})
	if err != nil {
		t.Fatal(err)
	}
	if len(other.Matches) != len(baseline.Matches) {
		t.Fatalf("scope widened to another image: %d vs %d", len(other.Matches), len(baseline.Matches))
	}
	if _, err := os.Stat(filepath.Join(dir, "sbom.cdx.openvex.json")); err != nil {
		t.Fatal(err)
	}
}
