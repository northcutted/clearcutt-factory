package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const openvex = `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://acme/vex/2026-10","author":"security","timestamp":"2026-10-18T00:00:00Z","version":1,"statements":[%s]}`

func statement(vuln, products string) string {
	return `{"vulnerability":{"name":"` + vuln + `"},"products":[` + products + `],"status":"not_affected","justification":"vulnerable_code_not_in_execute_path","impact_statement":"why"}`
}

func writeVEX(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestImageMatches: which pkg:oci products name an image.
func TestImageMatches(t *testing.T) {
	img := Image{Repository: "ghcr.io/acme/apps/catalog", Digests: []string{"sha256:index", "sha256:amd64"}}
	for purl, want := range map[string]bool{
		"pkg:oci/catalog?repository_url=ghcr.io/acme/apps/catalog":                true,
		"pkg:oci/catalog?repository_url=https://ghcr.io/acme/apps/catalog/":       true,
		"pkg:oci/catalog?repository_url=GHCR.io/Acme/apps/Catalog&arch=amd64":     true,
		"pkg:oci/catalog?repository_url=ghcr.io/acme/apps/catalog:1":              true,
		"pkg:oci/catalog?repository_url=ghcr.io/acme/apps/checkout":               false,
		"pkg:oci/catalog?repository_url=ghcr.io/acme/apps/catalog-evil":           false,
		"pkg:oci/catalog@sha256%3Aindex":                                          true,
		"pkg:oci/catalog@sha256:amd64?repository_url=ghcr.io/other/catalog":       true,  // a digest names the content, wherever it is
		"pkg:oci/catalog@sha256%3Aother?repository_url=ghcr.io/acme/apps/catalog": false, // another build of the same repository
		"pkg:oci/catalog":                   true,
		"pkg:oci/Catalog":                   true,
		"pkg:oci/acme/apps/catalog":         true,
		"pkg:oci/ghcr.io/acme/apps/catalog": true,
		"pkg:oci/checkout":                  false,
		"pkg:oci/apps/catalog":              false,
		"pkg:oci/catalog?tag=1":             true,
	} {
		if got := img.matches(purl); got != want {
			t.Errorf("%s: %v, want %v", purl, got, want)
		}
	}
}

// TestScopeStatements: image-scoped statements are rewritten to their
// subcomponents (every SBOM package with none) for the image they name and
// dropped for others; package-scoped statements pass everywhere; other
// documents pass through; and every statement passed is recorded.
func TestScopeStatements(t *testing.T) {
	dir := t.TempDir()
	sbom := writeVEX(t, dir, "sbom.cdx.json", `{"components":[{"purl":"pkg:apk/wolfi/python-3.14@3.14.0-r0?arch=x86_64"},{"purl":"pkg:apk/wolfi/brotli@1.2.1-r0?arch=x86_64"},{"name":"nopurl"},{"purl":"pkg:apk/wolfi/brotli@1.2.1-r0?arch=x86_64"}]}`)
	vex := writeVEX(t, dir, "triage.openvex.json", strings.Replace(openvex, "%s", strings.Join([]string{
		statement("CVE-2025-15367", `{"@id":"pkg:oci/catalog?repository_url=ghcr.io/acme/apps/catalog","subcomponents":[{"@id":"pkg:apk/wolfi/python-3.14"}]}`),
		statement("CVE-2026-1", `{"@id":"pkg:oci/catalog?repository_url=ghcr.io/acme/apps/catalog"}`),
		statement("CVE-2026-2", `{"@id":"pkg:oci/checkout?repository_url=ghcr.io/acme/apps/checkout","subcomponents":[{"@id":"pkg:golang/stdlib"}]}`),
		statement("GO-2026-6604", `{"@id":"pkg:golang/stdlib@1.26.4"},{"@id":"pkg:golang/stdlib@1.26.6"}`),
		statement("CVE-2026-3", `"pkg:oci/catalog","pkg:apk/wolfi/zlib"`),
	}, ","), 1))
	csaf := writeVEX(t, dir, "other.json", `{"document":{"category":"csaf_vex"}}`)
	notes := writeVEX(t, dir, "notes.openvex.json", strings.Replace(openvex, "%s", statement("CVE-2026-9", `{"@id":"pkg:oci/storefront?repository_url=ghcr.io/acme/apps/storefront"}`), 1))

	catalog := Image{Repository: "ghcr.io/acme/apps/catalog", Digests: []string{"sha256:c0", "sha256:c1"}}
	out := filepath.Join(dir, "out", "catalog.openvex.json")
	applied, passthrough, err := scopeStatements([]string{vex, csaf, notes}, catalog, sbom, out)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(passthrough, []string{csaf}) {
		t.Errorf("passthrough %v", passthrough)
	}
	all := []string{"pkg:apk/wolfi/brotli@1.2.1-r0?arch=x86_64", "pkg:apk/wolfi/python-3.14@3.14.0-r0?arch=x86_64"}
	want := []Applied{
		{Document: "https://acme/vex/2026-10", Vulnerability: "CVE-2025-15367", Status: "not_affected", Justification: "vulnerable_code_not_in_execute_path", Product: "pkg:oci/catalog?repository_url=ghcr.io/acme/apps/catalog", Scope: ScopeImage, Packages: []string{"pkg:apk/wolfi/python-3.14"}},
		{Document: "https://acme/vex/2026-10", Vulnerability: "CVE-2026-1", Status: "not_affected", Justification: "vulnerable_code_not_in_execute_path", Product: "pkg:oci/catalog?repository_url=ghcr.io/acme/apps/catalog", Scope: ScopeImage, Packages: all},
		{Document: "https://acme/vex/2026-10", Vulnerability: "GO-2026-6604", Status: "not_affected", Justification: "vulnerable_code_not_in_execute_path", Product: "pkg:golang/stdlib@1.26.4", Scope: ScopePackage, Packages: []string{"pkg:golang/stdlib@1.26.4"}},
		{Document: "https://acme/vex/2026-10", Vulnerability: "GO-2026-6604", Status: "not_affected", Justification: "vulnerable_code_not_in_execute_path", Product: "pkg:golang/stdlib@1.26.6", Scope: ScopePackage, Packages: []string{"pkg:golang/stdlib@1.26.6"}},
		{Document: "https://acme/vex/2026-10", Vulnerability: "CVE-2026-3", Status: "not_affected", Justification: "vulnerable_code_not_in_execute_path", Product: "pkg:oci/catalog", Scope: ScopeImage, Packages: all},
		{Document: "https://acme/vex/2026-10", Vulnerability: "CVE-2026-3", Status: "not_affected", Justification: "vulnerable_code_not_in_execute_path", Product: "pkg:apk/wolfi/zlib", Scope: ScopePackage, Packages: []string{"pkg:apk/wolfi/zlib"}},
	}
	if !reflect.DeepEqual(applied, want) {
		got, _ := json.MarshalIndent(applied, "", "  ")
		t.Errorf("applied:\n%s", got)
	}
	// The document written: OpenVEX, with each statement's products
	// rewritten and the rest of it kept.
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Context    string `json:"@context"`
		Author     string `json:"author"`
		Statements []struct {
			Vulnerability   map[string]string `json:"vulnerability"`
			Products        []map[string]any  `json:"products"`
			Status          string            `json:"status"`
			ImpactStatement string            `json:"impact_statement"`
		} `json:"statements"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Context != "https://openvex.dev/ns/v0.2.0" || !strings.Contains(doc.Author, "https://acme/vex/2026-10") || len(doc.Statements) != 4 {
		t.Fatalf("document:\n%s", b)
	}
	products := func(i int) []string {
		var out []string
		for _, p := range doc.Statements[i].Products {
			id, _ := p["@id"].(string)
			out = append(out, id)
		}
		return out
	}
	if p := products(0); !reflect.DeepEqual(p, []string{"pkg:apk/wolfi/python-3.14"}) || doc.Statements[0].Vulnerability["name"] != "CVE-2025-15367" || doc.Statements[0].ImpactStatement != "why" {
		t.Errorf("statement 0: %v %+v", p, doc.Statements[0])
	}
	if p := products(1); !reflect.DeepEqual(p, all) {
		t.Errorf("statement 1 (no subcomponents): %v", p)
	}
	if p := products(2); !reflect.DeepEqual(p, []string{"pkg:golang/stdlib@1.26.4", "pkg:golang/stdlib@1.26.6"}) {
		t.Errorf("statement 2 (packages): %v", p)
	}
	if p := products(3); !reflect.DeepEqual(p, append(append([]string{}, all...), "pkg:apk/wolfi/zlib")) {
		t.Errorf("statement 3 (0.0.1 strings): %v", p)
	}
	for _, s := range doc.Statements {
		if s.Vulnerability["name"] == "CVE-2026-2" || s.Vulnerability["name"] == "CVE-2026-9" {
			t.Errorf("another image's statement was passed: %s", s.Vulnerability["name"])
		}
	}

	// For another image, only the package statements remain; with only
	// image statements for other images, nothing is written.
	checkout := Image{Repository: "ghcr.io/acme/apps/checkout", Digests: []string{"sha256:k0"}}
	applied, _, err = scopeStatements([]string{vex}, checkout, sbom, filepath.Join(dir, "out", "checkout.openvex.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vulns []string
	for _, a := range applied {
		vulns = append(vulns, a.Vulnerability+":"+a.Scope)
	}
	if !reflect.DeepEqual(vulns, []string{"CVE-2026-2:image", "GO-2026-6604:package", "GO-2026-6604:package", "CVE-2026-3:package"}) {
		t.Errorf("checkout: %v", vulns)
	}
	nothing := filepath.Join(dir, "out", "nothing.openvex.json")
	if applied, _, err = scopeStatements([]string{notes}, checkout, sbom, nothing); err != nil || applied != nil {
		t.Errorf("no statements for checkout: %v %v", applied, err)
	}
	if _, err := os.Stat(nothing); err == nil {
		t.Error("an empty document was written")
	}
}

// TestPredicateRecordsVEX: the vulnerability attestation lists the VEX
// statements the scan was given, and the documents passed through.
func TestPredicateRecordsVEX(t *testing.T) {
	r := &Report{Raw: []byte(`{"descriptor":{"version":"0.121.0","db":{}}}`), VEX: []Applied{{Document: "d", Vulnerability: "CVE-1", Status: "not_affected", Product: "pkg:oci/x", Scope: ScopeImage, Packages: []string{"pkg:apk/wolfi/x"}}}, VEXDocuments: []string{"other.json"}}
	b, _ := json.Marshal(r.Predicate())
	var pred struct {
		Metadata struct {
			VEX struct {
				Statements []Applied `json:"statements"`
				Documents  []string  `json:"documents"`
			} `json:"vex"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(b, &pred); err != nil {
		t.Fatal(err)
	}
	if len(pred.Metadata.VEX.Statements) != 1 || pred.Metadata.VEX.Statements[0].Vulnerability != "CVE-1" || !reflect.DeepEqual(pred.Metadata.VEX.Documents, []string{"other.json"}) {
		t.Errorf("predicate metadata.vex: %s", b)
	}
	// Without VEX, the metadata has no vex key.
	b, _ = json.Marshal((&Report{Raw: []byte(`{}`)}).Predicate())
	if strings.Contains(string(b), `"vex"`) {
		t.Errorf("vex recorded without any: %s", b)
	}
}
