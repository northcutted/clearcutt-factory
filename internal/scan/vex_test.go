package scan

import (
	"context"
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

// TestImageNames: which products name an image, by the rule
// clearcutt-verify applies too: an image purl by digest, or by
// repository_url (and tag); a reference by repository, tag, or digest. A
// bare pkg:oci/NAME names no image.
func TestImageNames(t *testing.T) {
	img := Image{Repository: "ghcr.io/acme/apps/catalog", Tags: []string{"1", "latest"}, Digests: []string{"sha256:index", "sha256:amd64"}}
	for id, want := range map[string]bool{
		"pkg:oci/catalog?repository_url=ghcr.io/acme/apps/catalog":                true,
		"pkg:oci/catalog?repository_url=https://ghcr.io/acme/apps/catalog/":       true,
		"pkg:oci/catalog?repository_url=oci://ghcr.io/acme/apps/catalog":          true,
		"pkg:oci/catalog?repository_url=ghcr.io/acme/apps/catalog&arch=amd64":     true,
		"pkg:oci/catalog?repository_url=ghcr.io/acme/apps/catalog&tag=1":          true,
		"pkg:oci/catalog?repository_url=ghcr.io/acme/apps/catalog&tag=2":          false, // another tag
		"pkg:oci/catalog?repository_url=ghcr.io/acme/apps/catalog:1":              false, // a repository, not a reference
		"pkg:oci/catalog?repository_url=GHCR.io/Acme/apps/Catalog":                false,
		"pkg:oci/catalog?repository_url=ghcr.io/acme/apps/checkout":               false,
		"pkg:oci/catalog?repository_url=ghcr.io/acme/apps/catalog-evil":           false,
		"pkg:oci/catalog@sha256%3Aindex":                                          true,
		"pkg:oci/catalog@sha256:amd64?repository_url=ghcr.io/other/catalog":       true,  // a digest names the content, wherever it is
		"pkg:oci/catalog@sha256%3Aother?repository_url=ghcr.io/acme/apps/catalog": false, // another build of the same repository
		"pkg:docker/acme/catalog?repository_url=ghcr.io/acme/apps/catalog":        true,
		"pkg:oci/catalog":                         false, // bare: names no image (it would name every */catalog)
		"pkg:oci/acme/apps/catalog":               false,
		"pkg:oci/ghcr.io/acme/apps/catalog":       false,
		"pkg:oci/catalog?tag=1":                   false,
		"ghcr.io/acme/apps/catalog":               true,
		"ghcr.io/acme/apps/catalog:1":             true,
		"ghcr.io/acme/apps/catalog:2":             false,
		"ghcr.io/acme/apps/catalog@sha256:amd64":  true,
		"ghcr.io/acme/apps/catalog@sha256:other":  false,
		"ghcr.io/acme/apps/checkout@sha256:index": false,
		"sha256:index":                            true,
		"sha256:other":                            false,
		"catalog":                                 false,
		"ghcr.io/acme/apps/checkout":              false,
	} {
		if got := img.names(id); got != want {
			t.Errorf("%s: %v, want %v", id, got, want)
		}
	}
	// Docker Hub short names, as Docker spells them.
	hub := Image{Repository: "docker.io/library/debian", Tags: []string{"trixie"}}
	for _, id := range []string{"debian", "debian:trixie", "index.docker.io/library/debian", "pkg:oci/debian?repository_url=docker.io/library/debian"} {
		if !hub.names(id) {
			t.Errorf("%s doesn't name docker.io/library/debian", id)
		}
	}
	for id, want := range map[string]string{"pkg:oci/x": productImage, "pkg:docker/x": productImage, "ghcr.io/x": productImage, "pkg:apk/wolfi/x": productPackage, "": productOther} {
		if got := productKind(id); got != want {
			t.Errorf("productKind(%q) = %s, want %s", id, got, want)
		}
	}
}

// TestScopeStatements: image-scoped statements are rewritten to their
// subcomponents (every SBOM package with none; none, when none can be
// read) for the image they name and dropped for others; package-scoped
// statements pass everywhere; OpenVEX 0.0.1 statements are read as such;
// other documents pass through; and every statement passed is recorded.
func TestScopeStatements(t *testing.T) {
	dir := t.TempDir()
	sbom := writeVEX(t, dir, "sbom.cdx.json", `{"components":[{"purl":"pkg:apk/wolfi/python-3.14@3.14.0-r0?arch=x86_64"},{"purl":"pkg:apk/wolfi/brotli@1.2.1-r0?arch=x86_64"},{"name":"nopurl"},{"purl":"pkg:apk/wolfi/brotli@1.2.1-r0?arch=x86_64"}]}`)
	catalogRepo := `"@id":"pkg:oci/catalog?repository_url=ghcr.io/acme/apps/catalog"`
	vex := writeVEX(t, dir, "triage.openvex.json", strings.Replace(openvex, "%s", strings.Join([]string{
		statement("CVE-2025-15367", `{`+catalogRepo+`,"subcomponents":[{"@id":"pkg:apk/wolfi/python-3.14"}]}`),
		statement("CVE-2026-1", `{`+catalogRepo+`}`),
		statement("CVE-2026-2", `{"@id":"pkg:oci/checkout?repository_url=ghcr.io/acme/apps/checkout","subcomponents":[{"@id":"pkg:golang/stdlib"}]}`),
		statement("GO-2026-6604", `{"@id":"pkg:golang/stdlib@1.26.4"},{"@id":"pkg:golang/stdlib@1.26.6"}`),
		statement("CVE-2026-3", `"pkg:oci/catalog","pkg:apk/wolfi/zlib"`),
		statement("CVE-2026-4", `{`+catalogRepo+`,"subcomponents":[{"identifiers":{"purl":"pkg:apk/wolfi/openssl"}}]}`),
		statement("CVE-2026-5", `{`+catalogRepo+`,"subcomponents":[{"name":"openssl"}]}`),
		statement("CVE-2026-7", `{"identifiers":{"purl":"pkg:apk/wolfi/curl"}}`),
		statement("CVE-2026-8", `{"@id":"ghcr.io/acme/apps/catalog:1"}`),
	}, ","), 1))
	notes := writeVEX(t, dir, "notes.openvex.json", strings.Replace(openvex, "%s", statement("CVE-2026-9", `{"@id":"pkg:oci/storefront?repository_url=ghcr.io/acme/apps/storefront"}`), 1))
	old := writeVEX(t, dir, "old.openvex.json", `{"@context":"https://openvex.dev/ns","@id":"old","statements":[{"vulnerability":"CVE-2026-6","products":["pkg:oci/catalog?repository_url=ghcr.io/acme/apps/catalog"],"subcomponents":["pkg:apk/wolfi/glibc"],"status":"not_affected","justification":"component_not_present"}]}`)

	catalog := Image{Repository: "ghcr.io/acme/apps/catalog", Tags: []string{"1"}, Digests: []string{"sha256:c0", "sha256:c1"}}
	out := filepath.Join(dir, "out", "catalog.openvex.json")
	applied, err := scopeStatements([]string{vex, notes, old}, catalog, sbom, out)
	if err != nil {
		t.Fatal(err)
	}
	all := []string{"pkg:apk/wolfi/brotli@1.2.1-r0?arch=x86_64", "pkg:apk/wolfi/python-3.14@3.14.0-r0?arch=x86_64"}
	a := func(vuln, product, scope string, pkgs ...string) string {
		return vuln + " " + product + " " + scope + " " + strings.Join(pkgs, ",")
	}
	var got []string
	for _, x := range applied {
		got = append(got, a(x.Vulnerability, x.Product, x.Scope, x.Packages...))
	}
	want := []string{
		a("CVE-2025-15367", "pkg:oci/catalog?repository_url=ghcr.io/acme/apps/catalog", ScopeImage, "pkg:apk/wolfi/python-3.14"),
		a("CVE-2026-1", "pkg:oci/catalog?repository_url=ghcr.io/acme/apps/catalog", ScopeImage, all...),
		a("GO-2026-6604", "pkg:golang/stdlib@1.26.4", ScopePackage, "pkg:golang/stdlib@1.26.4"),
		a("GO-2026-6604", "pkg:golang/stdlib@1.26.6", ScopePackage, "pkg:golang/stdlib@1.26.6"),
		a("CVE-2026-3", "pkg:apk/wolfi/zlib", ScopePackage, "pkg:apk/wolfi/zlib"), // the bare pkg:oci/catalog names nothing
		a("CVE-2026-4", "pkg:oci/catalog?repository_url=ghcr.io/acme/apps/catalog", ScopeImage, "pkg:apk/wolfi/openssl"),
		// CVE-2026-5's subcomponent has no identifier: left out, not widened.
		a("CVE-2026-7", "pkg:apk/wolfi/curl", ScopePackage, "pkg:apk/wolfi/curl"),
		a("CVE-2026-8", "ghcr.io/acme/apps/catalog:1", ScopeImage, all...),
		a("CVE-2026-6", "pkg:oci/catalog?repository_url=ghcr.io/acme/apps/catalog", ScopeImage, "pkg:apk/wolfi/glibc"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("applied:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if applied[0].Document != "https://acme/vex/2026-10" || applied[0].Status != "not_affected" || applied[0].Justification != "vulnerable_code_not_in_execute_path" {
		t.Errorf("applied[0]: %+v", applied[0])
	}
	// The document written: OpenVEX 0.2, with each statement's products
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
			Subcomponents   any               `json:"subcomponents"`
			Status          string            `json:"status"`
			ImpactStatement string            `json:"impact_statement"`
		} `json:"statements"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Context != "https://openvex.dev/ns/v0.2.0" || !strings.Contains(doc.Author, "https://acme/vex/2026-10") || len(doc.Statements) != 9 {
		t.Fatalf("document:\n%s", b)
	}
	products := map[string][]string{}
	for _, st := range doc.Statements {
		for _, p := range st.Products {
			id, _ := p["@id"].(string)
			products[st.Vulnerability["name"]] = append(products[st.Vulnerability["name"]], id)
		}
		if st.Subcomponents != nil {
			t.Errorf("%s keeps statement subcomponents", st.Vulnerability["name"])
		}
	}
	for vuln, want := range map[string][]string{
		"CVE-2025-15367": {"pkg:apk/wolfi/python-3.14"},
		"CVE-2026-1":     all,
		"GO-2026-6604":   {"pkg:golang/stdlib@1.26.4", "pkg:golang/stdlib@1.26.6"},
		"CVE-2026-3":     {"pkg:apk/wolfi/zlib"},
		"CVE-2026-4":     {"pkg:apk/wolfi/openssl"},
		"CVE-2026-7":     {"pkg:apk/wolfi/curl"},
		"CVE-2026-8":     all,
		"CVE-2026-6":     {"pkg:apk/wolfi/glibc"},
	} {
		if !reflect.DeepEqual(products[vuln], want) {
			t.Errorf("%s: products %v, want %v", vuln, products[vuln], want)
		}
	}
	for _, vuln := range []string{"CVE-2026-2", "CVE-2026-5", "CVE-2026-9"} {
		if _, ok := products[vuln]; ok {
			t.Errorf("%s was passed", vuln)
		}
	}
	if doc.Statements[0].ImpactStatement != "why" {
		t.Errorf("statement 0 lost its impact statement: %+v", doc.Statements[0])
	}

	// For another image, only the package statements remain; with only
	// image statements for other images, nothing is written.
	checkout := Image{Repository: "ghcr.io/acme/apps/checkout", Digests: []string{"sha256:k0"}}
	applied, err = scopeStatements([]string{vex}, checkout, sbom, filepath.Join(dir, "out", "checkout.openvex.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vulns []string
	for _, a := range applied {
		vulns = append(vulns, a.Vulnerability+":"+a.Scope)
	}
	if !reflect.DeepEqual(vulns, []string{"CVE-2026-2:image", "GO-2026-6604:package", "GO-2026-6604:package", "CVE-2026-3:package", "CVE-2026-7:package"}) {
		t.Errorf("checkout: %v", vulns)
	}
	nothing := filepath.Join(dir, "out", "nothing.openvex.json")
	if applied, err = scopeStatements([]string{notes}, checkout, sbom, nothing); err != nil || applied != nil {
		t.Errorf("no statements for checkout: %v %v", applied, err)
	}
	if _, err := os.Stat(nothing); err == nil {
		t.Error("an empty document was written")
	}
}

// TestAttributeSuppressions: a finding grype left out is named with the
// statement that did it: by vulnerability name or alias, and package as
// grype matches purls; a VEX suppression that matches no statement passed
// is still listed, without one.
func TestAttributeSuppressions(t *testing.T) {
	applied := []Applied{
		{Document: "d", Vulnerability: "CVE-1", Product: "pkg:oci/x?repository_url=r/x", Status: "not_affected", Scope: ScopeImage, Packages: []string{"pkg:apk/wolfi/openssl"}, names: []string{"CVE-1"}},
		{Document: "d", Vulnerability: "GHSA-2", Product: "pkg:oci/x?repository_url=r/x", Status: "fixed", Scope: ScopeImage, Packages: []string{"pkg:apk/wolfi/a"}, names: []string{"GHSA-2", "CVE-2"}, anyPackage: true},
		{Document: "e", Vulnerability: "CVE-3", Product: "pkg:apk/wolfi/zlib@1.3", Status: "not_affected", Scope: ScopePackage, Packages: []string{"pkg:apk/wolfi/zlib@1.3"}, names: []string{"CVE-3"}},
	}
	for _, c := range []struct {
		ids  []string
		purl string
		want string // the statement's document and product, or ""
	}{
		{[]string{"CVE-1"}, "pkg:apk/wolfi/openssl@3.5-r0?arch=x86_64", "d pkg:oci/x?repository_url=r/x"},
		{[]string{"CVE-1"}, "pkg:apk/wolfi/curl@8", ""},
		{[]string{"GHSA-2", "CVE-2"}, "pkg:apk/wolfi/anything@1", "d pkg:oci/x?repository_url=r/x"},
		{[]string{"CVE-2"}, "pkg:apk/wolfi/anything@1", "d pkg:oci/x?repository_url=r/x"},
		{[]string{"CVE-3"}, "pkg:apk/wolfi/zlib@1.3?arch=aarch64", "e pkg:apk/wolfi/zlib@1.3"},
		{[]string{"CVE-3"}, "pkg:apk/wolfi/zlib@1.4", ""},
		{[]string{"CVE-9"}, "pkg:apk/wolfi/openssl@3", ""},
	} {
		s := attribute(applied, c.ids, Suppression{Vulnerability: c.ids[0], PURL: c.purl})
		if got := strings.TrimSpace(s.Document + " " + s.Product); got != c.want {
			t.Errorf("%v %s: %q, want %q", c.ids, c.purl, got, c.want)
		}
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

// TestGrypeRecordsSuppressions: what grype reports it left out for a VEX
// statement is recorded with the statement (metadata.vex.suppressed); what
// its own rules left out is not a VEX suppression.
func TestGrypeRecordsSuppressions(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	out := `{"matches":[],"ignoredMatches":[` +
		`{"vulnerability":{"id":"GHSA-x"},"relatedVulnerabilities":[{"id":"CVE-2025-15367"}],"artifact":{"name":"python-3.14","version":"3.14.0-r0","purl":"pkg:apk/wolfi/python-3.14@3.14.0-r0?arch=x86_64"},"appliedIgnoreRules":[{"namespace":"vex"}]},` +
		`{"vulnerability":{"id":"CVE-2026-0"},"artifact":{"name":"linux","version":"6"},"appliedIgnoreRules":[{"namespace":""}]}` +
		`],"descriptor":{"name":"grype","version":"0.120.1"}}`
	if err := os.WriteFile(filepath.Join(bin, "grype"), []byte("#!/bin/sh\ncat <<'J'\n"+out+"\nJ\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	sbom := writeVEX(t, dir, "sbom.cdx.json", `{"components":[{"purl":"pkg:apk/wolfi/python-3.14@3.14.0-r0?arch=x86_64"}]}`)
	vex := writeVEX(t, dir, "triage.openvex.json", strings.Replace(openvex, "%s",
		statement("CVE-2025-15367", `{"@id":"pkg:oci/catalog?repository_url=ghcr.io/acme/apps/catalog","subcomponents":[{"@id":"pkg:apk/wolfi/python-3.14"}]}`), 1))
	r, err := Grype(context.Background(), sbom, Image{Repository: "ghcr.io/acme/apps/catalog", Digests: []string{"sha256:c0"}}, []string{vex})
	if err != nil {
		t.Fatal(err)
	}
	want := []Suppression{{Vulnerability: "GHSA-x", Package: "python-3.14", Version: "3.14.0-r0", PURL: "pkg:apk/wolfi/python-3.14@3.14.0-r0?arch=x86_64",
		Document: "https://acme/vex/2026-10", Product: "pkg:oci/catalog?repository_url=ghcr.io/acme/apps/catalog", Status: "not_affected", Justification: "vulnerable_code_not_in_execute_path"}}
	if !reflect.DeepEqual(r.Suppressed, want) {
		t.Errorf("suppressed %+v", r.Suppressed)
	}
	b, _ := json.Marshal(r.Predicate())
	var pred struct {
		Metadata struct {
			VEX struct {
				Suppressed []Suppression `json:"suppressed"`
			} `json:"vex"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(b, &pred); err != nil || !reflect.DeepEqual(pred.Metadata.VEX.Suppressed, want) {
		t.Errorf("predicate: %v %s", err, b)
	}
}

// Malformed scoping must never become a statement about every package.
func TestVEXRejectsMalformedScopes(t *testing.T) {
	for _, product := range []string{
		`{"@id":"example.com/apps/catalog","subcomponents":{"@id":"pkg:apk/wolfi/glibc"}}`,
		`{"@id":"example.com/apps/catalog","subcomponents":"pkg:apk/wolfi/glibc"}`,
	} {
		dir := t.TempDir()
		sbom := writeVEX(t, dir, "sbom.json", `{"bomFormat":"CycloneDX","components":[{"purl":"pkg:apk/wolfi/glibc@1"},{"purl":"pkg:apk/wolfi/openssl@1"}]}`)
		f := writeVEX(t, dir, "bad.json", strings.Replace(openvex, "%s", statement("CVE-1", product), 1))
		if _, err := scopeStatements([]string{f}, Image{Repository: "example.com/apps/catalog"}, sbom, filepath.Join(dir, "out.json")); err == nil {
			t.Errorf("accepted malformed product %s", product)
		}
	}
	for _, body := range []string{
		`{"document":{"category":"csaf_vex"}}`,
		`{"@context":"https://openvex.dev/ns/v0.0.1","statements":[{"vulnerability":"CVE-1","products":["example.com/apps/catalog"],"subcomponents":{},"status":"not_affected"}]}`,
		strings.Replace(openvex, "%s", `{"products":["pkg:apk/wolfi/glibc"],"status":"not_affected"}`, 1),
		strings.Replace(openvex, "%s", `{"vulnerability":{"name":"CVE-1"},"products":["pkg:apk/wolfi/glibc"]}`, 1),
	} {
		dir := t.TempDir()
		sbom := writeVEX(t, dir, "sbom.json", `{"bomFormat":"CycloneDX","components":[{"purl":"pkg:apk/wolfi/glibc@1"},{"purl":"pkg:apk/wolfi/openssl@1"}]}`)
		f := writeVEX(t, dir, "bad.json", body)
		if _, err := scopeStatements([]string{f}, Image{Repository: "example.com/apps/catalog"}, sbom, filepath.Join(dir, "out.json")); err == nil {
			t.Errorf("accepted %s", body)
		}
	}
}

func TestVEXDoesNotKeepAlternatePackageIdentifiers(t *testing.T) {
	dir := t.TempDir()
	f := writeVEX(t, dir, "vex.json", strings.Replace(openvex, "%s", statement("CVE-1", `{"@id":"pkg:apk/wolfi/glibc","identifiers":{"purl":"pkg:apk/wolfi/openssl"},"subcomponents":[{"@id":"pkg:apk/wolfi/zlib"}]}`), 1))
	out := filepath.Join(dir, "out.json")
	if _, err := scopeStatements([]string{f}, Image{}, "unused", out); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "openssl") || strings.Contains(string(b), "zlib") {
		t.Fatalf("alternate identifiers escaped scoping: %s", b)
	}
}

func TestVEXPlatformDigestScope(t *testing.T) {
	dir := t.TempDir()
	f := writeVEX(t, dir, "vex.json", strings.Replace(openvex, "%s", statement("CVE-1", `{"@id":"pkg:oci/catalog@sha256%3Aamd64","subcomponents":[{"@id":"pkg:apk/wolfi/glibc"}]}`), 1))
	for _, platform := range []string{"amd64", "arm64"} {
		applied, err := scopeStatements([]string{f}, Image{Repository: "example.com/apps/catalog", Digests: []string{"sha256:index", "sha256:" + platform}}, "unused", filepath.Join(dir, platform+".json"))
		if err != nil {
			t.Fatal(err)
		}
		if (len(applied) > 0) != (platform == "amd64") {
			t.Errorf("%s: %+v", platform, applied)
		}
	}
}
