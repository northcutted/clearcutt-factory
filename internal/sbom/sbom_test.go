package sbom

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/northcutted/declarative-image-factory/internal/lock"
	"github.com/northcutted/declarative-image-factory/internal/manifest"
)

func testLock() *lock.Lock {
	return &lock.Lock{
		SourceDateEpoch: 1700000000,
		Base:            lock.Image{Ref: "cgr.dev/chainguard/wolfi-base:latest", Digest: "sha256:b"},
		Packages: lock.Packages{
			Repositories: []string{"https://apk.cgr.dev/chainguard"},
			Platforms: map[string][]lock.Package{"linux/arm64": {
				{Name: "jq", Version: "1.8.2-r2", Arch: "aarch64", License: "MIT", Checksum: "Q1x="},
			}},
		},
		Tools: []lock.Tool{
			{Name: "gh", From: "github-release", Repo: "cli/cli", Version: "2.1.0", Verification: lock.VerifiedChecksumFile,
				Artifacts: map[string]lock.Artifact{"linux/arm64": {URL: "https://github.com/cli/cli/releases/download/v2.1.0/gh.tgz", SHA256: "abc"}}},
			{Name: "kubectl", From: "url", Version: "1.37.1", Verification: lock.VerifiedPinned,
				Artifacts: map[string]lock.Artifact{"linux/arm64": {URL: "https://dl.k8s.io/kubectl", SHA256: "def"}}},
			{Name: "yq", From: "go", Package: "github.com/mikefarah/yq/v4", Version: "v4.54.1", Verification: lock.VerifiedGoSumDB},
		},
	}
}

func TestDeclared(t *testing.T) {
	m := &manifest.Manifest{Metadata: manifest.Metadata{Ref: "registry.example/demo"}}
	b := Declared(m, testLock(), "linux/arm64", "sha256:img", "v1")
	purls := map[string]bool{}
	for _, c := range b.Components {
		purls[c.PURL] = true
	}
	for _, want := range []string{
		"pkg:apk/chainguard/jq@1.8.2-r2?arch=aarch64",
		"pkg:github/cli/cli@v2.1.0",
		"pkg:generic/kubectl@1.37.1?download_url=https%3A%2F%2Fdl.k8s.io%2Fkubectl",
		"pkg:golang/github.com/mikefarah/yq/v4@v4.54.1",
		"pkg:oci/wolfi-base@sha256:b?arch=arm64&repository_url=cgr.dev%2Fchainguard%2Fwolfi-base",
	} {
		if !purls[want] {
			t.Errorf("missing purl %s in %v", want, purls)
		}
	}
	if b.Metadata.Timestamp != "2023-11-14T22:13:20Z" {
		t.Errorf("timestamp should come from SOURCE_DATE_EPOCH, got %s", b.Metadata.Timestamp)
	}
}

func TestMerge(t *testing.T) {
	m := &manifest.Manifest{Metadata: manifest.Metadata{Ref: "registry.example/demo"}}
	declared := Declared(m, testLock(), "linux/arm64", "sha256:img", "v1")
	scanned := `{"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"urn:uuid:1","components":[
	  {"type":"library","name":"jq","version":"1.8.2-r2","purl":"pkg:apk/wolfi/jq@1.8.2-r2?arch=aarch64&distro=wolfi"},
	  {"type":"library","name":"github.com/mikefarah/yq/v4","version":"v4.54.1","purl":"pkg:golang/github.com/mikefarah/yq/v4@v4.54.1"},
	  {"type":"file","name":"/etc/passwd"}
	],"dependencies":[{"ref":"x"}]}`
	// A declared component without a purl must not match scanned files.
	declared.Components = append(declared.Components, Component{Type: "application", Name: "app"})
	out, err := Merge([]byte(scanned), declared)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		SerialNumber string            `json:"serialNumber"`
		Components   []json.RawMessage `json:"components"`
		Dependencies []json.RawMessage `json:"dependencies"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	// scanned jq, yq, and the file are kept; base, gh, kubectl, and app are added.
	if len(doc.Components) != 7 || doc.SerialNumber != "urn:uuid:1" || len(doc.Dependencies) != 1 {
		t.Errorf("unexpected merge (%d components):\n%s", len(doc.Components), out)
	}
	if strings.Count(string(out), `"name": "jq"`) != 1 {
		t.Error("jq should not be duplicated")
	}
}
