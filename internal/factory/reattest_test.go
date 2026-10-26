package factory

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/northcutted/clearcutt-factory/internal/attest"
	"github.com/northcutted/clearcutt-factory/internal/registry"
)

// fakeGrype is a grype on PATH that logs its arguments, keeps the last
// SBOM it scanned, and finds one fixed Critical; GRYPE_DB_FAILS makes
// "grype db update" fail.
const fakeGrype = `#!/bin/sh
echo "$*" >> "$0.log"
if [ "$1" = db ]; then
  [ -z "$GRYPE_DB_FAILS" ] || { echo "db update failed" >&2; exit 1; }
  exit 0
fi
cp "${1#sbom:}" "$0.sbom"
echo '{"matches":[{"vulnerability":{"id":"CVE-2026-111497","severity":"Critical","fix":{"state":"fixed"}},"artifact":{"name":"brotli","version":"1.2.0"}}],"descriptor":{"name":"grype","version":"0.120.1","db":{"built":"2026-10-26T01:00:00Z"}}}'
`

// TestReattest: a published image's verified SBOMs are scanned again and
// a new vulnerability report attached to each platform image, signed,
// naming the SBOM it read; no tag moves and nothing else is signed. With
// --older-than, a recent report is left alone. An image without the org's
// signature, or a platform without a verified SBOM, isn't rescanned; the
// result says whether a verified reproduction attestation exists.
func TestReattest(t *testing.T) {
	w := newPublishWorld(t)
	bin := t.TempDir()
	grype := filepath.Join(bin, "grype")
	if err := os.WriteFile(grype, []byte(fakeGrype), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	gho := filepath.Join(w.dir, "github-output")
	t.Setenv("GITHUB_OUTPUT", gho)

	// A repository with the image's manifest and its org profile.
	repoDir := filepath.Join(w.dir, "repo")
	for name, body := range map[string]string{
		"factory.org.yaml": "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\nregistry: " + w.host + "\n" +
			"signing: {mode: keyless, verify: {certificateIdentity: https://github.com/acme/images/.github/workflows/images.yml@refs/heads/main, certificateOIDCIssuer: " + ghIssuer + "}}\n" +
			"vulnerabilities: {scanner: grype, failOn: critical}\n",
		"tools/image.yaml": "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: Image\nmetadata: {name: tools, tags: ['1']}\nspec: {base: cgr.dev/chainguard/wolfi-base:latest}\n",
	} {
		p := filepath.Join(repoDir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Published as a build publishes it: signed, with its recipe, and each
	// platform's SBOM and a vulnerability report from October 1st.
	repo := w.host + "/tools"
	art, recipe, outputs := w.image(1, "tools ")
	sbomDoc := `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"name":"brotli","version":"1.2.0","purl":"pkg:apk/wolfi/brotli@1.2.0"}]}`
	for _, po := range outputs {
		if err := os.WriteFile(po.sbomPath, []byte(sbomDoc), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(po.vulnPath, []byte(`{"metadata":{"scanFinishedOn":"2026-10-01T00:00:00Z"}}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	image := repo + "@" + art.Digest
	w.cosign.children(image, art)
	if _, _, _, err := publish(w.ctx, w.opts, w.org, art, repo, []string{"1"}, attest.RecipePredicateType, recipe, outputs, false, false, nil); err != nil {
		t.Fatalf("publish: %v\n%s", err, w.out.String())
	}
	w.cosign.calls()

	opts := Options{ManifestPath: filepath.Join(repoDir, "tools/image.yaml"), Version: "test", Stdout: &w.out, Stderr: &w.out}
	out := filepath.Join(w.dir, "out")
	reattest := func(ro ReattestOptions) error {
		t.Helper()
		w.out.Reset()
		_ = os.Remove(gho)
		_ = os.Remove(grype + ".log")
		ro.OutDir = out
		return Reattest(w.ctx, opts, ro)
	}
	output := func() string { b, _ := os.ReadFile(gho); return string(b) }

	if err := reattest(ReattestOptions{OlderThan: 7 * 24 * time.Hour}); err != nil {
		t.Fatalf("reattest: %v\n%s", err, w.out.String())
	}
	var want []string
	for _, po := range outputs {
		want = append(want, "attest vuln "+repo+"@"+po.digest)
	}
	if got := w.cosign.calls(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("cosign calls:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if w.tag("tools", "1") != art.Digest {
		t.Error("the tag moved")
	}
	if log, _ := os.ReadFile(grype + ".log"); !strings.HasPrefix(string(log), "db update\n") || strings.Count(string(log), "sbom:") != len(outputs) {
		t.Errorf("grype ran:\n%s", log)
	}
	if b, _ := os.ReadFile(grype + ".sbom"); string(b) != sbomDoc {
		t.Errorf("grype scanned %s, not the attested SBOM", b)
	}
	if got := output(); got != "image="+image+"\nrescanned=2\nreproduced=false\n" {
		t.Errorf("GITHUB_OUTPUT %q", got)
	}
	// The new report names the SBOM attestation it scanned, and finds the
	// Critical; the gate's verdict is reported, not an error.
	b, err := os.ReadFile(filepath.Join(out, "tools-reattest", "attestations", "vuln-linux-amd64.predicate.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pred struct {
		Scanner  struct{ Version string }
		Metadata struct {
			ScanFinishedOn string
			Rescan         struct {
				SBOM struct {
					PredicateType string
					Digest        map[string]string
				}
			}
		}
	}
	if err := json.Unmarshal(b, &pred); err != nil || pred.Metadata.Rescan.SBOM.PredicateType != attest.CycloneDXType || len(pred.Metadata.Rescan.SBOM.Digest["sha256"]) != 64 || pred.Scanner.Version != "0.120.1" {
		t.Errorf("new report: %v\n%s", err, b)
	}
	if !strings.Contains(w.out.String(), "the vulnerability gate (failOn: critical) would block") || !strings.Contains(w.out.String(), "Critical CVE-2026-111497 in brotli 1.2.0") {
		t.Errorf("gate not reported:\n%s", w.out.String())
	}
	var res ReattestResult
	if b, err := os.ReadFile(filepath.Join(out, "tools-reattest", "reattest.json")); err != nil || json.Unmarshal(b, &res) != nil || res.Image != image || !res.Platforms["linux/arm64"].Attached || len(res.Blocked) != 2 {
		t.Errorf("reattest.json: %v %+v", err, res)
	}

	// The reports are new now: --older-than leaves them, and grype isn't
	// run; without it, every platform is rescanned.
	if err := reattest(ReattestOptions{OlderThan: 7 * 24 * time.Hour}); err != nil {
		t.Fatalf("second reattest: %v\n%s", err, w.out.String())
	}
	if got := w.cosign.calls(); len(got) != 0 || !strings.Contains(w.out.String(), "not rescanned") || output() != "image="+image+"\nrescanned=0\nreproduced=false\n" {
		t.Errorf("recent reports rescanned: %v\n%s", got, w.out.String())
	}
	if _, err := os.Stat(grype + ".log"); err == nil {
		t.Error("grype ran with nothing to rescan")
	}

	// A verified reproduction attestation: reproduced=true. By --image.
	if err := (attest.Cosign{Mode: "keyless"}).Attest(w.ctx, image, attest.ReproductionPredicateType, recipe); err != nil {
		t.Fatal(err)
	}
	w.cosign.calls()
	opts.OrgPath = filepath.Join(repoDir, "factory.org.yaml")
	if err := reattest(ReattestOptions{Image: repo + ":1"}); err != nil {
		t.Fatalf("reattest --image: %v\n%s", err, w.out.String())
	}
	if got := output(); got != "image="+image+"\nrescanned=2\nreproduced=true\n" {
		t.Errorf("GITHUB_OUTPUT %q", got)
	}
	w.cosign.calls()

	// grype's database can't be updated: no stale scan is attached.
	t.Setenv("GRYPE_DB_FAILS", "1")
	if err := reattest(ReattestOptions{Image: image}); err == nil || !strings.Contains(err.Error(), "grype db update") {
		t.Errorf("db update failing: %v", err)
	}
	if got := w.cosign.calls(); len(got) != 0 {
		t.Errorf("attached with a stale database: %v", got)
	}
	t.Setenv("GRYPE_DB_FAILS", "")

	// A platform without a verified SBOM isn't rescanned; the others are,
	// and the run fails naming it.
	plats, _ := art.Platforms()
	state, _ := os.ReadFile(w.cosign.path + ".state")
	if err := os.WriteFile(w.cosign.path+".state", []byte(strings.ReplaceAll(string(state), "att cyclonedx "+repo+"@"+plats[0].Digest+"\n", "")), 0o644); err != nil {
		t.Fatal(err)
	}
	err = reattest(ReattestOptions{Image: image})
	if err == nil || !strings.Contains(err.Error(), plats[0].Platform+" ("+plats[0].Digest+"): no SBOM attestation the org's image signer made") {
		t.Errorf("missing SBOM: %v\n%s", err, w.out.String())
	}
	if got := w.cosign.calls(); strings.Join(got, "\n") != "attest vuln "+repo+"@"+plats[1].Digest {
		t.Errorf("missing SBOM: cosign calls %v", got)
	}

	// An image the org's signer didn't sign: refused, nothing attached.
	other, _, _ := w.image(2, "unsigned ")
	if _, err := registry.Push(w.ctx, other, w.host+"/unsigned", []string{"1"}); err != nil {
		t.Fatal(err)
	}
	if err := reattest(ReattestOptions{Image: w.host + "/unsigned:1"}); err == nil || !strings.Contains(err.Error(), "is not signed by the org's image signer") {
		t.Errorf("unsigned: %v", err)
	}
	if got := w.cosign.calls(); len(got) != 0 {
		t.Errorf("unsigned: cosign calls %v", got)
	}
	if err := reattest(ReattestOptions{Image: w.host + "/nowhere:1"}); err == nil || !strings.Contains(err.Error(), "has it been published?") {
		t.Errorf("unpublished: %v", err)
	}
}

// TestParseAge: days or Go durations.
func TestParseAge(t *testing.T) {
	for in, want := range map[string]time.Duration{"7d": 7 * 24 * time.Hour, "0d": 0, "36h": 36 * time.Hour, "90m": 90 * time.Minute} {
		if got, err := ParseAge(in); err != nil || got != want {
			t.Errorf("%s: %v %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "d", "7", "-1d", "1.5d", "7days", "-3h", "x"} {
		if got, err := ParseAge(bad); err == nil {
			t.Errorf("%q: %v", bad, got)
		}
	}
}
