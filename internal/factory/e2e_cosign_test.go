package factory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/northcutted/clearcutt-factory/internal/attest"
	"github.com/northcutted/clearcutt-factory/internal/lock"
	"github.com/northcutted/clearcutt-factory/internal/manifest"
	"github.com/northcutted/clearcutt-factory/internal/registry"
	"github.com/northcutted/clearcutt-factory/internal/sbom"
	"github.com/northcutted/clearcutt-factory/internal/scan"
)

// TestEndToEndCosign publishes a small two-platform image through publish,
// with the real cosign signing by a key (no transparency log), then checks
// with cosign itself, not factory's code, that the index and each platform
// image are signed, that the recipe and each platform's SBOM and
// vulnerability report are attached, and that latest names the signed
// digest. A second image's publish fails partway (cosign can't attach its
// vulnerability reports), which must leave latest where it was; the next
// run attaches only what is missing, and then moves it. So a change in
// cosign's formats or registry layout can't pass unnoticed: every check
// that decides "already published" runs against real bundles.
//
// It runs with CLEARCUTT_FACTORY_COSIGN_E2E=1 and cosign on PATH, against
// the registry in CLEARCUTT_FACTORY_E2E_REGISTRY (host:port, plain HTTP),
// or one in this process.
func TestEndToEndCosign(t *testing.T) {
	if os.Getenv("CLEARCUTT_FACTORY_COSIGN_E2E") == "" {
		t.Skip("set CLEARCUTT_FACTORY_COSIGN_E2E=1 to run (needs cosign)")
	}
	real, err := exec.LookPath("cosign")
	if err != nil {
		t.Fatal("cosign is not on PATH")
	}
	host := os.Getenv("CLEARCUTT_FACTORY_E2E_REGISTRY")
	if host == "" {
		srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0))))
		t.Cleanup(srv.Close)
		host = strings.TrimPrefix(srv.URL, "http://")
	}
	ctx := context.Background()
	dir := t.TempDir()
	cosign := func(args ...string) ([]byte, error) {
		t.Helper()
		cmd := exec.CommandContext(ctx, real, args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "COSIGN_PASSWORD=")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			return out, fmt.Errorf("cosign %s: %w\n%s", strings.Join(args, " "), err, stderr.String())
		}
		return out, nil
	}
	if _, err := cosign("generate-key-pair"); err != nil {
		t.Fatal(err)
	}
	// A signing config with no services: no Rekor, no timestamp authority
	// (docs/adopting.md, signing without a transparency log).
	if _, err := cosign("signing-config", "create", "--out", "no-tlog.json"); err != nil {
		t.Fatal(err)
	}
	key, pub, signingConfig := filepath.Join(dir, "cosign.key"), filepath.Join(dir, "cosign.pub"), filepath.Join(dir, "no-tlog.json")
	no := false
	org := manifest.DefaultOrg()
	org.Signing = manifest.Signing{Mode: "key", Key: key, Args: []string{"--signing-config", signingConfig},
		Verify: manifest.VerifyIdentity{Key: pub, Tlog: &no}}
	t.Setenv("COSIGN_PASSWORD", "")

	// A wrapper that fails the commands listed in its .fail file and logs
	// the rest before running the real cosign.
	wrapDir := t.TempDir()
	wrapper := filepath.Join(wrapDir, "cosign")
	if err := os.WriteFile(wrapper, []byte(`#!/bin/sh
printf '%s\n' "$*" >> "$0.log"
if [ -f "$0.fail" ] && [ "$1 $2 $3" = "$(cat "$0.fail")" ]; then echo "cosign wrapper: failing $1 $2 $3" >&2; exit 1; fi
exec "`+real+`" "$@"
`), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", wrapDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	calls := func() []string {
		b, _ := os.ReadFile(wrapper + ".log")
		_ = os.Remove(wrapper + ".log")
		var out []string
		for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			if f := strings.Fields(l); len(f) > 0 && (f[0] == "sign" || f[0] == "attest") {
				if f[0] == "attest" && f[2] == attest.VulnType {
					f[2] = "vuln"
				}
				out = append(out, strings.Join(f[:3], " "))
			}
		}
		return out
	}

	var out bytes.Buffer
	opts := Options{Version: "test", Stdout: &out, Stderr: &out}
	repo := host + "/e2e/cosign"
	image := func(day int, content string) (*registry.Artifact, string, []platformOutputs) {
		t.Helper()
		created := time.Date(2026, 10, day, 0, 0, 0, 0, time.UTC)
		idx := testIndex(t, func(string) v1.Image {
			img, err := mutate.CreatedAt(mutate.ConfigMediaType(mutate.MediaType(empty.Image, types.OCIManifestSchema1), types.OCIConfigJSON), v1.Time{Time: created})
			if err != nil {
				t.Fatal(err)
			}
			return img
		}, func(arch string) []v1.Layer {
			return []v1.Layer{testLayer(t, map[string]string{"etc/e2e": content + arch})}
		}, nil)
		d, _ := idx.Digest()
		art := &registry.Artifact{Digest: d.String(), Index: idx}
		work := filepath.Join(dir, content)
		recipe := filepath.Join(work, "recipe.predicate.json")
		if err := attest.WriteJSON(recipe, attest.Recipe{Factory: attest.FactoryInfo{Version: "test"}, Containerfile: "FROM scratch\n", Image: attest.ImageDigests{Ref: repo, Digest: art.Digest}}); err != nil {
			t.Fatal(err)
		}
		plats, err := art.Platforms()
		if err != nil {
			t.Fatal(err)
		}
		var outputs []platformOutputs
		for _, p := range plats {
			slug := strings.ReplaceAll(p.Platform, "/", "-")
			po := platformOutputs{platform: p.Platform, digest: p.Digest,
				sbomPath: filepath.Join(work, "sbom-"+slug+".cdx.json"), vulnPath: filepath.Join(work, "vuln-"+slug+".predicate.json")}
			bom := sbom.Rebased(repo, p.Platform, p.Digest, created, lock.Image{Ref: "registry.example/base", Digest: p.Digest}, lock.Image{Ref: repo, Digest: p.Digest}, "test")
			if err := attest.WriteJSON(po.sbomPath, bom); err != nil {
				t.Fatal(err)
			}
			report := &scan.Report{Raw: json.RawMessage(`{"matches": [], "descriptor": {"name": "grype", "version": "0.100.0"}}`), Started: created, Finished: created}
			if err := attest.WriteJSON(po.vulnPath, report.Predicate()); err != nil {
				t.Fatal(err)
			}
			outputs = append(outputs, po)
		}
		return art, recipe, outputs
	}
	publishNow := func(art *registry.Artifact, recipe string, outputs []platformOutputs) error {
		t.Helper()
		out.Reset()
		_, _, _, err := publish(ctx, opts, org, art, repo, []string{"latest"}, attest.RecipePredicateType, recipe, outputs, false, false, nil)
		return err
	}
	// verified checks with cosign alone what art carries.
	verified := func(art *registry.Artifact, outputs []platformOutputs) {
		t.Helper()
		keyArgs := []string{"--key", pub, "--insecure-ignore-tlog=true"}
		ref := repo + "@" + art.Digest
		check := func(args ...string) {
			t.Helper()
			if _, err := cosign(append(append(args[:1:1], keyArgs...), args[1:]...)...); err != nil {
				t.Error(err)
			}
		}
		check("verify", ref)
		check("verify-attestation", "--type", attest.RecipePredicateType, ref)
		for _, po := range outputs {
			pref := repo + "@" + po.digest
			check("verify", pref)
			check("verify-attestation", "--type", "cyclonedx", pref)
			check("verify-attestation", "--type", "vuln", pref)
		}
		if got, err := registry.Lookup(ctx, repo+":latest"); err != nil || got != art.Digest {
			t.Errorf("latest is %s (%v), want the signed %s", got, err, art.Digest)
		}
	}

	first, firstRecipe, firstOut := image(1, "first")
	if err := publishNow(first, firstRecipe, firstOut); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if got := calls(); len(got) != 2+2*len(firstOut) {
		t.Errorf("first publish ran %q", got)
	}
	verified(first, firstOut)
	if p := inspectPublication(ctx, org, repo+"@"+first.Digest, repo, attest.RecipePredicateType, "", expected(firstOut)); !p.complete(expected(firstOut)) {
		t.Errorf("factory doesn't see the first image as published: %+v", p)
	}

	// Unchanged: nothing is signed or attested again.
	if err := publishNow(first, firstRecipe, firstOut); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if got := calls(); len(got) != 0 || !strings.Contains(out.String(), "already published, signed, and attested") {
		t.Errorf("republishing ran %q\n%s", got, out.String())
	}

	// cosign fails at the vulnerability reports: latest stays.
	second, secondRecipe, secondOut := image(2, "second")
	if err := os.WriteFile(wrapper+".fail", []byte("attest --type "+attest.VulnType), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := publishNow(second, secondRecipe, secondOut); err == nil {
		t.Fatalf("publish succeeded with cosign failing\n%s", out.String())
	}
	if got, _ := registry.Lookup(ctx, repo+":latest"); got != first.Digest {
		t.Fatalf("latest moved to %s while the image lacked its vulnerability reports", got)
	}
	_ = calls()

	// The next run attaches only the vulnerability reports, then tags.
	_ = os.Remove(wrapper + ".fail")
	if err := publishNow(second, secondRecipe, secondOut); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	var want []string
	for range secondOut {
		want = append(want, "attest --type vuln")
	}
	if got := calls(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("healing run ran %q, want %q\n%s", got, want, out.String())
	}
	verified(second, secondOut)

	// reattest reads each platform's SBOM back through cosign, scans it
	// (with a stand-in grype: this checks cosign's side), and attaches a
	// second vulnerability report beside the first; latest stays. The
	// next run with --older-than finds the new report among the two
	// cosign returns, and leaves it.
	grypeDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(grypeDir, "grype"), []byte(fakeGrype), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", grypeDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GITHUB_OUTPUT", "")
	orgPath := filepath.Join(dir, "factory.org.yaml")
	if err := os.WriteFile(orgPath, []byte("apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\n"+
		"signing: {mode: key, key: "+key+", args: [--signing-config, "+signingConfig+"], verify: {key: "+pub+", tlog: false}}\n"+
		"vulnerabilities: {scanner: grype, vex: [vex.json]}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vex.json"), []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.test/vex","statements":[{"vulnerability":{"name":"CVE-2026-111497"},"products":[{"@id":"pkg:apk/wolfi/brotli"}],"status":"not_affected","justification":"component_not_present"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	reattestOpts := Options{OrgPath: orgPath, Version: "test", Stdout: &out, Stderr: &out}
	out.Reset()
	if err := Reattest(ctx, reattestOpts, ReattestOptions{Image: repo + ":latest", OlderThan: 7 * 24 * time.Hour, OutDir: filepath.Join(dir, "out")}); err != nil {
		t.Fatalf("reattest: %v\n%s", err, out.String())
	}
	if got := calls(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("reattest ran %q, want %q\n%s", got, want, out.String())
	}
	var scanned, attested any
	b, _ := os.ReadFile(filepath.Join(grypeDir, "grype.sbom"))
	a, _ := os.ReadFile(secondOut[len(secondOut)-1].sbomPath)
	if json.Unmarshal(b, &scanned) != nil || json.Unmarshal(a, &attested) != nil || fmt.Sprint(scanned) != fmt.Sprint(attested) {
		t.Errorf("grype scanned\n%s\nnot the attested SBOM\n%s", b, a)
	}
	for _, po := range secondOut {
		got, err := cosign("verify-attestation", "--key", pub, "--insecure-ignore-tlog=true", "--type", "vuln", repo+"@"+po.digest)
		if err != nil {
			t.Fatal(err)
		}
		all, err := attest.VerifyPredicates(ctx, repo+"@"+po.digest, attest.VulnType, []string{"--key", pub, "--insecure-ignore-tlog=true"})
		if err != nil {
			t.Fatal(err)
		}
		preserved := false
		for _, a := range all {
			var pred struct {
				Metadata struct {
					Rescan struct {
						SBOM struct {
							PredicateType string            `json:"predicateType"`
							Digest        map[string]string `json:"digest"`
						} `json:"sbom"`
					} `json:"rescan"`
					VEX struct {
						Statements []scan.Applied `json:"statements"`
					} `json:"vex"`
				} `json:"metadata"`
			}
			if json.Unmarshal(a.Predicate, &pred) == nil && pred.Metadata.Rescan.SBOM.PredicateType == attest.CycloneDXType && len(pred.Metadata.Rescan.SBOM.Digest["sha256"]) == 64 && len(pred.Metadata.VEX.Statements) == 1 && pred.Metadata.VEX.Statements[0].Product == "pkg:apk/wolfi/brotli" {
				preserved = true
			}
		}
		if !preserved {
			t.Error("cosign lost rescan SBOM identity or VEX metadata")
		}
		if n := strings.Count(strings.TrimSpace(string(got)), "\n") + 1; n != 2 {
			t.Errorf("%s carries %d vulnerability reports, want the build's and the rescan's", po.platform, n)
		}
	}
	if got, _ := registry.Lookup(ctx, repo+":latest"); got != second.Digest {
		t.Errorf("reattest moved latest to %s", got)
	}
	out.Reset()
	if err := Reattest(ctx, reattestOpts, ReattestOptions{Image: repo + ":latest", OlderThan: 7 * 24 * time.Hour, OutDir: filepath.Join(dir, "out")}); err != nil {
		t.Fatalf("second reattest: %v\n%s", err, out.String())
	}
	if got := calls(); len(got) != 0 || strings.Count(out.String(), "not rescanned") != len(secondOut) {
		t.Errorf("second reattest ran %q\n%s", got, out.String())
	}
	// A real signature or SBOM from a different key must not authorize a
	// rescan. Stub cosign tests cannot establish this identity boundary.
	if _, err := cosign("generate-key-pair", "--output-key-prefix", "other"); err != nil {
		t.Fatal(err)
	}
	originalOrg, err := os.ReadFile(orgPath)
	if err != nil {
		t.Fatal(err)
	}
	otherPub := filepath.Join(dir, "other.pub")
	if err := os.WriteFile(orgPath, []byte(strings.Replace(string(originalOrg), pub, otherPub, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := Reattest(ctx, reattestOpts, ReattestOptions{Image: repo + ":latest", OutDir: filepath.Join(dir, "wrong-key")}); err == nil || !strings.Contains(err.Error(), "is not signed by the org's image signer") {
		t.Fatalf("wrong image key accepted: %v", err)
	}
	if err := os.WriteFile(orgPath, originalOrg, 0o644); err != nil {
		t.Fatal(err)
	}
	bad, _, badOutputs := image(3, "wrong SBOM signer")
	badRepo := host + "/e2e/wrong-sbom"
	if _, err := registry.Push(ctx, bad, badRepo, []string{"latest"}); err != nil {
		t.Fatal(err)
	}
	signer := attest.Cosign{Mode: "key", Key: key, Args: []string{"--signing-config", signingConfig}, Stdout: &out, Stderr: &out}
	if err := signer.Sign(ctx, badRepo+"@"+bad.Digest); err != nil {
		t.Fatal(err)
	}
	signer.Key = filepath.Join(dir, "other.key")
	for _, po := range badOutputs {
		if err := signer.Attest(ctx, badRepo+"@"+po.digest, "cyclonedx", po.sbomPath); err != nil {
			t.Fatal(err)
		}
	}
	calls()
	out.Reset()
	if err := Reattest(ctx, reattestOpts, ReattestOptions{Image: badRepo + ":latest", OutDir: filepath.Join(dir, "wrong-sbom")}); err == nil || !strings.Contains(err.Error(), "no SBOM attestation the org's image signer made") {
		t.Fatalf("wrong SBOM key accepted: %v", err)
	}
	if got := calls(); len(got) != 0 || strings.Contains(out.String(), "updating grype") {
		t.Fatalf("untrusted SBOM scanned or attested: %v\n%s", got, out.String())
	}

}
