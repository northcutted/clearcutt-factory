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
	if err := os.WriteFile(wrapper+".fail", []byte("attest --type vuln"), 0o644); err != nil {
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
}
