package factory

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http/httptest"
	"os"
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
	"github.com/northcutted/clearcutt-factory/internal/manifest"
	"github.com/northcutted/clearcutt-factory/internal/rebase"
	"github.com/northcutted/clearcutt-factory/internal/registry"
)

// stateCosign is a cosign on PATH that keeps what it signs and attests (and
// each predicate) in files, verifies only that, and fails the commands
// listed in its .fail file: "sign", or "attest TYPE" (TYPE as given to
// --type). sign --recursive also signs the children an index has in its
// .children file.
type stateCosign struct {
	t    *testing.T
	path string
}

const stateCosignScript = `#!/bin/sh
printf '%s\n' "$*" >> "$0.log"
ref=
for a; do case "$a" in *@sha256:*) ref=$a ;; esac; done
key() { printf '%s %s' "$1" "$2" | cksum | cut -d' ' -f1; }
failing() { [ -f "$0.fail" ] && grep -qxF -- "$1" "$0.fail"; }
case "$1" in
sign)
  if failing sign; then echo "fake cosign: signing failed" >&2; exit 1; fi
  echo "sig $ref" >> "$0.state"
  if [ -f "$0.children" ]; then grep "^$ref " "$0.children" | while read -r _ child; do echo "sig $child" >> "$0.state"; done; fi
  ;;
attest)
  if failing "attest $3"; then echo "fake cosign: attesting $3 failed" >&2; exit 1; fi
  echo "att $3 $ref" >> "$0.state"
  mkdir -p "$0.d" && cp "$5" "$0.d/$(key "$3" "$ref")"
  ;;
verify)
  grep -qxF -- "sig $ref" "$0.state" 2>/dev/null || { echo "no signatures found" >&2; exit 1; }
  ;;
verify-attestation)
  t=$3
  case "$t" in https://cyclonedx.org/bom) t=cyclonedx ;; https://cosign.sigstore.dev/attestation/vuln/v1) t=vuln ;; esac
  if failing "verify-attestation $t"; then echo "untrusted attestation identity" >&2; exit 1; fi
  grep -qxF -- "att $t $ref" "$0.state" 2>/dev/null || { echo "no matching attestations" >&2; exit 1; }
  pred='{}'
  if [ -f "$0.d/$(key "$t" "$ref")" ]; then pred=$(cat "$0.d/$(key "$t" "$ref")"); fi
  if [ "$t" = vuln ] && [ -n "$RETURN_OLD_VULN" ]; then pred='{"metadata":{"scanFinishedOn":"2026-10-01T00:00:00Z"}}'; fi
  printf '{"payload":"%s"}\n'  "$(printf '{"predicateType":"%s","predicate":%s}' "$3" "$pred" | base64 | tr -d '\n')"
  ;;
esac
`

func newStateCosign(t *testing.T) *stateCosign {
	t.Helper()
	dir := t.TempDir()
	c := &stateCosign{t: t, path: filepath.Join(dir, "cosign")}
	if err := os.WriteFile(c.path, []byte(stateCosignScript), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return c
}

func (c *stateCosign) file(ext, body string) {
	c.t.Helper()
	if err := os.WriteFile(c.path+ext, []byte(body), 0o644); err != nil {
		c.t.Fatal(err)
	}
}

// fail makes the commands named fail ("sign", "attest vuln"), and no other.
func (c *stateCosign) fail(cmds ...string) { c.file(".fail", strings.Join(append(cmds, ""), "\n")) }

// children registers the platform images sign --recursive signs with ref.
func (c *stateCosign) children(ref string, art *registry.Artifact) {
	c.t.Helper()
	plats, err := art.Platforms()
	if err != nil {
		c.t.Fatal(err)
	}
	f, err := os.OpenFile(c.path+".children", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		c.t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	for _, p := range plats {
		_, _ = f.WriteString(ref + " " + strings.SplitN(ref, "@", 2)[0] + "@" + p.Digest + "\n")
	}
}

// calls returns the sign and attest commands run since the last call, as
// "sign REF" and "attest TYPE REF".
func (c *stateCosign) calls() []string {
	c.t.Helper()
	b, _ := os.ReadFile(c.path + ".log")
	_ = os.Remove(c.path + ".log")
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		f := strings.Fields(line)
		ref := ""
		for _, a := range f {
			if strings.Contains(a, "@sha256:") {
				ref = a
			}
		}
		switch {
		case len(f) > 0 && f[0] == "sign":
			out = append(out, "sign "+ref)
		case len(f) > 2 && f[0] == "attest":
			out = append(out, "attest "+f[2]+" "+ref)
		}
	}
	return out
}

// publishWorld is a registry, a cosign, and an org that signs keylessly
// and checks what it published against a signer.
type publishWorld struct {
	t      *testing.T
	ctx    context.Context
	host   string
	cosign *stateCosign
	org    *manifest.Org
	out    bytes.Buffer
	opts   Options
	dir    string
}

func newPublishWorld(t *testing.T) *publishWorld {
	t.Helper()
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(srv.Close)
	w := &publishWorld{t: t, ctx: context.Background(), host: strings.TrimPrefix(srv.URL, "http://"), cosign: newStateCosign(t), dir: t.TempDir()}
	w.org = manifest.DefaultOrg()
	w.org.Signing.Verify = manifest.VerifyIdentity{CertificateIdentity: "https://github.com/acme/images/.github/workflows/images.yml@refs/heads/main", CertificateOIDCIssuer: ghIssuer}
	w.opts = Options{Stdout: &w.out, Stderr: &w.out}
	return w
}

// image is an amd64+arm64 index, created on day (October 2026), with its
// recipe, SBOM, and vulnerability report written.
func (w *publishWorld) image(day int, content string) (*registry.Artifact, string, []platformOutputs) {
	w.t.Helper()
	created := time.Date(2026, 10, day, 0, 0, 0, 0, time.UTC)
	idx := testIndex(w.t, func(string) v1.Image {
		img, err := mutate.CreatedAt(mutate.ConfigMediaType(mutate.MediaType(empty.Image, types.OCIManifestSchema1), types.OCIConfigJSON), v1.Time{Time: created})
		if err != nil {
			w.t.Fatal(err)
		}
		return img
	}, func(arch string) []v1.Layer {
		return []v1.Layer{testLayer(w.t, map[string]string{"usr/bin/tool": content + arch})}
	}, nil)
	d, _ := idx.Digest()
	art := &registry.Artifact{Digest: d.String(), Index: idx}
	recipe, outputs := w.files(art, content)
	return art, recipe, outputs
}

// files writes the predicate and per-platform attestations of art.
func (w *publishWorld) files(art *registry.Artifact, name string) (string, []platformOutputs) {
	w.t.Helper()
	dir := filepath.Join(w.dir, name)
	recipe := filepath.Join(dir, "recipe.predicate.json")
	if err := attest.WriteJSON(recipe, map[string]string{"image": art.Digest}); err != nil {
		w.t.Fatal(err)
	}
	plats, err := art.Platforms()
	if err != nil {
		w.t.Fatal(err)
	}
	var outputs []platformOutputs
	for _, p := range plats {
		slug := strings.ReplaceAll(p.Platform, "/", "-")
		po := platformOutputs{platform: p.Platform, digest: p.Digest,
			sbomPath: filepath.Join(dir, "sbom-"+slug+".cdx.json"), vulnPath: filepath.Join(dir, "vuln-"+slug+".json")}
		for _, f := range []string{po.sbomPath, po.vulnPath} {
			if err := attest.WriteJSON(f, map[string]string{}); err != nil {
				w.t.Fatal(err)
			}
		}
		outputs = append(outputs, po)
	}
	return recipe, outputs
}

func (w *publishWorld) tag(repo, tag string) string {
	w.t.Helper()
	d, err := registry.Lookup(w.ctx, w.host+"/"+repo+":"+tag)
	if err != nil {
		w.t.Fatal(err)
	}
	return d
}

// TestPublishSignsBeforeTagging: an image is pushed by digest, signed, and
// attested before any tag moves, so a cosign failure leaves the tags where
// they were; the next run adds only what is missing and then moves them;
// and a run of an older job never takes a tag back (#3).
func TestPublishSignsBeforeTagging(t *testing.T) {
	w := newPublishWorld(t)
	repo := w.host + "/tools"
	pub := func(art *registry.Artifact, recipe string, outputs []platformOutputs, tags ...string) (bool, error) {
		t.Helper()
		ref := repo + "@" + art.Digest
		w.cosign.children(ref, art)
		_, published, _, err := publish(w.ctx, w.opts, w.org, art, repo, tags, attest.RecipePredicateType, recipe, outputs, false, false, nil)
		return published, err
	}

	v1art, v1recipe, v1out := w.image(1, "v1 ")
	if published, err := pub(v1art, v1recipe, v1out, "latest"); err != nil || !published {
		t.Fatalf("first publish: %v, %v\n%s", published, err, w.out.String())
	}
	if w.tag("tools", "latest") != v1art.Digest {
		t.Fatal("latest did not move to the first image")
	}
	ref := repo + "@" + v1art.Digest
	want := []string{"sign " + ref, "attest " + attest.RecipePredicateType + " " + ref}
	for _, po := range v1out {
		want = append(want, "attest cyclonedx "+repo+"@"+po.digest)
	}
	for _, po := range v1out {
		want = append(want, "attest vuln "+repo+"@"+po.digest)
	}
	if got := w.cosign.calls(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("cosign calls:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	// cosign fails at signing, then at the second vulnerability report:
	// the image is in the registry by digest, and latest stays.
	v2art, v2recipe, v2out := w.image(8, "v2 ")
	for _, failing := range []string{"sign", "attest vuln"} {
		w.cosign.fail(failing)
		w.out.Reset()
		if _, err := pub(v2art, v2recipe, v2out, "latest"); err == nil {
			t.Fatalf("%s failing: published\n%s", failing, w.out.String())
		}
		if got := w.tag("tools", "latest"); got != v1art.Digest {
			t.Fatalf("%s failing: latest moved to %s", failing, got)
		}
		if ok, _ := registry.Exists(w.ctx, repo+"@"+v2art.Digest); !ok {
			t.Fatalf("%s failing: the image was not pushed by digest", failing)
		}
		if w.tag("tools", "v2") != "" {
			t.Fatal("a tag was created")
		}
	}
	_ = w.cosign.calls()

	// The next run adds only the missing vulnerability reports (the
	// first attempt signed the image and attached the rest), then moves
	// latest.
	w.cosign.fail()
	w.out.Reset()
	if published, err := pub(v2art, v2recipe, v2out, "latest"); err != nil || !published {
		t.Fatalf("healing run: %v, %v\n%s", published, err, w.out.String())
	}
	var vulns []string
	for _, po := range v2out {
		vulns = append(vulns, "attest vuln "+repo+"@"+po.digest)
	}
	if got := w.cosign.calls(); strings.Join(got, "\n") != strings.Join(vulns, "\n") {
		t.Errorf("healing run's cosign calls:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(vulns, "\n"))
	}
	if !strings.Contains(w.out.String(), "is in the registry without the linux/amd64 vulnerability report, the linux/arm64 vulnerability report; adding them") {
		t.Errorf("output:\n%s", w.out.String())
	}
	if got := w.tag("tools", "latest"); got != v2art.Digest {
		t.Fatalf("after healing, latest is %s, want %s", got, v2art.Digest)
	}

	// Complete: nothing is signed or attested again, and only the tags
	// move.
	w.out.Reset()
	if published, err := pub(v2art, v2recipe, v2out, "latest", "v2"); err != nil || published {
		t.Fatalf("unchanged: %v, %v\n%s", published, err, w.out.String())
	}
	if got := w.cosign.calls(); len(got) != 0 {
		t.Errorf("cosign signed or attested again: %q", got)
	}
	if w.tag("tools", "v2") != v2art.Digest || !strings.Contains(w.out.String(), "already published, signed, and attested") {
		t.Errorf("v2 is %s\n%s", w.tag("tools", "v2"), w.out.String())
	}

	// A re-run of an older job publishes an image created before the one
	// latest holds: it is pushed, signed, and attested, and latest stays.
	oldArt, oldRecipe, oldOut := w.image(4, "v1.5 ")
	w.out.Reset()
	if published, err := pub(oldArt, oldRecipe, oldOut, "latest", "v1.5"); err != nil || !published {
		t.Fatalf("older job: %v, %v\n%s", published, err, w.out.String())
	}
	if got := w.tag("tools", "latest"); got != v2art.Digest {
		t.Fatalf("an older job's fresh push moved latest back to %s", got)
	}
	if w.tag("tools", "v1.5") != oldArt.Digest || !strings.Contains(w.out.String(), "warning: left "+repo+":latest where it is") {
		t.Errorf("v1.5 is %s\n%s", w.tag("tools", "v1.5"), w.out.String())
	}
}

// TestBuildResultBeforeTags: the build's result.json and GitHub Actions
// outputs say the image is published as soon as it is signed and
// attested, before its tags move, so a failure after that still leaves
// the record the reproduce and notify steps read.
func TestBuildResultBeforeTags(t *testing.T) {
	w := newPublishWorld(t)
	art, recipe, outputs := w.image(1, "a ")
	repo := w.host + "/app"
	w.cosign.children(repo+"@"+art.Digest, art)
	ghOut := filepath.Join(w.dir, "github-output")
	t.Setenv("GITHUB_OUTPUT", ghOut)
	resultPath := filepath.Join(w.dir, "result.json")
	result := Result{Repository: repo, Digest: art.Digest, Tags: []string{"latest"}}
	var atTags Result
	write := func() error { return attest.WriteJSON(resultPath, result) }
	m := &manifest.Manifest{Kind: manifest.KindImage, Metadata: manifest.Metadata{Name: "app", Ref: repo, Tags: []string{"latest", "bad tag"}}}
	err := publishBuild(w.ctx, w.opts, w.org, m, art, BuildOptions{}, recipe, outputs, &result, func() error {
		if err := write(); err != nil {
			return err
		}
		b, _ := os.ReadFile(resultPath)
		return json.Unmarshal(b, &atTags)
	})
	if err == nil {
		t.Fatal("an invalid tag was accepted")
	}
	if !atTags.Published || !atTags.Signed || atTags.Image != repo+"@"+art.Digest {
		t.Errorf("result.json before the tags moved: %+v", atTags)
	}
	if b, _ := os.ReadFile(ghOut); !strings.Contains(string(b), "published=true\n") || !strings.Contains(string(b), "digest="+art.Digest+"\n") {
		t.Errorf("GITHUB_OUTPUT:\n%s", b)
	}
}

// TestRebaseHealsCurrentImage: a rebase that finds the image already on
// the newest base completes its publication when it lacks something,
// rather than saying there is nothing to do (#3), and refuses an image no
// signer vouched for.
func TestRebaseHealsCurrentImage(t *testing.T) {
	w := newPublishWorld(t)
	host := w.host
	osRel := map[string]string{"etc/": "", "etc/os-release": "ID=wolfi\nVERSION_ID=20230201\n"}
	oldBase := testIndex(t, nil, func(arch string) []v1.Layer {
		return []v1.Layer{testLayer(t, osRel), testLayer(t, map[string]string{"usr/lib/libssl.so.3": "old " + arch})}
	}, nil)
	newBase := testIndex(t, nil, func(arch string) []v1.Layer {
		return []v1.Layer{testLayer(t, osRel), testLayer(t, map[string]string{"usr/lib/libssl.so.3": "patched " + arch})}
	}, nil)
	push(t, host+"/run:latest", oldBase)
	baseImage := func(arch string) v1.Image {
		im, _ := oldBase.IndexManifest()
		for _, d := range im.Manifests {
			if d.Platform.Architecture == arch {
				img, _ := oldBase.Image(d.Digest)
				return img
			}
		}
		return nil
	}
	built := testIndex(t, baseImage, func(arch string) []v1.Layer {
		return []v1.Layer{testLayer(t, map[string]string{"app/": "", "app/hello": "hello " + arch})}
	}, func(arch string) map[string]string {
		d, _ := baseImage(arch).Digest()
		return map[string]string{rebase.AnnotationBaseName: host + "/run:latest", rebase.AnnotationBaseDigest: d.String()}
	})
	push(t, host+"/hello:latest", built)
	push(t, host+"/run:latest", newBase)

	orgPath := filepath.Join(w.dir, "factory.org.yaml")
	if err := os.WriteFile(orgPath, []byte("apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\n"+
		"signing:\n  verify: {certificateIdentity: x, certificateOIDCIssuer: "+ghIssuer+"}\nsbom: {scan: false}\nvulnerabilities: {scanner: none}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	opts := Options{OrgPath: orgPath, Version: "test", Stdout: &w.out, Stderr: &w.out}
	ro := RebaseOptions{Image: host + "/hello:latest", OutDir: filepath.Join(w.dir, "out"), Push: true}
	rebaseNow := func() error {
		t.Helper()
		w.out.Reset()
		return Rebase(w.ctx, opts, ro)
	}

	// What the rebase gives (not pushed), so the fake cosign knows the
	// platform images sign --recursive signs.
	ro.Push = false
	if err := rebaseNow(); err != nil {
		t.Fatal(err)
	}
	ro.Push = true
	art, err := registry.OpenLayout(filepath.Join(ro.OutDir, "hello-rebase", "image"))
	if err != nil {
		t.Fatal(err)
	}
	rebasedRef := host + "/hello@" + art.Digest
	w.cosign.children(rebasedRef, art)

	// The rebase fails after signing it and attaching its record: the
	// image is pushed by digest and latest stays on the original.
	w.cosign.fail("attest cyclonedx")
	if err := rebaseNow(); err == nil {
		t.Fatalf("rebase with cosign failing succeeded\n%s", w.out.String())
	}
	original, _ := built.Digest()
	if w.tag("hello", "latest") != original.String() {
		t.Fatal("latest moved to an image without its SBOMs")
	}
	if ok, _ := registry.Exists(w.ctx, rebasedRef); !ok {
		t.Fatal("the rebased image was not pushed by digest")
	}
	_ = w.cosign.calls()

	// As a version that moved tags before signing would have left it:
	// latest on the rebased image, without its SBOMs. The next rebase
	// finds it on the newest base and attaches them.
	if err := registry.Tag(w.ctx, rebasedRef, []string{"latest"}); err != nil {
		t.Fatal(err)
	}
	w.cosign.fail()
	if err := rebaseNow(); err != nil {
		t.Fatalf("healing rebase: %v\n%s", err, w.out.String())
	}
	plats, _ := art.Platforms()
	var want []string
	for _, p := range plats {
		want = append(want, "attest cyclonedx "+host+"/hello@"+p.Digest)
	}
	if got := w.cosign.calls(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("healing rebase's cosign calls:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if !strings.Contains(w.out.String(), "already on the newest base, but not fully signed and attested") {
		t.Errorf("output:\n%s", w.out.String())
	}
	var res Result
	b, err := os.ReadFile(filepath.Join(ro.OutDir, "hello-rebase", "result.json"))
	if err == nil {
		err = json.Unmarshal(b, &res)
	}
	if err != nil || !res.Published || res.Image != rebasedRef {
		t.Errorf("result.json: %+v, %v", res, err)
	}
	// The SBOM says what the image was rebased from, as the rebase's own
	// would.
	from, err := registry.PlatformDigests(w.ctx, host+"/hello@"+original.String())
	if err != nil {
		t.Fatal(err)
	}
	sbom, _ := os.ReadFile(res.SBOMs["linux/amd64"])
	if !strings.Contains(string(sbom), "rebased-from") || !strings.Contains(string(sbom), from["linux/amd64"]) {
		t.Errorf("SBOM:\n%s", sbom)
	}

	// Complete now: nothing to do, and nothing signed or attested.
	if err := rebaseNow(); err != nil || !strings.Contains(w.out.String(), "already on the newest base, signed, and attested; nothing to do") {
		t.Fatalf("complete: %v\n%s", err, w.out.String())
	}
	if got := w.cosign.calls(); len(got) != 0 {
		t.Errorf("cosign signed or attested again: %q", got)
	}

	// Without a signer to check against, a current image isn't taken as
	// complete.
	noSigner := strings.Replace(string(must(os.ReadFile(orgPath))), "  verify: {certificateIdentity: x, certificateOIDCIssuer: "+ghIssuer+"}\n", "", 1)
	if err := os.WriteFile(orgPath, []byte(noSigner), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := rebaseNow(); err == nil || !strings.Contains(err.Error(), "no image signer to check that it is signed and attested (the org profile names none)") {
		t.Errorf("no signer: %v\n%s", err, w.out.String())
	}
	if err := os.WriteFile(orgPath, []byte(strings.Replace(noSigner, "signing:\n", "signing:\n  verify: {certificateIdentity: x, certificateOIDCIssuer: "+ghIssuer+"}\n", 1)), 0o644); err != nil {
		t.Fatal(err)
	}

	// An image on the newest base that no signer vouched for (pushed by
	// hand, say) is refused, not signed.
	stray := testIndex(t, nil, func(arch string) []v1.Layer {
		return []v1.Layer{testLayer(t, osRel), testLayer(t, map[string]string{"usr/lib/libssl.so.3": "patched " + arch}), testLayer(t, map[string]string{"app/hello": "stray " + arch})}
	}, func(arch string) map[string]string {
		im, _ := newBase.IndexManifest()
		for _, d := range im.Manifests {
			if d.Platform.Architecture == arch {
				return map[string]string{rebase.AnnotationBaseName: host + "/run:latest", rebase.AnnotationBaseDigest: d.Digest.String()}
			}
		}
		return nil
	})
	push(t, host+"/hello:latest", stray)
	err = rebaseNow()
	if err == nil || !strings.Contains(err.Error(), "carries no recipe or rebase record from the org's image signer, so a rebase can't vouch for it") {
		t.Errorf("unvouched image: %v\n%s", err, w.out.String())
	}
	if got := w.cosign.calls(); len(got) != 0 {
		t.Errorf("cosign signed an image no signer vouched for: %q", got)
	}
}

// TestStackPushSignsBeforeTagging: stack push (and profile push, the same
// code) tags the stack only once it is signed.
func TestStackPushSignsBeforeTagging(t *testing.T) {
	w := newPublishWorld(t)
	dir := t.TempDir()
	for n, body := range map[string]string{
		"factory.org.yaml": "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\nsigning: {mode: keyless}\n",
		"go.yaml":          "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: Stack\nmetadata: {name: go}\nspec:\n  build: golang:1\n  run: cgr.dev/chainguard/static:latest\n  steps: [{run: go build -o /out/app .}]\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ref := w.host + "/stacks/go:1"
	w.cosign.fail("sign")
	if err := StackPush(w.ctx, w.opts, filepath.Join(dir, "go.yaml"), ref, false); err == nil {
		t.Fatal("stack push succeeded with signing failing")
	}
	if w.tag("stacks/go", "1") != "" {
		t.Fatal("the tag names an unsigned stack")
	}
	w.cosign.fail()
	if err := StackPush(w.ctx, w.opts, filepath.Join(dir, "go.yaml"), ref, false); err != nil {
		t.Fatalf("%v\n%s", err, w.out.String())
	}
	if d := w.tag("stacks/go", "1"); d == "" || !slicesContains(w.cosign.calls(), "sign "+w.host+"/stacks/go@"+d) {
		t.Errorf("tag %q after signing", d)
	}
}

func slicesContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
