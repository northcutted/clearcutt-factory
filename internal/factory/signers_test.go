package factory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt-factory/internal/manifest"
)

const (
	ghIssuer = "https://token.actions.githubusercontent.com"
	reusable = `^https://github\.com/northcutted/clearcutt-factory/\.github/workflows/(images|fleet)\.yml@refs/tags/v\d+\.\d+\.\d+$`
)

func joined(signers [][]string) []string {
	var out []string
	for _, s := range signers {
		out = append(out, strings.Join(s, " "))
	}
	return out
}

func TestSignerArgs(t *testing.T) {
	images := manifest.VerifyIdentity{CertificateIdentityRegexp: reusable, CertificateOIDCIssuer: ghIssuer, SourceRepository: "https://github.com/acme/checkout"}
	stacks := manifest.VerifyIdentity{CertificateIdentity: "https://github.com/acme/platform/.github/workflows/stacks.yml@refs/heads/main", CertificateOIDCIssuer: ghIssuer}
	org := &manifest.Org{Signing: manifest.Signing{Verify: images, Stacks: stacks}}

	got, err := signerArgs(org, manifest.RoleImage, "")
	if err != nil || len(got) != 1 || joined(got)[0] != "--certificate-identity-regexp "+reusable+" --certificate-oidc-issuer "+ghIssuer+" --certificate-github-workflow-repository acme/checkout" {
		t.Errorf("images: %q %v", joined(got), err)
	}
	// Stacks have their own signer (#12), and fall back to the image signer.
	if got, _ := signerArgs(org, manifest.RoleStack, ""); len(got) != 1 || !strings.HasPrefix(joined(got)[0], "--certificate-identity https://github.com/acme/platform/") {
		t.Errorf("stacks: %q", joined(got))
	}
	org.Signing.Stacks = manifest.VerifyIdentity{}
	if got, _ := signerArgs(org, manifest.RoleStack, ""); len(got) != 1 || !strings.Contains(joined(got)[0], "acme/checkout") {
		t.Errorf("stacks fall back to verify: %q", joined(got))
	}
	if got, err := signerArgs(&manifest.Org{}, manifest.RoleImage, ""); err != nil || len(got) != 0 {
		t.Errorf("no signer: %q %v", got, err)
	}
}

func TestIdentityArgsSource(t *testing.T) {
	base := manifest.VerifyIdentity{CertificateIdentityRegexp: reusable, CertificateOIDCIssuer: ghIssuer}
	for _, c := range []struct {
		name   string
		mod    func(*manifest.VerifyIdentity)
		source string
		want   string // in the arguments, or the error
	}{
		{"image source", func(v *manifest.VerifyIdentity) { v.SourceMatchesImage = true }, "https://github.com/acme/catalog.git", "--certificate-github-workflow-repository acme/catalog"},
		{"image names none", func(v *manifest.VerifyIdentity) { v.SourceMatchesImage = true }, "", "names none"},
		{"owner and image", func(v *manifest.VerifyIdentity) {
			v.SourceMatchesImage, v.SourceRepositoryOwner = true, "https://github.com/acme"
		}, "https://github.com/acme/catalog", "acme/catalog"},
		{"outside the owner", func(v *manifest.VerifyIdentity) {
			v.SourceMatchesImage, v.SourceRepositoryOwner = true, "https://github.com/acme"
		}, "https://github.com/acme-evil/catalog", "not one of"},
		{"owner alone", func(v *manifest.VerifyIdentity) { v.SourceRepositoryOwner = "https://github.com/acme" }, "", "one exact repository"},
		{"image is not the repository", func(v *manifest.VerifyIdentity) {
			v.SourceMatchesImage, v.SourceRepository = true, "https://github.com/acme/a"
		}, "https://github.com/acme/b", "not https://github.com/acme/a"},
		{"ref", func(v *manifest.VerifyIdentity) { v.SourceRef = "refs/heads/main" }, "", "--certificate-github-workflow-ref refs/heads/main"},
	} {
		v := base
		c.mod(&v)
		args, err := identityArgs(v, c.source)
		got := strings.Join(args, " ")
		if err != nil {
			got = err.Error()
		}
		if !strings.Contains(got, c.want) {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestTrustPolicyRoles(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	write("trust.yaml", `apiVersion: clearcutt.dev/v1
kind: TrustPolicy
signers:
  - name: factory-builds
    identityRegexp: `+reusable+`
    issuer: `+ghIssuer+`
    sourceRepositoryOwner: https://github.com/acme
    sourceMatchesImage: true
  - name: platform-stacks
    roles: [stack]
    identity: https://github.com/acme/platform/.github/workflows/stacks.yml@refs/heads/main
    issuer: `+ghIssuer+`
`)
	org, err := manifest.LoadOrg(write("factory.org.yaml", "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\nsigning:\n  trustPolicy: trust.yaml\n"), "")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := signerArgs(org, manifest.RoleImage, "https://github.com/acme/checkout"); err != nil || len(got) != 1 || !strings.HasSuffix(joined(got)[0], "--certificate-github-workflow-repository acme/checkout") {
		t.Errorf("image signers: %q %v", joined(got), err)
	}
	if got, err := signerArgs(org, manifest.RoleImage, "https://github.com/mallory/x"); err == nil || len(got) != 0 {
		t.Errorf("image outside the owner: %q %v", joined(got), err)
	}
	if got, _ := signerArgs(org, manifest.RoleStack, ""); len(got) != 1 || !strings.Contains(joined(got)[0], "stacks.yml") {
		t.Errorf("stack signers: %q", joined(got))
	}
	if !needsImageSource(org, manifest.RoleImage) || needsImageSource(org, manifest.RoleStack) {
		t.Error("needsImageSource")
	}

	for body, want := range map[string]string{
		"apiVersion: v1\nkind: Trust\n": "expected apiVersion",
		"apiVersion: clearcutt.dev/v1\nkind: TrustPolicy\nsigners: [{roles: [admin], identity: x, issuer: y}]\n":                         "role \"admin\"",
		"apiVersion: clearcutt.dev/v1\nkind: TrustPolicy\nsigners: [{identity: x}]\n":                                                    "needs certificateOIDCIssuer",
		"apiVersion: clearcutt.dev/v1\nkind: TrustPolicy\nsigners: [{key: k.pub, sourceRepository: https://github.com/a/b}]\n":           "keyless",
		"apiVersion: clearcutt.dev/v1\nkind: TrustPolicy\nsigners: [{identity: x, issuer: y, sourceRepository: https://gitlab.com/a}]\n": "https://github.com/",
	} {
		if _, err := manifest.LoadTrustPolicy(write("bad.yaml", body)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want %q", body, err, want)
		}
	}
	if _, err := manifest.LoadOrg(write("bad.org.yaml", "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\nsigning:\n  verify: {certificateIdentity: x, certificateIdentityRegexp: y, certificateOIDCIssuer: z}\n"), ""); err == nil || !strings.Contains(err.Error(), "not both") {
		t.Errorf("identity and regexp: %v", err)
	}
}
