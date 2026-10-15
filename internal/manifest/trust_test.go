package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testIssuer   = "https://token.actions.githubusercontent.com"
	testReusable = `^https://github\.com/northcutted/clearcutt-factory/\.github/workflows/images\.yml@refs/tags/v\d+\.\d+\.\d+$`
	testStacks   = "https://github.com/acme/platform/.github/workflows/stacks.yml@refs/heads/main"
)

func writeFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for n, body := range files {
		p := filepath.Join(dir, n)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// TestTrustPolicyKeyPaths: key files are relative to the file that names
// them, the org profile or the trust policy; URIs and absolute paths stay.
func TestTrustPolicyKeyPaths(t *testing.T) {
	abs := filepath.Join(t.TempDir(), "abs.pub")
	dir := writeFiles(t, map[string]string{
		"factory.org.yaml": "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\nsigning:\n  mode: key\n  key: keys/cosign.key\n  verify: {key: keys/cosign.pub}\n  trustPolicy: policy/trust.yaml\n",
		"policy/trust.yaml": "apiVersion: clearcutt.dev/v1\nkind: TrustPolicy\nsigners:\n" +
			"  - {name: images, key: keys/images.pub}\n" +
			"  - {name: stacks, roles: [stack], key: ../platform/stacks.pub}\n" +
			"  - {name: kms, key: \"awskms:///alias/images\"}\n" +
			"  - {name: absolute, key: " + abs + "}\n",
	})
	org, err := LoadOrg(filepath.Join(dir, "factory.org.yaml"), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, got, want string }{
		{"signing.key", org.Signing.Key, filepath.Join(dir, "keys/cosign.key")},
		{"signing.verify", org.Signing.Verify.Key, filepath.Join(dir, "keys/cosign.pub")},
		{"trust policy", org.Trust.Signers[0].Key, filepath.Join(dir, "policy/keys/images.pub")},
		{"trust policy, up", org.Trust.Signers[1].Key, filepath.Join(dir, "platform/stacks.pub")},
		{"KMS", org.Trust.Signers[2].Key, "awskms:///alias/images"},
		{"absolute", org.Trust.Signers[3].Key, abs},
		{"stack signer", org.Signers(RoleStack)[0].Key, filepath.Join(dir, "platform/stacks.pub")},
	} {
		if c.got != c.want {
			t.Errorf("%s: key %s, want %s", c.name, c.got, c.want)
		}
	}
}

// TestStackSignersNameTheirRepository: a stack names no source repository,
// so a signer can't check stacks with sourceMatchesImage. It is refused
// where factory would check stacks with it, instead of failing every check.
func TestStackSignersNameTheirRepository(t *testing.T) {
	images := "{certificateIdentityRegexp: '" + testReusable + "', certificateOIDCIssuer: " + testIssuer + ", sourceMatchesImage: true, sourceRepositoryOwner: https://github.com/acme}"
	stacks := "{certificateIdentity: " + testStacks + ", certificateOIDCIssuer: " + testIssuer + "}"
	trust := func(roles string) string {
		return "apiVersion: clearcutt.dev/v1\nkind: TrustPolicy\nsigners:\n  - {name: factory-builds, roles: " + roles + ", identityRegexp: '" + testReusable + "', issuer: " + testIssuer + ", sourceMatchesImage: true}\n" +
			"  - {name: platform-stacks, roles: [stack], identity: " + testStacks + ", issuer: " + testIssuer + "}\n"
	}
	for _, c := range []struct {
		name, signing, policy, trust string
		want                         string // in the error; empty for none
	}{
		{"images bind to their source", "  verify: " + images + "\n  stacks: " + stacks + "\n", "requireSignedStacks: true", "", ""},
		{"stack checks off", "  verify: " + images + "\n", "", "", ""},
		{"stacks fall back to verify", "  verify: " + images + "\n", "requireSignedStacks: true", "", "signing.verify signs stacks while signing.stacks is unset"},
		{"signing.stacks", "  verify: " + images + "\n  stacks: {certificateIdentity: " + testStacks + ", certificateOIDCIssuer: " + testIssuer + ", sourceMatchesImage: true}\n", "", "", "signing.stacks: sourceMatchesImage only applies to images"},
		{"trust policy, image signer", "  trustPolicy: trust.yaml\n", "requireSignedStacks: true", trust("[image]"), ""},
		{"trust policy, stack checks off", "  trustPolicy: trust.yaml\n", "", trust("[image, stack]"), ""},
		{"trust policy, stack signer", "  trustPolicy: trust.yaml\n", "requireSignedStacks: true", trust("[image, stack]"), "signers[0] factory-builds signs stacks"},
	} {
		files := map[string]string{"factory.org.yaml": "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\nsigning:\n" + c.signing + "policy: {" + c.policy + "}\n"}
		if c.trust != "" {
			files["trust.yaml"] = c.trust
		}
		_, err := LoadOrg(filepath.Join(writeFiles(t, files), "factory.org.yaml"), "")
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: got %v, want %q", c.name, err, c.want)
		}
	}
}
