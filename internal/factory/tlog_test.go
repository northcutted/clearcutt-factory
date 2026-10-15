package factory

import (
	"strings"
	"testing"

	"github.com/northcutted/clearcutt-factory/internal/manifest"
)

// TestIdentityArgsTlog: a key signer with tlog: false is verified with
// cosign --insecure-ignore-tlog, for that signer only.
func TestIdentityArgsTlog(t *testing.T) {
	no, yes := false, true
	org := &manifest.Org{Trust: &manifest.TrustPolicy{Signers: []manifest.TrustedSigner{
		{Name: "offline", Key: "offline.pub", Tlog: &no},
		{Name: "logged", Key: "logged.pub", Tlog: &yes},
		{Name: "default", Key: "default.pub"},
	}}}
	signers, err := signerArgs(org, manifest.RoleImage, "")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"--key offline.pub --insecure-ignore-tlog=true", "--key logged.pub", "--key default.pub"}
	if len(signers) != len(want) {
		t.Fatalf("signers: %q", signers)
	}
	for i, w := range want {
		if got := strings.Join(signers[i], " "); got != w {
			t.Errorf("signer %d: %q, want %q", i, got, w)
		}
	}
}
