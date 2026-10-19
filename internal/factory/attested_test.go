package factory

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt-factory/internal/attest"
	"github.com/northcutted/clearcutt-factory/internal/manifest"
)

// TestAttestedEither: a build finds an image the fleet rebased (and a rebase
// one that was built) with its predicate, so neither attests it again.
func TestAttestedEither(t *testing.T) {
	// A cosign that verifies one attestation type and logs its calls.
	dir := t.TempDir()
	cosign := filepath.Join(dir, "cosign")
	script := `#!/bin/sh
printf '%s\n' "$*" >> "$0.log"
[ "$1" = verify-attestation ] && [ "$3" = "$(cat "$0.type")" ] || exit 1
printf '{"payload":"%s"}\n' "$(printf '{"predicateType":"%s","predicate":{}}' "$3" | base64 | tr -d '\n')"
`
	if err := os.WriteFile(cosign, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	calls := func() []string {
		b, _ := os.ReadFile(cosign + ".log")
		_ = os.Remove(cosign + ".log")
		return strings.Fields(strings.ReplaceAll(string(b), " ", "_"))
	}
	ctx := context.Background()
	org := &manifest.Org{Signing: manifest.Signing{Mode: "key", Verify: manifest.VerifyIdentity{Key: "cosign.pub"}}}
	ref := "registry.example/app@sha256:" + strings.Repeat("a", 64)

	for _, c := range []struct {
		name, has, publishing string
		want                  bool
		calls                 int
	}{
		{"built, building again", attest.RecipePredicateType, attest.RecipePredicateType, true, 2},
		{"rebased, building from the pinned lock", attest.RebasePredicateType, attest.RecipePredicateType, true, 3},
		{"built, rebasing to the same image", attest.RecipePredicateType, attest.RebasePredicateType, true, 3},
		{"neither", "none", attest.RecipePredicateType, false, 3},
	} {
		if err := os.WriteFile(cosign+".type", []byte(c.has), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := inspectPublication(ctx, org, ref, "registry.example/app", c.publishing, "", nil).predicate; got != c.want {
			t.Errorf("%s: predicate = %v, want %v", c.name, got, c.want)
		}
		cl := calls()
		if len(cl) != c.calls || !strings.HasPrefix(cl[0], "verify_") || !strings.HasPrefix(cl[1], "verify-attestation_--type_"+c.publishing+"_") {
			t.Errorf("%s: cosign calls %q", c.name, cl)
		}
	}
}
