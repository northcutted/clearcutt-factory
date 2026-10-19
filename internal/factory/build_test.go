package factory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBuildFailure: a failed build shows the failing step's own output,
// not only BuildKit's summary, which is mostly the Containerfile.
func TestBuildFailure(t *testing.T) {
	var log []string
	log = append(log, "#11 [linux/arm64 tool-gh 1/2] ADD …", "#11 DONE 0.2s", "#12 [linux/amd64 packages-amd64 2/2] RUN <<'FACTORY_EOF' …")
	for i := 0; i < 50; i++ {
		log = append(log, "#12 1.0 (1/48) Installing pkg")
	}
	log = append(log, "#12 2.0 clearcutt-factory: jq is 1.8.2-r3 Q1x=, but the lock pins 1.8.2-r3 Q1y=", "#12 ERROR: process \"/bin/sh -c set -eu\" did not complete successfully: exit code: 1", "------")
	for i := 0; i < 45; i++ {
		log = append(log, " 1 | >>> Containerfile line")
	}
	p := filepath.Join(t.TempDir(), "build.log")
	if err := os.WriteFile(p, []byte(strings.Join(log, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := buildFailure(p)
	if !strings.Contains(got, "clearcutt-factory: jq is 1.8.2-r3 Q1x=, but the lock pins") || strings.Contains(got, "#11") || !strings.HasSuffix(got, " 1 | >>> Containerfile line") {
		t.Errorf("buildFailure:\n%s", got)
	}
	if n := strings.Count(got, "\n") + 1; n > 80 {
		t.Errorf("%d lines", n)
	}
}
