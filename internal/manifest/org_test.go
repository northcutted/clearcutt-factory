package manifest

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestBuilderContainer: builder.config is relative to the profile and must
// exist; config and network only apply to the container factory starts.
func TestBuilderContainer(t *testing.T) {
	const head = "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\n"
	dir := writeFiles(t, map[string]string{
		"buildkit/buildkitd.toml": "[registry.\"localhost:5000\"]\n  http = true\n",
		"ok.yaml":                 head + "builder: {config: buildkit/buildkitd.toml, network: host}\n",
		"missing.yaml":            head + "builder: {config: nowhere.toml}\n",
		"remote.yaml":             head + "builder: {addr: \"tcp://buildkitd:1234\", network: host}\n",
	})
	org, err := LoadOrg(filepath.Join(dir, "ok.yaml"), "")
	if err != nil {
		t.Fatal(err)
	}
	if org.Builder.Config != filepath.Join(dir, "buildkit", "buildkitd.toml") || org.Builder.Network != "host" {
		t.Errorf("builder: %+v", org.Builder)
	}
	for file, want := range map[string]string{
		"missing.yaml": "builder.config: " + filepath.Join(dir, "nowhere.toml") + " is not a file",
		"remote.yaml":  "with builder.addr, configure that buildkitd instead",
	} {
		if _, err := LoadOrg(filepath.Join(dir, file), ""); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", file, err, want)
		}
	}
}
