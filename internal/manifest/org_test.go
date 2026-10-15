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

// TestStackKey: signing.stackKey is relative to the profile, like
// signing.key, and only for key mode.
func TestStackKey(t *testing.T) {
	const head = "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\n"
	dir := writeFiles(t, map[string]string{
		"key.yaml":     head + "signing: {mode: key, key: keys/images.key, stackKey: keys/stacks.key}\n",
		"kms.yaml":     head + "signing: {mode: key, key: keys/images.key, stackKey: \"awskms:///alias/stacks\"}\n",
		"keyless.yaml": head + "signing: {mode: keyless, stackKey: keys/stacks.key}\n",
	})
	org, err := LoadOrg(filepath.Join(dir, "key.yaml"), "")
	if err != nil || org.Signing.StackKey != filepath.Join(dir, "keys", "stacks.key") {
		t.Errorf("stackKey: %v %q", err, org.Signing.StackKey)
	}
	if org, err = LoadOrg(filepath.Join(dir, "kms.yaml"), ""); err != nil || org.Signing.StackKey != "awskms:///alias/stacks" {
		t.Errorf("KMS stackKey: %v %q", err, org.Signing.StackKey)
	}
	if _, err := LoadOrg(filepath.Join(dir, "keyless.yaml"), ""); err == nil || !strings.Contains(err.Error(), "signing.stackKey is only used when signing.mode is key") {
		t.Errorf("keyless stackKey: %v", err)
	}
}
