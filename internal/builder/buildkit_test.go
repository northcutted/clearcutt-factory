package builder

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestContainerOptions(t *testing.T) {
	if o := containerOptions(Config{}); len(o) != 0 {
		t.Errorf("defaults add options: %q", o)
	}
	got := strings.Join(containerOptions(Config{BuildkitdConfig: "/home/me/buildkitd.toml", Network: "host"}), " ")
	want := "--network host --mount type=bind,source=/home/me/buildkitd.toml,target=/etc/buildkit/buildkitd.toml,readonly --env BUILDKITD_FLAGS=--config=/etc/buildkit/buildkitd.toml"
	if got != want {
		t.Errorf("containerOptions:\n got %s\nwant %s", got, want)
	}
}

// fakeRuntime puts an executable named name on PATH that records its
// arguments in args.txt beside it, writes stderr to its stderr, and exits
// with code.
func fakeRuntime(t *testing.T, name, stderr string, code int) string {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"" + filepath.Join(dir, "args.txt") + "\"\nprintf '%s' '" + strings.ReplaceAll(stderr, "'", `'\''`) + "' >&2\nexit " + strconv.Itoa(code) + "\n"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("CLEARCUTT_FACTORY_RUNTIME", name)
	return filepath.Join(dir, "args.txt")
}

// A runtime in a VM that can't see the build's directories (a podman
// machine sharing only the home directory, say) fails with its own terse
// message; the build names the cause and the fix instead.
func TestBuildNamesAPathTheRuntimeCantSee(t *testing.T) {
	for _, tc := range []struct {
		runtime, stderr, want string
	}{
		{"podman", "Error: statfs /tmp/x/checkout/context: no such file or directory\n", "podman can't see /tmp/x/checkout/context, which the build mounts into its BuildKit container: a podman machine shares only some host directories"},
		{"docker", "docker: Error response from daemon: Mounts denied: \nThe path /opt/x/out is not shared from the host and is not known to Docker.\nYou can configure shared paths from Docker -> Preferences... -> Resources -> File Sharing.\n", "docker can't see /opt/x/out, which the build mounts into its BuildKit container: the runtime's VM shares only some host directories (Docker Desktop: Settings → Resources → File sharing)"},
	} {
		t.Run(tc.runtime, func(t *testing.T) {
			fakeRuntime(t, tc.runtime, tc.stderr, 125)
			dir := t.TempDir()
			_, err := Build(context.Background(), Config{Stderr: io.Discard}, Request{ContextDir: dir, OutDir: filepath.Join(dir, "out"), Platforms: []string{"linux/amd64"}, BuildKitImage: "moby/buildkit:v0.33.1"})
			var nse *NotSharedError
			if !errors.As(err, &nse) || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("got %v\nwant an error containing %q", err, tc.want)
			}
		})
	}
	// Any other failure stays a build failure.
	fakeRuntime(t, "podman", "Error: something else\n", 1)
	dir := t.TempDir()
	_, err := Build(context.Background(), Config{}, Request{ContextDir: dir, OutDir: filepath.Join(dir, "out"), Platforms: []string{"linux/amd64"}, BuildKitImage: "moby/buildkit:v0.33.1"})
	var nse *NotSharedError
	if err == nil || errors.As(err, &nse) || !strings.Contains(err.Error(), "build failed") {
		t.Errorf("another failure: %v", err)
	}
}

// The runtime is given the real paths of the directories it mounts, so a
// VM that shares /private (macOS's /tmp is /private/tmp) sees them.
func TestBuildMountsRealPaths(t *testing.T) {
	args := fakeRuntime(t, "podman", "", 1)
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(real, "out"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, _ = Build(context.Background(), Config{}, Request{ContextDir: link, OutDir: filepath.Join(link, "out"), Platforms: []string{"linux/amd64"}, BuildKitImage: "moby/buildkit:v0.33.1"})
	b, err := os.ReadFile(args)
	if err != nil {
		t.Fatal(err)
	}
	resolved, _ := filepath.EvalSymlinks(real)
	got := string(b)
	for _, want := range []string{"type=bind,source=" + resolved + ",target=/ctx,readonly", "type=bind,source=" + filepath.Join(resolved, "out") + ",target=/out"} {
		if !strings.Contains(got, want+"\n") {
			t.Errorf("runtime arguments lack %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, link) {
		t.Errorf("runtime arguments name the symbolic link %s:\n%s", link, got)
	}
}
