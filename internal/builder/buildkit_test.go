package builder

import (
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
