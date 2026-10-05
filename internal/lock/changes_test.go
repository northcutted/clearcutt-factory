package lock

import (
	"strings"
	"testing"
)

func TestChanges(t *testing.T) {
	d := func(c string) string { return "sha256:" + strings.Repeat(c, 64) }
	old := &Lock{
		Base: Image{Ref: "debian:trixie-slim", Digest: d("a")},
		Packages: Packages{Platforms: map[string][]Package{
			"linux/amd64": {{Name: "jq", Version: "1.7"}, {Name: "curl", Version: "8.1"}, {Name: "gone", Version: "1"}},
			"linux/arm64": {{Name: "jq", Version: "1.7"}, {Name: "curl", Version: "8.1"}, {Name: "gone", Version: "1"}},
		}},
		Tools: []Tool{
			{Name: "kubectl", Version: "1.37.0"},
			{Name: "crane", Image: &Image{Ref: "crane", Digest: d("c")}},
			{Name: "old"},
		},
	}
	cur := &Lock{
		Base: Image{Ref: "debian:trixie-slim", Digest: d("b")},
		Packages: Packages{Platforms: map[string][]Package{
			"linux/amd64": {{Name: "jq", Version: "1.8"}, {Name: "curl", Version: "8.2"}},
			"linux/arm64": {{Name: "jq", Version: "1.8"}, {Name: "curl", Version: "8.1"}},
		}},
		Tools: []Tool{
			{Name: "kubectl", Version: "1.37.1"},
			{Name: "crane", Image: &Image{Ref: "crane", Digest: d("d")}},
			{Name: "new", Version: "2"},
		},
	}
	got := strings.Join(Changes(old, cur), "\n")
	for _, want := range []string{
		"base debian:trixie-slim: sha256:aaaaaaaaaaaa → sha256:bbbbbbbbbbbb",
		"package jq: 1.7 → 1.8",
		"package curl: 8.1 → 8.2 on linux/amd64",
		"package gone: removed (1)",
		"tool kubectl: 1.37.0 → 1.37.1",
		"tool crane: new hashes or digests",
		"tool new: added 2",
		"tool old: removed",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if len(Changes(cur, cur)) != 0 {
		t.Errorf("identical locks reported changes: %q", Changes(cur, cur))
	}
}
