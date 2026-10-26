package lock

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt-factory/internal/manifest"
)

func sample() *Lock {
	return &Lock{
		APIVersion: manifest.APIVersion, Kind: Kind, InputsDigest: "sha256:in", SourceDateEpoch: 1791504000,
		Base: Image{Ref: "cgr.dev/chainguard/wolfi-base:latest", Digest: "sha256:aaaa"},
		Packages: Packages{Manager: ManagerAPK, Platforms: map[string][]Package{
			"linux/amd64": {{Name: "jq", Version: "1.8.2-r3", Arch: "x86_64", Checksum: "Q1abc="}},
		}},
		Tools: []Tool{{Name: "kubectl", From: manifest.FromURL, Version: "1.37.1", Verification: VerifiedPinned, SpecDigest: "sha256:spec",
			Artifacts: map[string]Artifact{"linux/amd64": {URL: "https://dl.k8s.io/v1.37.1/kubectl", SHA256: strings.Repeat("ab", 32)}}}},
	}
}

// TestContentDigest: a written lock reads back; one edited by hand (a
// checksum, a URL, a digest) is refused as edited; one without a content
// digest (an older lock) as missing it. The digest covers which release
// wrote the lock too.
func TestContentDigest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "image.lock.yaml")
	l := sample()
	l.Generator = Generator("v0.4.0")
	if err := l.Write(path); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path); err != nil {
		t.Fatalf("read back: %v", err)
	}
	written, _ := os.ReadFile(path)
	if !strings.Contains(string(written), "generator: clearcutt-factory v0.4.0\n") || !strings.Contains(string(written), "contentDigest: sha256:") {
		t.Errorf("written lock lacks the generator or the digest:\n%s", written)
	}
	for name, edit := range map[string]func(s string) string{
		"checksum":  func(s string) string { return strings.Replace(s, "Q1abc=", "Q1abd=", 1) },
		"url":       func(s string) string { return strings.Replace(s, "dl.k8s.io", "dl.k8s.evil", 1) },
		"digest":    func(s string) string { return strings.Replace(s, "sha256:aaaa", "sha256:aaab", 1) },
		"sha256":    func(s string) string { return strings.Replace(s, "abab", "abac", 1) },
		"generator": func(s string) string { return strings.Replace(s, "v0.4.0", "v0.3.0", 1) },
	} {
		if err := os.WriteFile(path, []byte(edit(string(written))), 0o644); err != nil {
			t.Fatal(err)
		}
		got, err := Read(path)
		var e *EditedError
		if !errors.As(err, &e) || e.Missing || got == nil {
			t.Errorf("%s edited: got %v (lock %v), want an EditedError", name, err, got != nil)
			continue
		}
		if edited, missing := IsEdited(err); !edited || missing || !strings.Contains(err.Error(), "edited by hand") {
			t.Errorf("%s edited: IsEdited %v %v: %v", name, edited, missing, err)
		}
	}
	// No digest at all: an older lock, or one whose line was removed.
	lines := strings.Split(string(written), "\n")
	var kept []string
	for _, ln := range lines {
		if !strings.HasPrefix(ln, "contentDigest:") {
			kept = append(kept, ln)
		}
	}
	if err := os.WriteFile(path, []byte(strings.Join(kept, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := Read(path)
	if edited, missing := IsEdited(err); !edited || !missing || got == nil || !strings.Contains(err.Error(), "has no contentDigest") {
		t.Errorf("no digest: %v (lock %v)", err, got != nil)
	}
	if edited, _ := IsEdited(errors.New("other")); edited {
		t.Error("IsEdited of another error")
	}
}

// TestNewerLock: a lock written by a newer minor release is refused with a
// message that says so; by a newer patch release it is read (patch
// releases keep the format), unless it can't be decoded, when the message
// names the newer release rather than the unknown field alone.
// Development builds on either side skip the check.
func TestNewerLock(t *testing.T) {
	dir := t.TempDir()
	write := func(generator, extra string) string {
		t.Helper()
		l := sample()
		l.Generator = generator
		p := filepath.Join(dir, "image.lock.yaml")
		if err := l.Write(p); err != nil {
			t.Fatal(err)
		}
		if extra != "" {
			b, _ := os.ReadFile(p)
			if err := os.WriteFile(p, append(b, []byte(extra)...), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return p
	}
	for _, c := range []struct {
		generator, extra, version string
		newer                     bool
		want                      string
	}{
		{"clearcutt-factory v0.5.0", "", "v0.4.2", true, "written by clearcutt-factory v0.5.0, newer than this clearcutt-factory (v0.4.2)"},
		{"clearcutt-factory v1.0.0", "", "v0.9.9", true, ""},
		{"clearcutt-factory v0.4.9", "", "v0.4.2", false, ""},
		{"clearcutt-factory v0.4.2", "", "v0.4.2", false, ""},
		{"clearcutt-factory v0.3.0", "", "v0.4.2", false, ""},
		{"clearcutt-factory v0.5.0", "", "dev", false, ""},
		{"clearcutt-factory v0.5.0", "", "v0.4.2-3-gabcdef-dirty", true, ""},
		{"", "", "v0.4.2", false, ""},
		{"clearcutt-factory v0.4.3", "future: 1\n", "v0.4.2", true, "field future not found"},
		{"clearcutt-factory v0.4.2", "future: 1\n", "v0.4.2", false, "field future not found"},
	} {
		p := write(c.generator, c.extra)
		_, err := ReadFor(p, c.version)
		var ne *NewerError
		if errors.As(err, &ne) != c.newer {
			t.Errorf("%q read by %s: got %v, want newer=%v", c.generator, c.version, err, c.newer)
		}
		if c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%q read by %s: got %v, want %q", c.generator, c.version, err, c.want)
		}
		if c.extra == "" && !c.newer && err != nil {
			t.Errorf("%q read by %s: %v", c.generator, c.version, err)
		}
	}
}

// TestWriteFileAtomic: the file holds the old content until the new one is
// complete, and no temporary file is left behind.
func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "image.Containerfile")
	if err := os.WriteFile(p, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(p, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "new" {
		t.Errorf("content %q", b)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("left files behind: %v", entries)
	}
	// Into a directory that doesn't exist: fails, leaving nothing.
	if err := WriteFileAtomic(filepath.Join(dir, "missing", "x"), []byte("x"), 0o644); err == nil {
		t.Error("wrote into a missing directory")
	}
	// Content compares by pins, not by generator or digest.
	a, b := sample(), sample()
	b.Generator, b.ContentDigest = "clearcutt-factory v9.9.9", "sha256:x"
	if string(a.Content()) != string(b.Content()) || string(a.Marshal()) == string(b.Marshal()) {
		t.Error("Content should leave out the generator and the digest; Marshal should not")
	}
}
