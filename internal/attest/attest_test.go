package attest

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestContextRoundTrip(t *testing.T) {
	src := t.TempDir()
	mustWrite(t, filepath.Join(src, "Containerfile"), "FROM scratch\n", 0o644)
	mustWrite(t, filepath.Join(src, "files/0/sub/a.txt"), "hello", 0o640)
	entries, err := ContextEntries(src, "Containerfile")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Path != "files/0/sub/a.txt" || string(entries[0].Content) != "hello" || entries[0].Mode != 0o640 {
		t.Fatalf("entries: %+v", entries)
	}

	r := &Recipe{Containerfile: "FROM scratch\n", Context: entries}
	dst := t.TempDir()
	if err := r.Materialize(dst, "Containerfile"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "files/0/sub/a.txt")); string(b) != "hello" {
		t.Error("context file not restored")
	}

	r.Context[0].Content = []byte("tampered")
	if err := r.Materialize(t.TempDir(), "Containerfile"); err == nil {
		t.Error("expected sha256 mismatch error")
	}
	r.Context[0] = ContextEntry{Path: "../escape", SHA256: entries[0].SHA256, Content: []byte("hello")}
	if err := r.Materialize(t.TempDir(), "Containerfile"); err == nil {
		t.Error("expected path escape error")
	}
}

func mustWrite(t *testing.T, p, body string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

func TestRecipeFromEnvelopes(t *testing.T) {
	st := NewStatement("registry.example/demo", "sha256:abc", RecipePredicateType, Recipe{Containerfile: "FROM x", Image: ImageDigests{Digest: "sha256:abc"}})
	other := NewStatement("registry.example/demo", "sha256:abc", VulnType, map[string]any{})
	env := func(s Statement) string {
		b, _ := json.Marshal(s)
		e, _ := json.Marshal(map[string]string{"payloadType": "application/vnd.in-toto+json", "payload": base64.StdEncoding.EncodeToString(b)})
		return string(e)
	}
	out := env(other) + "\nnot json\n" + env(st) + "\n"
	raw, err := predicateFromEnvelopes([]byte(out), RecipePredicateType)
	if err != nil {
		t.Fatal(err)
	}
	var r Recipe
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	if r.Containerfile != "FROM x" || r.Image.Digest != "sha256:abc" {
		t.Errorf("recipe: %+v", r)
	}
	if st.Subject[0].Digest["sha256"] != "abc" {
		t.Errorf("subject: %+v", st.Subject)
	}
}
