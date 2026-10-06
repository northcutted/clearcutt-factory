package schema

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the committed schemas")

// TestSchemasCurrent fails when schemas/ is out of date with the types;
// go test ./internal/schema -update regenerates it.
func TestSchemasCurrent(t *testing.T) {
	files, err := Generate("../manifest")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		path := filepath.Join("..", "..", "schemas", f.Name)
		if *update {
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, f.Content, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		old, err := os.ReadFile(path)
		if err != nil || string(old) != string(f.Content) {
			t.Errorf("schemas/%s is out of date; run go test ./internal/schema -update", f.Name)
		}
	}
}

func TestManifestSchema(t *testing.T) {
	files, err := Generate("../manifest")
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Required   []string                   `json:"required"`
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(files[0].Content, &m); err != nil {
		t.Fatal(err)
	}
	if strings.Join(m.Required, ",") != "apiVersion,kind,metadata,spec" {
		t.Errorf("required = %v", m.Required)
	}
	spec := string(m.Properties["spec"])
	for _, want := range []string{`"packages"`, `"tools"`, `"stack"`, `"test"`, `"oneOf"`, "PackageManager overrides detection"} {
		if !strings.Contains(spec, want) {
			t.Errorf("spec schema lacks %s", want)
		}
	}
	if strings.Contains(spec, "VEXFiles") || strings.Contains(spec, `"StackPath"`) {
		t.Error("internal fields leaked into the schema")
	}
}
