// Package schema generates JSON Schemas for the YAML files users write
// (manifests, stacks, the org profile) from the Go types that decode them,
// with the types' doc comments as descriptions, so editors can complete and
// check them.
package schema

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/northcutted/clearcutt-factory/internal/manifest"
)

// BaseURL is where the published schemas live; $id points there.
const BaseURL = "https://raw.githubusercontent.com/northcutted/clearcutt-factory/main/schemas/"

// File is one generated schema.
type File struct {
	Name    string
	Content []byte
}

// Generate returns the schemas, reading doc comments from the manifest
// package's source in srcDir.
func Generate(srcDir string) ([]File, error) {
	docs, err := comments(srcDir)
	if err != nil {
		return nil, err
	}
	g := &gen{docs: docs}
	specs := []struct {
		file, title string
		typ         reflect.Type
		kinds       []string
	}{
		{"manifest.schema.json", "ClearCutt Factory image or app manifest", reflect.TypeOf(manifest.Manifest{}), []string{manifest.KindImage, manifest.KindApp}},
		{"stack.schema.json", "ClearCutt Factory stack", reflect.TypeOf(manifest.Stack{}), []string{manifest.KindStack}},
		{"org.schema.json", "ClearCutt Factory org profile (factory.org.yaml)", reflect.TypeOf(manifest.Org{}), []string{manifest.KindOrg}},
	}
	var out []File
	for _, s := range specs {
		root := g.object(s.typ)
		props := root["properties"].(map[string]any)
		props["apiVersion"] = map[string]any{"const": manifest.APIVersion}
		props["kind"] = map[string]any{"enum": s.kinds}
		root["required"] = mergeRequired(root["required"], "apiVersion", "kind")
		doc := map[string]any{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id":     BaseURL + s.file,
			"title":   s.title,
		}
		for k, v := range root {
			doc[k] = v
		}
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		if err := enc.Encode(doc); err != nil {
			return nil, err
		}
		out = append(out, File{Name: s.file, Content: buf.Bytes()})
	}
	return out, nil
}

type gen struct {
	docs map[string]string // "Type.Field" or "Type" → doc text
}

var archMapType = reflect.TypeOf(manifest.ArchMap{})

func (g *gen) schema(t reflect.Type) map[string]any {
	if t == archMapType {
		return map[string]any{"oneOf": []any{
			map[string]any{"type": "string"},
			map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}},
		}}
	}
	switch t.Kind() {
	case reflect.Pointer:
		return g.schema(t.Elem())
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int32, reflect.Int64:
		return map[string]any{"type": "integer"}
	case reflect.Slice:
		return map[string]any{"type": "array", "items": g.schema(t.Elem())}
	case reflect.Map:
		return map[string]any{"type": "object", "additionalProperties": g.schema(t.Elem())}
	case reflect.Struct:
		return g.object(t)
	}
	panic(fmt.Sprintf("schema: unsupported type %s", t))
}

func (g *gen) object(t reflect.Type) map[string]any {
	props := map[string]any{}
	var required []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("yaml")
		name, opts, _ := strings.Cut(tag, ",")
		if name == "-" || name == "" || !f.IsExported() {
			continue
		}
		s := g.schema(f.Type)
		if d := g.docs[t.Name()+"."+f.Name]; d != "" {
			s["description"] = d
		}
		props[name] = s
		if !strings.Contains(opts, "omitempty") {
			required = append(required, name)
		}
	}
	o := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if d := g.docs[t.Name()]; d != "" {
		o["description"] = d
	}
	if len(required) > 0 {
		sort.Strings(required)
		o["required"] = required
	}
	return o
}

func mergeRequired(cur any, names ...string) []string {
	var out []string
	if c, ok := cur.([]string); ok {
		out = append(out, c...)
	}
	for _, n := range names {
		found := false
		for _, x := range out {
			found = found || x == n
		}
		if !found {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// comments reads type and field doc comments from the Go package in dir.
func comments(dir string) (map[string]string, error) {
	fset := token.NewFileSet()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return nil, err
		}
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				ts := spec.(*ast.TypeSpec)
				typeDoc := ts.Doc
				if typeDoc == nil {
					typeDoc = gd.Doc
				}
				out[ts.Name.Name] = clean(typeDoc)
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					continue
				}
				for _, field := range st.Fields.List {
					text := clean(field.Doc)
					if text == "" {
						text = clean(field.Comment)
					}
					for _, n := range field.Names {
						out[ts.Name.Name+"."+n.Name] = text
					}
				}
			}
		}
	}
	return out, nil
}

// clean turns a comment group into one paragraph of text.
func clean(g *ast.CommentGroup) string {
	if g == nil {
		return ""
	}
	return strings.Join(strings.Fields(g.Text()), " ")
}
