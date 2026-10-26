package diff

import (
	"archive/tar"
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/northcutted/clearcutt-factory/internal/registry"
)

// file is one tar entry: its name, content, and mtime.
type file struct {
	name, content string
	mtime         int64
}

// layer builds a layer holding files in the order given.
func layer(t *testing.T, files ...file) v1.Layer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range files {
		h := &tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.content)), Typeflag: tar.TypeReg, ModTime: time.Unix(f.mtime, 0)}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write([]byte(f.content))
	}
	_ = tw.Close()
	b := buf.Bytes()
	l, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil }, tarball.WithMediaType(types.OCILayer))
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// image builds a linux/<arch> image from layers, with env set in its config.
func image(t *testing.T, arch string, env []string, layers ...v1.Layer) v1.Image {
	t.Helper()
	img := mutate.ConfigMediaType(mutate.MediaType(empty.Image, types.OCIManifestSchema1), types.OCIConfigJSON)
	img, err := mutate.AppendLayers(img, layers...)
	if err != nil {
		t.Fatal(err)
	}
	cf, err := img.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	cf = cf.DeepCopy()
	cf.OS, cf.Architecture, cf.Config.Env = "linux", arch, env
	if img, err = mutate.ConfigFile(img, cf); err != nil {
		t.Fatal(err)
	}
	return img
}

// index builds an index of images by architecture.
func index(t *testing.T, images map[string]v1.Image) *registry.Artifact {
	t.Helper()
	var adds []mutate.IndexAddendum
	for _, arch := range []string{"amd64", "arm64"} {
		img, ok := images[arch]
		if !ok {
			continue
		}
		adds = append(adds, mutate.IndexAddendum{Add: img, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: arch}}})
	}
	idx := mutate.IndexMediaType(mutate.AppendManifests(empty.Index, adds...), types.OCIImageIndex)
	d, err := idx.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return &registry.Artifact{Digest: d.String(), Index: idx}
}

func digestOf(t *testing.T, img v1.Image) string {
	t.Helper()
	d, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return d.String()
}

// TestArtifacts: the explanation of a mismatch names, per platform, the
// first differing layer and the files that differ in it (changed, missing,
// added), or that only the config differs, or that a platform is missing
// from the rebuild; identical platforms are named as such.
func TestArtifacts(t *testing.T) {
	tool := file{"usr/bin/tool", "v1", 1700000000}
	base := layer(t, file{"etc/os-release", "ID=wolfi", 1700000000})
	same := image(t, "amd64", nil, base, layer(t, tool))
	want := index(t, map[string]v1.Image{
		"amd64": same,
		"arm64": image(t, "arm64", nil, base, layer(t, tool, file{"usr/bin/old", "x", 1700000000})),
	})
	got := index(t, map[string]v1.Image{
		"amd64": same,
		"arm64": image(t, "arm64", nil, base, layer(t, file{"usr/bin/tool", "v2", 1700000000}, file{"usr/bin/new", "y", 1700000000})),
	})
	out, err := Artifacts(want, got, 30)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"linux/amd64: identical (" + digestOf(t, same) + ")",
		"linux/arm64: sha256:",
		"first differing layer #1:",
		"    - usr/bin/old",
		"    + usr/bin/new",
		"    ~ usr/bin/tool (644 0:0 1700000000 ",
	} {
		if !strings.Contains(out, line) {
			t.Errorf("missing %q in:\n%s", line, out)
		}
	}
	// The base layer is the same in both, so it isn't the first differing one.
	if strings.Contains(out, "layer #0") || strings.Contains(out, "os-release") {
		t.Errorf("the shared base layer was reported:\n%s", out)
	}

	// A platform the rebuild lacks; a layer count that differs; the same
	// files in another order (tar headers or compression differ); and
	// layers identical with another config.
	for _, c := range []struct {
		name      string
		want, got *registry.Artifact
		lines     []string
	}{
		{"missing platform",
			index(t, map[string]v1.Image{"amd64": same, "arm64": image(t, "arm64", nil, base)}),
			index(t, map[string]v1.Image{"amd64": same}),
			[]string{"linux/arm64: missing from rebuild"}},
		{"layer count",
			index(t, map[string]v1.Image{"amd64": image(t, "amd64", nil, base, layer(t, tool))}),
			index(t, map[string]v1.Image{"amd64": image(t, "amd64", nil, base)}),
			[]string{"  layer count differs: 2 vs 1"}},
		{"same files, other order",
			index(t, map[string]v1.Image{"amd64": image(t, "amd64", nil, layer(t, tool, file{"usr/bin/b", "b", 1}))}),
			index(t, map[string]v1.Image{"amd64": image(t, "amd64", nil, layer(t, file{"usr/bin/b", "b", 1}, tool))}),
			[]string{"first differing layer #0", "(same files; tar headers or compression differ)"}},
		{"mtime",
			index(t, map[string]v1.Image{"amd64": image(t, "amd64", nil, layer(t, tool))}),
			index(t, map[string]v1.Image{"amd64": image(t, "amd64", nil, layer(t, file{tool.name, tool.content, 1700000001}))}),
			[]string{"~ usr/bin/tool (644 0:0 1700000000 ", " → 644 0:0 1700000001 "}},
		{"config only",
			index(t, map[string]v1.Image{"amd64": image(t, "amd64", []string{"A=1"}, base)}),
			index(t, map[string]v1.Image{"amd64": image(t, "amd64", []string{"A=2"}, base)}),
			[]string{"  layers identical; image config differs: sha256:"}},
	} {
		out, err := Artifacts(c.want, c.got, 30)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		for _, line := range c.lines {
			if !strings.Contains(out, line) {
				t.Errorf("%s: missing %q in:\n%s", c.name, line, out)
			}
		}
	}
}

// TestArtifactsCapsFiles: a long list of differing files is cut at
// maxFiles, saying how many more there are.
func TestArtifactsCapsFiles(t *testing.T) {
	var a, b []file
	for i := 0; i < 8; i++ {
		n := "f" + string(rune('a'+i))
		a = append(a, file{n, "1", 1})
		b = append(b, file{n, "2", 1})
	}
	want := index(t, map[string]v1.Image{"amd64": image(t, "amd64", nil, layer(t, a...))})
	got := index(t, map[string]v1.Image{"amd64": image(t, "amd64", nil, layer(t, b...))})
	out, err := Artifacts(want, got, 3)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(out, "    ~ ") != 3 || !strings.Contains(out, "… and 5 more") {
		t.Errorf("not capped at 3:\n%s", out)
	}
	// A single-image artifact (one platform built) is compared the same way.
	single := func(img v1.Image) *registry.Artifact { return &registry.Artifact{Digest: digestOf(t, img), Image: img} }
	out, err = Artifacts(single(image(t, "arm64", nil, layer(t, a...))), single(image(t, "arm64", nil, layer(t, b...))), 30)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "linux/arm64: sha256:") || strings.Count(out, "    ~ ") != 8 {
		t.Errorf("single image:\n%s", out)
	}
}
