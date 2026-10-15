package rebase

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// testdata/checkout holds real manifests and configs (named by their sha256)
// from ClearCutt's showcase, a local registry where factory built and
// rebased images with BuildKit v0.33.1:
//
//   - the app checkout (index 1c3879ed…), built on run-go 61f9383c… (amd64)
//     and d2d2f1cb… (arm64), images factory built, so their own layers carry
//     BuildKit's buildkit/rewritten-timestamp annotation;
//   - the next build of run-go, 0817dbb5… and 47007eca…;
//   - checkout rebuilt with BuildKit from its lock pinned to that run-go
//     (index 25f2ca6b…, platform manifests c6befc46… and c06c942d…).
const (
	checkoutApp     = "sha256:1c3879ed773232c5d41bdbeb40eef956646a6730b1c5f582e172a4a724f4ef2e"
	checkoutRebuilt = "sha256:25f2ca6b05e50a0e17cc0ebbdba04045adb1114af4e98e4da780c9f7d7369614"
	// checkoutLegacy is what factory v0.1.1 pushed when it rebased checkout.
	checkoutLegacy = "sha256:ccf63a29fd08a861731e7ad120f380b59720aa335da41d83fe8ef402a4b1ef96"
	runGo          = "localhost:5001/platform/run-go:1"
)

var newRunGo = map[string]string{
	"amd64": "sha256:0817dbb5292b2ecefe56c550637f040de9331885f78aae6bd1aa2d537e7605e0",
	"arm64": "sha256:47007eca050d2990d043eebce30ec44ef57f6beaa81f23891ca8969baf99fdf7",
}

// TestImageAsBuilt rebases checkout onto the new run-go and requires the
// image BuildKit built from source on it, bit for bit, and the Legacy format
// to still give what factory v0.1.1 pushed.
func TestImageAsBuilt(t *testing.T) {
	for _, c := range []struct {
		name   string
		format Format
		want   string
	}{{"AsBuilt", AsBuilt, checkoutRebuilt}, {"Legacy", Legacy, checkoutLegacy}} {
		t.Run(c.name, func(t *testing.T) {
			app := blobIndex(t, checkoutApp)
			im, err := app.IndexManifest()
			if err != nil {
				t.Fatal(err)
			}
			rebased := map[v1.Hash]v1.Image{}
			for _, d := range im.Manifests {
				img := blobImage(t, d.Digest.String())
				m, err := img.Manifest()
				if err != nil {
					t.Fatal(err)
				}
				oldBase := blobImage(t, m.Annotations[AnnotationBaseDigest])
				r, err := c.format.Image(img, oldBase, blobImage(t, newRunGo[d.Platform.Architecture]), runGo)
				if err != nil {
					t.Fatal(err)
				}
				rebased[d.Digest] = r.Image
			}
			idx, err := c.format.Index(app, rebased, runGo)
			if err != nil {
				t.Fatal(err)
			}
			got, err := idx.Digest()
			if err != nil {
				t.Fatal(err)
			}
			if got.String() == c.want {
				return
			}
			t.Errorf("rebased index is %s, want %s", got, c.want)
			if c.want != checkoutRebuilt {
				return
			}
			wm, err := v1.ParseIndexManifest(bytes.NewReader(readBlob(t, checkoutRebuilt)))
			if err != nil {
				t.Fatal(err)
			}
			gm, _ := idx.IndexManifest()
			for i := range gm.Manifests {
				img, _ := idx.Image(gm.Manifests[i].Digest)
				raw, _ := img.RawManifest()
				if w := readBlob(t, wm.Manifests[i].Digest.String()); !bytes.Equal(raw, w) {
					t.Errorf("%s: rebased manifest\n%s\nBuildKit's\n%s", gm.Manifests[i].Platform, raw, w)
				}
			}
		})
	}
}

// TestAsBuiltKeepsOnlyBuildKitAnnotations checks the descriptor rules on
// their own: BuildKit's eStargz and OverlayBD layer annotations stay, every
// other annotation and field beyond media type, digest, size, and URLs goes.
func TestAsBuiltKeepsOnlyBuildKitAnnotations(t *testing.T) {
	h := v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("a", 64)}
	d := asBuilt(v1.Descriptor{
		MediaType: types.OCILayer, Size: 3, Digest: h,
		Annotations: map[string]string{
			"buildkit/rewritten-timestamp":             "1791849600",
			"org.opencontainers.image.title":           "layer.tar.gz",
			"containerd.io/snapshot/stargz/toc.digest": "sha256:toc",
			"io.containers.estargz.uncompressed-size":  "1024",
		},
		Platform: &v1.Platform{OS: "linux", Architecture: "amd64"},
		Data:     []byte("abc"),
	})
	want := map[string]string{"containerd.io/snapshot/stargz/toc.digest": "sha256:toc", "io.containers.estargz.uncompressed-size": "1024"}
	if d.MediaType != types.OCILayer || d.Size != 3 || d.Digest != h || d.Platform != nil || d.Data != nil || len(d.Annotations) != len(want) {
		t.Fatalf("asBuilt = %+v", d)
	}
	for k, v := range want {
		if d.Annotations[k] != v {
			t.Errorf("annotation %s = %q, want %q", k, d.Annotations[k], v)
		}
	}
	if d := asBuilt(v1.Descriptor{MediaType: types.OCILayer, Digest: h, Annotations: map[string]string{"buildkit/rewritten-timestamp": "1"}}); d.Annotations != nil {
		t.Errorf("annotations should be absent, not empty: %+v", d.Annotations)
	}
}

func readBlob(t *testing.T, digest string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "checkout", strings.TrimPrefix(digest, "sha256:")))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// blobImage is an image from testdata/checkout. Its layers are described
// but not stored, which is all a rebase needs to assemble the result.
func blobImage(t *testing.T, digest string) v1.Image {
	t.Helper()
	raw := readBlob(t, digest)
	m, err := v1.ParseManifest(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	img, err := partial.CompressedToImage(&blobCore{manifest: raw, parsed: m, config: readBlob(t, m.Config.Digest.String())})
	if err != nil {
		t.Fatal(err)
	}
	return img
}

type blobCore struct {
	manifest, config []byte
	parsed           *v1.Manifest
}

func (c *blobCore) RawManifest() ([]byte, error)        { return c.manifest, nil }
func (c *blobCore) RawConfigFile() ([]byte, error)      { return c.config, nil }
func (c *blobCore) MediaType() (types.MediaType, error) { return c.parsed.MediaType, nil }
func (c *blobCore) LayerByDigest(h v1.Hash) (partial.CompressedLayer, error) {
	for _, d := range c.parsed.Layers {
		if d.Digest == h {
			return describedLayer{d}, nil
		}
	}
	return nil, errors.New("no such layer")
}

// describedLayer is a layer known only by its descriptor.
type describedLayer struct{ d v1.Descriptor }

func (l describedLayer) Digest() (v1.Hash, error)            { return l.d.Digest, nil }
func (l describedLayer) Size() (int64, error)                { return l.d.Size, nil }
func (l describedLayer) MediaType() (types.MediaType, error) { return l.d.MediaType, nil }
func (l describedLayer) Compressed() (io.ReadCloser, error) {
	return nil, errors.New("layer contents are not in testdata")
}

// blobIndex is an index from testdata/checkout over blobImages.
func blobIndex(t *testing.T, digest string) v1.ImageIndex {
	t.Helper()
	raw := readBlob(t, digest)
	m, err := v1.ParseIndexManifest(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	images := map[v1.Hash]v1.Image{}
	for _, d := range m.Manifests {
		images[d.Digest] = blobImage(t, d.Digest.String())
	}
	return &index{manifest: raw, parsed: m, images: images}
}
