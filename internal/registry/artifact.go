package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// The OCI 1.1 empty config descriptor for artifacts.
var emptyConfig = []byte("{}")

// titleAnnotation names a file in an artifact.
const titleAnnotation = "org.opencontainers.image.title"

// Limits on what is read back from an artifact.
const (
	maxFileSize  = 4 << 20
	maxFiles     = 64
	maxTotalSize = 16 << 20
)

// File is one file of an OCI artifact: a layer of MediaType whose title is
// Name, a relative slash-separated path.
type File struct {
	Name      string
	MediaType string
	Content   []byte
}

// PushFile pushes content as a single-file OCI artifact of artifactType to
// ref and returns its digest.
func PushFile(ctx context.Context, ref, artifactType, fileName string, content []byte) (string, error) {
	return PushFiles(ctx, ref, artifactType, []File{{Name: fileName, MediaType: artifactType, Content: content}})
}

// PushFiles pushes files, in order, as an OCI artifact of artifactType to
// ref and returns its digest.
func PushFiles(ctx context.Context, ref, artifactType string, files []File) (string, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return "", err
	}
	img, err := filesArtifact(artifactType, files)
	if err != nil {
		return "", err
	}
	if err := remote.Write(r, img, opts(ctx)...); err != nil {
		return "", fmt.Errorf("pushing %s: %w", ref, err)
	}
	d, err := img.Digest()
	if err != nil {
		return "", err
	}
	return d.String(), nil
}

// FileDigest is the digest PushFile gives the artifact, without pushing it.
func FileDigest(artifactType, fileName string, content []byte) (string, error) {
	return FilesDigest(artifactType, []File{{Name: fileName, MediaType: artifactType, Content: content}})
}

// FilesDigest is the digest PushFiles gives the artifact, without pushing it.
func FilesDigest(artifactType string, files []File) (string, error) {
	b, err := PackFiles(artifactType, files)
	if err != nil {
		return "", err
	}
	return b.Digest, nil
}

// Bundle is an artifact of files: its manifest as stored, the manifest's
// digest (the artifact's), and its files.
type Bundle struct {
	Manifest []byte
	Digest   string
	Files    []File
}

// PackFiles is the artifact PushFiles pushes, without pushing it.
func PackFiles(artifactType string, files []File) (*Bundle, error) {
	img, err := filesArtifact(artifactType, files)
	if err != nil {
		return nil, err
	}
	raw, err := img.RawManifest()
	if err != nil {
		return nil, err
	}
	d, err := img.Digest()
	if err != nil {
		return nil, err
	}
	return &Bundle{Manifest: raw, Digest: d.String(), Files: files}, nil
}

// filesArtifact assembles the artifact; its digest depends only on its
// arguments.
func filesArtifact(artifactType string, files []File) (v1.Image, error) {
	config := static.NewLayer(emptyConfig, "application/vnd.oci.empty.v1+json")
	cd, err := partial.Descriptor(config)
	if err != nil {
		return nil, err
	}
	a := &artifact{config: config, layers: map[v1.Hash]v1.Layer{}}
	m := v1.Manifest{
		SchemaVersion: 2,
		MediaType:     types.OCIManifestSchema1,
		ArtifactType:  artifactType,
		Config:        *cd,
	}
	for _, f := range files {
		layer := static.NewLayer(f.Content, types.MediaType(f.MediaType))
		ld, err := partial.Descriptor(layer)
		if err != nil {
			return nil, err
		}
		ld.Annotations = map[string]string{titleAnnotation: f.Name}
		m.Layers = append(m.Layers, *ld)
		a.layers[ld.Digest] = layer
	}
	if a.manifest, err = json.Marshal(m); err != nil {
		return nil, err
	}
	return partial.CompressedToImage(a)
}

// FetchFile reads a single-file artifact of artifactType at ref and returns
// its content and the artifact's digest.
func FetchFile(ctx context.Context, ref, artifactType string) ([]byte, string, error) {
	files, d, _, err := fetchFiles(ctx, ref, artifactType, false)
	if err != nil {
		return nil, "", err
	}
	if len(files) != 1 || files[0].MediaType != artifactType {
		return nil, "", fmt.Errorf("%s is not a %s artifact", ref, artifactType)
	}
	return files[0].Content, d, nil
}

// FetchFiles reads every file of an artifact of artifactType at ref, each
// checked against its digest, and returns them with the artifact's digest.
// Files must have distinct titles that are local relative paths.
func FetchFiles(ctx context.Context, ref, artifactType string) ([]File, string, error) {
	b, err := FetchBundle(ctx, ref, artifactType)
	if err != nil {
		return nil, "", err
	}
	return b.Files, b.Digest, nil
}

// FetchBundle is FetchFiles, keeping the artifact's manifest as the
// registry served it, so that a copy kept elsewhere can be checked against
// the digest with ReadBundle.
func FetchBundle(ctx context.Context, ref, artifactType string) (*Bundle, error) {
	files, d, raw, err := fetchFiles(ctx, ref, artifactType, true)
	if err != nil {
		return nil, err
	}
	return &Bundle{Manifest: raw, Digest: d, Files: files}, nil
}

// ReadBundle reads back an artifact of artifactType kept outside a
// registry, e.g. in a local cache: manifest must be the manifest digest
// names, and read returns each file it lists by name, which must match the
// digest the manifest gives it. What it returns is the artifact digest
// names, or an error.
func ReadBundle(manifest []byte, digest, artifactType string, read func(name string, size int64) ([]byte, error)) ([]File, error) {
	h, err := v1.NewHash(digest)
	if err != nil {
		return nil, err
	}
	return checkFiles(digest, manifest, h, artifactType, true, func(n string, l v1.Descriptor) ([]byte, error) { return read(n, l.Size) })
}

// fetchFiles is FetchBundle; named false accepts a single file without
// a title.
func fetchFiles(ctx context.Context, ref, artifactType string, named bool) ([]File, string, []byte, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return nil, "", nil, err
	}
	desc, err := remote.Get(r, opts(ctx)...)
	if err != nil {
		return nil, "", nil, fmt.Errorf("fetching %s: %w", ref, err)
	}
	files, err := checkFiles(ref, desc.Manifest, desc.Digest, artifactType, named, func(_ string, l v1.Descriptor) ([]byte, error) {
		return readBlob(ctx, r.Context().Digest(l.Digest.String()))
	})
	if err != nil {
		return nil, "", nil, err
	}
	return files, desc.Digest.String(), desc.Manifest, nil
}

// checkFiles checks that raw, the manifest of what (a reference, for
// messages), has digest and is an artifact of artifactType, and reads its
// files with read, checking each against its digest.
func checkFiles(what string, raw []byte, digest v1.Hash, artifactType string, named bool, read func(name string, l v1.Descriptor) ([]byte, error)) ([]File, error) {
	if got, _, err := v1.SHA256(bytes.NewReader(raw)); err != nil || got != digest {
		return nil, fmt.Errorf("%s: the manifest does not match its digest %s", what, digest)
	}
	var m v1.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	if m.ArtifactType != artifactType || len(m.Layers) == 0 || len(m.Layers) > maxFiles {
		return nil, fmt.Errorf("%s is not a %s artifact", what, artifactType)
	}
	var files []File
	seen := map[string]bool{}
	total := int64(0)
	for _, l := range m.Layers {
		n := l.Annotations[titleAnnotation]
		if n == "" && !named && len(m.Layers) == 1 {
			n = "file"
		}
		if n == "" || !filepath.IsLocal(filepath.FromSlash(n)) || seen[n] {
			return nil, fmt.Errorf("%s: file name %q is missing, repeated, or not a relative path", what, n)
		}
		seen[n] = true
		if total += l.Size; l.Size < 0 || l.Size > maxFileSize || total > maxTotalSize {
			return nil, fmt.Errorf("%s: %s is too large", what, n)
		}
		content, err := read(n, l)
		if err != nil {
			return nil, fmt.Errorf("%s: %s: %w", what, n, err)
		}
		if got, _, _ := v1.SHA256(bytes.NewReader(content)); got != l.Digest {
			return nil, fmt.Errorf("%s: %s does not match its digest", what, n)
		}
		files = append(files, File{Name: n, MediaType: string(l.MediaType), Content: content})
	}
	return files, nil
}

func readBlob(ctx context.Context, d name.Digest) ([]byte, error) {
	l, err := remote.Layer(d, opts(ctx)...)
	if err != nil {
		return nil, err
	}
	rc, err := l.Compressed()
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	return io.ReadAll(io.LimitReader(rc, maxFileSize+1))
}

// artifact is a minimal OCI artifact: an empty config and its files.
type artifact struct {
	manifest []byte
	config   v1.Layer
	layers   map[v1.Hash]v1.Layer
}

func (a *artifact) RawManifest() ([]byte, error)        { return a.manifest, nil }
func (a *artifact) RawConfigFile() ([]byte, error)      { return emptyConfig, nil }
func (a *artifact) MediaType() (types.MediaType, error) { return types.OCIManifestSchema1, nil }
func (a *artifact) LayerByDigest(h v1.Hash) (partial.CompressedLayer, error) {
	if l, ok := a.layers[h]; ok {
		return l, nil
	}
	if d, _ := a.config.Digest(); h == d {
		return a.config, nil
	}
	return nil, fmt.Errorf("blob %s is not part of this artifact", h)
}
