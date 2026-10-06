package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// The OCI 1.1 empty config descriptor for artifacts.
var emptyConfig = []byte("{}")

// PushFile pushes content as a single-file OCI artifact of artifactType to
// ref and returns its digest.
func PushFile(ctx context.Context, ref, artifactType, fileName string, content []byte) (string, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return "", err
	}
	layer := static.NewLayer(content, types.MediaType(artifactType))
	config := static.NewLayer(emptyConfig, "application/vnd.oci.empty.v1+json")
	ld, err := partial.Descriptor(layer)
	if err != nil {
		return "", err
	}
	ld.Annotations = map[string]string{"org.opencontainers.image.title": fileName}
	cd, err := partial.Descriptor(config)
	if err != nil {
		return "", err
	}
	m := v1.Manifest{
		SchemaVersion: 2,
		MediaType:     types.OCIManifestSchema1,
		ArtifactType:  artifactType,
		Config:        *cd,
		Layers:        []v1.Descriptor{*ld},
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	img, err := partial.CompressedToImage(&artifact{manifest: raw, config: config, layer: layer, layerDigest: ld.Digest})
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

// FetchFile reads a single-file artifact of artifactType at ref and returns
// its content and the artifact's digest.
func FetchFile(ctx context.Context, ref, artifactType string) ([]byte, string, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return nil, "", err
	}
	desc, err := remote.Get(r, opts(ctx)...)
	if err != nil {
		return nil, "", fmt.Errorf("fetching %s: %w", ref, err)
	}
	var m v1.Manifest
	if err := json.Unmarshal(desc.Manifest, &m); err != nil {
		return nil, "", fmt.Errorf("%s: %w", ref, err)
	}
	if m.ArtifactType != artifactType || len(m.Layers) != 1 || string(m.Layers[0].MediaType) != artifactType {
		return nil, "", fmt.Errorf("%s is not a %s artifact", ref, artifactType)
	}
	l, err := remote.Layer(r.Context().Digest(m.Layers[0].Digest.String()), opts(ctx)...)
	if err != nil {
		return nil, "", err
	}
	rc, err := l.Compressed()
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = rc.Close() }()
	content, err := io.ReadAll(io.LimitReader(rc, 4<<20))
	if err != nil {
		return nil, "", err
	}
	if got, _, _ := v1.SHA256(bytes.NewReader(content)); got != m.Layers[0].Digest {
		return nil, "", fmt.Errorf("%s: content does not match its digest", ref)
	}
	return content, desc.Digest.String(), nil
}

// artifact is a minimal OCI artifact: an empty config and one file.
type artifact struct {
	manifest    []byte
	config      v1.Layer
	layer       v1.Layer
	layerDigest v1.Hash
}

func (a *artifact) RawManifest() ([]byte, error)        { return a.manifest, nil }
func (a *artifact) RawConfigFile() ([]byte, error)      { return emptyConfig, nil }
func (a *artifact) MediaType() (types.MediaType, error) { return types.OCIManifestSchema1, nil }
func (a *artifact) LayerByDigest(h v1.Hash) (partial.CompressedLayer, error) {
	if h == a.layerDigest {
		return a.layer, nil
	}
	if d, _ := a.config.Digest(); h == d {
		return a.config, nil
	}
	return nil, fmt.Errorf("blob %s is not part of this artifact", h)
}
