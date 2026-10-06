// Package registry wraps go-containerregistry for the few operations factory
// needs: resolve digests, read files out of images, and move OCI layouts.
package registry

import (
	"archive/tar"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

func opts(ctx context.Context) []remote.Option {
	return []remote.Option{remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain)}
}

// Digest resolves ref to the digest of what it points at (an index for
// multi-platform images).
func Digest(ctx context.Context, ref string) (string, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return "", err
	}
	desc, err := remote.Head(r, opts(ctx)...)
	if err != nil {
		// Some registries reject HEAD; fall back to GET.
		d, gerr := remote.Get(r, opts(ctx)...)
		if gerr != nil {
			return "", fmt.Errorf("resolving %s: %w", ref, err)
		}
		return d.Digest.String(), nil
	}
	return desc.Digest.String(), nil
}

// ReadFiles returns the contents of the named paths (relative, no leading
// slash) from the flattened filesystem of ref for platform. A path ending in
// "/" selects every regular file below it. Missing files are absent from the
// result.
func ReadFiles(ctx context.Context, ref, platform string, paths ...string) (map[string][]byte, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return nil, err
	}
	p, err := v1.ParsePlatform(platform)
	if err != nil {
		return nil, err
	}
	img, err := remote.Image(r, append(opts(ctx), remote.WithPlatform(*p))...)
	if err != nil {
		return nil, fmt.Errorf("pulling %s for %s: %w", ref, platform, err)
	}
	rc := mutate.Extract(img)
	defer func() { _ = rc.Close() }()

	want := map[string]bool{}
	var dirs []string
	for _, p := range paths {
		if strings.HasSuffix(p, "/") {
			dirs = append(dirs, p)
		} else {
			want[p] = true
		}
	}
	out := map[string][]byte{}
	tr := tar.NewReader(rc)
	for len(dirs) > 0 || len(out) < len(want) {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		n := strings.TrimPrefix(path.Clean("/"+h.Name), "/")
		inDir := false
		for _, d := range dirs {
			inDir = inDir || strings.HasPrefix(n, d)
		}
		if (want[n] || inDir) && h.Typeflag == tar.TypeReg {
			b, err := io.ReadAll(tr)
			if err != nil {
				return nil, err
			}
			out[n] = b
		}
	}
	return out, nil
}

// Artifact is a built or pushed image: a multi-platform index, or a single
// image when only one platform was built.
type Artifact struct {
	Digest string
	Index  v1.ImageIndex // nil for a single image
	Image  v1.Image      // nil for an index
}

// OpenLayout returns the artifact stored in an OCI layout written by BuildKit
// (the layout's index.json points at exactly one index or image).
func OpenLayout(dir string) (*Artifact, error) {
	lp, err := layout.FromPath(dir)
	if err != nil {
		return nil, err
	}
	top, err := lp.ImageIndex()
	if err != nil {
		return nil, err
	}
	im, err := top.IndexManifest()
	if err != nil {
		return nil, err
	}
	if len(im.Manifests) != 1 {
		return nil, fmt.Errorf("%s: expected one entry in index.json, found %d", dir, len(im.Manifests))
	}
	d := im.Manifests[0]
	a := &Artifact{Digest: d.Digest.String()}
	if d.MediaType.IsIndex() {
		a.Index, err = top.ImageIndex(d.Digest)
	} else {
		a.Image, err = top.Image(d.Digest)
	}
	return a, err
}

// Fetch returns the pushed artifact at ref.
func Fetch(ctx context.Context, ref string) (*Artifact, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return nil, err
	}
	desc, err := remote.Get(r, opts(ctx)...)
	if err != nil {
		return nil, err
	}
	a := &Artifact{Digest: desc.Digest.String()}
	if desc.MediaType.IsIndex() {
		a.Index, err = desc.ImageIndex()
	} else {
		a.Image, err = desc.Image()
	}
	return a, err
}

// PlatformImage is one platform-specific image of an artifact.
type PlatformImage struct {
	Platform string
	Digest   string
	Image    v1.Image
}

// Platforms lists the platform images, skipping attestation manifests.
func (a *Artifact) Platforms() ([]PlatformImage, error) {
	if a.Image != nil {
		cfg, err := a.Image.ConfigFile()
		if err != nil {
			return nil, err
		}
		return []PlatformImage{{Platform: cfg.OS + "/" + cfg.Architecture, Digest: a.Digest, Image: a.Image}}, nil
	}
	im, err := a.Index.IndexManifest()
	if err != nil {
		return nil, err
	}
	var out []PlatformImage
	for _, d := range im.Manifests {
		if d.Platform == nil || d.Platform.OS == "unknown" {
			continue
		}
		img, err := a.Index.Image(d.Digest)
		if err != nil {
			return nil, err
		}
		p := d.Platform.OS + "/" + d.Platform.Architecture
		out = append(out, PlatformImage{Platform: p, Digest: d.Digest.String(), Image: img})
	}
	return out, nil
}

// PlatformDigests returns the digest of each platform image of ref.
func PlatformDigests(ctx context.Context, ref string) (map[string]string, error) {
	a, err := Fetch(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", ref, err)
	}
	plats, err := a.Platforms()
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, p := range plats {
		out[p.Platform] = p.Digest
	}
	return out, nil
}

// WriteImageLayout writes a single image as its own OCI layout (scanners want
// one image, not a multi-platform index).
func WriteImageLayout(dir string, img v1.Image) error {
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	lp, err := layout.Write(dir, empty.Index)
	if err != nil {
		return err
	}
	return lp.AppendImage(img)
}

// Exists reports whether ref (by digest) is in its registry.
func Exists(ctx context.Context, ref string) (bool, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return false, err
	}
	_, err = remote.Head(r, opts(ctx)...)
	var terr *transport.Error
	switch {
	case err == nil:
		return true, nil
	case errors.As(err, &terr) && terr.StatusCode == http.StatusNotFound:
		return false, nil
	}
	return false, fmt.Errorf("checking %s: %w", ref, err)
}

// Tag points each tag of ref's repository at ref (by digest).
func Tag(ctx context.Context, ref string, tags []string) error {
	d, err := name.NewDigest(ref)
	if err != nil {
		return err
	}
	desc, err := remote.Get(d, opts(ctx)...)
	if err != nil {
		return err
	}
	for _, tag := range tags {
		if err := remote.Tag(d.Context().Tag(tag), desc, opts(ctx)...); err != nil {
			return fmt.Errorf("tagging %s: %w", d.Context().Tag(tag), err)
		}
	}
	return nil
}

// WriteLayout writes the artifact as an OCI layout (one entry in index.json,
// as BuildKit writes it).
func WriteLayout(dir string, a *Artifact) error {
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	lp, err := layout.Write(dir, empty.Index)
	if err != nil {
		return err
	}
	if a.Index != nil {
		return lp.AppendIndex(a.Index)
	}
	return lp.AppendImage(a.Image)
}

// Push uploads the artifact to repo by digest, then points each tag at it. It
// returns the pushed digest reference.
func Push(ctx context.Context, a *Artifact, repo string, tags []string) (string, error) {
	r, err := name.NewRepository(repo)
	if err != nil {
		return "", err
	}
	byDigest := r.Digest(a.Digest)
	var t remote.Taggable = a.Image
	if a.Index != nil {
		t = a.Index
		err = remote.WriteIndex(byDigest, a.Index, opts(ctx)...)
	} else {
		err = remote.Write(byDigest, a.Image, opts(ctx)...)
	}
	if err != nil {
		return "", fmt.Errorf("pushing %s: %w", byDigest, err)
	}
	for _, tag := range tags {
		if err := remote.Tag(r.Tag(tag), t, opts(ctx)...); err != nil {
			return "", fmt.Errorf("tagging %s: %w", r.Tag(tag), err)
		}
	}
	return byDigest.String(), nil
}

// Qualify spells out a reference's registry and repository (golang:1 →
// docker.io/library/golang:1), the way BuildKit and go-containerregistry read
// short names. Runtimes like podman may otherwise map short names elsewhere.
func Qualify(ref string) string {
	r, err := name.ParseReference(ref)
	if err != nil {
		return ref
	}
	repo := r.Context().Name()
	if rest, ok := strings.CutPrefix(repo, name.DefaultRegistry+"/"); ok {
		repo = "docker.io/" + rest
	}
	// Keep any tag (even next to a digest, for readability; the digest wins).
	base, _, _ := strings.Cut(ref, "@")
	out := repo
	if i := strings.LastIndex(base, ":"); i > strings.LastIndex(base, "/") {
		out += base[i:]
	}
	if d, ok := r.(name.Digest); ok {
		out += "@" + d.DigestStr()
	}
	return out
}

// PlatformRef returns ref narrowed to the image for platform: when ref names
// a multi-platform index, the platform's own manifest by digest (which the
// index digest pins). Docker's classic image store can't keep two platforms
// pulled under one index digest, so containers run the platform image.
func PlatformRef(ctx context.Context, ref, platform string) (string, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return "", err
	}
	want, err := v1.ParsePlatform(platform)
	if err != nil {
		return "", err
	}
	desc, err := remote.Get(r, opts(ctx)...)
	if err != nil {
		return "", fmt.Errorf("resolving %s: %w", ref, err)
	}
	if !desc.MediaType.IsIndex() {
		return ref, nil
	}
	idx, err := desc.ImageIndex()
	if err != nil {
		return "", err
	}
	im, err := idx.IndexManifest()
	if err != nil {
		return "", err
	}
	for _, d := range im.Manifests {
		if d.Platform != nil && d.MediaType.IsImage() && d.Platform.Satisfies(*want) {
			return Qualify(r.Context().Name()) + "@" + d.Digest.String(), nil
		}
	}
	return "", fmt.Errorf("%s has no %s image", ref, platform)
}

// Registry returns the registry host of an image reference, normalized the
// way Docker config files key it.
func Registry(ref string) (string, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return "", err
	}
	return r.Context().RegistryStr(), nil
}

// WriteDockerConfig writes a config.json carrying credentials for registries,
// resolved through the local keychain (including credential helpers), so a
// containerized BuildKit can pull private images. Registries without
// credentials are omitted.
func WriteDockerConfig(path string, registries []string) error {
	type entry struct {
		Auth string `json:"auth,omitempty"`
	}
	auths := map[string]entry{}
	for _, reg := range registries {
		r, err := name.NewRegistry(reg)
		if err != nil {
			return err
		}
		a, err := authn.DefaultKeychain.Resolve(r)
		if err != nil {
			return err
		}
		cfg, err := a.Authorization()
		if err != nil {
			return err
		}
		auth := cfg.Auth
		if auth == "" && cfg.Username != "" {
			auth = base64.StdEncoding.EncodeToString([]byte(cfg.Username + ":" + cfg.Password))
		}
		if auth == "" {
			continue
		}
		key := reg
		if reg == name.DefaultRegistry {
			key = "https://index.docker.io/v1/"
		}
		auths[key] = entry{Auth: auth}
	}
	b, err := json.Marshal(map[string]any{"auths": auths})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}
