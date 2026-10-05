// Package diff explains why two builds of the same recipe differ, down to the
// files inside the first differing layer.
package diff

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/northcutted/declarative-image-factory/internal/registry"
)

// Artifacts describes differences between want and got, platform by platform.
func Artifacts(want, got *registry.Artifact, maxFiles int) (string, error) {
	wp, err := want.Platforms()
	if err != nil {
		return "", err
	}
	gp, err := got.Platforms()
	if err != nil {
		return "", err
	}
	byPlat := map[string]registry.PlatformImage{}
	for _, p := range gp {
		byPlat[p.Platform] = p
	}
	var b strings.Builder
	for _, w := range wp {
		g, ok := byPlat[w.Platform]
		if !ok {
			fmt.Fprintf(&b, "%s: missing from rebuild\n", w.Platform)
			continue
		}
		if w.Digest == g.Digest {
			fmt.Fprintf(&b, "%s: identical (%s)\n", w.Platform, w.Digest)
			continue
		}
		fmt.Fprintf(&b, "%s: %s → %s\n", w.Platform, w.Digest, g.Digest)
		if err := images(&b, w.Image, g.Image, maxFiles); err != nil {
			return "", err
		}
	}
	return b.String(), nil
}

func images(b *strings.Builder, want, got v1.Image, maxFiles int) error {
	wl, err := want.Layers()
	if err != nil {
		return err
	}
	gl, err := got.Layers()
	if err != nil {
		return err
	}
	if len(wl) != len(gl) {
		fmt.Fprintf(b, "  layer count differs: %d vs %d\n", len(wl), len(gl))
	}
	for i := 0; i < min(len(wl), len(gl)); i++ {
		wd, _ := wl[i].Digest()
		gd, _ := gl[i].Digest()
		if wd == gd {
			continue
		}
		fmt.Fprintf(b, "  first differing layer #%d: %s vs %s\n", i, wd, gd)
		wf, err := files(wl[i])
		if err != nil {
			return err
		}
		gf, err := files(gl[i])
		if err != nil {
			return err
		}
		var lines []string
		for name, w := range wf {
			g, ok := gf[name]
			switch {
			case !ok:
				lines = append(lines, "    - "+name)
			case w != g:
				lines = append(lines, fmt.Sprintf("    ~ %s (%s → %s)", name, w, g))
			}
		}
		for name := range gf {
			if _, ok := wf[name]; !ok {
				lines = append(lines, "    + "+name)
			}
		}
		sort.Strings(lines)
		if len(lines) == 0 {
			lines = []string{"    (same files; tar headers or compression differ)"}
		}
		if len(lines) > maxFiles {
			lines = append(lines[:maxFiles], fmt.Sprintf("    … and %d more", len(lines)-maxFiles))
		}
		b.WriteString(strings.Join(lines, "\n") + "\n")
		return nil
	}
	wc, _ := want.ConfigName()
	gc, _ := got.ConfigName()
	if wc != gc {
		fmt.Fprintf(b, "  layers identical; image config differs: %s vs %s\n", wc, gc)
	}
	return nil
}

// files summarizes each entry as "mode uid:gid mtime sha256".
func files(l v1.Layer) (map[string]string, error) {
	rc, err := l.Uncompressed()
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	out := map[string]string{}
	tr := tar.NewReader(rc)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		h256 := sha256.New()
		if _, err := io.Copy(h256, tr); err != nil {
			return nil, err
		}
		out[h.Name] = fmt.Sprintf("%o %d:%d %d %s%s", h.Mode, h.Uid, h.Gid, h.ModTime.Unix(),
			hex.EncodeToString(h256.Sum(nil))[:12], h.Linkname)
	}
}
