package factory

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/northcutted/clearcutt-factory/internal/lock"
	"github.com/northcutted/clearcutt-factory/internal/rebase"
	"github.com/northcutted/clearcutt-factory/internal/registry"
)

// moveTags points tags of repo at art, an image published before, and
// returns the tags it moved. A tag that holds an image superseding art (see
// supersedes) stays where it is unless force is set: republishing an image
// must not take a tag back to it, e.g. a rebuild from a lock that still
// pins the base an app was rebased off.
func moveTags(ctx context.Context, opts Options, art *registry.Artifact, repo string, tags []string, force bool) ([]string, error) {
	ref := repo + "@" + art.Digest
	var moved []string
	for _, tag := range tags {
		if !force {
			why, err := supersedes(ctx, repo+":"+tag, art)
			if err != nil {
				return moved, fmt.Errorf("checking what %s:%s holds before moving it to %s (--force-tags skips the check): %w", repo, tag, art.Digest, err)
			}
			if why != "" {
				opts.logf("warning: left %s:%s where it is: it holds %s; pass --force-tags to move it back to %s", repo, tag, why, shortDigest(art.Digest))
				continue
			}
		}
		if err := registry.Tag(ctx, ref, []string{tag}); err != nil {
			return moved, err
		}
		moved = append(moved, tag)
	}
	return moved, nil
}

// supersedes says why the image at tagRef is newer than art, or returns ""
// when the tag may move to art. It is newer when
//
//   - it carries art's own layers on another base, and art's base tag has
//     moved on from art's base: a rebase of art (or a rebuild with the same
//     layers) onto a newer build of the base. Rebasing an image again
//     keeps its layers, so this holds for rebases of rebases too; or
//   - it was created later than art: built from a newer lock (a build's
//     created time is the lock's SOURCE_DATE_EPOCH) or rebased onto a base
//     created later.
//
// A tag that doesn't exist or already points at art may move.
func supersedes(ctx context.Context, tagRef string, art *registry.Artifact) (string, error) {
	ok, err := registry.Exists(ctx, tagRef)
	if err != nil || !ok {
		return "", err
	}
	cur, err := registry.Fetch(ctx, tagRef)
	if err != nil {
		return "", err
	}
	if cur.Digest == art.Digest {
		return "", nil
	}
	curPlats, err := cur.Platforms()
	if err != nil {
		return "", err
	}
	artPlats, err := art.Platforms()
	if err != nil {
		return "", err
	}
	base, err := rebasedPast(ctx, curPlats, artPlats)
	if err != nil {
		return "", err
	}
	if base != "" {
		return fmt.Sprintf("%s, this image rebased onto a newer build of %s (merge the lock update that pins it)", shortDigest(cur.Digest), base), nil
	}
	ct, err := latestCreated(curPlats)
	if err != nil {
		return "", err
	}
	at, err := latestCreated(artPlats)
	if err != nil {
		return "", err
	}
	if ct.After(at) {
		return fmt.Sprintf("%s, created %s, after this image (%s): built from a newer lock, or rebased onto a newer base",
			shortDigest(cur.Digest), ct.UTC().Format(time.RFC3339), at.UTC().Format(time.RFC3339)), nil
	}
	return "", nil
}

// rebasedPast returns the base art names when, on every platform, cur
// carries art's own layers (those above art's base) on another base, and
// the base's tag no longer points at art's base. Otherwise it returns "".
func rebasedPast(ctx context.Context, cur, art []registry.PlatformImage) (string, error) {
	curByPlatform := map[string]registry.PlatformImage{}
	for _, p := range cur {
		curByPlatform[p.Platform] = p
	}
	current := map[string]map[string]string{} // base tag → platform → digest
	var name string
	for _, a := range art {
		am, err := a.Image.Manifest()
		if err != nil {
			return "", err
		}
		baseName, baseDigest := am.Annotations[rebase.AnnotationBaseName], am.Annotations[rebase.AnnotationBaseDigest]
		c, ok := curByPlatform[a.Platform]
		if baseName == "" || baseDigest == "" || !ok {
			return "", nil
		}
		cm, err := c.Image.Manifest()
		if err != nil {
			return "", err
		}
		if cm.Annotations[rebase.AnnotationBaseDigest] == baseDigest {
			return "", nil
		}
		baseRef := lock.RepoOf(baseName) + "@" + baseDigest
		base, err := registry.Fetch(ctx, baseRef)
		if err != nil {
			return "", fmt.Errorf("fetching %s's base %s: %w", a.Platform, baseRef, err)
		}
		if base.Image == nil {
			return "", nil
		}
		bm, err := base.Image.Manifest()
		if err != nil {
			return "", err
		}
		if rebase.BasedOn(am, bm) != nil {
			return "", nil
		}
		own := am.Layers[len(bm.Layers):]
		if len(own) == 0 || len(cm.Layers) < len(own) {
			return "", nil
		}
		for i, l := range cm.Layers[len(cm.Layers)-len(own):] {
			if l.Digest != own[i].Digest {
				return "", nil
			}
		}
		if current[baseName] == nil {
			if current[baseName], err = registry.PlatformDigests(ctx, baseName); err != nil {
				return "", err
			}
		}
		if current[baseName][a.Platform] == baseDigest {
			return "", nil
		}
		name = baseName
	}
	return name, nil
}

// latestCreated returns the latest created time of the platform images.
func latestCreated(plats []registry.PlatformImage) (time.Time, error) {
	var t time.Time
	for _, p := range plats {
		cf, err := p.Image.ConfigFile()
		if err != nil {
			return time.Time{}, err
		}
		if cf.Created.After(t) {
			t = cf.Created.Time
		}
	}
	return t, nil
}

// shortDigest abbreviates a digest for messages.
func shortDigest(d string) string {
	if algo, hex, ok := strings.Cut(d, ":"); ok && len(hex) > 12 {
		return algo + ":" + hex[:12]
	}
	return d
}
