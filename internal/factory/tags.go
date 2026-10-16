package factory

import (
	"context"
	"errors"
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
// pins the base an app was rebased off. A tag in held that has moved
// since stays too (see retag) and is returned in left.
func moveTags(ctx context.Context, opts Options, art *registry.Artifact, repo string, tags []string, force bool, held map[string]string) (moved []string, left movedTags, err error) {
	ref := repo + "@" + art.Digest
	for _, tag := range tags {
		if !force {
			why, err := supersedes(ctx, repo+":"+tag, art)
			if err != nil {
				return moved, left, fmt.Errorf("checking what %s:%s holds before moving it to %s (--force-tags skips the check): %w", repo, tag, art.Digest, err)
			}
			if why != "" {
				opts.logf("warning: left %s:%s where it is: it holds %s; pass --force-tags to move it back to %s", repo, tag, why, shortDigest(art.Digest))
				continue
			}
		}
		ok, err := retag(ctx, ref, tag, held, &left)
		if err != nil {
			return moved, left, err
		}
		if ok {
			moved = append(moved, tag)
		}
	}
	return moved, left, nil
}

// retag points tag at ref, an image already in the registry. A tag in held
// moves only if it still holds the digest held names for it ("" for none):
// what it held when the caller decided to move it. Otherwise it stays, it
// is added to left, and retag returns false.
func retag(ctx context.Context, ref, tag string, held map[string]string, left *movedTags) (bool, error) {
	want, ok := held[tag]
	if !ok {
		return true, registry.Tag(ctx, ref, []string{tag})
	}
	err := registry.TagIf(ctx, ref, tag, want)
	var moved *registry.MovedError
	if errors.As(err, &moved) {
		*left = append(*left, moved)
		return false, nil
	}
	return err == nil, err
}

// movedTags lists tags left where they are because they moved after the
// caller looked: another publish took them.
type movedTags []*registry.MovedError

func (m movedTags) Error() string {
	s := make([]string, len(m))
	for i, e := range m {
		s[i] = e.Error()
	}
	return strings.Join(s, "; ")
}

func (m movedTags) orNil() error {
	if len(m) == 0 {
		return nil
	}
	return m
}

// onNewerBase looks up what each of repo's tags holds ("" for none) before
// a build moves them to art, and says why art must not take them as it is:
// a tag holds an image on a newer build of art's base. That is, on some
// platform, the same base (org.opencontainers.image.base.name) at another
// digest while the base's tag no longer points at art's, where the base's
// tag points now or created after art's base. why is "" when no tag holds
// such an image, or art doesn't name its base.
func onNewerBase(ctx context.Context, art *registry.Artifact, repo string, tags []string) (why string, held map[string]string, err error) {
	plats, err := art.Platforms()
	if err != nil {
		return "", nil, err
	}
	type base struct{ name, digest string }
	bases := map[string]base{} // platform → art's base
	for _, p := range plats {
		m, err := p.Image.Manifest()
		if err != nil {
			return "", nil, err
		}
		n, d := m.Annotations[rebase.AnnotationBaseName], m.Annotations[rebase.AnnotationBaseDigest]
		if n == "" || d == "" {
			return "", nil, nil
		}
		bases[p.Platform] = base{registry.Qualify(n), d}
	}
	held = map[string]string{}
	current := map[string]map[string]string{} // base tag → platform → digest
	for _, tag := range tags {
		d, err := registry.Lookup(ctx, repo+":"+tag)
		if err != nil {
			return "", nil, err
		}
		held[tag] = d
		if why != "" || d == "" || d == art.Digest {
			continue
		}
		cur, err := registry.Fetch(ctx, repo+"@"+d)
		if err != nil {
			return "", nil, err
		}
		curPlats, err := cur.Platforms()
		if err != nil {
			return "", nil, err
		}
		for _, c := range curPlats {
			b, ok := bases[c.Platform]
			if !ok {
				continue
			}
			cm, err := c.Image.Manifest()
			if err != nil {
				return "", nil, err
			}
			cd := cm.Annotations[rebase.AnnotationBaseDigest]
			if registry.Qualify(cm.Annotations[rebase.AnnotationBaseName]) != b.name || cd == "" || cd == b.digest {
				continue
			}
			if current[b.name] == nil {
				if current[b.name], err = registry.PlatformDigests(ctx, b.name); err != nil {
					return "", nil, err
				}
			}
			now := current[b.name][c.Platform]
			if now == b.digest {
				continue
			}
			newer := cd == now
			if !newer {
				if newer, err = createdAfter(ctx, b.name, cd, b.digest); err != nil {
					return "", nil, err
				}
			}
			if newer {
				why = fmt.Sprintf("%s:%s holds %s, on a newer build of %s (%s) than this image's (%s)", repo, tag, shortDigest(d), b.name, shortDigest(cd), shortDigest(b.digest))
				break
			}
		}
	}
	return why, held, nil
}

// createdAfter reports whether image a of base (by digest) was created
// after image b.
func createdAfter(ctx context.Context, base, a, b string) (bool, error) {
	var t [2]time.Time
	for i, d := range []string{a, b} {
		img, err := registry.Fetch(ctx, lock.RepoOf(base)+"@"+d)
		if err != nil {
			return false, fmt.Errorf("fetching %s's build %s: %w", base, d, err)
		}
		plats, err := img.Platforms()
		if err != nil {
			return false, err
		}
		if t[i], err = latestCreated(plats); err != nil {
			return false, err
		}
	}
	return t[0].After(t[1]), nil
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
