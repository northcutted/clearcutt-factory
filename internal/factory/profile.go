package factory

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/northcutted/clearcutt-factory/internal/attest"
	"github.com/northcutted/clearcutt-factory/internal/lock"
	"github.com/northcutted/clearcutt-factory/internal/manifest"
	"github.com/northcutted/clearcutt-factory/internal/registry"
)

// ProfilePushOptions are profile push's settings.
type ProfilePushOptions struct {
	// Ref is where to publish, e.g. ghcr.io/acme/factory/org:1.
	Ref string
	// Key signs the profile with this key (a file or KMS URI) instead of
	// signing.stackKey or signing.key, whatever signing.mode says.
	Key    string
	NoSign bool
}

// ProfilePush publishes an org profile so that repositories can extend it
// (extends: {ref: REF, signer: …}), then signs it as stack push signs
// stacks. The artifact holds the profile and the files it names (its trust
// policy, public keys, and VEX documents), so it is complete on its own. A
// profile is published by its content, so when the registry already has
// that digest, signed by signing.profile (or signing is off), it only
// moves the tag.
func ProfilePush(ctx context.Context, opts Options, file string, po ProfilePushOptions) error {
	if po.Key != "" && po.NoSign {
		return errors.New("--key signs the profile; drop --key or --no-sign")
	}
	org, bundled, err := manifest.PackProfile(file)
	if err != nil {
		return err
	}
	files := make([]registry.File, len(bundled))
	for i, f := range bundled {
		files[i] = registry.File{Name: f.Name, MediaType: f.MediaType, Content: f.Content}
	}
	d, err := registry.FilesDigest(manifest.ProfileArtifactType, files)
	if err != nil {
		return err
	}
	repo := lock.RepoOf(po.Ref)
	pushed := repo + "@" + d
	signer := stackSigner(opts, org, StackPushOptions{Key: po.Key, NoSign: po.NoSign})
	if signer != nil && signer.Mode == "key" && signer.Key == "" {
		return errors.New("signing.mode is key, and the profile names no key to sign it with (signing.stackKey or signing.key): pass --key")
	}
	exists, err := registry.Exists(ctx, pushed)
	if err != nil {
		return err
	}
	if exists && (signer == nil || signedBy(ctx, org.Signing.Profile, pushed)) {
		r, err := name.ParseReference(po.Ref)
		if err != nil {
			return err
		}
		if t, ok := r.(name.Tag); ok {
			if err := registry.Tag(ctx, pushed, []string{t.TagStr()}); err != nil {
				return err
			}
			opts.printf("profile %s is already published at %s; moved %s", rel(file), pushed, t.TagStr())
		} else {
			opts.printf("profile %s is already published at %s", rel(file), pushed)
		}
		return githubOutput(Result{Image: pushed, Repository: repo, Digest: d, Signed: signer != nil, Published: false})
	}
	if _, err := registry.PushFiles(ctx, po.Ref, manifest.ProfileArtifactType, files); err != nil {
		return err
	}
	opts.printf("pushed profile %s to %s (%d files)", rel(file), pushed, len(files))
	if signer != nil {
		if err := signer.Run(ctx, "sign", pushed); err != nil {
			return err
		}
		opts.printf("signed %s", pushed)
	}
	if org.Signing.Profile.IsZero() {
		opts.printf("note: set signing.profile to who signs it, so that pushing it unchanged only moves the tag")
	}
	return githubOutput(Result{Image: pushed, Repository: repo, Digest: d, Signed: signer != nil, Published: true})
}

// signedBy reports whether ref carries a signature from v. With no
// signer, it can't tell, and says no.
func signedBy(ctx context.Context, v manifest.VerifyIdentity, ref string) bool {
	if v.IsZero() {
		return false
	}
	args, err := identityArgs(v, "")
	return err == nil && attest.VerifySignature(ctx, ref, args) == nil
}

// loadOrg loads the org profile for startDir (or --org). A shared profile
// it extends is fetched at the digest pin returns for its reference (where
// the reference points now when pin is nil or returns "") and verified
// against extends.signer.
func loadOrg(ctx context.Context, opts Options, startDir string, pin func(ref string) string) (*manifest.Org, error) {
	return manifest.LoadOrgWith(opts.OrgPath, startDir, func(e manifest.Extends) (string, string, error) {
		digest := ""
		if pin != nil {
			digest = pin(e.Ref)
		}
		return fetchProfile(ctx, e, digest)
	})
}

// lockedProfile returns the digest m's lock pins for the shared profile
// ref, if any.
func lockedProfile(m *manifest.Manifest) func(ref string) string {
	return func(ref string) string {
		if l, err := lock.Read(m.LockPath()); err == nil && l.Profile != nil && l.Profile.Ref == ref {
			return l.Profile.Digest
		}
		return ""
	}
}

// fetchProfile checks that the shared profile e names, at digest (or
// where its reference points now), is signed by e.Signer, then returns its
// unpacked factory.org.yaml from the local cache, fetching it if needed.
// It runs on every load: a profile that isn't signed, or is signed by
// someone else, never loads.
func fetchProfile(ctx context.Context, e manifest.Extends, digest string) (path, d string, err error) {
	repo := lock.RepoOf(e.Ref)
	if digest == "" {
		if digest, err = registry.Digest(ctx, e.Ref); err != nil {
			return "", "", err
		}
	}
	pinned := repo + "@" + digest
	args, err := identityArgs(e.Signer, "")
	if err != nil {
		return "", "", fmt.Errorf("extends.signer: %w", err)
	}
	if err := attest.VerifySignature(ctx, pinned, args); err != nil {
		return "", "", fmt.Errorf("%s is not signed by extends.signer: %w", pinned, err)
	}
	base, err := cacheDir("profiles")
	if err != nil {
		return "", "", err
	}
	dir := filepath.Join(base, strings.ReplaceAll(digest, ":", "-"))
	path = filepath.Join(dir, manifest.OrgFileName)
	if _, err := os.Stat(path); err == nil {
		return path, digest, nil
	}
	files, got, err := registry.FetchFiles(ctx, pinned, manifest.ProfileArtifactType)
	if err != nil {
		return "", "", err
	}
	if got != digest {
		return "", "", fmt.Errorf("%s resolved to %s", pinned, got)
	}
	// Unpack beside the cache entry, then move it in, so a cached profile
	// is always complete.
	tmp, err := os.MkdirTemp(base, ".unpack-")
	if err != nil {
		return "", "", err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	profile := false
	for _, f := range files {
		if f.Name == manifest.OrgFileName {
			if f.MediaType != manifest.ProfileMediaType {
				return "", "", fmt.Errorf("%s: %s is a %s, not an org profile", pinned, f.Name, f.MediaType)
			}
			profile = true
		}
		p := filepath.Join(tmp, filepath.FromSlash(f.Name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return "", "", err
		}
		if err := os.WriteFile(p, f.Content, 0o644); err != nil {
			return "", "", err
		}
	}
	if !profile {
		return "", "", fmt.Errorf("%s has no %s", pinned, manifest.OrgFileName)
	}
	if err := os.Rename(tmp, dir); err != nil {
		if _, serr := os.Stat(path); serr != nil {
			return "", "", err
		}
	}
	return path, digest, nil
}
