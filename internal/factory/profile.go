package factory

import (
	"context"
	"errors"
	"fmt"
	"time"

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
	// By digest, then signed, then tagged, as stack push does.
	if _, err := registry.PushFiles(ctx, pushed, manifest.ProfileArtifactType, files); err != nil {
		return err
	}
	opts.printf("pushed profile %s to %s (%d files)", rel(file), pushed, len(files))
	if signer != nil {
		if err := signer.Run(ctx, "sign", pushed); err != nil {
			return err
		}
		opts.printf("signed %s", pushed)
	}
	if err := tagAs(ctx, po.Ref, pushed); err != nil {
		return err
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
// against extends.signer (or any of extends.signers); the repository's own
// (extends.path) is packed as profile push would publish it.
func loadOrg(ctx context.Context, opts Options, startDir string, pin func(ref string) string) (*manifest.Org, error) {
	return manifest.LoadOrgWith(opts.OrgPath, startDir, func(e manifest.Extends) (string, string, error) {
		if e.Path != "" {
			return localProfile(e.Path)
		}
		digest := ""
		if pin != nil {
			digest = pin(e.Ref)
		}
		return fetchProfile(ctx, opts, e, digest)
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
// where its reference points now), is signed by one of e.AllSigners
// (verifyProfile), then returns its factory.org.yaml, unpacked with the
// files it names, read at that digest from the local cache or the
// registry. A profile that isn't signed, or is signed by someone else,
// never loads.
func fetchProfile(ctx context.Context, opts Options, e manifest.Extends, digest string) (path, d string, err error) {
	repo := lock.RepoOf(e.Ref)
	if digest == "" {
		if digest, err = registry.Digest(ctx, e.Ref); err != nil {
			return "", "", err
		}
	}
	pinned := repo + "@" + digest
	if err := verifyProfile(ctx, opts, e, pinned); err != nil {
		return "", "", err
	}
	path, err = cachedProfile(digest, func() (*registry.Bundle, error) {
		return registry.FetchBundle(ctx, pinned, manifest.ProfileArtifactType)
	})
	return path, digest, err
}

// verifyProfile checks with cosign that one of e.AllSigners signed pinned.
// Unless reverify says to check again, a check this machine made within
// profileVerifiedFor counts instead: pinned names the content by digest,
// so a digest that was signed stays signed, and the content is still read
// by that digest. Only successes are recorded, so a failure is checked
// again every time.
func verifyProfile(ctx context.Context, opts Options, e manifest.Extends, pinned string) error {
	signers := e.AllSigners()
	args := make([][]string, len(signers))
	ids := make([]string, len(signers))
	for i, v := range signers {
		var err error
		if args[i], err = identityArgs(v, ""); err != nil {
			return fmt.Errorf("extends: %w", err)
		}
		ids[i] = signerID(v)
	}
	if !reverify(opts) {
		for _, id := range ids {
			if at, ok := verifiedAt(pinned, id); ok {
				if opts.Verbose {
					opts.logf("%s: signature checked on this machine at %s; --reverify checks it again", pinned, at.Format(time.RFC3339))
				}
				return nil
			}
		}
	}
	var errs []error
	for i := range signers {
		err := attest.VerifySignature(ctx, pinned, args[i])
		if err == nil {
			recordVerified(pinned, ids[i])
			return nil
		}
		errs = append(errs, err)
	}
	if len(errs) == 0 {
		errs = append(errs, errors.New("no signer to verify against"))
	}
	return fmt.Errorf("%s is not signed by %s: %w", pinned, e.SignerField(), errors.Join(errs...))
}

// localProfile packs the repository's own shared profile at path (from
// extends.path) as profile push would, and returns it unpacked and the
// digest profile push would publish it at. It isn't signed: it is the
// repository's own file.
func localProfile(path string) (string, string, error) {
	_, bundled, err := manifest.PackProfile(path)
	if err != nil {
		return "", "", err
	}
	files := make([]registry.File, len(bundled))
	for i, f := range bundled {
		files[i] = registry.File{Name: f.Name, MediaType: f.MediaType, Content: f.Content}
	}
	b, err := registry.PackFiles(manifest.ProfileArtifactType, files)
	if err != nil {
		return "", "", err
	}
	p, err := cachedProfile(b.Digest, func() (*registry.Bundle, error) { return b, nil })
	return p, b.Digest, err
}
