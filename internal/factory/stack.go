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

// StackPushOptions are stack push's settings.
type StackPushOptions struct {
	// Ref is where to publish, e.g. ghcr.io/acme/stacks/go:1.
	Ref string
	// Key signs the stack with this key (a file or KMS URI) instead of
	// signing.stackKey or signing.key, whatever signing.mode says.
	Key    string
	NoSign bool
}

// StackPush is StackPushWith without a key of its own.
func StackPush(ctx context.Context, opts Options, file, ref string, noSign bool) error {
	return StackPushWith(ctx, opts, file, StackPushOptions{Ref: ref, NoSign: noSign})
}

// StackPushWith publishes a stack file to a registry so apps in any
// repository can name it (spec.stack: REF), then signs it. Build and run
// images given as factory manifests are resolved to references first, the
// build image pinned by the digest its tag holds now (see
// manifest.Stack.Resolved), so pushing after the build image was rebuilt
// publishes a new stack. A stack is published by its content, so when the
// registry already has that digest, signed by one of the org's stack
// signers (or signing is off), it only moves the tag: running it again
// doesn't pile up signatures.
func StackPushWith(ctx context.Context, opts Options, file string, so StackPushOptions) error {
	if so.Key != "" && so.NoSign {
		return errors.New("--key signs the stack; drop --key or --no-sign")
	}
	abs, err := filepath.Abs(file)
	if err != nil {
		return err
	}
	org, err := loadOrg(ctx, opts, filepath.Dir(abs), nil)
	if err != nil {
		return err
	}
	st, err := manifest.LoadStack(abs)
	if err != nil {
		return err
	}
	if st, err = st.Resolved(org, func(ref string) (string, error) { return registry.Digest(ctx, ref) }); err != nil {
		return err
	}
	content := st.Marshal()
	d, err := registry.FileDigest(manifest.StackArtifactType, "stack.yaml", content)
	if err != nil {
		return err
	}
	pushed := lock.RepoOf(so.Ref) + "@" + d
	signer := stackSigner(opts, org, so)
	exists, err := registry.Exists(ctx, pushed)
	if err != nil {
		return err
	}
	if exists && (signer == nil || stackSigned(ctx, org, pushed)) {
		r, err := name.ParseReference(so.Ref)
		if err != nil {
			return err
		}
		if t, ok := r.(name.Tag); ok {
			if err := registry.Tag(ctx, pushed, []string{t.TagStr()}); err != nil {
				return err
			}
			opts.printf("stack %s is already published at %s; moved %s", st.Metadata.Name, pushed, t.TagStr())
		} else {
			opts.printf("stack %s is already published at %s", st.Metadata.Name, pushed)
		}
		return githubOutput(Result{Image: pushed, Repository: lock.RepoOf(so.Ref), Digest: d, Signed: signer != nil, Published: false})
	}
	// By digest, then signed, then tagged: the tag never names an
	// unsigned stack, even when signing fails.
	if _, err := registry.PushFile(ctx, pushed, manifest.StackArtifactType, "stack.yaml", content); err != nil {
		return err
	}
	opts.printf("pushed stack %s to %s", st.Metadata.Name, pushed)
	if signer != nil {
		if err := signer.Run(ctx, "sign", pushed); err != nil {
			return err
		}
		opts.printf("signed %s", pushed)
	}
	if err := tagAs(ctx, so.Ref, pushed); err != nil {
		return err
	}
	// image, repository, and digest for later workflow steps (notify.yml's
	// clearcutt.stack-published), as build and rebase write them.
	return githubOutput(Result{Image: pushed, Repository: lock.RepoOf(so.Ref), Digest: d, Signed: signer != nil, Published: true})
}

// tagAs points the tag ref names (if it names one) at pushed.
func tagAs(ctx context.Context, ref, pushed string) error {
	r, err := name.ParseReference(ref)
	if err != nil {
		return err
	}
	if t, ok := r.(name.Tag); ok {
		return registry.Tag(ctx, pushed, []string{t.TagStr()})
	}
	return nil
}

// stackSigner is how stack push signs, or nil when it doesn't: with --key,
// else signing.stackKey in key mode, else as images are signed.
func stackSigner(opts Options, org *manifest.Org, so StackPushOptions) *attest.Cosign {
	c := &attest.Cosign{Mode: org.Signing.Mode, Key: org.Signing.Key, Args: org.Signing.Args, Stdout: opts.Stderr, Stderr: opts.Stderr}
	switch {
	case so.NoSign:
		return nil
	case so.Key != "":
		c.Mode, c.Key = "key", so.Key
	case org.Signing.Mode == "none":
		return nil
	case org.Signing.StackKey != "":
		c.Key = org.Signing.StackKey
	}
	return c
}

// stackSigned reports whether the stack at ref carries a signature from one
// of the org's stack signers. With none set, it can't tell, and says no.
func stackSigned(ctx context.Context, org *manifest.Org, ref string) bool {
	signers, err := signerArgs(org, manifest.RoleStack, "")
	if err != nil || len(signers) == 0 {
		return false
	}
	_, err = firstVerified(signers, func(args []string) (struct{}, error) { return struct{}{}, attest.VerifySignature(ctx, ref, args) })
	return err == nil
}

// fetchAppStack fetches an app's registry stack to the local cache and
// points the manifest at it. The lock's pin wins unless fresh.
func fetchAppStack(ctx context.Context, m *manifest.Manifest, fresh bool) error {
	if m.Kind != manifest.KindApp || m.Spec.Stack == "" || manifest.IsStackFile(m.Spec.Stack) {
		return nil
	}
	ref := m.Spec.Stack
	target := ref
	if !fresh {
		if l := lockPins(m.LockPath()); l != nil && l.App != nil && l.App.StackArtifact != nil && l.App.StackArtifact.Ref == ref {
			target = lock.RepoOf(ref) + "@" + l.App.StackArtifact.Digest
		}
	}
	path, digest, err := fetchStack(ctx, target)
	if err != nil {
		return err
	}
	m.Spec.StackPath = path
	m.StackFrom = &manifest.StackArtifact{Ref: ref, Digest: digest}
	return nil
}

// fetchStack returns a cached copy of the stack at ref, fetching it if
// needed. Copies are cached by digest, so a pinned stack is read once.
func fetchStack(ctx context.Context, ref string) (path, digest string, err error) {
	dir, err := cacheDir("stacks")
	if err != nil {
		return "", "", err
	}
	cached := func(d string) string {
		return filepath.Join(dir, strings.ReplaceAll(d, ":", "-")+".yaml")
	}
	if _, d, ok := strings.Cut(ref, "@"); ok {
		if _, err := os.Stat(cached(d)); err == nil {
			return cached(d), d, nil
		}
	}
	content, d, err := registry.FetchFile(ctx, ref, manifest.StackArtifactType)
	if err != nil {
		return "", "", err
	}
	if _, want, ok := strings.Cut(ref, "@"); ok && want != d {
		return "", "", fmt.Errorf("%s resolved to %s", ref, d)
	}
	if err := os.WriteFile(cached(d), content, 0o644); err != nil {
		return "", "", err
	}
	return cached(d), d, nil
}

// verifyStack checks the signature of a registry stack, at the digest the
// manifest was loaded with, when the org requires it.
func verifyStack(ctx context.Context, m *manifest.Manifest, org *manifest.Org) error {
	if m.StackFrom == nil || !org.Policy.RequireSignedStacks {
		return nil
	}
	signers, err := signerArgs(org, manifest.RoleStack, "")
	if err != nil {
		return fmt.Errorf("policy.requireSignedStacks: %w", err)
	}
	if len(signers) == 0 {
		return errors.New("policy.requireSignedStacks needs a stack signer: signing.stacks (or signing.verify, or stack signers in signing.trustPolicy) in the org profile")
	}
	ref := lock.RepoOf(m.StackFrom.Ref) + "@" + m.StackFrom.Digest
	if _, err := firstVerified(signers, func(args []string) (struct{}, error) { return struct{}{}, attest.VerifySignature(ctx, ref, args) }); err != nil {
		return fmt.Errorf("stack %s is not signed by the org's stack signer (policy.requireSignedStacks): %w", ref, err)
	}
	return nil
}

// cacheDir returns (and creates) a directory under the user cache.
func cacheDir(name string) (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "clearcutt-factory", name)
	return dir, os.MkdirAll(dir, 0o755)
}
