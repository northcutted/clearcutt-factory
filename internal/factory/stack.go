package factory

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/northcutted/clearcutt-factory/internal/attest"
	"github.com/northcutted/clearcutt-factory/internal/lock"
	"github.com/northcutted/clearcutt-factory/internal/manifest"
	"github.com/northcutted/clearcutt-factory/internal/registry"
)

// StackPush publishes a stack file to a registry so apps in any repository
// can name it (spec.stack: REF), then signs it. Build and run images given
// as factory manifests are resolved to references first.
func StackPush(ctx context.Context, opts Options, file, ref string, noSign bool) error {
	abs, err := filepath.Abs(file)
	if err != nil {
		return err
	}
	org, err := manifest.LoadOrg(opts.OrgPath, filepath.Dir(abs))
	if err != nil {
		return err
	}
	st, err := manifest.LoadStack(abs)
	if err != nil {
		return err
	}
	if st, err = st.Resolved(org); err != nil {
		return err
	}
	d, err := registry.PushFile(ctx, ref, manifest.StackArtifactType, "stack.yaml", st.Marshal())
	if err != nil {
		return err
	}
	pushed := lock.RepoOf(ref) + "@" + d
	opts.printf("pushed stack %s to %s", st.Metadata.Name, pushed)
	if org.Signing.Mode != "none" && !noSign {
		c := attest.Cosign{Mode: org.Signing.Mode, Key: org.Signing.Key, Args: org.Signing.Args, Stdout: opts.Stderr, Stderr: opts.Stderr}
		if err := c.Run(ctx, "sign", pushed); err != nil {
			return err
		}
		opts.printf("signed %s", pushed)
	}
	return nil
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
		if l, err := lock.Read(m.LockPath()); err == nil && l.App != nil && l.App.StackArtifact != nil && l.App.StackArtifact.Ref == ref {
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

// verifyStack checks a registry stack's signature when the org requires it.
func verifyStack(ctx context.Context, m *manifest.Manifest, org *manifest.Org) error {
	if m.StackFrom == nil || !org.Policy.RequireSignedStacks {
		return nil
	}
	args := verifyArgs(org)
	if len(args) == 0 {
		return errors.New("policy.requireSignedStacks needs signing.verify in the org profile")
	}
	ref := lock.RepoOf(m.StackFrom.Ref) + "@" + m.StackFrom.Digest
	if err := attest.VerifySignature(ctx, ref, args); err != nil {
		return fmt.Errorf("stack %s is not signed by the org's signer (policy.requireSignedStacks): %w", ref, err)
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
