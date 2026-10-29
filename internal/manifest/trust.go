package manifest

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

// TrustPolicy is a ClearCutt trust policy: who signs an organization's
// images and stacks. It is shared by the ClearCutt tools (clearcutt-verify
// reads the same file), so one document says whom the organization trusts.
// The canonical JSON Schema is clearcutt-verify's
// contract/trust-policy.v1.schema.json.
type TrustPolicy struct {
	APIVersion string          `yaml:"apiVersion"`
	Kind       string          `yaml:"kind"`
	Signers    []TrustedSigner `yaml:"signers"`
}

const (
	TrustAPIVersion = "clearcutt.dev/v1"
	KindTrust       = "TrustPolicy"
	RoleImage       = "image"
	RoleStack       = "stack"
	// RoleEstate signers sign clearcutt-verify's estate report bundles.
	// factory reads the policy they are in and leaves them to verify:
	// nothing here is checked against them.
	RoleEstate = "estate"
)

// TrustedSigner is one signer and what it may sign. Its fields match
// clearcutt-verify's trusted signers. A key file is relative to the trust
// policy; a cosign KMS URI is used as is.
type TrustedSigner struct {
	// Name labels the signer in messages.
	Name string `yaml:"name,omitempty"`
	// Roles is what the signer may sign: image (the default), stack, or
	// estate (clearcutt-verify's report bundles, which factory ignores).
	Roles                 []string `yaml:"roles,omitempty"`
	Identity              string   `yaml:"identity,omitempty"`
	IdentityRegexp        string   `yaml:"identityRegexp,omitempty"`
	Issuer                string   `yaml:"issuer,omitempty"`
	Key                   string   `yaml:"key,omitempty"`
	SourceRepository      string   `yaml:"sourceRepository,omitempty"`
	SourceRepositoryOwner string   `yaml:"sourceRepositoryOwner,omitempty"`
	SourceRef             string   `yaml:"sourceRef,omitempty"`
	SourceMatchesImage    bool     `yaml:"sourceMatchesImage,omitempty"`
	// Tlog false accepts this key signer's evidence without a transparency
	// log entry (cosign --insecure-ignore-tlog), for a key that signs
	// without one. Keyless signers can't set it.
	Tlog *bool `yaml:"tlog,omitempty"`
}

// LoadTrustPolicy reads and checks a trust policy file. Key files are
// relative to it.
func LoadTrustPolicy(path string) (*TrustPolicy, error) {
	t, err := decodeFile[TrustPolicy](path)
	if err != nil {
		return nil, err
	}
	if t.APIVersion != TrustAPIVersion || t.Kind != KindTrust {
		return nil, fmt.Errorf("%s: expected apiVersion %q and kind %q", path, TrustAPIVersion, KindTrust)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	var errs []error
	for i := range t.Signers {
		t.Signers[i].Key = keyPath(filepath.Dir(abs), t.Signers[i].Key)
		s := t.Signers[i]
		for _, r := range s.Roles {
			if r != RoleImage && r != RoleStack && r != RoleEstate {
				errs = append(errs, fmt.Errorf("signers[%d]: role %q must be image, stack, or estate", i, r))
			}
		}
		if err := s.Verify().validate(); err != nil {
			errs = append(errs, fmt.Errorf("signers[%d] %s: %w", i, s.Name, err))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return t, nil
}

// For returns the signers that may sign role.
func (t *TrustPolicy) For(role string) []VerifyIdentity {
	var out []VerifyIdentity
	for _, s := range t.Signers {
		if s.may(role) {
			out = append(out, s.Verify())
		}
	}
	return out
}

func (s TrustedSigner) may(role string) bool {
	if len(s.Roles) == 0 {
		return role == RoleImage
	}
	return slices.Contains(s.Roles, role)
}

// Signers returns who the org trusts to sign role (an image or a stack):
// the trust policy's signers for it when signing.trustPolicy is set, else
// signing.verify, which signing.stacks replaces for stacks.
func (o *Org) Signers(role string) []VerifyIdentity {
	switch {
	case o.Trust != nil:
		return o.Trust.For(role)
	case role == RoleStack && !o.Signing.Stacks.IsZero():
		return []VerifyIdentity{o.Signing.Stacks}
	case !o.Signing.Verify.IsZero():
		return []VerifyIdentity{o.Signing.Verify}
	}
	return nil
}

// BaseSigners returns who the org trusts to sign a base (a stack's build
// or run image): its image signers that name a sourceRepository, so each
// vouches only for runs in that one repository. An owner-scoped signer
// (sourceRepositoryOwner without sourceRepository) accepts a run in any of
// the owner's repositories: right for apps, which a new repository adds
// without a change to the trust policy, but with it any of them could
// vouch for an image every app builds or ships on, with write access to
// the registry the only other boundary. A key, or an identity without
// source constraints, names no repository either.
func (o *Org) BaseSigners() []VerifyIdentity {
	var out []VerifyIdentity
	for _, v := range o.Signers(RoleImage) {
		if v.SourceRepository != "" {
			out = append(out, v)
		}
	}
	return out
}

// Verify is the signer as a verify identity.
func (s TrustedSigner) Verify() VerifyIdentity {
	return VerifyIdentity{
		Key: s.Key, CertificateIdentity: s.Identity, CertificateIdentityRegexp: s.IdentityRegexp, CertificateOIDCIssuer: s.Issuer,
		SourceRepository: s.SourceRepository, SourceRepositoryOwner: s.SourceRepositoryOwner, SourceRef: s.SourceRef, SourceMatchesImage: s.SourceMatchesImage,
		Tlog: s.Tlog,
	}
}

func (v VerifyIdentity) validate() error {
	if v.Tlog != nil && !*v.Tlog && v.Key == "" {
		return errors.New("tlog: false applies to key signers: a keyless certificate is only valid with a transparency log entry showing it was used in time")
	}
	if v.IsZero() {
		if v.SourceRepository != "" || v.SourceRepositoryOwner != "" || v.SourceRef != "" || v.SourceMatchesImage {
			return errors.New("source constraints need a certificate identity and issuer")
		}
		return nil
	}
	if v.CertificateIdentity != "" && v.CertificateIdentityRegexp != "" {
		return errors.New("set certificateIdentity or certificateIdentityRegexp, not both")
	}
	keyless := v.CertificateIdentity != "" || v.CertificateIdentityRegexp != ""
	if v.Key != "" && keyless {
		return errors.New("set a key or a certificate identity, not both")
	}
	if keyless && v.CertificateOIDCIssuer == "" {
		return errors.New("a certificate identity needs certificateOIDCIssuer")
	}
	constrained := v.SourceRepository != "" || v.SourceRepositoryOwner != "" || v.SourceRef != "" || v.SourceMatchesImage
	if constrained && !keyless {
		return errors.New("source constraints apply to keyless (GitHub Actions) signers")
	}
	// The source fields are those of a GitHub Actions certificate, as in
	// clearcutt-verify's trust policy, which refuses them with another
	// issuer.
	if constrained && v.CertificateOIDCIssuer != GitHubActionsIssuer {
		return fmt.Errorf("source constraints need the GitHub Actions issuer (%s), not %q", GitHubActionsIssuer, v.CertificateOIDCIssuer)
	}
	for _, u := range []string{v.SourceRepository, v.SourceRepositoryOwner} {
		if u != "" && !strings.HasPrefix(u, "https://github.com/") {
			return fmt.Errorf("%q must be a https://github.com/ URL", u)
		}
	}
	if r := strings.TrimPrefix(v.SourceRepository, "https://github.com/"); v.SourceRepository != "" && strings.Count(strings.TrimSuffix(r, "/"), "/") != 1 {
		return fmt.Errorf("sourceRepository %q must be https://github.com/OWNER/REPO", v.SourceRepository)
	}
	// Exactly https://github.com/OWNER (a trailing slash allowed), as
	// clearcutt-verify reads it: the certificate's repository must be
	// https://github.com/OWNER/<repo>, its owner segment exactly OWNER.
	if o := v.SourceRepositoryOwner; o != "" {
		if rest, ok := strings.CutPrefix(strings.TrimSuffix(o, "/"), "https://github.com/"); !ok || rest == "" || strings.Contains(rest, "/") {
			return fmt.Errorf("sourceRepositoryOwner %q must be https://github.com/OWNER", o)
		}
	}
	return nil
}

// GitHubActionsIssuer is the OIDC issuer of GitHub Actions' certificates,
// the only ones the source constraints apply to.
const GitHubActionsIssuer = "https://token.actions.githubusercontent.com"
