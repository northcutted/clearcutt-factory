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
)

// TrustedSigner is one signer and what it may sign. Its fields match
// clearcutt-verify's trusted signers. A key file is relative to the trust
// policy; a cosign KMS URI is used as is.
type TrustedSigner struct {
	// Name labels the signer in messages.
	Name string `yaml:"name,omitempty"`
	// Roles is what the signer may sign: image (the default) and/or stack.
	Roles                 []string `yaml:"roles,omitempty"`
	Identity              string   `yaml:"identity,omitempty"`
	IdentityRegexp        string   `yaml:"identityRegexp,omitempty"`
	Issuer                string   `yaml:"issuer,omitempty"`
	Key                   string   `yaml:"key,omitempty"`
	SourceRepository      string   `yaml:"sourceRepository,omitempty"`
	SourceRepositoryOwner string   `yaml:"sourceRepositoryOwner,omitempty"`
	SourceRef             string   `yaml:"sourceRef,omitempty"`
	SourceMatchesImage    bool     `yaml:"sourceMatchesImage,omitempty"`
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
			if r != RoleImage && r != RoleStack {
				errs = append(errs, fmt.Errorf("signers[%d]: role %q must be image or stack", i, r))
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

// Verify is the signer as a verify identity.
func (s TrustedSigner) Verify() VerifyIdentity {
	return VerifyIdentity{
		Key: s.Key, CertificateIdentity: s.Identity, CertificateIdentityRegexp: s.IdentityRegexp, CertificateOIDCIssuer: s.Issuer,
		SourceRepository: s.SourceRepository, SourceRepositoryOwner: s.SourceRepositoryOwner, SourceRef: s.SourceRef, SourceMatchesImage: s.SourceMatchesImage,
	}
}

func (v VerifyIdentity) validate() error {
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
	for _, u := range []string{v.SourceRepository, v.SourceRepositoryOwner} {
		if u != "" && !strings.HasPrefix(u, "https://github.com/") {
			return fmt.Errorf("%q must be a https://github.com/ URL", u)
		}
	}
	if r := strings.TrimPrefix(v.SourceRepository, "https://github.com/"); v.SourceRepository != "" && strings.Count(strings.TrimSuffix(r, "/"), "/") != 1 {
		return fmt.Errorf("sourceRepository %q must be https://github.com/OWNER/REPO", v.SourceRepository)
	}
	return nil
}
