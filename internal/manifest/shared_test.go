package manifest

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

const (
	testProfileSigner = "https://github.com/acme/platform/.github/workflows/profile.yml@refs/heads/main"
	testSharedDigest  = "sha256:5555555555555555555555555555555555555555555555555555555555555555"

	sharedProfile = `apiVersion: factory.clearcutt.dev/v1alpha1
kind: OrgProfile
tags: [latest]
defaults:
  labels: {org.opencontainers.image.vendor: acme}
builder:
  buildkit: moby/buildkit:v0.33.1
signing:
  mode: keyless
  stacks: {certificateIdentity: "` + testStacks + `", certificateOIDCIssuer: "` + testIssuer + `"}
vulnerabilities:
  failOn: high
  onlyFixed: true
  vex: [vex/platform.json]
policy:
  requireSignedStacks: true
  requiredLabels: [org.opencontainers.image.source]
  allowTOFU: true
  allowedHosts: [github.com, .example.com]
  allowedRegistries: [ghcr.io/acme/, cgr.dev/chainguard/]
`
	extendsHeader = `apiVersion: factory.clearcutt.dev/v1alpha1
kind: OrgProfile
extends:
  ref: registry.example/factory/org:1
  signer: {certificateIdentity: "` + testProfileSigner + `", certificateOIDCIssuer: "` + testIssuer + `"}
`
)

// sharedLoader serves the shared profile body (with its files) as if it
// were fetched and verified.
func sharedLoader(t *testing.T, files map[string]string) (ProfileLoader, string) {
	t.Helper()
	dir := writeFiles(t, files)
	path := filepath.Join(dir, OrgFileName)
	return func(e Extends) (string, string, error) {
		if e.Ref != "registry.example/factory/org:1" || e.Signer.CertificateIdentity != testProfileSigner {
			return "", "", errors.New("unexpected extends")
		}
		return path, testSharedDigest, nil
	}, dir
}

// loadExtending loads a repository's profile (extendsHeader plus local)
// over the shared profile.
func loadExtending(t *testing.T, shared, local string) (*Org, string, error) {
	t.Helper()
	load, sharedDir := sharedLoader(t, map[string]string{OrgFileName: shared, "vex/platform.json": "{}", "trust.yaml": "apiVersion: clearcutt.dev/v1\nkind: TrustPolicy\nsigners: [{name: images, key: images.pub}, {name: stacks, roles: [stack], key: stacks.pub}]\n"})
	dir := writeFiles(t, map[string]string{OrgFileName: extendsHeader + local, "vex/local.json": "{}", "trust.yaml": "apiVersion: clearcutt.dev/v1\nkind: TrustPolicy\nsigners: []\n"})
	o, err := LoadOrgWith(filepath.Join(dir, OrgFileName), "", load)
	return o, sharedDir, err
}

// TestExtendTightens: a repository may add what the shared profile leaves
// unset and tighten its gate and policy.
func TestExtendTightens(t *testing.T) {
	for _, c := range []struct {
		name, shared, local string
		check               func(o *Org, sharedDir string) string
	}{
		{"nothing added", sharedProfile, "", func(o *Org, dir string) string {
			switch {
			case o.Shared == nil || o.Shared.Digest != testSharedDigest || o.Shared.Ref != "registry.example/factory/org:1":
				return "shared profile not recorded"
			case o.Vulnerabilities.FailOn != "high" || !o.Vulnerabilities.OnlyFixed || !o.Policy.AllowTOFU || !o.Policy.RequireSignedStacks:
				return "gate or policy not the shared profile's"
			case !slices.Equal(o.Vulnerabilities.VEXFiles, []string{filepath.Join(dir, "vex/platform.json")}):
				return "shared VEX not applied: " + strings.Join(o.Vulnerabilities.VEXFiles, " ")
			case len(o.Signers(RoleStack)) != 1 || o.Signers(RoleStack)[0].CertificateIdentity != testStacks:
				return "stack signer not the shared profile's"
			case o.Builder.BuildKit != "moby/buildkit:v0.33.1" || o.Builder.Frontend != "docker/dockerfile:1" || o.Signing.Mode != "keyless":
				return "builder or signing mode not the shared profile's (with defaults)"
			}
			return ""
		}},
		{"per-repository settings", sharedProfile,
			"registry: ghcr.io/acme/apps\nsigning:\n  verify: {certificateIdentityRegexp: x, certificateOIDCIssuer: " + testIssuer + ", sourceRepository: https://github.com/acme/checkout}\n",
			func(o *Org, _ string) string {
				if o.Registry != "ghcr.io/acme/apps" || o.Signing.Verify.SourceRepository != "https://github.com/acme/checkout" || o.Signers(RoleStack)[0].CertificateIdentity != testStacks {
					return "registry or image signer not added, or the stack signer moved"
				}
				return ""
			}},
		{"stricter gate", sharedProfile, "vulnerabilities: {failOn: medium, onlyFixed: false}\n", func(o *Org, _ string) string {
			if o.Vulnerabilities.FailOn != "medium" || o.Vulnerabilities.OnlyFixed {
				return "gate not tightened"
			}
			return ""
		}},
		{"stricter policy", sharedProfile,
			"policy:\n  requireNonRoot: true\n  requiredLabels: [team]\n  allowTOFU: false\n  allowedHosts: [api.example.com, github.com]\n  allowedRegistries: [ghcr.io/acme/apps/]\n",
			func(o *Org, _ string) string {
				p := o.Policy
				switch {
				case !p.RequireNonRoot || p.AllowTOFU || !p.RequireSignedStacks:
					return "switches not tightened"
				case !slices.Equal(p.RequiredLabels, []string{"org.opencontainers.image.source", "team"}):
					return "required labels not the union: " + strings.Join(p.RequiredLabels, " ")
				case !slices.Equal(p.AllowedHosts, []string{"api.example.com", "github.com"}) || !slices.Equal(p.AllowedRegistries, []string{"ghcr.io/acme/apps/"}):
					return "allow lists not narrowed"
				}
				return ""
			}},
		{"restating the shared profile, and this machine's builder", sharedProfile,
			"tags: [latest]\nbuilder: {buildkit: moby/buildkit:v0.33.1, frontend: docker/dockerfile:1, addr: tcp://buildkitd:1234}\nsigning: {mode: keyless}\nvulnerabilities: {scanner: grype, failOn: high}\n",
			func(o *Org, _ string) string {
				if o.Builder.Addr != "tcp://buildkitd:1234" {
					return "builder.addr not taken"
				}
				return ""
			}},
		{"labels added", sharedProfile, "defaults: {labels: {team: payments}}\n", func(o *Org, _ string) string {
			if o.Defaults.Labels["team"] != "payments" || o.Defaults.Labels["org.opencontainers.image.vendor"] != "acme" {
				return "labels not merged"
			}
			return ""
		}},
		{"SBOM scans on, local VEX off",
			strings.Replace(sharedProfile, "  onlyFixed: true\n", "  onlyFixed: false\n  allowLocalVEX: true\n", 1) + "sbom: {scan: false}\n",
			"sbom: {scan: true}\nvulnerabilities: {allowLocalVEX: false}\n",
			func(o *Org, _ string) string {
				if !*o.SBOM.Scan || o.Vulnerabilities.AllowLocalVEX {
					return "not tightened"
				}
				return ""
			}},
		{"local VEX the shared profile allows", strings.Replace(sharedProfile, "  onlyFixed: true\n", "  allowLocalVEX: true\n", 1),
			"vulnerabilities: {vex: [vex/local.json]}\n",
			func(o *Org, _ string) string {
				if len(o.Vulnerabilities.VEXFiles) != 2 || !strings.HasSuffix(o.Vulnerabilities.VEXFiles[1], "vex/local.json") {
					return "local VEX not applied after the shared: " + strings.Join(o.Vulnerabilities.VEXFiles, " ")
				}
				return ""
			}},
		{"no signers in the shared profile: the repository names them", strings.Replace(strings.Replace(sharedProfile, "  stacks: {", "  # {", 1), "  requireSignedStacks: true\n", "", 1),
			"signing:\n  verify: {certificateIdentity: x, certificateOIDCIssuer: " + testIssuer + "}\n  stacks: {certificateIdentity: y, certificateOIDCIssuer: " + testIssuer + "}\npolicy: {requireSignedStacks: true}\n",
			func(o *Org, _ string) string {
				if o.Signers(RoleStack)[0].CertificateIdentity != "y" || !o.Policy.RequireSignedStacks {
					return "repository signers not taken"
				}
				return ""
			}},
	} {
		o, dir, err := loadExtending(t, c.shared, c.local)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if msg := c.check(o, dir); msg != "" {
			t.Errorf("%s: %s", c.name, msg)
		}
	}
}

// TestExtendRefusesLoosening: anything that would loosen or change the
// shared profile is an error naming the field, not silently overridden.
func TestExtendRefusesLoosening(t *testing.T) {
	strictOff := strings.Replace(strings.Replace(sharedProfile, "  onlyFixed: true\n", "  onlyFixed: false\n", 1), "  allowTOFU: true\n", "  allowTOFU: false\n", 1)
	verifyOnly := strings.Replace(sharedProfile, "  stacks: {", "  verify: {", 1)
	withTrust := strings.Replace(sharedProfile, "  stacks: {", "  trustPolicy: trust.yaml\n  # {", 1)
	for _, c := range []struct{ name, shared, local, want string }{
		{"looser failOn", sharedProfile, "vulnerabilities: {failOn: critical}\n", "vulnerabilities.failOn: critical is looser than the shared profile's high"},
		{"onlyFixed on", strictOff, "vulnerabilities: {onlyFixed: true}\n", "vulnerabilities.onlyFixed: the shared profile leaves it off"},
		{"allowTOFU on", strictOff, "policy: {allowTOFU: true}\n", "policy.allowTOFU: the shared profile leaves it off"},
		{"allowLocalVEX on", sharedProfile, "vulnerabilities: {allowLocalVEX: true}\n", "vulnerabilities.allowLocalVEX: the shared profile leaves it off"},
		{"local VEX", sharedProfile, "vulnerabilities: {vex: [vex/local.json]}\n", "vulnerabilities.vex: the shared profile doesn't take VEX statements"},
		{"no scanner", sharedProfile, "vulnerabilities: {scanner: none}\n", "vulnerabilities.scanner: the shared profile sets grype"},
		{"no SBOM scan", sharedProfile, "sbom: {scan: false}\n", "sbom.scan: the shared profile scans"},
		{"requireSignedStacks off", sharedProfile, "policy: {requireSignedStacks: false}\n", "policy.requireSignedStacks: the shared profile turns it on"},
		{"requireNonRoot off", sharedProfile + "  requireNonRoot: true\n", "policy: {requireNonRoot: false}\n", "policy.requireNonRoot: the shared profile turns it on"},
		{"registry outside", sharedProfile, "policy: {allowedRegistries: [ghcr.io/acme/apps/, docker.io/]}\n", "policy.allowedRegistries: docker.io/ is outside"},
		{"host outside", sharedProfile, "policy: {allowedHosts: [evil.com]}\n", "policy.allowedHosts: evil.com is outside"},
		{"broader host suffix", sharedProfile, "policy: {allowedHosts: [.com]}\n", "policy.allowedHosts: .com is outside"},
		{"signing off", sharedProfile, "signing: {mode: none}\n", "signing.mode: the shared profile sets keyless"},
		{"another BuildKit", sharedProfile, "builder: {buildkit: moby/buildkit:latest}\n", "builder.buildkit: the shared profile sets moby/buildkit:v0.33.1"},
		{"another default toolbox", sharedProfile, "builder: {toolbox: alpine}\n", "builder.toolbox: the shared profile sets cgr.dev/chainguard/wolfi-base:latest"},
		{"other tags", sharedProfile, "tags: [edge]\n", "tags: the shared profile sets [latest]"},
		{"another stack signer", sharedProfile, "signing:\n  stacks: {certificateIdentity: me, certificateOIDCIssuer: " + testIssuer + "}\n", "signing.stacks: the shared profile names this signer"},
		{"a stack signer over the shared image signer", verifyOnly, "signing:\n  stacks: {certificateIdentity: me, certificateOIDCIssuer: " + testIssuer + "}\n", "signing.stacks: the shared profile's signing.verify signs stacks too"},
		{"an image signer under a shared trust policy", withTrust, "signing:\n  verify: {certificateIdentity: me, certificateOIDCIssuer: " + testIssuer + "}\n", "signing.verify: the shared profile's trust policy"},
		{"a trust policy of its own", sharedProfile, "signing: {trustPolicy: trust.yaml}\n", "signing.trustPolicy: whom to trust comes from the shared profile"},
		{"a profile signer", sharedProfile, "signing:\n  profile: {certificateIdentity: me, certificateOIDCIssuer: " + testIssuer + "}\n", "signing.profile is who signs a profile you publish"},
		{"a label changed", sharedProfile, "defaults: {labels: {org.opencontainers.image.vendor: mallory}}\n", "defaults.labels: the shared profile sets org.opencontainers.image.vendor"},
		{"other mirrors", sharedProfile + "mirrors: [{from: https://a/, to: https://b/}]\n", "mirrors: [{from: https://a/, to: https://c/}]\n", "mirrors: the shared profile sets them"},
		{"another registry", sharedProfile + "registry: ghcr.io/acme/images\n", "registry: ghcr.io/mallory\n", "registry: the shared profile sets ghcr.io/acme/images"},
	} {
		_, _, err := loadExtending(t, c.shared, c.local)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}

	// Every loosening is reported at once.
	_, _, err := loadExtending(t, sharedProfile, "vulnerabilities: {failOn: critical}\npolicy: {requireSignedStacks: false, allowTOFU: true}\nsigning: {mode: none}\n")
	if err == nil || strings.Count(err.Error(), "\n") < 3 || !strings.Contains(err.Error(), "may only add to and tighten") {
		t.Errorf("several at once: %v", err)
	}
}

// TestExtendCoversEveryField: every field of the profile has a merge rule,
// so a field added later can't silently fall out of a merged profile (or
// let a repository set it unchecked).
func TestExtendCoversEveryField(t *testing.T) {
	// What a repository's profile can't set on its own: who to trust, what
	// the shared profile fixes (its values or factory's defaults), and
	// switches that only turn off.
	refused := map[string]bool{}
	for _, f := range strings.Fields("signing.trustPolicy signing.profile builder.buildkit builder.frontend builder.toolbox builder.go builder.nix builder.nixpkgs signing.mode vulnerabilities.scanner vulnerabilities.onlyFixed vulnerabilities.allowLocalVEX vulnerabilities.vex policy.allowTOFU") {
		refused[f] = true
	}
	machine := map[string]bool{"builder.runtime": true, "builder.addr": true, "builder.config": true, "builder.network": true}
	leaves := orgLeaves(reflect.TypeOf(Org{}), "", nil)
	if len(leaves) < 35 {
		t.Fatalf("only %d fields found", len(leaves))
	}
	for _, f := range leaves {
		if f.path == "extends" || f.path == "apiVersion" || f.path == "kind" {
			continue
		}
		// Set in the shared profile only: it applies.
		var s, l Org
		set := keySet{f.path: true}
		sample(reflect.ValueOf(&s).Elem().FieldByIndex(f.index))
		out, err := extendWith(&s, &l, keySet{})
		got := reflect.ValueOf(out).Elem().FieldByIndex(f.index)
		switch {
		case machine[f.path]:
			if !got.IsZero() {
				t.Errorf("%s: a shared profile's value applies, but it is the machine's", f.path)
			}
		case err != nil || !reflect.DeepEqual(got.Interface(), reflect.ValueOf(&s).Elem().FieldByIndex(f.index).Interface()):
			t.Errorf("%s: set in the shared profile only, it doesn't apply (%v)", f.path, err)
		}

		// Set in the repository's only: it applies, or is refused.
		s, l = Org{}, Org{}
		sample(reflect.ValueOf(&l).Elem().FieldByIndex(f.index))
		out, err = extendWith(&s, &l, set)
		got = reflect.ValueOf(out).Elem().FieldByIndex(f.index)
		want := reflect.ValueOf(&l).Elem().FieldByIndex(f.index).Interface()
		switch {
		case refused[f.path] && err == nil:
			t.Errorf("%s: set in the repository's profile only, it isn't refused", f.path)
		case !refused[f.path] && (err != nil || !reflect.DeepEqual(got.Interface(), want)):
			t.Errorf("%s: set in the repository's profile only, it doesn't apply (%v)", f.path, err)
		}
	}
}

type leaf struct {
	path  string
	index []int
}

// orgLeaves lists the profile's YAML fields, descending into its sections.
func orgLeaves(t reflect.Type, prefix string, index []int) []leaf {
	var out []leaf
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		n, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if n == "" || n == "-" {
			continue
		}
		idx := append(slices.Clone(index), i)
		if f.Type.Kind() == reflect.Struct && f.Type != reflect.TypeOf(VerifyIdentity{}) {
			out = append(out, orgLeaves(f.Type, prefix+n+".", idx)...)
			continue
		}
		out = append(out, leaf{prefix + n, idx})
	}
	return out
}

// sample sets v to a value that is set (and for a switch, on).
func sample(v reflect.Value) {
	switch v.Kind() {
	case reflect.String:
		v.SetString("sample")
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Slice:
		s := reflect.MakeSlice(v.Type(), 1, 1)
		sample(s.Index(0))
		v.Set(s)
	case reflect.Map:
		m := reflect.MakeMap(v.Type())
		m.SetMapIndex(reflect.ValueOf("k"), reflect.ValueOf("v"))
		v.Set(m)
	case reflect.Pointer:
		p := reflect.New(v.Type().Elem())
		sample(p.Elem())
		v.Set(p)
	case reflect.Struct:
		if v.Type() == reflect.TypeOf(VerifyIdentity{}) {
			v.FieldByName("Key").SetString("sample.pub")
			return
		}
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() {
				sample(v.Field(i))
			}
		}
	}
}

// TestSharedProfileChecks: what a published (or fetched) shared profile
// can't hold.
func TestSharedProfileChecks(t *testing.T) {
	for _, c := range []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"extends another", map[string]string{OrgFileName: extendsHeader}, "a shared profile can't extend another"},
		{"this machine's builder", map[string]string{OrgFileName: strings.Replace(sharedProfile, "builder:\n", "builder:\n  network: host\n", 1)}, "builder.network describes the machine that builds"},
		{"a private key file", map[string]string{OrgFileName: strings.Replace(sharedProfile, "  mode: keyless\n", "  mode: key\n  key: cosign.key\n", 1)}, "signing.key is a key file, and a published profile can't carry a private key"},
		{"signed stacks, no stack signer", map[string]string{OrgFileName: strings.Replace(sharedProfile, "  stacks: {", "  # {", 1)}, "policy.requireSignedStacks: name the stack signer"},
		{"VEX outside", map[string]string{OrgFileName: strings.Replace(sharedProfile, "vex/platform.json", "../platform.json", 1)}, "is outside the shared profile"},
		{"a trust policy key outside", map[string]string{
			OrgFileName:  strings.Replace(sharedProfile, "  stacks: {", "  trustPolicy: trust.yaml\n  # {", 1),
			"trust.yaml": "apiVersion: clearcutt.dev/v1\nkind: TrustPolicy\nsigners: [{name: s, roles: [stack], key: /etc/stacks.pub}]\n",
		}, "signing.trustPolicy signers[0].key: /etc/stacks.pub is outside"},
	} {
		c.files["vex/platform.json"] = "{}"
		dir := writeFiles(t, c.files)
		_, err := ReadShared(filepath.Join(dir, OrgFileName))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
		if _, _, err := PackProfile(filepath.Join(dir, OrgFileName)); err == nil {
			t.Errorf("%s: published", c.name)
		}
	}
}

// TestExtendsNamesItsSigner: extends must say who signs the shared
// profile; it can't be left to the profile.
func TestExtendsNamesItsSigner(t *testing.T) {
	load, _ := sharedLoader(t, map[string]string{OrgFileName: sharedProfile, "vex/platform.json": "{}"})
	for _, c := range []struct{ name, body, want string }{
		{"a bare reference", "extends: registry.example/factory/org:1\n", "extends needs ref and signer"},
		{"no signer", "extends: {ref: registry.example/factory/org:1}\n", "signer is required"},
		{"no ref", "extends: {signer: {key: k.pub}}\n", "ref is required"},
		{"an unknown field", "extends: {ref: registry.example/factory/org:1, signr: {key: k.pub}}\n", "signr"},
		{"sourceMatchesImage", "extends: {ref: registry.example/factory/org:1, signer: {certificateIdentity: x, certificateOIDCIssuer: " + testIssuer + ", sourceMatchesImage: true}}\n", "a profile names no source repository"},
		{"a keyless signer without issuer", "extends: {ref: registry.example/factory/org:1, signer: {certificateIdentity: x}}\n", "needs certificateOIDCIssuer"},
	} {
		dir := writeFiles(t, map[string]string{OrgFileName: "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\n" + c.body})
		if _, err := LoadOrgWith(filepath.Join(dir, OrgFileName), "", load); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}

	// The signer's key file is relative to the profile that names it.
	dir := writeFiles(t, map[string]string{OrgFileName: "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\nextends: {ref: r/org:1, signer: {key: keys/profile.pub}}\n"})
	var got Extends
	_, _ = LoadOrgWith(filepath.Join(dir, OrgFileName), "", func(e Extends) (string, string, error) { got = e; return "", "", errors.New("stop") })
	if got.Signer.Key != filepath.Join(dir, "keys/profile.pub") {
		t.Errorf("signer key %q", got.Signer.Key)
	}
	// Without a loader (LoadOrg), a profile that extends doesn't load.
	if _, err := LoadOrg(filepath.Join(dir, OrgFileName), ""); err == nil {
		t.Error("loaded without fetching the shared profile")
	}
}

// TestExtendsSigners: extends.signers names several signers, any one of
// which may sign the shared profile (to rotate it); signer is the form with
// one. Each is checked as signer is.
func TestExtendsSigners(t *testing.T) {
	sharedDir := writeFiles(t, map[string]string{OrgFileName: sharedProfile, "vex/platform.json": "{}"})
	var got Extends
	load := func(e Extends) (string, string, error) {
		got = e
		return filepath.Join(sharedDir, OrgFileName), testSharedDigest, nil
	}
	keyless := "{certificateIdentity: " + testProfileSigner + ", certificateOIDCIssuer: " + testIssuer + "}"
	for _, c := range []struct{ name, body, want string }{
		{"signers", "signers:\n    - {key: keys/old.pub}\n    - " + keyless + "\n", ""},
		{"signer and signers", "signer: {key: keys/old.pub}\n  signers: [{key: keys/new.pub}]\n", "set signer or signers, not both"},
		{"no signers", "signers: []\n", "signers is empty"},
		{"an empty signer", "signers: [{key: keys/old.pub}, {}]\n", "signers[1] names no signer"},
		{"sourceMatchesImage", "signers: [{key: k.pub}, {certificateIdentity: x, certificateOIDCIssuer: " + testIssuer + ", sourceMatchesImage: true}]\n", "signers[1]: sourceMatchesImage only applies to images"},
		{"a keyless signer without issuer", "signers: [{certificateIdentity: x}]\n", "signers[0]: a certificate identity needs certificateOIDCIssuer"},
		{"a signer with key and identity", "signers: [{key: k.pub, certificateIdentity: x, certificateOIDCIssuer: " + testIssuer + "}]\n", "signers[0]: set a key or a certificate identity, not both"},
	} {
		got = Extends{}
		dir := writeFiles(t, map[string]string{OrgFileName: "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\nextends:\n  ref: registry.example/factory/org:1\n  " + c.body})
		o, err := LoadOrgWith(filepath.Join(dir, OrgFileName), "", load)
		if c.want != "" {
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("%s: %v, want %q", c.name, err, c.want)
			}
			if got.Ref != "" {
				t.Errorf("%s: the shared profile was loaded", c.name)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		// Every signer reaches the loader, key files relative to the
		// profile that names them.
		all := got.AllSigners()
		if len(all) != 2 || all[0].Key != filepath.Join(dir, "keys/old.pub") || all[1].CertificateIdentity != testProfileSigner || got.SignerField() != "any of extends.signers" {
			t.Errorf("%s: signers %+v", c.name, all)
		}
		if o.Shared == nil || o.Vulnerabilities.FailOn != "high" {
			t.Errorf("%s: shared profile not applied", c.name)
		}
	}

	// signer is signers with one entry.
	e := Extends{Ref: "r/org:1", Signer: VerifyIdentity{Key: "k.pub"}}
	if all := e.AllSigners(); len(all) != 1 || all[0].Key != "k.pub" || e.SignerField() != "extends.signer" {
		t.Errorf("signer: %+v", all)
	}
}

// TestPackProfile: the published profile carries the files it names,
// renamed inside the artifact, and depends only on content.
func TestPackProfile(t *testing.T) {
	files := map[string]string{
		"org/factory.org.yaml": "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\n" +
			"signing:\n  verify: {key: ../keys/images.pub}\n  trustPolicy: trust.yaml\n  profile: {key: \"awskms:///alias/profile\"}\n" +
			"vulnerabilities:\n  failOn: high\n  vex: [../vex/a/triage.json, ../vex/b/triage.json]\n",
		"org/trust.yaml":    "apiVersion: clearcutt.dev/v1\nkind: TrustPolicy\nsigners:\n  - {name: images, key: ../keys/images.pub}\n  - {name: stacks, roles: [stack], key: stacks.pub}\n",
		"org/stacks.pub":    "-----BEGIN PUBLIC KEY-----\nstacks\n-----END PUBLIC KEY-----\n",
		"keys/images.pub":   "-----BEGIN PUBLIC KEY-----\nimages\n-----END PUBLIC KEY-----\n",
		"vex/a/triage.json": `{"a": 1}`,
		"vex/b/triage.json": `{"b": 2}`,
	}
	dir := writeFiles(t, files)
	o, packed, err := PackProfile(filepath.Join(dir, "org/factory.org.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if o.Signing.Mode != "keyless" || o.Vulnerabilities.FailOn != "high" {
		t.Errorf("loaded profile: %+v", o)
	}
	var names []string
	byName := map[string]BundledFile{}
	for _, f := range packed {
		names = append(names, f.Name)
		byName[f.Name] = f
	}
	if want := []string{"factory.org.yaml", "keys/images.pub", "keys/stacks.pub", "trust-policy.yaml", "vex/triage.json", "vex/2-triage.json"}; !slices.Equal(names, want) {
		t.Fatalf("files %q, want %q", names, want)
	}
	profile := string(byName["factory.org.yaml"].Content)
	for _, want := range []string{"key: keys/images.pub", "trustPolicy: trust-policy.yaml", "key: awskms:///alias/profile", "- vex/triage.json\n", "- vex/2-triage.json\n"} {
		if !strings.Contains(profile, want) {
			t.Errorf("published profile lacks %q:\n%s", want, profile)
		}
	}
	if strings.Contains(profile, "mode:") || strings.Contains(profile, "buildkit") {
		t.Errorf("defaults were published (they'd fix what the profile leaves to factory):\n%s", profile)
	}
	if tp := string(byName["trust-policy.yaml"].Content); !strings.Contains(tp, "key: keys/images.pub") || !strings.Contains(tp, "key: keys/stacks.pub") {
		t.Errorf("trust policy keys not renamed:\n%s", tp)
	}
	if byName["vex/2-triage.json"].MediaType != VEXMediaType || string(byName["vex/2-triage.json"].Content) != `{"b": 2}` {
		t.Errorf("vex: %+v", byName["vex/2-triage.json"])
	}

	// The same content, elsewhere, packs the same; unpacked, it reads back.
	other := writeFiles(t, files)
	_, again, err := PackProfile(filepath.Join(other, "org/factory.org.yaml"))
	if err != nil || !reflect.DeepEqual(again, packed) {
		t.Errorf("packing depends on where the profile is: %v", err)
	}
	unpacked := t.TempDir()
	for _, f := range packed {
		p := filepath.Join(unpacked, filepath.FromSlash(f.Name))
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, f.Content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	s, err := ReadShared(filepath.Join(unpacked, OrgFileName))
	if err != nil {
		t.Fatal(err)
	}
	if s.Trust == nil || s.Signers(RoleStack)[0].Key != filepath.Join(unpacked, "keys/stacks.pub") || len(s.Vulnerabilities.VEXFiles) != 2 {
		t.Errorf("unpacked: %+v", s)
	}

	// A private key isn't published as a verifier's key.
	_ = os.WriteFile(filepath.Join(dir, "keys/images.pub"), []byte("-----BEGIN ENCRYPTED SIGSTORE PRIVATE KEY-----\n"), 0o644)
	if _, _, err := PackProfile(filepath.Join(dir, "org/factory.org.yaml")); err == nil || !strings.Contains(err.Error(), "is a private key") {
		t.Errorf("private key: %v", err)
	}
}

// TestManifestVEXUnderSharedProfile: a manifest's spec.vex is local VEX
// too.
func TestManifestVEXUnderSharedProfile(t *testing.T) {
	dir := writeFiles(t, map[string]string{"image.yaml": "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: Image\nmetadata: {name: x}\nspec:\n  base: cgr.dev/chainguard/static:latest\n  vex: [triage.json]\n"})
	load := func() *Manifest {
		m, err := Load(filepath.Join(dir, "image.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	o := DefaultOrg()
	o.Registry = "registry.example"
	if err := load().ApplyOrg(o); err != nil {
		t.Errorf("no shared profile: %v", err)
	}
	o.Shared = &SharedProfile{Ref: "registry.example/factory/org:1"}
	if err := load().ApplyOrg(o); err == nil || !strings.Contains(err.Error(), "spec.vex: the shared profile registry.example/factory/org:1 doesn't take VEX statements") {
		t.Errorf("shared, local VEX refused: %v", err)
	}
	o.Vulnerabilities.AllowLocalVEX = true
	if err := load().ApplyOrg(o); err != nil {
		t.Errorf("shared, local VEX allowed: %v", err)
	}
}
