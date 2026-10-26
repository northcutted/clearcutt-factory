package scan

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"
)

// Image is what a scan is of, for VEX statements scoped to an image: its
// repository (ghcr.io/acme/apps/catalog) and the digests that name it (the
// index's and the platform image's).
type Image struct {
	Repository string
	Digests    []string
}

// Applied is one VEX statement as it was passed to the scanner, recorded
// in the vulnerability attestation so a suppression is visible there.
type Applied struct {
	// Document is the OpenVEX document's @id, else its file name.
	Document      string `json:"document"`
	Vulnerability string `json:"vulnerability"`
	Status        string `json:"status"`
	Justification string `json:"justification,omitempty"`
	// Product is the statement's product as written in the document.
	Product string `json:"product"`
	// Scope is image for a product that named this image (pkg:oci), which
	// was rewritten to the packages it applies to, or package for a product
	// that names a package, which applies to every image.
	Scope string `json:"scope"`
	// Packages are the package purls the statement was passed with: the
	// image product's subcomponents, or, with none, every package of the
	// SBOM; a package product itself.
	Packages []string `json:"packages"`
}

// Scope names in Applied.
const (
	ScopeImage   = "image"
	ScopePackage = "package"
)

// scopeStatements rewrites the OpenVEX statements of files for a scan of
// img over the SBOM at sbomPath, and writes one OpenVEX document to
// outPath holding the statements that apply: a statement whose product
// names this image (pkg:oci, by a digest of the image, by repository_url,
// or by the bare repository name) is rewritten to one whose products are
// the image product's subcomponents (every package in the SBOM, when it
// names none), since grype applies only package products when scanning
// an SBOM; a statement whose product names a package is kept, and applies
// to every image; a statement naming another image is left out. Documents
// that aren't OpenVEX are returned in passthrough, to be passed as they
// are. It returns what was written (nil when nothing applied).
func scopeStatements(files []string, img Image, sbomPath, outPath string) (applied []Applied, passthrough []string, err error) {
	var statements []map[string]any
	var sources []string
	var sbomPackages []string
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, nil, err
		}
		var doc struct {
			Context    string            `json:"@context"`
			ID         string            `json:"@id"`
			Statements []json.RawMessage `json:"statements"`
		}
		if err := json.Unmarshal(b, &doc); err != nil || !strings.Contains(doc.Context, "openvex") {
			passthrough = append(passthrough, f)
			continue
		}
		name := doc.ID
		if name == "" {
			name = filepath.Base(f)
		}
		for _, raw := range doc.Statements {
			var st map[string]any
			if err := json.Unmarshal(raw, &st); err != nil {
				return nil, nil, fmt.Errorf("%s: statement: %w", f, err)
			}
			vuln := vulnerabilityName(st["vulnerability"])
			status, _ := st["status"].(string)
			justification, _ := st["justification"].(string)
			var products []any
			for _, p := range asList(st["products"]) {
				id, subs := product(p)
				if id == "" {
					continue
				}
				a := Applied{Document: name, Vulnerability: vuln, Status: status, Justification: justification, Product: id}
				if !strings.HasPrefix(id, "pkg:oci/") {
					// A package (or anything else grype may match):
					// applies wherever that package is. As an object
					// (OpenVEX 0.2), whatever form the document used.
					a.Scope, a.Packages = ScopePackage, []string{id}
					if _, ok := p.(map[string]any); !ok {
						p = map[string]any{"@id": id}
					}
					products = append(products, p)
					applied = append(applied, a)
					continue
				}
				if !img.matches(id) {
					continue
				}
				pkgs := subs
				if len(pkgs) == 0 {
					if sbomPackages == nil {
						if sbomPackages, err = packagesOf(sbomPath); err != nil {
							return nil, nil, err
						}
					}
					pkgs = sbomPackages
				}
				a.Scope, a.Packages = ScopeImage, pkgs
				for _, pk := range pkgs {
					products = append(products, map[string]any{"@id": pk})
				}
				applied = append(applied, a)
			}
			if len(products) == 0 {
				continue
			}
			out := map[string]any{}
			for k, v := range st {
				out[k] = v
			}
			out["products"] = products
			statements = append(statements, out)
		}
		if !slices.Contains(sources, name) {
			sources = append(sources, name)
		}
	}
	if len(statements) == 0 {
		return nil, passthrough, nil
	}
	doc := map[string]any{
		"@context":   "https://openvex.dev/ns/v0.2.0",
		"@id":        "https://github.com/northcutted/clearcutt-factory/vex/" + strings.ReplaceAll(img.Repository, "/", "-"),
		"author":     "clearcutt-factory, from " + strings.Join(sources, ", "),
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
		"version":    1,
		"statements": statements,
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return nil, nil, err
	}
	return applied, passthrough, os.WriteFile(outPath, append(b, '\n'), 0o644)
}

// matches reports whether an OpenVEX product purl (pkg:oci/…) names the
// image: by one of its digests (the purl's version), else by its
// repository_url qualifier, else by the bare name (the repository's last
// path element, or the repository with or without its registry).
func (img Image) matches(purl string) bool {
	p, qualifiers, _ := strings.Cut(strings.TrimPrefix(purl, "pkg:oci/"), "?")
	p, _, _ = strings.Cut(p, "#")
	name, version, hasVersion := strings.Cut(p, "@")
	if v, err := url.PathUnescape(version); err == nil {
		version = v
	}
	name, _ = url.PathUnescape(name)
	if hasVersion {
		return version != "" && slices.Contains(img.Digests, version)
	}
	if q, err := url.ParseQuery(qualifiers); err == nil && q.Get("repository_url") != "" {
		return sameRepository(q.Get("repository_url"), img.Repository)
	}
	repo := strings.ToLower(img.Repository)
	name = strings.ToLower(name)
	if name == repo || name == repo[strings.LastIndex(repo, "/")+1:] {
		return true
	}
	if _, rest, ok := strings.Cut(repo, "/"); ok && name == rest {
		return true
	}
	return false
}

// sameRepository compares repositories as names: without a scheme, a
// trailing slash, a tag, or a digest, case-insensitively.
func sameRepository(a, b string) bool {
	norm := func(s string) string {
		s = strings.ToLower(strings.TrimSpace(s))
		if i := strings.Index(s, "://"); i >= 0 {
			s = s[i+3:]
		}
		s = strings.TrimSuffix(s, "/")
		if i := strings.Index(s, "@"); i >= 0 {
			s = s[:i]
		}
		if i := strings.LastIndex(s, ":"); i > strings.LastIndex(s, "/") {
			s = s[:i]
		}
		return s
	}
	return norm(a) == norm(b)
}

// product returns a statement product's purl and its subcomponents' purls:
// OpenVEX 0.2 objects ({"@id": …, "subcomponents": [{"@id": …}]}) or 0.0.1
// strings.
func product(p any) (string, []string) {
	switch v := p.(type) {
	case string:
		return v, nil
	case map[string]any:
		id, _ := v["@id"].(string)
		var subs []string
		for _, s := range asList(v["subcomponents"]) {
			if sid, _ := product(s); sid != "" {
				subs = append(subs, sid)
			}
		}
		return id, subs
	}
	return "", nil
}

func asList(v any) []any {
	l, _ := v.([]any)
	return l
}

func vulnerabilityName(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case map[string]any:
		if n, ok := x["name"].(string); ok {
			return n
		}
		if n, ok := x["@id"].(string); ok {
			return n
		}
	}
	return ""
}

// packagesOf lists the purls of the components of a CycloneDX SBOM.
func packagesOf(sbomPath string) ([]string, error) {
	b, err := os.ReadFile(sbomPath)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Components []struct {
			PURL string `json:"purl"`
		} `json:"components"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", sbomPath, err)
	}
	var out []string
	for _, c := range doc.Components {
		if c.PURL != "" && !slices.Contains(out, c.PURL) {
			out = append(out, c.PURL)
		}
	}
	sort.Strings(out)
	return out, nil
}
