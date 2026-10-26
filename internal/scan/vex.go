package scan

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
)

// Image is what a scan is of, for VEX statements scoped to an image: its
// repository (ghcr.io/acme/apps/catalog), its tags, and the digests that
// name it (the index's and the platform image's).
type Image struct {
	Repository string
	Tags       []string
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
	// Scope is image for a product that named this image, which was
	// rewritten to the packages it applies to, or package for a product
	// that names a package, which applies to every image.
	Scope string `json:"scope"`
	// Packages are the package purls the statement was passed with: the
	// image product's subcomponents, or, with none, every package of the
	// SBOM; a package product itself.
	Packages []string `json:"packages"`

	// names are the vulnerability's name and aliases, and anyPackage says
	// an image product named no subcomponents, for attributing what the
	// scanner suppressed.
	names      []string
	anyPackage bool
}

// Scope names in Applied.
const (
	ScopeImage   = "image"
	ScopePackage = "package"
)

// scopeStatements rewrites the OpenVEX statements of files for a scan of
// img over the SBOM at sbomPath, and writes one OpenVEX document to
// outPath holding the statements that apply, by the rule clearcutt-verify
// applies to its rescans:
//
//   - A product that is an image purl (pkg:oci/… or pkg:docker/…) names
//     the image when its version (percent-decoded) is one of the image's
//     digests, or, with no version, when its repository_url qualifier is
//     the image's repository (and its tag qualifier, if any, one of the
//     image's tags). A bare pkg:oci/NAME names no image.
//   - A product that isn't a purl names the image when it is the image's
//     repository, repository:tag, repository@digest, or one of its
//     digests.
//   - Any other purl is a package: the statement is passed as it is, and
//     applies wherever the scanner finds that package, in every image.
//   - A statement about this image is rewritten to the packages its
//     subcomponents name (by @id or identifiers.purl; in an OpenVEX 0.0.1
//     document, the statement's subcomponents), since grype, scanning an
//     SBOM, applies only package products; with no subcomponents, to every
//     package in the SBOM. Subcomponents none of which can be read leave
//     the statement out: it never widens to every package.
//
// Statements about other images are left out. Documents that aren't
// OpenVEX are returned in passthrough, to be passed as they are. It
// returns what was written (nil when nothing applied).
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
		docName := doc.ID
		if docName == "" {
			docName = filepath.Base(f)
		}
		for _, raw := range doc.Statements {
			var st map[string]any
			if err := json.Unmarshal(raw, &st); err != nil {
				return nil, nil, fmt.Errorf("%s: statement: %w", f, err)
			}
			vuln, names := vulnerability(st["vulnerability"])
			status, _ := st["status"].(string)
			justification, _ := st["justification"].(string)
			// OpenVEX 0.0.1 names subcomponents on the statement.
			stmtSubs, stmtHasSubs := components(st["subcomponents"])
			var products []any
			for _, p := range asList(st["products"]) {
				id, subs, hasSubs := product(p)
				if id == "" {
					continue
				}
				a := Applied{Document: docName, Vulnerability: vuln, Status: status, Justification: justification, Product: id, names: names}
				switch productKind(id) {
				case productPackage:
					// Applies wherever that package is. As an object
					// (OpenVEX 0.2), whatever form the document used.
					a.Scope, a.Packages = ScopePackage, []string{id}
					obj, ok := p.(map[string]any)
					if !ok || obj["@id"] != id {
						obj = map[string]any{"@id": id}
					}
					products = append(products, obj)
					applied = append(applied, a)
					continue
				case productOther:
					continue
				}
				if !img.names(id) {
					continue
				}
				if !hasSubs && stmtHasSubs {
					subs, hasSubs = stmtSubs, true
				}
				pkgs := subs
				if hasSubs && len(pkgs) == 0 {
					// Subcomponents it names but none we can read: it
					// applies to no package, never to every one.
					continue
				}
				if !hasSubs {
					if sbomPackages == nil {
						if sbomPackages, err = packagesOf(sbomPath); err != nil {
							return nil, nil, err
						}
					}
					pkgs, a.anyPackage = sbomPackages, true
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
			delete(out, "subcomponents")
			out["products"] = products
			if v, ok := st["vulnerability"].(string); ok {
				// OpenVEX 0.2 names the vulnerability as an object.
				out["vulnerability"] = map[string]any{"name": v}
			}
			statements = append(statements, out)
		}
		if !slices.Contains(sources, docName) {
			sources = append(sources, docName)
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

// Kinds of VEX product.
const (
	productImage   = "image"
	productPackage = "package"
	productOther   = "other"
)

// productKind says what a product names: an image (a pkg:oci or
// pkg:docker purl, or a reference that isn't a purl), or a package (any
// other purl).
func productKind(id string) string {
	id = strings.TrimSpace(id)
	switch {
	case id == "":
		return productOther
	case strings.HasPrefix(id, "pkg:oci/"), strings.HasPrefix(id, "pkg:docker/"):
		return productImage
	case strings.HasPrefix(id, "pkg:"):
		return productPackage
	}
	return productImage
}

// names reports whether an image product names the image (see
// scopeStatements).
func (img Image) names(id string) bool {
	id = strings.TrimSpace(id)
	isDigest := func(d string) bool {
		d = strings.ToLower(strings.TrimSpace(d))
		for _, x := range img.Digests {
			if x != "" && d == strings.ToLower(x) {
				return true
			}
		}
		return false
	}
	repo := normalizeRepo(img.Repository)
	sameRepo := func(r string) bool {
		r = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(r), "https://"), "oci://"), "/")
		return r != "" && normalizeRepo(qualify(r)) == repo
	}
	if !strings.HasPrefix(id, "pkg:") {
		// A reference: repository, repository:tag, repository@digest, or a digest.
		if isDigest(id) {
			return true
		}
		if ref, digest, ok := strings.Cut(id, "@"); ok {
			return sameRepo(ref) && isDigest(digest)
		}
		if sameRepo(id) {
			return true
		}
		if tag := tagOf(id); tag != "" {
			return sameRepo(repoOf(id)) && slices.Contains(img.Tags, tag)
		}
		return false
	}
	// An image purl: pkg:oci/NAME[@VERSION][?QUALIFIERS].
	rest := id[strings.Index(id, "/")+1:]
	rest, query, _ := strings.Cut(rest, "?")
	rest, _, _ = strings.Cut(rest, "#")
	_, version, hasVersion := strings.Cut(rest, "@")
	q, _ := url.ParseQuery(query)
	if hasVersion {
		if v, err := url.PathUnescape(version); err == nil {
			version = v
		}
		return isDigest(version)
	}
	repoURL := q.Get("repository_url")
	if repoURL == "" || !sameRepo(repoURL) {
		return false
	}
	if tag := q.Get("tag"); tag != "" && !slices.Contains(img.Tags, tag) {
		return false
	}
	return true
}

// normalizeRepo names Docker Hub repositories docker.io/…, not
// index.docker.io/….
func normalizeRepo(ref string) string {
	if rest, ok := strings.CutPrefix(ref, "index.docker.io/"); ok {
		return "docker.io/" + rest
	}
	return ref
}

// qualify spells out Docker Hub short names (debian:trixie-slim →
// docker.io/library/debian:trixie-slim), keeping a tag.
func qualify(ref string) string {
	r, err := name.ParseReference(ref)
	if err != nil {
		return ref
	}
	repo := r.Context().Name()
	if rest, ok := strings.CutPrefix(repo, name.DefaultRegistry+"/"); ok {
		repo = "docker.io/" + rest
	}
	base, _, _ := strings.Cut(ref, "@")
	if i := strings.LastIndex(base, ":"); i > strings.LastIndex(base, "/") {
		repo += base[i:]
	}
	return repo
}

func repoOf(ref string) string {
	ref, _, _ = strings.Cut(ref, "@")
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		ref = ref[:i]
	}
	return ref
}

func tagOf(ref string) string {
	ref, _, _ = strings.Cut(ref, "@")
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		return ref[i+1:]
	}
	return ""
}

// product returns a statement product's identifier (its @id, else
// identifiers.purl; or the string an OpenVEX 0.0.1 document gives), its
// subcomponents' identifiers, and whether it names subcomponents at all.
func product(p any) (id string, subs []string, hasSubs bool) {
	switch v := p.(type) {
	case string:
		return v, nil, false
	case map[string]any:
		subs, hasSubs = components(v["subcomponents"])
		return componentID(v), subs, hasSubs
	}
	return "", nil, false
}

// components reads a list of subcomponents: the identifiers that can be
// read, and whether the list names any.
func components(v any) (ids []string, named bool) {
	for _, c := range asList(v) {
		named = true
		if id := componentID(c); id != "" {
			ids = append(ids, id)
		}
	}
	return ids, named
}

// componentID is a product's or subcomponent's @id, else its
// identifiers.purl; a string is its own.
func componentID(c any) string {
	switch v := c.(type) {
	case string:
		return strings.TrimSpace(v)
	case map[string]any:
		if id, _ := v["@id"].(string); strings.TrimSpace(id) != "" {
			return strings.TrimSpace(id)
		}
		if ids, ok := v["identifiers"].(map[string]any); ok {
			if purl, _ := ids["purl"].(string); strings.TrimSpace(purl) != "" {
				return strings.TrimSpace(purl)
			}
		}
	}
	return ""
}

func asList(v any) []any {
	l, _ := v.([]any)
	return l
}

// vulnerability returns a statement's vulnerability name and every name it
// goes by (the name, @id, and aliases).
func vulnerability(v any) (string, []string) {
	switch x := v.(type) {
	case string:
		return x, []string{x}
	case map[string]any:
		var names []string
		for _, k := range []string{"name", "@id"} {
			if n, ok := x[k].(string); ok && n != "" {
				names = append(names, n)
			}
		}
		for _, a := range asList(x["aliases"]) {
			if n, ok := a.(string); ok && n != "" {
				names = append(names, n)
			}
		}
		if len(names) > 0 {
			return names[0], names
		}
	}
	return "", nil
}

// Suppression is a finding the scanner left out because of a VEX
// statement, with the statement that did it, as far as it can be told.
type Suppression struct {
	Vulnerability string `json:"vulnerability"`
	Package       string `json:"package"`
	Version       string `json:"version"`
	PURL          string `json:"purl,omitempty"`
	// The statement: its document, its product as written, status, and
	// justification. Empty when the scanner applied a VEX statement that
	// matches none of those passed.
	Document      string `json:"document,omitempty"`
	Product       string `json:"product,omitempty"`
	Status        string `json:"status,omitempty"`
	Justification string `json:"justification,omitempty"`
}

// attribute names the statement that suppressed a finding: the first
// passed whose vulnerability (or an alias) is one of ids and whose packages
// include the finding's, as grype matches purls.
func attribute(applied []Applied, ids []string, s Suppression) Suppression {
	for _, a := range applied {
		if !namesAny(a.names, ids) {
			continue
		}
		hit := a.anyPackage
		for _, p := range a.Packages {
			hit = hit || purlMatches(p, s.PURL)
		}
		if hit {
			s.Document, s.Product, s.Status, s.Justification = a.Document, a.Product, a.Status, a.Justification
			return s
		}
	}
	return s
}

func namesAny(names, ids []string) bool {
	for _, n := range names {
		for _, id := range ids {
			if strings.EqualFold(strings.TrimSpace(n), strings.TrimSpace(id)) {
				return true
			}
		}
	}
	return false
}

// purlMatches reports whether a VEX product purl names a package purl the
// way grype matches them: the type, namespace, and name are equal; the
// version, when the product has one; and every qualifier the product has.
func purlMatches(product, artifact string) bool {
	pName, pVersion, pQ := splitPURL(product)
	aName, aVersion, aQ := splitPURL(artifact)
	if pName == "" || pName != aName {
		return false
	}
	if pVersion != "" && pVersion != aVersion {
		return false
	}
	for k, v := range pQ {
		if aQ[k] != v {
			return false
		}
	}
	return true
}

// splitPURL splits pkg:type/namespace/name@version?qualifiers#subpath into
// the type/namespace/name path, the version, and the qualifiers.
func splitPURL(purl string) (id, version string, qualifiers map[string]string) {
	purl = strings.TrimSpace(purl)
	if !strings.HasPrefix(purl, "pkg:") {
		return "", "", nil
	}
	purl, _, _ = strings.Cut(purl, "#")
	purl, query, _ := strings.Cut(purl, "?")
	id, version, _ = strings.Cut(strings.TrimPrefix(purl, "pkg:"), "@")
	if v, err := url.PathUnescape(version); err == nil {
		version = v
	}
	id = strings.ToLower(path.Clean("/" + id))[1:]
	qualifiers = map[string]string{}
	q, _ := url.ParseQuery(query)
	for k, vs := range q {
		if len(vs) > 0 {
			qualifiers[strings.ToLower(k)] = vs[0]
		}
	}
	return id, version, qualifiers
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
