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

// scopeStatements reads the OpenVEX documents files (readVEX) and writes
// to outPath one OpenVEX document holding the statements that apply to a
// scan of img over the SBOM at sbomPath, by the rule clearcutt-verify
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
//   - Any other purl is a package: the statement is passed with that
//     product alone, as {"@id": purl}, and applies wherever the scanner
//     finds that package, in every image.
//   - A statement about this image is rewritten to the packages its
//     subcomponents name (by @id, else identifiers.purl), since grype,
//     scanning an SBOM, applies only package products; with no
//     subcomponents, to every package in the SBOM. Subcomponents none of
//     which names a package leave the statement out: it never widens to
//     every package.
//
// Each product a statement names becomes a statement of its own, as
// clearcutt-verify writes them. Statements about other images are left
// out. It returns what was written (nil when nothing applied, and then
// nothing is written).
func scopeStatements(files []string, img Image, sbomPath, outPath string) ([]Applied, error) {
	docs, err := readVEX(files)
	if err != nil {
		return nil, err
	}
	var applied []Applied
	var statements []vexStatement
	var sources []string
	var sbomPackages []string
	for _, d := range docs {
		for _, st := range d.statements {
			for _, p := range st.Products {
				a := Applied{Document: d.name, Vulnerability: st.Vulnerability.Name, Status: st.Status, Justification: st.Justification, Product: p.ID, names: st.Vulnerability.names()}
				var pkgs []string
				switch productKind(p.ID) {
				case productPackage:
					a.Scope, pkgs = ScopePackage, []string{p.ID}
				case productImage:
					if !img.names(p.ID) {
						continue
					}
					a.Scope = ScopeImage
					for _, c := range p.Subcomponents {
						if c.ID != "" {
							pkgs = append(pkgs, c.ID)
						}
					}
					if len(p.Subcomponents) == 0 {
						if sbomPackages == nil {
							if sbomPackages, err = packagesOf(sbomPath); err != nil {
								return nil, err
							}
						}
						pkgs, a.anyPackage = sbomPackages, true
					}
				default:
					continue
				}
				if len(pkgs) == 0 {
					// Subcomponents it names but none we can read: it
					// applies to no package, never to every one.
					continue
				}
				a.Packages = pkgs
				out := st
				out.Subcomponents = nil
				out.Products = nil
				for _, pk := range pkgs {
					out.Products = append(out.Products, vexProduct{ID: pk})
				}
				statements = append(statements, out)
				applied = append(applied, a)
				if !slices.Contains(sources, d.name) {
					sources = append(sources, d.name)
				}
			}
		}
	}
	if len(statements) == 0 {
		return nil, nil
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
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return nil, err
	}
	return applied, os.WriteFile(outPath, append(b, '\n'), 0o644)
}

// vexDocument is an OpenVEX document as readVEX read it.
type vexDocument struct {
	// name is the document's @id, else its file name.
	name       string
	statements []vexStatement
}

// vexStatement is one OpenVEX statement, with the fields clearcutt-verify
// reads and passes to grype; others are dropped. Subcomponents is where
// OpenVEX 0.0.1 names them, on the statement; readVEX moves them to the
// products.
type vexStatement struct {
	Vulnerability   vexVulnerability `json:"vulnerability"`
	Products        []vexProduct     `json:"products"`
	Subcomponents   []vexComponent   `json:"subcomponents,omitempty"`
	Status          string           `json:"status"`
	Justification   string           `json:"justification,omitempty"`
	Timestamp       string           `json:"timestamp,omitempty"`
	ImpactStatement string           `json:"impact_statement,omitempty"`
	ActionStatement string           `json:"action_statement,omitempty"`
}

type vexVulnerability struct {
	ID      string   `json:"@id,omitempty"`
	Name    string   `json:"name"`
	Aliases []string `json:"aliases,omitempty"`
}

// UnmarshalJSON reads a vulnerability as an object, or as the plain
// string OpenVEX 0.0.1 uses, which is its name.
func (v *vexVulnerability) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*v = vexVulnerability{Name: s}
		return nil
	}
	type plain vexVulnerability
	var p plain
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	*v = vexVulnerability(p)
	return nil
}

// names lists the vulnerability's name and aliases.
func (v vexVulnerability) names() []string {
	return append([]string{v.Name}, v.Aliases...)
}

type vexProduct struct {
	ID            string         `json:"@id"`
	Identifiers   map[string]any `json:"identifiers,omitempty"`
	Subcomponents []vexComponent `json:"subcomponents,omitempty"`
}

type vexComponent struct {
	ID          string         `json:"@id"`
	Identifiers map[string]any `json:"identifiers,omitempty"`
}

// UnmarshalJSON reads a product as an object, or as the plain string
// older documents use; with no @id, its identifiers.purl names it.
func (p *vexProduct) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*p = vexProduct{ID: s}
		return nil
	}
	type plain vexProduct
	var v plain
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*p = vexProduct(v)
	if p.ID == "" {
		if purl, ok := p.Identifiers["purl"].(string); ok {
			p.ID = purl
		}
	}
	return nil
}

// UnmarshalJSON reads a subcomponent as a product is read.
func (c *vexComponent) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*c = vexComponent{ID: s}
		return nil
	}
	type plain vexComponent
	var v plain
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*c = vexComponent(v)
	if c.ID == "" {
		if purl, ok := c.Identifiers["purl"].(string); ok {
			c.ID = purl
		}
	}
	return nil
}

// readVEX reads OpenVEX documents as clearcutt-verify reads them, and
// refuses what it refuses: a file that isn't an OpenVEX document (its
// @context must start with https://openvex.dev/ns), a field of the wrong
// type (subcomponents that aren't a list, say), and a statement that names
// no vulnerability, no product, a product without an @id (or
// identifiers.purl), or no status. Nothing malformed is passed on, so
// nothing malformed can widen a statement. OpenVEX 0.0.1 is read as 0.2:
//
//   - a vulnerability given as a string S is {"name": S};
//   - a product or subcomponent given as a string S is {"@id": S};
//   - subcomponents on the statement are given to each of its products
//     that names none of its own (a product's own are kept), and the
//     statement's are dropped.
func readVEX(files []string) ([]vexDocument, error) {
	var out []vexDocument
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var doc struct {
			Context    string         `json:"@context"`
			ID         string         `json:"@id"`
			Statements []vexStatement `json:"statements"`
		}
		if err := json.Unmarshal(b, &doc); err != nil {
			return nil, fmt.Errorf("%s: not an OpenVEX document: %w", f, err)
		}
		if !strings.HasPrefix(doc.Context, "https://openvex.dev/ns") {
			return nil, fmt.Errorf("%s: not an OpenVEX document (@context %q)", f, doc.Context)
		}
		for i := range doc.Statements {
			st := &doc.Statements[i]
			switch {
			case st.Vulnerability.Name == "":
				return nil, fmt.Errorf("%s: statements[%d] names no vulnerability", f, i)
			case len(st.Products) == 0:
				return nil, fmt.Errorf("%s: statements[%d] (%s) names no product", f, i, st.Vulnerability.Name)
			case st.Status == "":
				return nil, fmt.Errorf("%s: statements[%d] (%s) has no status", f, i, st.Vulnerability.Name)
			}
			for j := range st.Products {
				p := &st.Products[j]
				if p.ID == "" {
					return nil, fmt.Errorf("%s: statements[%d] (%s) products[%d] has no @id", f, i, st.Vulnerability.Name, j)
				}
				if len(p.Subcomponents) == 0 {
					p.Subcomponents = st.Subcomponents
				}
			}
			st.Subcomponents = nil
		}
		name := doc.ID
		if name == "" {
			name = filepath.Base(f)
		}
		out = append(out, vexDocument{name: name, statements: doc.Statements})
	}
	return out, nil
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
