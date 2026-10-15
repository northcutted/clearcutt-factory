// Package attest builds in-toto statements (including factory's recipe
// predicate) and drives cosign to sign and attach them.
package attest

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

const (
	StatementType = "https://in-toto.io/Statement/v1"

	// RecipePredicateType identifies factory's reproducibility recipe.
	RecipePredicateType = "https://github.com/northcutted/clearcutt-factory/recipe/v1"
	// RebasePredicateType identifies the record of a rebase, which is
	// enough to repeat it.
	RebasePredicateType = "https://github.com/northcutted/clearcutt-factory/rebase/v1"
	// ReproductionPredicateType identifies the record that an image was
	// reproduced: rebuilt from its recipe, or its rebase repeated from its
	// record, giving the same digest.
	ReproductionPredicateType = "https://github.com/northcutted/clearcutt-factory/reproduction/v1"

	// Predicate types from before the project was named clearcutt-factory,
	// accepted when verifying images published then.
	legacyRecipePredicateType = "https://github.com/northcutted/declarative-image-factory/recipe/v1"
	legacyRebasePredicateType = "https://github.com/northcutted/declarative-image-factory/rebase/v1"
	CycloneDXType             = "https://cyclonedx.org/bom"
	VulnType                  = "https://cosign.sigstore.dev/attestation/vuln/v1"

	// maxEmbeddedContext caps the context bytes embedded in the recipe; larger
	// contexts record hashes only and rebuilds need the source checkout.
	maxEmbeddedContext = 2 << 20
)

type Statement struct {
	Type          string    `json:"_type"`
	Subject       []Subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     any       `json:"predicate"`
}

type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// NewStatement wraps predicate for the image repo@digest.
func NewStatement(repo, digest, predicateType string, predicate any) Statement {
	algo, hexd, _ := strings.Cut(digest, ":")
	return Statement{
		Type:          StatementType,
		Subject:       []Subject{{Name: repo, Digest: map[string]string{algo: hexd}}},
		PredicateType: predicateType,
		Predicate:     predicate,
	}
}

// Recipe is everything needed to rebuild the image and check the digest.
type Recipe struct {
	Factory       FactoryInfo    `json:"factory"`
	Build         BuildSettings  `json:"build"`
	Containerfile string         `json:"containerfile"`
	Manifest      string         `json:"manifest"`
	Lock          string         `json:"lock"`
	Context       []ContextEntry `json:"context,omitempty"`
	Image         ImageDigests   `json:"image"`

	// Verified names the attestation the recipe was read from.
	Verified Evidence `json:"-"`
}

// Rebase records a rebase: the image whose layers moved, the base each
// platform left, and the base it moved onto. Repeating the rebase from
// these digests yields Result again.
type Rebase struct {
	Factory FactoryInfo `json:"factory"`
	// Image is the image that was rebased (repo@digest).
	Image string `json:"image"`
	// From is the old base of each platform (repo@digest of its image).
	From map[string]string `json:"from"`
	Onto RebaseBase        `json:"onto"`
	// Config lists, per platform, configuration that followed the base.
	Config map[string][]string `json:"config,omitempty"`
	Result ImageDigests        `json:"result"`

	// Verified names the attestation the record was read from.
	Verified Evidence `json:"-"`
}

// Reproduction records that an image was reproduced: rebuilt without cache
// from its signed recipe (method recipe-rebuild), or its rebase repeated from
// its signed record (rebase-repeat), giving the image's digest again. Its
// subject is the image (the index) that was reproduced.
type Reproduction struct {
	// Method is recipe-rebuild or rebase-repeat.
	Method string `json:"method"`
	// Image is the image that was reproduced (repo@digest).
	Image string `json:"image"`
	// Digest is what the reproduction gave, which is the image's digest.
	Digest string `json:"digest"`
	// From is the verified recipe or rebase record it was reproduced from.
	From Evidence `json:"from"`
	// Factory is the clearcutt-factory that reproduced it.
	Factory FactoryInfo `json:"factory"`
	// BuildKit is the pinned BuildKit the recipe was rebuilt with
	// (recipe-rebuild only).
	BuildKit string `json:"buildkit,omitempty"`
	// Builder is where it was reproduced.
	Builder Builder `json:"builder"`
	// ReproducedAt is when (RFC 3339, UTC).
	ReproducedAt string `json:"reproducedAt"`
}

// Evidence names an attestation: its predicate type and the digest of its
// in-toto statement (the signed DSSE payload).
type Evidence struct {
	PredicateType string            `json:"predicateType"`
	Digest        map[string]string `json:"digest"`
}

// Builder is the machine, and the CI run if any, that reproduced an image.
type Builder struct {
	// ID is the CI run: on GitHub Actions, the run attempt's URL.
	ID string `json:"id,omitempty"`
	// Workflow is the workflow the run belongs to (GitHub's
	// GITHUB_WORKFLOW_REF: the calling workflow, for a reusable one), and
	// Job the job in it.
	Workflow string `json:"workflow,omitempty"`
	Job      string `json:"job,omitempty"`
	// Runner is github-hosted or self-hosted, on GitHub Actions.
	Runner string `json:"runner,omitempty"`
	// OS and Arch are the machine's (Go's GOOS and GOARCH).
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

// RebaseBase is the new base: its name (recorded in the image's base
// annotation) and what it resolved to.
type RebaseBase struct {
	Name string `json:"name"`
	Ref  string `json:"ref"`
}

type FactoryInfo struct {
	Version string `json:"version"`
}

type BuildSettings struct {
	BuildKit        string   `json:"buildkit"`
	Platforms       []string `json:"platforms"`
	SourceDateEpoch int64    `json:"sourceDateEpoch"`
	Output          string   `json:"output"`
	// Annotations are extra exporter options appended to Output.
	Annotations []string `json:"annotations,omitempty"`
}

type ContextEntry struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256,omitempty"`
	Mode    uint32 `json:"mode"`
	Content []byte `json:"content,omitempty"`
	// Link is a symlink's target (no content or hash).
	Link string `json:"link,omitempty"`
}

type ImageDigests struct {
	Ref       string            `json:"ref"`
	Digest    string            `json:"digest"`
	Platforms map[string]string `json:"platforms"`
}

// ContextEntries records the staged build context (minus the Containerfile),
// embedding contents when they are small enough.
func ContextEntries(dir, containerfile string) ([]ContextEntry, error) {
	var entries []ContextEntry
	total := 0
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		if rel == containerfile {
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			link, err := os.Readlink(p)
			if err != nil {
				return err
			}
			entries = append(entries, ContextEntry{Path: rel, Mode: 0o777, Link: link})
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%s: only regular files, directories, and symlinks can be in the build context", rel)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		total += len(b)
		entries = append(entries, ContextEntry{Path: rel, SHA256: hex.EncodeToString(sum[:]), Mode: uint32(info.Mode().Perm()), Content: b})
		return nil
	})
	if err != nil {
		return nil, err
	}
	if total > maxEmbeddedContext {
		for i := range entries {
			entries[i].Content = nil
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries, nil
}

// Materialize writes the recipe's Containerfile and context into dir.
func (r *Recipe) Materialize(dir, containerfile string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, containerfile), []byte(r.Containerfile), 0o644); err != nil {
		return err
	}
	for _, e := range r.Context {
		p := filepath.Join(dir, filepath.FromSlash(e.Path))
		if !strings.HasPrefix(p, filepath.Clean(dir)+string(filepath.Separator)) {
			return fmt.Errorf("recipe context path %q escapes the context", e.Path)
		}
		if e.Link != "" {
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				return err
			}
			if err := os.Symlink(e.Link, p); err != nil {
				return err
			}
			continue
		}
		if e.Content == nil {
			return fmt.Errorf("recipe does not embed %s (context too large); rebuild from the source checkout with -f", e.Path)
		}
		sum := sha256.Sum256(e.Content)
		if hex.EncodeToString(sum[:]) != e.SHA256 {
			return fmt.Errorf("recipe context %s does not match its recorded sha256", e.Path)
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, e.Content, fs.FileMode(e.Mode)); err != nil {
			return err
		}
	}
	return nil
}

// WriteJSON writes v as indented JSON.
func WriteJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// Cosign signs images and attaches attestations.
type Cosign struct {
	Mode   string // keyless or key
	Key    string
	Args   []string
	Stdout io.Writer
	Stderr io.Writer
}

// Run runs a cosign command with the signing key and arguments.
func (c Cosign) Run(ctx context.Context, args ...string) error { return c.run(ctx, args...) }

// VerifySignature verifies ref's cosign signature against args (a key, or
// a certificate identity and issuer).
func VerifySignature(ctx context.Context, ref string, args []string) error {
	bin, err := exec.LookPath("cosign")
	if err != nil {
		return errors.New("cosign not found on PATH")
	}
	cmd := exec.CommandContext(ctx, bin, append(append([]string{"verify", "--output", "json"}, args...), ref)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cosign verify: %w\n%s", err, stderr.String())
	}
	return nil
}

func (c Cosign) run(ctx context.Context, args ...string) error {
	bin, err := exec.LookPath("cosign")
	if err != nil {
		return errors.New("cosign not found on PATH (needed to sign; set signing.mode: none to skip)")
	}
	if c.Mode == "key" {
		args = append(args, "--key", c.Key)
	}
	args = append(append(args, "--yes"), c.Args...)
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdout, cmd.Stderr = c.Stdout, c.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cosign %s: %w", args[0], err)
	}
	return nil
}

// Sign signs ref (an index digest) and every platform image in it.
func (c Cosign) Sign(ctx context.Context, ref string) error {
	return c.run(ctx, "sign", "--recursive", ref)
}

// Attest attaches a signed attestation of predicateType to ref.
func (c Cosign) Attest(ctx context.Context, ref, predicateType, predicatePath string) error {
	return c.run(ctx, "attest", "--type", predicateType, "--predicate", predicatePath, ref)
}

// VerifyRecipe verifies and returns the recipe attestation on ref.
func VerifyRecipe(ctx context.Context, ref string, args []string) (*Recipe, error) {
	raw, ev, err := verifyEither(ctx, ref, RecipePredicateType, legacyRecipePredicateType, args)
	if err != nil {
		return nil, err
	}
	var r Recipe
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("parsing recipe: %w", err)
	}
	r.Verified = ev
	return &r, nil
}

// VerifyRebase verifies and returns the rebase record on ref.
func VerifyRebase(ctx context.Context, ref string, args []string) (*Rebase, error) {
	raw, ev, err := verifyEither(ctx, ref, RebasePredicateType, legacyRebasePredicateType, args)
	if err != nil {
		return nil, err
	}
	var r Rebase
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("parsing rebase record: %w", err)
	}
	r.Verified = ev
	return &r, nil
}

// verifyEither verifies the current predicate type, then the legacy one.
func verifyEither(ctx context.Context, ref, current, legacy string, args []string) (json.RawMessage, Evidence, error) {
	raw, ev, err := verifyStatement(ctx, ref, current, args)
	if err == nil {
		return raw, ev, nil
	}
	if raw, ev, lerr := verifyStatement(ctx, ref, legacy, args); lerr == nil {
		return raw, ev, nil
	}
	return nil, Evidence{}, err
}

// VerifyPredicate verifies the attestations of predicateType on ref with
// cosign and returns the predicate.
func VerifyPredicate(ctx context.Context, ref, predicateType string, args []string) (json.RawMessage, error) {
	raw, _, err := verifyStatement(ctx, ref, predicateType, args)
	return raw, err
}

// verifyStatement verifies the attestations of predicateType on ref with
// cosign and returns the predicate and which statement it came from.
func verifyStatement(ctx context.Context, ref, predicateType string, args []string) (json.RawMessage, Evidence, error) {
	bin, err := exec.LookPath("cosign")
	if err != nil {
		return nil, Evidence{}, errors.New("cosign not found on PATH")
	}
	cmd := exec.CommandContext(ctx, bin, append([]string{"verify-attestation", "--type", predicateType, "--output", "json"}, append(args, ref)...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, Evidence{}, fmt.Errorf("cosign verify-attestation: %w\n%s", err, stderr.String())
	}
	return predicateFromEnvelopes(out, predicateType)
}

// predicateFromEnvelopes extracts the predicate from cosign's DSSE envelope
// output (one JSON envelope per line), and names the statement it is in by
// the sha256 of the payload.
func predicateFromEnvelopes(out []byte, predicateType string) (json.RawMessage, Evidence, error) {
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 64<<20), 64<<20)
	for sc.Scan() {
		var env struct {
			Payload string `json:"payload"`
		}
		if json.Unmarshal(sc.Bytes(), &env) != nil || env.Payload == "" {
			continue
		}
		payload, err := base64.StdEncoding.DecodeString(env.Payload)
		if err != nil {
			continue
		}
		var st struct {
			PredicateType string          `json:"predicateType"`
			Predicate     json.RawMessage `json:"predicate"`
		}
		if json.Unmarshal(payload, &st) == nil && st.PredicateType == predicateType {
			sum := sha256.Sum256(payload)
			return st.Predicate, Evidence{PredicateType: predicateType, Digest: map[string]string{"sha256": hex.EncodeToString(sum[:])}}, nil
		}
	}
	return nil, Evidence{}, fmt.Errorf("no %s attestation found in cosign output", predicateType)
}
