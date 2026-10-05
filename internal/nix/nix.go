// Package nix locks nixpkgs packages: it evaluates store paths with a pinned
// nix container and walks their closures through a binary cache, checking
// every path's signature.
package nix

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/northcutted/declarative-image-factory/internal/container"
	"github.com/northcutted/declarative-image-factory/internal/lock"
)

const (
	DefaultCache = "https://cache.nixos.org"
	// DefaultKey is cache.nixos.org's public signing key.
	DefaultKey = "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
)

// Systems maps OCI architectures to Nix system names.
var Systems = map[string]string{"amd64": "x86_64-linux", "arm64": "aarch64-linux"}

// evalScript prints {system: {attr: outPath}} for every requested attribute.
// $1 is the flake ref, $2 the systems, the rest are attribute paths. The bin
// output is used when a package splits one off.
const evalScript = `set -eu
REF="$1"; SYSTEMS="$2"; shift 2
attrs=""
for a in "$@"; do attrs="$attrs \"$a\""; done
systems=""
for s in $SYSTEMS; do systems="$systems \"$s\""; done
nix --extra-experimental-features 'nix-command flakes' eval --json --impure --expr "
let
  p = builtins.getFlake \"$REF\";
  get = sys: attr: (p.legacyPackages.\${sys}.lib.getBin (p.lib.attrByPath (p.lib.splitString \".\" attr) (throw \"nixpkgs has no attribute \${attr}\") p.legacyPackages.\${sys})).outPath;
in builtins.listToAttrs (map (sys: { name = sys; value = builtins.listToAttrs (map (a: { name = a; value = get sys a; }) [ $attrs ]); }) [ $systems ])
"
`

// Eval returns store paths by system and attribute.
func Eval(ctx context.Context, run container.RunFunc, image, flakeRef string, systems, attrs []string) (map[string]map[string]string, error) {
	args := append([]string{flakeRef, strings.Join(systems, " ")}, attrs...)
	out, err := run(ctx, image, "", evalScript, args...)
	if err != nil {
		return nil, err
	}
	var paths map[string]map[string]string
	if err := json.Unmarshal(out, &paths); err != nil {
		return nil, fmt.Errorf("parsing nix eval output: %w", err)
	}
	return paths, nil
}

// NarInfo is the binary cache's description of one store path.
type NarInfo struct {
	StorePath  string
	NarHash    string
	NarSize    string
	References []string
	Sigs       []string
}

// ParseNarInfo parses a .narinfo document.
func ParseNarInfo(r io.Reader) (*NarInfo, error) {
	ni := &NarInfo{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ": ")
		if !ok {
			continue
		}
		switch k {
		case "StorePath":
			ni.StorePath = v
		case "NarHash":
			ni.NarHash = v
		case "NarSize":
			ni.NarSize = v
		case "References":
			ni.References = strings.Fields(v)
		case "Sig":
			ni.Sigs = append(ni.Sigs, v)
		}
	}
	if ni.StorePath == "" || ni.NarHash == "" {
		return nil, fmt.Errorf("narinfo is missing StorePath or NarHash")
	}
	return ni, sc.Err()
}

// Verify checks that one of the narinfo signatures is valid for a trusted key
// ("name:base64-ed25519-public-key").
func (ni *NarInfo) Verify(trusted []string) error {
	refs := make([]string, len(ni.References))
	for i, r := range ni.References {
		refs[i] = "/nix/store/" + r
	}
	fingerprint := fmt.Sprintf("1;%s;%s;%s;%s", ni.StorePath, ni.NarHash, ni.NarSize, strings.Join(refs, ","))
	for _, k := range trusted {
		kname, kb64, ok := strings.Cut(k, ":")
		if !ok {
			continue
		}
		pub, err := base64.StdEncoding.DecodeString(kb64)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return fmt.Errorf("trusted key %s is not an ed25519 public key", kname)
		}
		for _, s := range ni.Sigs {
			sname, sb64, ok := strings.Cut(s, ":")
			if !ok || sname != kname {
				continue
			}
			sig, err := base64.StdEncoding.DecodeString(sb64)
			if err == nil && ed25519.Verify(pub, []byte(fingerprint), sig) {
				return nil
			}
		}
	}
	return fmt.Errorf("%s has no valid signature from a trusted key", ni.StorePath)
}

var storePathRE = regexp.MustCompile(`^/nix/store/([0-9a-z]{32})-(.+)$`)

// Closure walks path's references through the cache, verifying each narinfo.
// It fails if any path is missing from the cache, since the build would then
// have to compile it.
func Closure(ctx context.Context, client *http.Client, cache string, trusted []string, path string) ([]lock.NixPath, error) {
	seen := map[string]bool{}
	var out []lock.NixPath
	queue := []string{path}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		if seen[p] {
			continue
		}
		seen[p] = true
		m := storePathRE.FindStringSubmatch(p)
		if m == nil {
			return nil, fmt.Errorf("not a store path: %s", p)
		}
		ni, err := fetchNarInfo(ctx, client, cache, m[1])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		if ni.StorePath != p {
			return nil, fmt.Errorf("cache returned %s for %s", ni.StorePath, p)
		}
		if err := ni.Verify(trusted); err != nil {
			return nil, err
		}
		out = append(out, lock.NixPath{Path: p, NarHash: ni.NarHash})
		for _, r := range ni.References {
			queue = append(queue, "/nix/store/"+r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func fetchNarInfo(ctx context.Context, client *http.Client, cache, hash string) (*NarInfo, error) {
	u := strings.TrimSuffix(cache, "/") + "/" + hash + ".narinfo"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("not in the binary cache %s (it would have to be built from source)", cache)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	return ParseNarInfo(resp.Body)
}

// NameVersion splits a store path's name into package name and version,
// e.g. ripgrep-14.1.1 → ripgrep, 14.1.1; glibc-2.40-66-bin → glibc, 2.40-66.
func NameVersion(storePath string) (name, version string) {
	m := storePathRE.FindStringSubmatch(storePath)
	if m == nil {
		return storePath, ""
	}
	full := m[2]
	parts := strings.Split(full, "-")
	for i := 1; i < len(parts); i++ {
		if parts[i] != "" && parts[i][0] >= '0' && parts[i][0] <= '9' {
			name = strings.Join(parts[:i], "-")
			rest := parts[i:]
			// Drop a trailing output name (bin, lib, dev, …).
			if n := len(rest); n > 1 && !strings.ContainsAny(rest[n-1][:1], "0123456789") {
				rest = rest[:n-1]
			}
			return name, strings.Join(rest, "-")
		}
	}
	return full, ""
}

// HashPart returns the 32-character hash of a store path.
func HashPart(storePath string) string {
	if m := storePathRE.FindStringSubmatch(storePath); m != nil {
		return m[1]
	}
	return ""
}

// nixAlphabet is nix's base32 alphabet (no e, o, u, t).
const nixAlphabet = "0123456789abcdfghijklmnpqrsvwxyz"

// DecodeBase32 decodes nix's base32, which reads characters least
// significant first.
func DecodeBase32(s string) ([]byte, error) {
	n := len(s) * 5 / 8
	out := make([]byte, n)
	for i := 0; i < len(s); i++ {
		c := strings.IndexByte(nixAlphabet, s[len(s)-i-1])
		if c < 0 {
			return nil, fmt.Errorf("invalid nix base32 character %q", s[len(s)-i-1])
		}
		b := i * 5
		j, k := b/8, b%8
		if j < n {
			out[j] |= byte(c << k)
		}
		if k > 3 && j+1 < n {
			out[j+1] |= byte(c >> (8 - k))
		} else if k > 3 && c>>(8-k) != 0 {
			return nil, fmt.Errorf("invalid nix base32 %q", s)
		}
	}
	return out, nil
}
