// Package apk reads APK repository indexes and resolves a fully pinned package
// set, so `apk add` installs the same versions on every build.
package apk

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/rsa"
	_ "crypto/sha1" // APKINDEX signatures may use SHA-1
	_ "crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// Package is one entry of an APKINDEX.
type Package struct {
	Name         string
	Version      string
	Arch         string
	Checksum     string
	Origin       string
	License      string
	Depends      []string
	Provides     []string
	InstallIf    []string
	ProviderPrio int
	Repo         string
}

// Index is the union of the indexes of several repositories for one arch.
type Index struct {
	Arch     string
	byName   map[string][]*Package
	provides map[string][]*Package
}

// FetchIndex downloads and merges the APKINDEX of each repository for arch
// (apk arch names: x86_64, aarch64). Each index must be signed by one of keys
// (file name → PEM public key, as in /etc/apk/keys).
func FetchIndex(ctx context.Context, client *http.Client, repos []string, arch string, keys map[string][]byte) (*Index, error) {
	idx := &Index{Arch: arch, byName: map[string][]*Package{}, provides: map[string][]*Package{}}
	for _, repo := range repos {
		url := strings.TrimSuffix(repo, "/") + "/" + arch + "/APKINDEX.tar.gz"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
		}
		data, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", url, err)
		}
		if err := VerifyIndexSignature(data, keys); err != nil {
			return nil, fmt.Errorf("%s: %w", url, err)
		}
		pkgs, err := ParseIndexArchive(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", url, err)
		}
		for _, p := range pkgs {
			p.Repo = repo
			idx.add(p)
		}
	}
	return idx, nil
}

func (idx *Index) add(p *Package) {
	idx.byName[p.Name] = append(idx.byName[p.Name], p)
	for _, prov := range p.Provides {
		name, _, _ := splitDep(prov)
		idx.provides[name] = append(idx.provides[name], p)
	}
}

// Has reports whether any version of the named package is in the index.
func (idx *Index) Has(name string) bool { return len(idx.byName[name]) > 0 }

// NewIndex builds an index from parsed packages (used by tests).
func NewIndex(arch string, pkgs []*Package) *Index {
	idx := &Index{Arch: arch, byName: map[string][]*Package{}, provides: map[string][]*Package{}}
	for _, p := range pkgs {
		idx.add(p)
	}
	return idx
}

// VerifyIndexSignature checks an APKINDEX.tar.gz: its first gzip stream holds
// .SIGN.RSA[256].<key> entries signing the raw bytes of the rest of the file.
func VerifyIndexSignature(data []byte, keys map[string][]byte) error {
	br := bytes.NewReader(data)
	zr, err := gzip.NewReader(br)
	if err != nil {
		return err
	}
	zr.Multistream(false)
	sigTar, err := io.ReadAll(zr)
	if err != nil {
		return err
	}
	// gzip reads br directly (it is an io.ByteReader), so br stops exactly at
	// the end of the first stream.
	signed := data[len(data)-br.Len():]

	tr := tar.NewReader(bytes.NewReader(sigTar))
	var tried []string
	for {
		h, err := tr.Next()
		if err != nil {
			break // the signature segment has no end-of-archive marker
		}
		rest, ok := strings.CutPrefix(h.Name, ".SIGN.")
		if !ok {
			continue
		}
		alg, keyName, ok := strings.Cut(rest, ".")
		if !ok {
			continue
		}
		sig, err := io.ReadAll(tr)
		if err != nil {
			return err
		}
		tried = append(tried, keyName)
		pemBytes, ok := keys[keyName]
		if !ok {
			continue
		}
		pub, err := parseRSAKey(pemBytes)
		if err != nil {
			return fmt.Errorf("key %s: %w", keyName, err)
		}
		var hash crypto.Hash
		switch alg {
		case "RSA256":
			hash = crypto.SHA256
		case "RSA":
			hash = crypto.SHA1
		default:
			continue
		}
		hh := hash.New()
		hh.Write(signed)
		if rsa.VerifyPKCS1v15(pub, hash, hh.Sum(nil), sig) == nil {
			return nil
		}
		return fmt.Errorf("index signature by %s does not verify", keyName)
	}
	if len(tried) == 0 {
		return errors.New("index is not signed")
	}
	return fmt.Errorf("index is signed by %s, none of which the base image trusts (/etc/apk/keys)", strings.Join(tried, ", "))
}

func parseRSAKey(b []byte) (*rsa.PublicKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("not PEM")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := k.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA key")
	}
	return pub, nil
}

// ParseIndexArchive reads APKINDEX.tar.gz: concatenated gzip streams (signature,
// then DESCRIPTION + APKINDEX) that together form one tar stream.
func ParseIndexArchive(r io.Reader) ([]*Package, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil, errors.New("APKINDEX not found in archive")
		}
		if err != nil {
			return nil, err
		}
		if h.Name == "APKINDEX" {
			return ParseIndex(tr)
		}
	}
}

// ParseIndex parses the plain-text APKINDEX (also the format of
// /lib/apk/db/installed).
func ParseIndex(r io.Reader) ([]*Package, error) {
	var pkgs []*Package
	cur := &Package{}
	flush := func() {
		if cur.Name != "" {
			pkgs = append(pkgs, cur)
		}
		cur = &Package{}
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		if len(line) < 2 || line[1] != ':' {
			continue
		}
		val := line[2:]
		switch line[0] {
		case 'P':
			cur.Name = val
		case 'V':
			cur.Version = val
		case 'A':
			cur.Arch = val
		case 'C':
			cur.Checksum = val
		case 'o':
			cur.Origin = val
		case 'L':
			cur.License = val
		case 'D':
			cur.Depends = strings.Fields(val)
		case 'p':
			cur.Provides = strings.Fields(val)
		case 'i':
			cur.InstallIf = strings.Fields(val)
		case 'k':
			cur.ProviderPrio, _ = strconv.Atoi(val)
		}
	}
	flush()
	return pkgs, sc.Err()
}

// splitDep splits "name>=1.2" into ("name", ">=", "1.2"). Conflicts ("!name")
// keep their "!" prefix in name.
func splitDep(dep string) (name, op, ver string) {
	i := strings.IndexAny(dep, "<>=~")
	if i < 0 {
		return dep, "", ""
	}
	name, rest := dep[:i], dep[i:]
	j := strings.IndexFunc(rest, func(r rune) bool { return !strings.ContainsRune("<>=~", r) })
	if j < 0 {
		return name, rest, ""
	}
	return name, rest[:j], rest[j:]
}
