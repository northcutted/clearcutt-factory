package factory

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/northcutted/clearcutt-factory/internal/manifest"
	"github.com/northcutted/clearcutt-factory/internal/registry"
)

// Shared profiles are cached under the user cache directory
// (clearcutt-factory/):
//
//   - profiles/<digest>/ holds a shared profile's artifact: its manifest
//     (manifest.json) and its files, unpacked (files/). Entries are
//     content-addressed, and read only after the manifest is checked
//     against the digest and every file against the manifest, so what
//     loads is what the digest names, whoever could write the cache.
//   - verified/ records, per pinned digest and signer, when cosign last
//     found that signer's signature on it (verifyProfile).

// profileVerifiedFor is how long a signature check of a shared profile
// made on this machine counts.
const profileVerifiedFor = 24 * time.Hour

// reverifyEnv set to 1 checks a shared profile's signature on every load;
// 0 lets CI reuse a recent check.
const reverifyEnv = "CLEARCUTT_FACTORY_REVERIFY"

// verifyClock dates verification records; tests set it.
var verifyClock = time.Now

// reverify reports whether a shared profile's signature is checked with
// cosign on every load: with --reverify or CLEARCUTT_FACTORY_REVERIFY=1,
// and by default in CI (CI or GITHUB_ACTIONS set to true), where builds
// that publish run and a cache may be shared between jobs.
// CLEARCUTT_FACTORY_REVERIFY=0 turns the CI default off; a value it can't
// read checks.
func reverify(opts Options) bool {
	if opts.Reverify {
		return true
	}
	if v := os.Getenv(reverifyEnv); v != "" {
		b, err := strconv.ParseBool(v)
		return err != nil || b
	}
	ci := func(k string) bool { b, _ := strconv.ParseBool(os.Getenv(k)); return b }
	return ci("CI") || ci("GITHUB_ACTIONS")
}

// cachedProfile returns the factory.org.yaml of the shared profile at
// digest, unpacked in the cache with the files it names. A missing entry,
// or one that doesn't match the digest, is (re)written from get.
func cachedProfile(digest string, get func() (*registry.Bundle, error)) (string, error) {
	base, err := cacheDir("profiles")
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, strings.ReplaceAll(digest, ":", "-"))
	path := filepath.Join(dir, "files", manifest.OrgFileName)
	if readCachedProfile(dir, digest) == nil {
		return path, nil
	}
	b, err := get()
	if err != nil {
		return "", err
	}
	if b.Digest != digest {
		return "", fmt.Errorf("%s resolved to %s", digest, b.Digest)
	}
	if err := checkProfileFiles(b.Files); err != nil {
		return "", fmt.Errorf("%s: %w", digest, err)
	}
	// Write beside the entry, then move it in, so an entry is always
	// complete.
	tmp, err := os.MkdirTemp(base, ".unpack-")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	if err := os.WriteFile(filepath.Join(tmp, "manifest.json"), b.Manifest, 0o644); err != nil {
		return "", err
	}
	for _, f := range b.Files {
		p := filepath.Join(tmp, "files", filepath.FromSlash(f.Name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return "", err
		}
		if err := os.WriteFile(p, f.Content, 0o644); err != nil {
			return "", err
		}
	}
	if err := os.Rename(tmp, dir); err != nil {
		// Another process wrote it meanwhile; or the entry is from an
		// older release, or was changed: replace it.
		if readCachedProfile(dir, digest) == nil {
			return path, nil
		}
		if err := os.RemoveAll(dir); err != nil {
			return "", err
		}
		if err := os.Rename(tmp, dir); err != nil {
			return "", err
		}
	}
	return path, nil
}

// readCachedProfile checks the cache entry dir against digest: its
// manifest has that digest, and every file matches the manifest.
func readCachedProfile(dir, digest string) error {
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return err
	}
	files, err := registry.ReadBundle(raw, digest, manifest.ProfileArtifactType, func(name string, size int64) ([]byte, error) {
		f, err := os.Open(filepath.Join(dir, "files", filepath.FromSlash(name)))
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }()
		return io.ReadAll(io.LimitReader(f, size+1))
	})
	if err != nil {
		return err
	}
	return checkProfileFiles(files)
}

// checkProfileFiles requires a shared profile's artifact to hold its
// factory.org.yaml.
func checkProfileFiles(files []registry.File) error {
	for _, f := range files {
		if f.Name == manifest.OrgFileName {
			if f.MediaType != manifest.ProfileMediaType {
				return fmt.Errorf("%s is a %s, not an org profile", f.Name, f.MediaType)
			}
			return nil
		}
	}
	return fmt.Errorf("no %s", manifest.OrgFileName)
}

// verification records that cosign found Signer's signature on Pinned.
type verification struct {
	Pinned     string    `json:"pinned"`
	Signer     string    `json:"signer"`
	VerifiedAt time.Time `json:"verifiedAt"`
}

// signerID identifies v in verification records: its settings, with a
// key file replaced by its content's digest, so that a key file changed
// in place is another signer. It is "" (not recorded) when the key file
// can't be read.
func signerID(v manifest.VerifyIdentity) string {
	if v.Key != "" && !strings.Contains(v.Key, "://") {
		b, err := os.ReadFile(v.Key)
		if err != nil {
			return ""
		}
		sum := sha256.Sum256(b)
		v.Key = "sha256:" + hex.EncodeToString(sum[:])
	}
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

func verificationFile(pinned, id string) (string, error) {
	dir, err := cacheDir("verified")
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(pinned + "\n" + id))
	return filepath.Join(dir, hex.EncodeToString(sum[:])+".json"), nil
}

// verifiedAt returns when cosign last found id's signature on pinned on
// this machine, if within profileVerifiedFor.
func verifiedAt(pinned, id string) (time.Time, bool) {
	if id == "" {
		return time.Time{}, false
	}
	p, err := verificationFile(pinned, id)
	if err != nil {
		return time.Time{}, false
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return time.Time{}, false
	}
	var v verification
	if json.Unmarshal(b, &v) != nil || v.Pinned != pinned || v.Signer != id {
		return time.Time{}, false
	}
	// A record from the future (a clock set back) doesn't count either.
	age := verifyClock().Sub(v.VerifiedAt)
	return v.VerifiedAt, age > -time.Minute && age < profileVerifiedFor
}

// recordVerified notes that cosign found id's signature on pinned now. A
// record that can't be written only means checking again next time.
func recordVerified(pinned, id string) {
	if id == "" {
		return
	}
	p, err := verificationFile(pinned, id)
	if err != nil {
		return
	}
	b, err := json.Marshal(verification{Pinned: pinned, Signer: id, VerifiedAt: verifyClock().UTC()})
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".record-")
	if err != nil {
		return
	}
	_, werr := tmp.Write(b)
	if cerr := tmp.Close(); werr != nil || cerr != nil || os.Rename(tmp.Name(), p) != nil {
		_ = os.Remove(tmp.Name())
	}
}
