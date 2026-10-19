package render

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/northcutted/clearcutt-factory/internal/lock"
	"github.com/northcutted/clearcutt-factory/internal/manifest"
)

var (
	hex64RE = regexp.MustCompile(`^[a-f0-9]{64}$`)
	// apk package names, versions, and APKINDEX checksums (Q1: SHA-1 of the
	// control segment, Q2: SHA-256), base64.
	apkNameRE     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)
	apkVersionRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~-]*$`)
	apkChecksumRE = regexp.MustCompile(`^Q[12][A-Za-z0-9+/]+=*$`)
	// A .deb or .rpm file name (Debian quotes an epoch's colon as %3a).
	pkgFileRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~%-]*$`)
	nixStorePath = regexp.MustCompile(`^/nix/store/[a-z0-9]{32}-[A-Za-z0-9+._?=-]+$`)
)

// checkInputs refuses a manifest or lock with any value the Containerfile
// can't hold as it is: Render prints every one of them either unquoted, or
// quoted on a line that a newline would end, or in a heredoc that a line
// equal to its delimiter would end (see heredoc). Load-time validation
// applies the same rules to the manifest, so this only fires for locks
// edited by hand, or callers that skip it.
func checkInputs(m *manifest.Manifest, l *lock.Lock) error {
	var errs []error
	check := func(field string, err error) {
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", field, err))
		}
	}
	image := func(field string, i lock.Image) {
		check(field, manifest.CheckRef(i.Pinned()))
		check(field+".digest", manifest.CheckDigest(i.Digest))
	}

	check("manifest file name", manifest.CheckLine(filepath.Base(m.Path)))
	check("metadata.name", manifest.CheckName(m.Metadata.Name))
	check("metadata.ref", manifest.CheckRef(m.Metadata.Ref))
	for _, p := range m.Spec.Platforms {
		check("spec.platforms", manifest.CheckPlatform(p))
	}
	errs = append(errs, m.CheckSafe()...)

	image("lock builder.buildkit", l.Builder.BuildKit)
	image("lock builder.frontend", l.Builder.Frontend)
	image("lock builder.toolbox", l.Builder.Toolbox)
	image("lock base", l.Base)
	for _, t := range l.Tools {
		where := "lock tools (" + t.Name + ")"
		if t.Version != "" {
			check(where+".version", manifest.CheckWord(t.Version))
		}
		if t.Verification != "" {
			check(where+".verification", manifest.CheckWord(t.Verification))
		}
		if t.Image != nil {
			image(where+".image", *t.Image)
		}
		for p, a := range t.Artifacts {
			check(where+" "+p+".url", manifest.CheckRef(a.URL))
			if !hex64RE.MatchString(a.SHA256) {
				check(where+" "+p+".sha256", fmt.Errorf("%q is not a hex sha256", a.SHA256))
			}
			if a.Extract != "" {
				check(where+" "+p+".extract", manifest.CheckLine(a.Extract))
			}
		}
		for p, n := range t.Nix {
			if !nixStorePath.MatchString(n.Path) {
				check(where+" "+p, fmt.Errorf("%q is not a nix store path", n.Path))
			}
		}
	}
	pk := l.Packages
	for _, v := range []struct{ field, value string }{{"manager", pk.Manager}, {"distro", pk.Distro}, {"snapshot", pk.Snapshot}} {
		check("lock packages."+v.field, manifest.CheckLine(v.value))
	}
	for _, r := range pk.Repositories {
		check("lock packages.repositories", manifest.CheckRef(r))
	}
	for p, pkgs := range pk.Platforms {
		for _, x := range pkgs {
			where := fmt.Sprintf("lock packages %s (%s)", p, x.Name)
			if pk.EffectiveManager() == lock.ManagerAPK {
				if !apkNameRE.MatchString(x.Name) || !apkVersionRE.MatchString(x.Version) {
					check(where, fmt.Errorf("%q %q is not an apk package name and version", x.Name, x.Version))
				}
				if !apkChecksumRE.MatchString(x.Checksum) {
					check(where, fmt.Errorf("checksum %q is not an APKINDEX checksum (Q1…); run clearcutt-factory lock --update", x.Checksum))
				}
				continue
			}
			if x.URL != "" {
				check(where+".url", manifest.CheckRef(x.URL))
			}
			if x.Filename != "" && !pkgFileRE.MatchString(x.Filename) {
				check(where+".filename", fmt.Errorf("%q is not a package file name", x.Filename))
			}
			if x.SHA256 != "" && !hex64RE.MatchString(x.SHA256) {
				check(where+".sha256", fmt.Errorf("%q is not a hex sha256", x.SHA256))
			}
		}
	}
	if l.App != nil {
		image("lock app.build", l.App.Build)
		for p, d := range l.App.RunPlatforms {
			check("lock app.runPlatforms "+p, manifest.CheckDigest(d))
		}
	}
	return errors.Join(errs...)
}

// heredocTag is the delimiter of the heredocs factory writes, unless the
// content holds it.
const heredocTag = "FACTORY_EOF"

// heredoc returns a RUN heredoc of content: "<<'DELIM'\ncontent\nDELIM\n".
// BuildKit ends a heredoc at the first line equal to its delimiter, so the
// delimiter is one that appears nowhere in content: FACTORY_EOF, or when the
// content holds that, FACTORY_EOF_ and the start of the content's sha256
// (with a counter, should that appear too). It depends only on the
// content, so rendering stays reproducible, and a script can't end its
// heredoc early to add instructions of its own.
func heredoc(content string) string {
	delim := heredocTag
	sum := sha256.Sum256([]byte(content))
	for i := 0; strings.Contains(content, delim); i++ {
		delim = heredocTag + "_" + hex.EncodeToString(sum[:8])
		if i > 0 {
			delim += "_" + strconv.Itoa(i)
		}
	}
	return "<<'" + delim + "'\n" + content + "\n" + delim + "\n"
}
